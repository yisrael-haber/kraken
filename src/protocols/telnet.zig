const std = @import("std");
const c = @import("c");
const t = @import("telnet");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const limits = @import("../limits.zig");

// libtelnet is a codec: it parses the bytes it is given into events and hands back the
// bytes to send. A session wraps a connected TCP socket with the same send/receive shape
// as protocols/tls, and the library's option negotiation (RFC 1143) answers the peer on
// its own, by the `us` and `them` lists the script passes. Everything the library reports
// comes back to the script as events; nothing is decided on its behalf beyond that.

const metatable = "kraken.telnet";

const Named = struct { [:0]const u8, u8 };

const option_names = [_]Named{
    .{ "binary", 0 },          .{ "echo", 1 },            .{ "sga", 3 },       .{ "status", 5 },
    .{ "timing_mark", 6 },     .{ "terminal_type", 24 },  .{ "eor", 25 },      .{ "naws", 31 },
    .{ "terminal_speed", 32 }, .{ "flow_control", 33 },   .{ "linemode", 34 }, .{ "x_display", 35 },
    .{ "environ", 36 },        .{ "authentication", 37 }, .{ "encrypt", 38 },  .{ "new_environ", 39 },
    .{ "charset", 42 },        .{ "mssp", 70 },
};

const command_names = [_]Named{
    .{ "eof", 236 }, .{ "susp", 237 }, .{ "abort", 238 }, .{ "eor", 239 }, .{ "nop", 241 }, .{ "dm", 242 },
    .{ "brk", 243 }, .{ "ip", 244 },   .{ "ao", 245 },    .{ "ayt", 246 }, .{ "ec", 247 },  .{ "el", 248 },
    .{ "ga", 249 },
};

const negotiations = [_]Named{ .{ "will", 251 }, .{ "wont", 252 }, .{ "do", 253 }, .{ "dont", 254 } };

const Kind = enum(c_uint) {
    command = t.TELNET_EV_IAC,
    will = t.TELNET_EV_WILL,
    wont = t.TELNET_EV_WONT,
    do = t.TELNET_EV_DO,
    dont = t.TELNET_EV_DONT,
    subnegotiation = t.TELNET_EV_SUBNEGOTIATION,
    warning = t.TELNET_EV_WARNING,
    @"error" = t.TELNET_EV_ERROR,
};

const Session = struct {
    wire: stream.Stream,
    telnet: ?*t.telnet_t = null,
    /// libtelnet borrows this option table until release.
    telopts: [257]t.telnet_telopt_t = undefined,
    state: ?*c.lua_State = null,
    /// Receive storage belongs to the active Lua call, not the session.
    input: []u8 = &.{},
    received: usize = 0,
    events: c_int = 0,
    lua_failed: bool = false,
    /// Coalesce tiny IAC escapes; large library spans go straight to the wire.
    output: [4096]u8 = undefined,
    queued: usize = 0,

    pub fn release(self: *Session) void {
        if (self.telnet) |telnet| t.telnet_free(telnet);
        self.telnet = null;
    }

    fn flush(self: *Session) void {
        if (self.wire.failure != null) return;
        _ = self.wire.transfer(.send, self.output[0..self.queued]) catch {};
        self.queued = 0;
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "send", sendLua },                 .{ "receive", receiveLua }, .{ "negotiate", negotiateLua },
        .{ "subnegotiate", subnegotiateLua }, .{ "command", commandLua }, .{ "close", closeLua },
    }, lua.collector(Session, metatable));
    lua.pushFunctions(state, .{.{ "session", sessionLua }});
    pushNames(state, &option_names, "options");
    pushNames(state, &command_names, "commands");
    return 1;
}

fn pushNames(state: ?*c.lua_State, comptime names: []const Named, name: [*:0]const u8) void {
    c.lua_createtable(state, 0, names.len);
    for (names) |entry| lua.setInteger(state, entry[0], entry[1]);
    c.lua_setfield(state, -2, name);
}

/// `telnet.session(tcp [, options])`: a session over a connected TCP socket. Telnet has
/// no handshake and is the same in both directions, so one constructor serves clients and
/// servers. `us` lists the options the script will perform when the peer asks, `them`
/// those it lets the peer perform; with neither, every request is refused. `proxy = true`
/// turns the library's automatic answers off: every negotiation is reported and the
/// script replies with `negotiate`.
fn sessionLua(state: ?*c.lua_State) callconv(.c) c_int {
    stream.optionsTable(state, false);
    _ = create(state, stream.Stream.fromLua(state), 2);
    return 1;
}

/// A session over `wire`, left on the stack top, configured by the options table at `options`.
fn create(state: ?*c.lua_State, wire: stream.Stream, options: c_int) *Session {
    const session = stream.new(state, metatable, Session{ .wire = wire, .state = state });
    // Every option has an entry that refuses both ways until a list accepts it.
    for (&session.telopts, 0..) |*entry, option| entry.* = .{ .telopt = @intCast(option), .us = t.TELNET_WONT, .him = t.TELNET_DONT };
    session.telopts[256] = .{ .telopt = -1, .us = 0, .him = 0 };
    inline for (.{ "us", "them" }, 0..) |name, which| {
        if (lua.tableField(state, options, name)) |list| {
            for (1..@as(usize, @intCast(c.lua_rawlen(state, list))) + 1) |index| {
                _ = c.lua_rawgeti(state, list, @intCast(index));
                const entry = &session.telopts[optionCode(state, -1)];
                if (which == 0) entry.us = t.TELNET_WILL else entry.him = t.TELNET_DO;
                c.lua_pop(state, 1);
            }
            c.lua_pop(state, 1);
        }
    }
    const proxy = lua.optionalBoolean(state, options, "proxy");
    session.telnet = t.telnet_init(&session.telopts, handler, if (proxy) t.TELNET_FLAG_PROXY else 0, session) orelse
        lua.raise(state, "Telnet session allocation failed", .{});
    return session;
}

/// An option as a number from 0 to 255, or a name from `telnet.options`.
fn optionCode(state: ?*c.lua_State, index: c_int) u8 {
    return code(state, index, &option_names, "option", 0, 255);
}

fn code(state: ?*c.lua_State, index: c_int, comptime names: []const Named, what: [*:0]const u8, low: c.lua_Integer, high: c.lua_Integer) u8 {
    if (c.lua_type(state, index) == c.LUA_TSTRING) {
        const given = lua.toBytes(state, index).?;
        for (names) |entry| if (std.mem.eql(u8, entry[0], given)) return entry[1];
        lua.raise(state, "unknown %s \"%s\"", .{ what, given.ptr });
    }
    const number = c.luaL_checkinteger(state, index);
    if (number < low or number > high) lua.raise(state, "%s must be between %d and %d", .{ what, @as(c_int, @intCast(low)), @as(c_int, @intCast(high)) });
    return @intCast(number);
}

// Only event construction enters Lua, inside pcall. A Lua allocation failure
// returns to the library normally; the caller raises after libtelnet returns.
fn handler(_: ?*t.telnet_t, event: [*c]t.telnet_event_t, user: ?*anyopaque) callconv(.c) void {
    const session: *Session = @ptrCast(@alignCast(user.?));
    if (session.wire.failure != null or session.lua_failed) return;
    const ev = event.*;
    switch (ev.type) {
        t.TELNET_EV_DATA => {
            @memcpy(session.input[session.received..][0..ev.data.size], ev.data.buffer[0..ev.data.size]);
            session.received += ev.data.size;
        },
        t.TELNET_EV_SEND => {
            const bytes = ev.data.buffer[0..ev.data.size];
            if (bytes.len > session.output.len - session.queued) session.flush();
            if (session.wire.failure != null) return;
            if (bytes.len >= session.output.len) {
                _ = session.wire.transfer(.send, @constCast(bytes)) catch {};
            } else {
                @memcpy(session.output[session.queued..][0..bytes.len], bytes);
                session.queued += bytes.len;
            }
        },
        else => {
            // TTYPE, ENVIRON, MSSP and ZMP also emit the raw subnegotiation.
            _ = std.enums.fromInt(Kind, ev.type) orelse return;
            if (session.events == 0) return;
            c.lua_pushcfunction(session.state, pushEvent);
            c.lua_pushlightuserdata(session.state, event);
            c.lua_pushvalue(session.state, session.events);
            session.lua_failed = c.lua_pcallk(session.state, 2, 0, 0, 0, null) != c.LUA_OK;
        },
    }
}

fn pushEvent(state: ?*c.lua_State) callconv(.c) c_int {
    const event: *const t.telnet_event_t = @ptrCast(@alignCast(c.lua_touserdata(state, 1).?));
    c.lua_createtable(state, 0, 3);
    const kind: Kind = @enumFromInt(event.type);
    lua.setString(state, "type", @tagName(kind));
    switch (kind) {
        .command => lua.setInteger(state, "command", event.iac.cmd),
        .will, .wont, .do, .dont => lua.setInteger(state, "option", event.neg.telopt),
        .subnegotiation => {
            lua.setInteger(state, "option", event.sub.telopt);
            lua.setString(state, "data", event.sub.buffer[0..event.sub.size]);
        },
        .warning, .@"error" => lua.setString(state, "message", std.mem.span(event.@"error".msg)),
    }
    c.lua_rawseti(state, 2, @intCast(c.lua_rawlen(state, 2) + 1));
    return 0;
}

// Calls.

const checkSession = lua.liveChecker(Session, metatable, "telnet", "Telnet session is closed");

/// Ends the session after a failure that left the stream in an unknown state.
fn fail(state: ?*c.lua_State, session: *Session, what: [*:0]const u8) noreturn {
    const timed_out = session.wire.timedOut();
    session.release();
    session.wire.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "Telnet %s failed", .{what});
}

fn finish(state: ?*c.lua_State, session: *Session) void {
    if (session.lua_failed) {
        session.release();
        session.wire.close();
        _ = c.lua_error(state);
        unreachable;
    }
    session.flush();
    if (session.wire.failure != null) fail(state, session, "send");
}

/// `session:send(data [, timeout_ms])`: sends `data`, doubling any 255 byte.
fn sendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const data = session.wire.beginSend(state);
    t.telnet_send(session.telnet, data.ptr, data.len);
    finish(state, session);
    return 0;
}

/// `session:receive(count [, timeout_ms])`: once any bytes arrive, the application data
/// they carried, which may be empty, and the list of events they held; `nil` after the
/// peer closes. At most `count` raw bytes are read, so the data is never longer.
fn receiveLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const count = session.wire.beginReceive(state);
    var raw: [limits.socket_receive_capacity]u8 = undefined;
    var decoded: [limits.socket_receive_capacity]u8 = undefined;
    c.lua_createtable(state, 0, 0);
    const events = c.lua_gettop(state);
    // Callback arguments must fit without an unprotected stack allocation.
    if (c.lua_checkstack(state, 3) == 0) lua.raise(state, "Telnet callback stack allocation failed", .{});
    while (true) {
        session.received = 0;
        const read = session.wire.transfer(.receive, raw[0..count]) catch |err| switch (err) {
            error.Closed => {
                c.lua_pushnil(state);
                return 1;
            },
            error.Timeout => socket.raiseTimeout(state),
            error.Failed => fail(state, session, "receive"),
        };
        session.input = decoded[0..count];
        session.events = events;
        t.telnet_recv(session.telnet, &raw, read);
        session.input = &.{};
        session.events = 0;
        finish(state, session);
        if (session.received > 0 or c.lua_rawlen(state, events) > 0) break;
    }
    lua.pushBytes(state, decoded[0..session.received]);
    c.lua_insert(state, -2);
    return 2;
}

/// `session:negotiate(command, option [, timeout_ms])`: sends WILL, WONT, DO or DONT, as
/// `"will"`, `"wont"`, `"do"` or `"dont"`. Outside `proxy` mode the library drops a request
/// that would not change the option's state.
fn negotiateLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const request = code(state, 2, &negotiations, "negotiation", 251, 254);
    const option = optionCode(state, 3);
    session.wire.begin(socket.luaTimeout(state, 4));
    t.telnet_negotiate(session.telnet, request, option);
    finish(state, session);
    return 0;
}

/// `session:subnegotiate(option, data [, timeout_ms])`: sends IAC SB, the option, `data`
/// with 255 bytes doubled, and IAC SE.
fn subnegotiateLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const option = optionCode(state, 2);
    const data = lua.checkBytes(state, 3);
    session.wire.begin(socket.luaTimeout(state, 4));
    t.telnet_subnegotiation(session.telnet, option, data.ptr, data.len);
    finish(state, session);
    return 0;
}

/// `session:command(command [, timeout_ms])`: sends IAC and a command, a number from 0 to
/// 255 or a name from `telnet.commands`.
fn commandLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const byte = code(state, 2, &command_names, "command", 0, 255);
    session.wire.begin(socket.luaTimeout(state, 3));
    t.telnet_iac(session.telnet, byte);
    finish(state, session);
    return 0;
}

/// `session:close()`: ends the session and closes the TCP socket. Telnet has no closing
/// message.
fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    session.release();
    session.wire.close();
    return 0;
}

// The tests run two sessions end to end over stream.Pipe, through every option and
// method of the module.

/// A client and a server as the Lua globals `client` and `server`, configured by the two
/// option tables that `options` returns, with the pipes between them.
const Pair = struct {
    link: stream.Duplex = .{},
    state: *c.lua_State = undefined,

    fn open(self: *Pair, options: [*:0]const u8) !void {
        self.state = lua.testState("protocols/telnet", module);
        try std.testing.expect(c.LUA_OK == c.luaL_loadstring(self.state, options));
        try std.testing.expect(c.LUA_OK == c.lua_pcallk(self.state, 0, 2, 0, 0, null));
        _ = create(self.state, .{ .source = .{ .pipes = self.link.client() } }, 1);
        c.lua_setglobal(self.state, "client");
        _ = create(self.state, .{ .source = .{ .pipes = self.link.server() } }, 2);
        c.lua_setglobal(self.state, "server");
    }

    fn close(self: *Pair) void {
        c.lua_close(self.state);
    }
};

test "telnet negotiates by the option lists and passes data, subnegotiations and commands" {
    var pair: Pair = .{};
    try pair.open("return { us = { \"naws\" }, them = { \"echo\" } }, {}");
    defer pair.close();
    try lua.expectScript(pair.state,
        \\local telnet = require("protocols/telnet")
        \\assert(telnet.options.naws == 31 and telnet.commands.nop == 241)
        \\-- The server offers to echo and asks for the window size; the client accepts both
        \\-- by its lists, and answers without the script's help.
        \\server:negotiate("will", "echo")
        \\server:negotiate("do", telnet.options.naws)
        \\local data, events = client:receive(64, 1000)
        \\assert(data == "" and #events == 2)
        \\assert(events[1].type == "will" and events[1].option == 1)
        \\assert(events[2].type == "do" and events[2].option == 31)
        \\data, events = server:receive(64, 1000)
        \\assert(#events == 2 and events[1].type == "do" and events[1].option == 1)
        \\assert(events[2].type == "will" and events[2].option == 31)
        \\-- A subnegotiation carries its option and bytes, which may include 255.
        \\client:subnegotiate("naws", "\0\80\255\24")
        \\data, events = server:receive(64, 1000)
        \\assert(#events == 1 and events[1].type == "subnegotiation" and events[1].option == 31)
        \\assert(events[1].data == "\0\80\255\24")
        \\-- Data is escaped on the wire and comes back whole.
        \\client:send("hi\255there")
        \\data, events = server:receive(64, 1000)
        \\assert(data == "hi\255there" and #events == 0)
        \\server:command("nop")
        \\client:command(telnet.commands.ga)
        \\data, events = client:receive(64, 1000)
        \\assert(events[1].type == "command" and events[1].command == 241)
        \\data, events = server:receive(64, 1000)
        \\assert(events[1].type == "command" and events[1].command == 249)
        \\-- An option the lists do not accept is refused, and the refusal is not reported.
        \\server:negotiate("will", "binary")
        \\local ok, message = pcall(client.receive, client, 64, 0)
        \\assert(not ok and message:find("timed out"))
        \\ok, message = pcall(server.receive, server, 64, 0)
        \\assert(not ok and message:find("timed out"))
        \\local payload = string.rep("x", 20000) .. string.rep("\255", 12000) .. "\0tail"
        \\client:send(payload)
        \\local parts, received = {}, 0
        \\while received < #payload do
        \\    local part, events = server:receive(32767)
        \\    assert(#events == 0)
        \\    parts[#parts + 1], received = part, received + #part
        \\end
        \\assert(table.concat(parts) == payload)
        \\-- Bad arguments.
        \\assert(not pcall(client.negotiate, client, "maybe", 1))
        \\assert(not pcall(client.negotiate, client, "do", "nonsense"))
        \\assert(not pcall(client.command, client, 256))
        \\assert(not pcall(client.send, client, 1))
        \\client:close()
        \\assert(not pcall(client.send, client, "x"))
    );
}

test "telnet proxy mode reports every negotiation and answers none" {
    var pair: Pair = .{};
    try pair.open("return { proxy = true }, { us = { \"echo\" } }");
    defer pair.close();
    try lua.expectScript(pair.state,
        \\-- The server would accept ECHO, but the proxy client is asked and does not answer.
        \\server:negotiate("will", "echo")
        \\local data, events = client:receive(64, 1000)
        \\assert(#events == 1 and events[1].type == "will" and events[1].option == 1)
        \\assert(not pcall(server.receive, server, 64, 0))
        \\client:negotiate("do", "echo")
        \\data, events = server:receive(64, 1000)
        \\assert(#events == 1 and events[1].type == "do" and events[1].option == 1)
    );
}

// Fail allocation specifically while the native event callback constructs Lua results.
const AllocationFailure = struct {
    original: c.lua_Alloc,
    context: ?*anyopaque,
    session: *Session,

    fn allocate(context: ?*anyopaque, pointer: ?*anyopaque, old: usize, size: usize) callconv(.c) ?*anyopaque {
        const self: *AllocationFailure = @ptrCast(@alignCast(context.?));
        if (size > old and self.session.events != 0) return null;
        return self.original.?(self.context, pointer, old, size);
    }
};

test "Telnet callback allocation failure returns through libtelnet before closing" {
    var pair: Pair = .{};
    try pair.open("return {}, {}");
    defer pair.close();
    try lua.expectScript(pair.state, "server:command('nop')");
    _ = c.lua_getglobal(pair.state, "client");
    const session = lua.checkUserdata(pair.state, -1, Session, metatable);
    c.lua_pop(pair.state, 1);
    var failure: AllocationFailure = .{ .original = null, .context = null, .session = session };
    failure.original = c.lua_getallocf(pair.state, &failure.context);
    // Compile before injecting failure so it targets the callback, not the test script.
    try std.testing.expectEqual(c.LUA_OK, c.luaL_loadstring(pair.state,
        \\local ok, message = pcall(client.receive, client, 64)
        \\assert(not ok and message:find("memory"), message)
        \\assert(not pcall(client.send, client, "x"))
    ));
    c.lua_setallocf(pair.state, AllocationFailure.allocate, &failure);
    defer c.lua_setallocf(pair.state, failure.original, failure.context);
    try std.testing.expectEqual(c.LUA_OK, c.lua_pcallk(pair.state, 0, 0, 0, 0, null));
}
