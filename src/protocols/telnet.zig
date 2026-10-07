const std = @import("std");
const c = @import("c");
const t = @import("telnet");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const limits = @import("../limits.zig");
const Connection = @import("connection.zig").Connection;

// libtelnet is a codec: it parses the bytes it is given into events and hands back the
// bytes to send. A session wraps a connected TCP socket with the same send/receive shape
// as protocols/tls, and the library's option negotiation (RFC 1143) answers the peer on
// its own, by the `us` and `them` lists the script passes. Everything the library reports
// comes back to the script as events; nothing is decided on its behalf beyond that.

const metatable = "kraken.telnet";
const allocator = std.heap.c_allocator;
/// Data is handed to the library in pieces, so a large send never queues all of its bytes.
const send_chunk = 16 * 1024;

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

const Kind = enum { will, wont, do, dont, subnegotiation, command, warning, @"error" };

/// What the library reported during one call. A subnegotiation's data, or a message,
/// is `session.payloads[start..][0..len]`.
const Event = struct { kind: Kind, value: u8 = 0, start: usize = 0, len: usize = 0 };

const Session = struct {
    wire: Connection,
    telnet: ?*t.telnet_t = null,
    /// The library keeps a pointer to this table: the options the script accepts, ended by -1.
    telopts: [257]t.telnet_telopt_t = undefined,
    /// What the current call collected: application data, the bytes the library wants sent,
    /// and its events with their payloads. Callbacks only append here; Lua and the socket
    /// are touched after the library call returns.
    input: std.ArrayList(u8) = .empty,
    output: std.ArrayList(u8) = .empty,
    events: std.ArrayList(Event) = .empty,
    payloads: std.ArrayList(u8) = .empty,
    out_of_memory: bool = false,

    fn clear(self: *Session) void {
        self.input.clearRetainingCapacity();
        self.output.clearRetainingCapacity();
        self.events.clearRetainingCapacity();
        self.payloads.clearRetainingCapacity();
    }

    pub fn release(self: *Session) void {
        if (self.telnet) |telnet| t.telnet_free(telnet);
        self.input.deinit(allocator);
        self.output.deinit(allocator);
        self.events.deinit(allocator);
        self.payloads.deinit(allocator);
        self.* = .{ .wire = self.wire };
    }

    fn add(self: *Session, kind: Kind, value: u8, payload: []const u8) void {
        self.events.append(allocator, .{ .kind = kind, .value = value, .start = self.payloads.items.len, .len = payload.len }) catch {
            self.out_of_memory = true;
            return;
        };
        self.payloads.appendSlice(allocator, payload) catch {
            self.out_of_memory = true;
        };
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
    _ = create(state, Connection.fromLua(state), 2);
    return 1;
}

/// A session over `wire`, left on the stack top, configured by the options table at `options`.
fn create(state: ?*c.lua_State, wire: Connection, options: c_int) *Session {
    const session = stream.new(state, metatable, Session{ .wire = wire });
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

// The library's events, collected while it runs.

fn handler(_: ?*t.telnet_t, event: [*c]t.telnet_event_t, user: ?*anyopaque) callconv(.c) void {
    const session: *Session = @ptrCast(@alignCast(user.?));
    const ev = event.*;
    switch (@as(c_uint, @intCast(ev.type))) {
        t.TELNET_EV_DATA => session.input.appendSlice(allocator, ev.data.buffer[0..ev.data.size]) catch {
            session.out_of_memory = true;
        },
        t.TELNET_EV_SEND => session.output.appendSlice(allocator, ev.data.buffer[0..ev.data.size]) catch {
            session.out_of_memory = true;
        },
        t.TELNET_EV_IAC => session.add(.command, ev.iac.cmd, ""),
        t.TELNET_EV_WILL => session.add(.will, ev.neg.telopt, ""),
        t.TELNET_EV_WONT => session.add(.wont, ev.neg.telopt, ""),
        t.TELNET_EV_DO => session.add(.do, ev.neg.telopt, ""),
        t.TELNET_EV_DONT => session.add(.dont, ev.neg.telopt, ""),
        t.TELNET_EV_SUBNEGOTIATION => session.add(.subnegotiation, ev.sub.telopt, ev.sub.buffer[0..ev.sub.size]),
        t.TELNET_EV_WARNING => session.add(.warning, 0, std.mem.span(ev.@"error".msg)),
        t.TELNET_EV_ERROR => session.add(.@"error", 0, std.mem.span(ev.@"error".msg)),
        // TTYPE, ENVIRON, MSSP and ZMP are the same subnegotiation, already reported above.
        else => {},
    }
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

/// Writes the bytes the library queued: the data or command just given to it, or its
/// answers to what it just parsed.
fn flush(state: ?*c.lua_State, session: *Session) void {
    if (session.out_of_memory) fail(state, session, "allocation");
    var sent: usize = 0;
    while (sent < session.output.items.len) {
        const result = session.wire.transfer(.send, session.output.items[sent..]);
        if (result <= 0) fail(state, session, "send");
        sent += @intCast(result);
    }
    session.output.clearRetainingCapacity();
}

/// `session:send(data [, timeout_ms])`: sends `data`, doubling any 255 byte.
fn sendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    var data = lua.checkBytes(state, 2);
    session.wire.begin(socket.luaTimeout(state, 3));
    while (data.len > 0) {
        const piece = data[0..@min(data.len, send_chunk)];
        session.clear();
        t.telnet_send(session.telnet, piece.ptr, piece.len);
        flush(state, session);
        data = data[piece.len..];
    }
    return 0;
}

/// `session:receive(count [, timeout_ms])`: once any bytes arrive, the application data
/// they carried, which may be empty, and the list of events they held; `nil` after the
/// peer closes. At most `count` raw bytes are read, so the data is never longer.
fn receiveLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const count = socket.receiveCount(state, 2);
    session.wire.begin(socket.luaTimeout(state, 3));
    var buffer: [limits.socket_receive_capacity]u8 = undefined;
    while (true) {
        session.clear();
        const read = session.wire.transfer(.receive, buffer[0..count]);
        if (read == Connection.codes.closed) {
            c.lua_pushnil(state);
            return 1;
        }
        if (read == Connection.codes.want_read) socket.raiseTimeout(state);
        if (read < 0) fail(state, session, "receive");
        t.telnet_recv(session.telnet, &buffer, @intCast(read));
        flush(state, session);
        if (session.input.items.len > 0 or session.events.items.len > 0) break;
    }
    lua.pushBytes(state, session.input.items);
    c.lua_createtable(state, @intCast(session.events.items.len), 0);
    for (session.events.items, 1..) |event, index| {
        c.lua_createtable(state, 0, 3);
        lua.setString(state, "type", @tagName(event.kind));
        const payload = session.payloads.items[event.start..][0..event.len];
        switch (event.kind) {
            .will, .wont, .do, .dont => lua.setInteger(state, "option", event.value),
            .subnegotiation => {
                lua.setInteger(state, "option", event.value);
                lua.setString(state, "data", payload);
            },
            .command => lua.setInteger(state, "command", event.value),
            .warning, .@"error" => lua.setString(state, "message", payload),
        }
        c.lua_rawseti(state, -2, @intCast(index));
    }
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
    session.clear();
    t.telnet_negotiate(session.telnet, request, option);
    flush(state, session);
    return 0;
}

/// `session:subnegotiate(option, data [, timeout_ms])`: sends IAC SB, the option, `data`
/// with 255 bytes doubled, and IAC SE.
fn subnegotiateLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const option = optionCode(state, 2);
    const data = lua.checkBytes(state, 3);
    session.wire.begin(socket.luaTimeout(state, 4));
    session.clear();
    t.telnet_subnegotiation(session.telnet, option, data.ptr, data.len);
    flush(state, session);
    return 0;
}

/// `session:command(command [, timeout_ms])`: sends IAC and a command, a number from 0 to
/// 255 or a name from `telnet.commands`.
fn commandLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const byte = code(state, 2, &command_names, "command", 0, 255);
    session.wire.begin(socket.luaTimeout(state, 3));
    session.clear();
    t.telnet_iac(session.telnet, byte);
    flush(state, session);
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
        _ = create(self.state, .{ .pipes = self.link.client() }, 1);
        c.lua_setglobal(self.state, "client");
        _ = create(self.state, .{ .pipes = self.link.server() }, 2);
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
