const std = @import("std");
const c = @import("c");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const etpan_stream = @import("etpan_stream.zig");
const command = @import("../command.zig");

// libetpan does the protocol: its POP3 client reads the greeting, logs in with USER and PASS
// or APOP, lists, retrieves and deletes messages, and quits, over the connection that
// etpan_stream.zig gives it. It lists the mailbox once (LIST, then UIDL) and keeps the
// table, which RETR, TOP and DELE look their message up in.

const metatable = "kraken.pop3";

const Session = struct {
    wire: etpan_stream.Wire = .{},
    pop3: ?*etpan.mailpop3 = null,

    /// Ends the session without protocol I/O; mailpop3_free would send QUIT otherwise.
    fn release(self: *Session) void {
        const pop3 = self.pop3 orelse return;
        self.pop3 = null;
        self.wire.mute = true;
        etpan.mailpop3_free(pop3);
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "login", loginLua },       .{ "apop", apopLua },   .{ "stat", statLua },     .{ "list", listLua },
        .{ "retrieve", retrieveLua }, .{ "top", topLua },     .{ "delete", deleteLua }, .{ "reset", resetLua },
        .{ "info", infoLua },         .{ "close", closeLua },
    }, collectLua);
    lua.pushFunctions(state, .{.{ "connect", connectLua }});
    return 1;
}

/// `pop3.connect(tcp [, timeout_ms])` or `pop3.connect(tls_session [, timeout_ms])`: a POP3
/// client over a connected TCP socket, or over a `protocols/tls` session for POP3S. It
/// reads the greeting.
fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const timeout = socket.luaTimeout(state, 2);
    c.lua_settop(state, 1);
    c.lua_createtable(state, 0, 0);
    c.lua_settop(state, 1);
    const session = etpan_stream.create(state, Session, metatable);
    open(state, session, timeout);
    return 1;
}

fn open(state: ?*c.lua_State, session: *Session, timeout: ?u64) void {
    const pop3 = etpan.mailpop3_new(0, null) orelse lua.raise(state, "POP3 allocation failed", .{});
    session.pop3 = pop3;
    session.wire.transport.begin(timeout);
    check(state, session, etpan.mailpop3_connect(pop3, session.wire.open(state)), "greeting");
}

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.pop3 == null) lua.raise(state, "POP3 session is closed", .{});
    return session;
}

const error_names = [_][:0]const u8{
    "no error",           "bad state",          "unauthorized",       "stream error",       "denied",
    "bad user",           "bad password",       "cannot list",        "no such message",    "out of memory",
    "connection refused", "APOP not supported", "CAPA not supported", "STLS not supported", "TLS error",
    "quit failed",
};

/// Raises for a library error `code`. A broken connection ends the session; a refusal by
/// the server is an error that leaves it usable.
fn check(state: ?*c.lua_State, session: *Session, code: c_int, what: [*:0]const u8) void {
    if (code == etpan.MAILPOP3_NO_ERROR) return;
    const pop3 = session.pop3.?;
    if (session.wire.broken or code == etpan.MAILPOP3_ERROR_STREAM) {
        session.release();
        session.wire.closeConnection();
        session.wire.raiseBroken(state, "POP3");
    }
    const name: [*:0]const u8 = if (code >= 0 and code < error_names.len) error_names[@intCast(code)] else "error";
    if (pop3.*.pop3_response != null) {
        lua.raise(state, "POP3 %s failed: %s (%s)", .{ what, name, pop3.*.pop3_response });
    }
    lua.raise(state, "POP3 %s failed: %s", .{ what, name });
}

/// `session:login(user, password [, timeout_ms])`: USER and PASS.
fn loginLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const user = lua.checkBytes(state, 2);
    const password = lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    check(state, session, etpan.mailpop3_user(session.pop3, user.ptr), "USER");
    check(state, session, etpan.mailpop3_pass(session.pop3, password.ptr), "PASS");
    return 0;
}

/// `session:apop(user, password [, timeout_ms])`: APOP, which needs the greeting's timestamp.
fn apopLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const user = lua.checkBytes(state, 2);
    const password = lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    check(state, session, etpan.mailpop3_apop(session.pop3, user.ptr, password.ptr), "APOP");
    return 0;
}

/// `session:stat([timeout_ms])`: the number of messages and their total size.
fn statLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    session.wire.begin(state, 2);
    var result: ?*etpan.struct_mailpop3_stat_response = null;
    check(state, session, etpan.mailpop3_stat(session.pop3, &result), "STAT");
    c.lua_pushinteger(state, result.?.msgs_count);
    c.lua_pushinteger(state, @intCast(result.?.msgs_size));
    etpan.mailpop3_stat_resp_free(result);
    return 2;
}

/// `session:list([timeout_ms])`: the messages as `{ index, size, uidl }`, `uidl` being
/// absent when the server has no UIDL. The first call asks the server; later calls reuse
/// the answer.
fn listLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    session.wire.begin(state, 2);
    var table: [*c]etpan.carray = null;
    check(state, session, etpan.mailpop3_list(session.pop3, &table), "LIST");
    const count = etpan.carray_count(table);
    c.lua_createtable(state, @intCast(count), 0);
    for (0..count) |position| {
        const info: *etpan.struct_mailpop3_msg_info = @ptrCast(@alignCast(etpan.carray_get(table, @intCast(position))));
        c.lua_createtable(state, 0, 3);
        lua.setInteger(state, "index", info.msg_index);
        lua.setInteger(state, "size", info.msg_size);
        if (info.msg_uidl != null) lua.setString(state, "uidl", std.mem.span(info.msg_uidl));
        c.lua_rawseti(state, -2, @intCast(position + 1));
    }
    return 1;
}

/// `session:retrieve(index [, timeout_ms])`: the whole message, with its dots unstuffed.
fn retrieveLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const index = messageIndex(state, 2);
    session.wire.begin(state, 3);
    var message: [*c]u8 = null;
    var length: usize = 0;
    check(state, session, etpan.mailpop3_retr(session.pop3, index, &message, &length), "RETR");
    lua.pushBytes(state, message[0..length]);
    etpan.mailpop3_retr_free(message);
    return 1;
}

/// `session:top(index, lines [, timeout_ms])`: the message's headers and its first `lines` lines.
fn topLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const index = messageIndex(state, 2);
    const lines = c.luaL_checkinteger(state, 3);
    if (lines < 0 or lines > std.math.maxInt(c_int)) lua.raise(state, "lines must be zero or more", .{});
    session.wire.begin(state, 4);
    var message: [*c]u8 = null;
    var length: usize = 0;
    check(state, session, etpan.mailpop3_top(session.pop3, index, @intCast(lines), &message, &length), "TOP");
    lua.pushBytes(state, message[0..length]);
    etpan.mailpop3_top_free(message);
    return 1;
}

/// `session:delete(index [, timeout_ms])`: DELE; the server removes it when the session quits.
fn deleteLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const index = messageIndex(state, 2);
    session.wire.begin(state, 3);
    check(state, session, etpan.mailpop3_dele(session.pop3, index), "DELE");
    return 0;
}

/// `session:reset([timeout_ms])`: RSET, which undoes the deletions of this session.
fn resetLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    session.wire.begin(state, 2);
    check(state, session, etpan.mailpop3_rset(session.pop3), "RSET");
    return 0;
}

fn messageIndex(state: ?*c.lua_State, position: c_int) c_uint {
    const index = c.luaL_checkinteger(state, position);
    if (index < 1 or index > std.math.maxInt(c_int)) lua.raise(state, "message index must be 1 or more", .{});
    return @intCast(index);
}

/// `session:info()`: the server's last response line.
fn infoLua(state: ?*c.lua_State) callconv(.c) c_int {
    const pop3 = checkSession(state).pop3.?;
    c.lua_createtable(state, 0, 1);
    if (pop3.*.pop3_response != null) lua.setString(state, "response", std.mem.span(pop3.*.pop3_response));
    return 1;
}

/// `session:close()`: QUIT, then ends the session and closes the TCP socket.
fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.pop3) |pop3| {
        session.wire.transport.begin(stream.close_timeout);
        _ = etpan.mailpop3_quit(pop3);
        session.release();
    }
    session.wire.closeConnection();
    return 0;
}

fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

// The test runs a real Lua session over in-memory pipes against a scripted server.

const Duplex = struct {
    to_server: stream.Pipe = .{},
    to_client: stream.Pipe = .{},

    pub fn transfer(self: *Duplex, action: command.SocketAction, bytes: []u8, codes: stream.Codes) c_int {
        return if (action == .send) self.to_server.transfer(.send, bytes, codes) else self.to_client.transfer(.receive, bytes, codes);
    }
};

var test_link: ?*Duplex = null;
var test_log: [1024]u8 = undefined;
var test_log_len: usize = 0;

/// Runs when the client waits for a reply: logs what it sent and answers the last command.
fn scriptedServer() void {
    const link = test_link.?;
    const request = link.to_server.bytes[0..link.to_server.len];
    @memcpy(test_log[test_log_len..][0..request.len], request);
    test_log_len += request.len;
    link.to_server.len = 0;
    const reply: []const u8 = blk: {
        if (std.mem.startsWith(u8, request, "USER")) break :blk "+OK\r\n";
        if (std.mem.startsWith(u8, request, "PASS")) break :blk if (std.mem.indexOf(u8, request, "secret") != null) "+OK logged in\r\n" else "-ERR invalid password\r\n";
        if (std.mem.startsWith(u8, request, "STAT")) break :blk "+OK 2 300\r\n";
        if (std.mem.startsWith(u8, request, "LIST")) break :blk "+OK 2 messages\r\n1 100\r\n2 200\r\n.\r\n";
        if (std.mem.startsWith(u8, request, "UIDL")) break :blk "+OK\r\n1 abc\r\n2 def\r\n.\r\n";
        if (std.mem.startsWith(u8, request, "RETR 1")) break :blk "+OK 100 octets\r\nSubject: one\r\n\r\n..dot\r\nbody\r\n.\r\n";
        if (std.mem.startsWith(u8, request, "TOP 2 1")) break :blk "+OK\r\nSubject: two\r\n\r\nfirst\r\n.\r\n";
        if (std.mem.startsWith(u8, request, "DELE")) break :blk "+OK marked\r\n";
        if (std.mem.startsWith(u8, request, "RSET")) break :blk "+OK\r\n";
        if (std.mem.startsWith(u8, request, "QUIT")) break :blk "+OK bye\r\n";
        break :blk "-ERR unknown\r\n";
    };
    _ = link.to_client.transfer(.send, @constCast(reply), .{ .closed = -1, .want_read = -1, .failed = -1 });
}

/// Opens a session over `test_link`, like `connect`.
fn openOverPipes(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_settop(state, 0);
    c.lua_createtable(state, 0, 0);
    const session = stream.new(state, metatable, Session{});
    session.wire.own = .{ .vm = undefined, .socket = &stream.test_socket };
    session.wire.transport = &session.wire.own;
    session.wire.attach(Duplex, test_link.?);
    open(state, session, null);
    return 1;
}

test "pop3 session round trip against a scripted server" {
    const state = lua.testState("protocols/pop3", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    link.to_client.on_empty = scriptedServer;
    test_link = &link;
    test_log_len = 0;
    _ = link.to_client.transfer(.send, @constCast("+OK POP3 ready <1.2@example.test>\r\n"), .{ .closed = -1, .want_read = -1, .failed = -1 });
    c.lua_pushcclosure(state, openOverPipes, 0);
    try std.testing.expect(c.LUA_OK == c.lua_pcallk(state, 0, 1, 0, 0, null));
    c.lua_setglobal(state, "mail");
    try lua.expectScript(state,
        \\local ok, err = pcall(mail.login, mail, "user", "wrong")
        \\assert(not ok and err:find("invalid password", 1, true), err)
        \\mail:login("user", "secret")
        \\local count, size = mail:stat()
        \\assert(count == 2 and size == 300 and mail:info().response:find("2 300", 1, true))
        \\local list = mail:list()
        \\assert(#list == 2 and list[1].index == 1 and list[1].size == 100 and list[1].uidl == "abc" and list[2].uidl == "def")
        \\assert(mail:retrieve(1):find("Subject: one\r\n\r\n.dot\r\nbody", 1, true))
        \\assert(mail:top(2, 1):find("Subject: two", 1, true))
        \\mail:delete(1)
        \\mail:reset()
        \\ok, err = pcall(mail.retrieve, mail, 9)
        \\assert(not ok and err:find("no such message", 1, true), err)
        \\assert(not pcall(mail.retrieve, mail, 0))
        \\mail:close()
        \\assert(not pcall(mail.stat, mail))
    );
    @memcpy(test_log[test_log_len..][0..link.to_server.len], link.to_server.bytes[0..link.to_server.len]);
    const log = test_log[0 .. test_log_len + link.to_server.len];
    for ([_][]const u8{ "USER user\r\n", "PASS secret\r\n", "RETR 1\r\n", "TOP 2 1\r\n", "DELE 1\r\n", "RSET\r\n", "QUIT" }) |expected| {
        if (std.mem.indexOf(u8, log, expected) == null) {
            std.debug.print("the client never sent {s}\n", .{expected});
            return error.TestUnexpectedResult;
        }
    }
}

test "pop3 session ends when the server goes silent" {
    const state = lua.testState("protocols/pop3", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    test_link = &link;
    c.lua_pushcclosure(state, openOverPipes, 0);
    // The pipe is empty: no greeting ever comes.
    try std.testing.expect(c.LUA_OK != c.lua_pcallk(state, 0, 1, 0, 0, null));
    try std.testing.expect(std.mem.indexOf(u8, lua.toBytes(state, -1).?, "POP3 connection failed") != null);
}
