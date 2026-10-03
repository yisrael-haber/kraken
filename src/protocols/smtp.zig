const std = @import("std");
const c = @import("c");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const etpan_stream = @import("etpan_stream.zig");
const command = @import("../command.zig");

// libetpan does the protocol: its SMTP client reads the greeting, says EHLO, authenticates
// with AUTH PLAIN or LOGIN, runs the MAIL, RCPT and DATA exchange and quits, over the
// connection that etpan_stream.zig gives it. A patch to the vendored mailsmtp.c lets the
// script name what EHLO announces, which libetpan would take from the host's own name.

const metatable = "kraken.smtp";
const hostname_capacity = 255;

const Session = struct {
    wire: etpan_stream.Wire = .{},
    smtp: ?*etpan.mailsmtp = null,
    /// The name HELO and EHLO announce; the library keeps a pointer to it.
    hostname: [hostname_capacity:0]u8 = @splat(0),

    /// Ends the session without protocol I/O; mailsmtp_free would send QUIT otherwise.
    fn release(self: *Session) void {
        const smtp = self.smtp orelse return;
        self.smtp = null;
        self.wire.mute = true;
        etpan.mailsmtp_free(smtp);
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "login", loginLua }, .{ "send", sendLua }, .{ "info", infoLua }, .{ "close", closeLua },
    }, collectLua);
    lua.pushFunctions(state, .{.{ "connect", connectLua }});
    return 1;
}

/// `smtp.connect(tcp [, options [, timeout_ms]])` or `smtp.connect(tls_session [, ...])`: an
/// SMTP client over a connected TCP socket, or over a `protocols/tls` session for SMTPS. It
/// reads the greeting and says EHLO (HELO if the server refuses EHLO). `options.hostname` is
/// the name announced, `"localhost"` by default.
fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const timeout = socket.luaTimeout(state, 3);
    if (c.lua_isnoneornil(state, 2)) {
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 0);
    }
    c.luaL_checktype(state, 2, c.LUA_TTABLE);
    c.lua_settop(state, 2);
    const session = etpan_stream.create(state, Session, metatable);
    open(state, session, 2, timeout);
    return 1;
}

fn open(state: ?*c.lua_State, session: *Session, options: c_int, timeout: ?u64) void {
    const name = lua.optionalString(state, options, "hostname") orelse "localhost";
    if (name.len > hostname_capacity) lua.raise(state, "hostname is longer than %d bytes", .{@as(c_int, hostname_capacity)});
    @memcpy(session.hostname[0..name.len], name);
    const smtp = etpan.mailsmtp_new(0, null) orelse lua.raise(state, "SMTP allocation failed", .{});
    smtp.*.smtp_hostname = &session.hostname;
    session.smtp = smtp;
    session.wire.transport.begin(timeout);
    check(state, session, etpan.mailsmtp_connect(smtp, session.wire.open(state)), "greeting");
    var code = etpan.mailesmtp_ehlo(smtp);
    if (code == etpan.MAILSMTP_ERROR_NOT_IMPLEMENTED) code = etpan.mailsmtp_helo(smtp);
    check(state, session, code, "EHLO");
}

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.smtp == null) lua.raise(state, "SMTP session is closed", .{});
    return session;
}

/// Raises for a library error `code`. A broken connection ends the session; a refusal by
/// the server is an error that leaves it usable.
fn check(state: ?*c.lua_State, session: *Session, code: c_int, what: [*:0]const u8) void {
    if (code == etpan.MAILSMTP_NO_ERROR) return;
    const smtp = session.smtp.?;
    if (session.wire.broken or code == etpan.MAILSMTP_ERROR_STREAM) {
        session.release();
        session.wire.closeConnection();
        session.wire.raiseBroken(state, "SMTP");
    }
    const response: [*:0]const u8 = if (smtp.*.response != null) @ptrCast(smtp.*.response) else "no response";
    lua.raise(state, "SMTP %s failed: %d %s", .{ what, smtp.*.response_code, response });
}

/// `session:login(user, password [, timeout_ms])`: AUTH PLAIN or LOGIN, whichever the server offers.
fn loginLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const user = lua.checkBytes(state, 2);
    const password = lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    check(state, session, etpan.mailsmtp_auth(session.smtp, user.ptr, password.ptr), "login");
    return 0;
}

/// `session:send({ from, to, message } [, timeout_ms])`: MAIL FROM, RCPT TO for each
/// address in `to` (a string or a list), then DATA with `message`, which is the whole
/// message, headers included; libetpan only stuffs its dots and ends it.
fn sendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    c.luaL_checktype(state, 2, c.LUA_TTABLE);
    session.wire.begin(state, 3);
    const from = lua.requiredString(state, 2, "from");
    const message = lua.requiredString(state, 2, "message");
    const recipients = recipientList(state);
    check(state, session, etpan.mailesmtp_mail(session.smtp, from.ptr, 0, null), "MAIL FROM");
    for (1..@as(usize, @intCast(c.lua_rawlen(state, recipients))) + 1) |index| {
        _ = c.lua_rawgeti(state, recipients, @intCast(index));
        const to = lua.stringAt(state, -1, "to");
        c.lua_pop(state, 1);
        check(state, session, etpan.mailesmtp_rcpt(session.smtp, to.ptr, 0, null), "RCPT TO");
    }
    check(state, session, etpan.mailsmtp_data(session.smtp), "DATA");
    check(state, session, etpan.mailsmtp_data_message(session.smtp, message.ptr, message.len), "message");
    return 0;
}

/// The stack index of `to` as a list: a string becomes a list of one.
fn recipientList(state: ?*c.lua_State) c_int {
    switch (c.lua_getfield(state, 2, "to")) {
        c.LUA_TTABLE => {},
        c.LUA_TSTRING => {
            c.lua_createtable(state, 1, 0);
            c.lua_pushvalue(state, -2);
            c.lua_rawseti(state, -2, 1);
        },
        else => lua.raise(state, "to must be an address or a list of addresses", .{}),
    }
    return c.lua_gettop(state);
}

/// `session:info()`: the server's last response and what its EHLO offered.
fn infoLua(state: ?*c.lua_State) callconv(.c) c_int {
    const smtp = checkSession(state).smtp.?;
    c.lua_createtable(state, 0, 5);
    lua.setInteger(state, "code", smtp.*.response_code);
    if (smtp.*.response != null) lua.setString(state, "response", std.mem.span(smtp.*.response));
    if (smtp.*.smtp_max_msg_size > 0) lua.setInteger(state, "size", smtp.*.smtp_max_msg_size);
    pushFlags(state, "extensions", smtp.*.esmtp, &.{
        .{ "expn", etpan.MAILSMTP_ESMTP_EXPN },             .{ "8bitmime", etpan.MAILSMTP_ESMTP_8BITMIME }, .{ "size", etpan.MAILSMTP_ESMTP_SIZE },
        .{ "etrn", etpan.MAILSMTP_ESMTP_ETRN },             .{ "starttls", etpan.MAILSMTP_ESMTP_STARTTLS }, .{ "dsn", etpan.MAILSMTP_ESMTP_DSN },
        .{ "pipelining", etpan.MAILSMTP_ESMTP_PIPELINING },
    });
    pushFlags(state, "auth", smtp.*.auth, &.{
        .{ "cram_md5", etpan.MAILSMTP_AUTH_CRAM_MD5 },     .{ "plain", etpan.MAILSMTP_AUTH_PLAIN },   .{ "login", etpan.MAILSMTP_AUTH_LOGIN },
        .{ "digest_md5", etpan.MAILSMTP_AUTH_DIGEST_MD5 }, .{ "gssapi", etpan.MAILSMTP_AUTH_GSSAPI }, .{ "ntlm", etpan.MAILSMTP_AUTH_NTLM },
    });
    return 1;
}

/// Sets `name` on the table at the stack top to a table of the `flags` bits that are set.
fn pushFlags(state: ?*c.lua_State, name: [*:0]const u8, value: c_int, comptime flags: []const struct { [:0]const u8, c_int }) void {
    c.lua_createtable(state, 0, flags.len);
    inline for (flags) |flag| {
        if (value & flag[1] != 0) {
            c.lua_pushboolean(state, 1);
            c.lua_setfield(state, -2, flag[0]);
        }
    }
    c.lua_setfield(state, -2, name);
}

/// `session:close()`: QUIT, then ends the session and closes the TCP socket.
fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.smtp) |smtp| {
        session.wire.transport.begin(stream.close_timeout);
        _ = etpan.mailsmtp_quit(smtp);
        session.wire.mute = true;
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
var test_log: [4096]u8 = undefined;
var test_log_len: usize = 0;

/// Runs when the client waits for a reply: logs what it sent and answers the last command.
fn scriptedServer() void {
    const link = test_link.?;
    const request = link.to_server.bytes[0..link.to_server.len];
    @memcpy(test_log[test_log_len..][0..request.len], request);
    test_log_len += request.len;
    link.to_server.len = 0;
    const reply: []const u8 = blk: {
        if (std.mem.startsWith(u8, request, "EHLO")) break :blk "250-mail.example.test\r\n250-SIZE 1000\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n";
        // AUTH PLAIN is two steps: the command, then the credentials as one base64 line.
        if (std.mem.startsWith(u8, request, "AUTH PLAIN")) break :blk "334 \r\n";
        if (std.mem.indexOfScalar(u8, request, ' ') == null and request.len > 4 and request[0] >= 'A' and request[request.len - 1] == '\n' and !std.mem.startsWith(u8, request, "QUIT") and !std.mem.startsWith(u8, request, "DATA")) {
            break :blk if (std.mem.indexOf(u8, request, "AHUAdw==") != null) "235 2.7.0 Authentication successful\r\n" else "535 5.7.8 Authentication credentials invalid\r\n";
        }
        if (std.mem.startsWith(u8, request, "MAIL")) break :blk "250 2.1.0 Ok\r\n";
        if (std.mem.startsWith(u8, request, "RCPT")) break :blk if (std.mem.indexOf(u8, request, "nobody") != null) "550 5.1.1 No such user\r\n" else "250 2.1.5 Ok\r\n";
        if (std.mem.startsWith(u8, request, "DATA")) break :blk "354 End data with <CR><LF>.<CR><LF>\r\n";
        if (std.mem.endsWith(u8, request, "\r\n.\r\n")) break :blk "250 2.0.0 Ok: queued as 1234\r\n";
        if (std.mem.startsWith(u8, request, "QUIT")) break :blk "221 2.0.0 Bye\r\n";
        break :blk "500 5.5.2 Error\r\n";
    };
    _ = link.to_client.transfer(.send, @constCast(reply), .{ .closed = -1, .want_read = -1, .failed = -1 });
}

/// Opens a session over `test_link` with the options table at index 1, like `connect`.
fn openOverPipes(state: ?*c.lua_State) callconv(.c) c_int {
    const session = stream.new(state, metatable, Session{});
    session.wire.own = .{ .vm = undefined, .socket = &stream.test_socket };
    session.wire.transport = &session.wire.own;
    session.wire.attach(Duplex, test_link.?);
    open(state, session, 1, null);
    return 1;
}

/// Pushes the session `openOverPipes` makes from the options `chunk` returns, or returns the Lua error.
fn testSession(state: ?*c.lua_State, chunk: [*:0]const u8) !bool {
    try std.testing.expect(c.LUA_OK == c.luaL_loadstring(state, chunk));
    try std.testing.expect(c.LUA_OK == c.lua_pcallk(state, 0, 1, 0, 0, null));
    c.lua_pushcclosure(state, openOverPipes, 0);
    c.lua_insert(state, -2);
    return c.LUA_OK == c.lua_pcallk(state, 1, 1, 0, 0, null);
}

test "smtp session round trip against a scripted server" {
    const state = lua.testState("protocols/smtp", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    link.to_client.on_empty = scriptedServer;
    test_link = &link;
    test_log_len = 0;
    _ = link.to_client.transfer(.send, @constCast("220 mail.example.test ESMTP\r\n"), .{ .closed = -1, .want_read = -1, .failed = -1 });
    try std.testing.expect(try testSession(state, "return { hostname = 'kraken.lab' }"));
    c.lua_setglobal(state, "mail");
    try lua.expectScript(state,
        \\local info = mail:info()
        \\assert(info.code == 250 and info.size == 1000 and info.extensions.size and info.extensions.starttls)
        \\assert(info.auth.plain and info.auth.login and not info.auth.cram_md5)
        \\local ok, err = pcall(mail.login, mail, "user", "wrong")
        \\assert(not ok and err:find("535", 1, true) and err:find("Authentication credentials invalid", 1, true), err)
        \\mail:login("u", "w")
        \\mail:send({ from = "a@example.test", to = { "b@example.test", "c@example.test" },
        \\    message = "From: a@example.test\r\nSubject: hi\r\n\r\n.dot first\r\nbody\r\n" })
        \\assert(mail:info().response:find("queued as 1234", 1, true))
        \\ok, err = pcall(mail.send, mail, { from = "a@example.test", to = "nobody@example.test", message = "x\r\n" })
        \\assert(not ok and err:find("550", 1, true) and err:find("No such user", 1, true), err)
        \\assert(not pcall(mail.send, mail, { from = "a@example.test", message = "x" }))
        \\mail:close()
        \\assert(not pcall(mail.info, mail))
    );
    // QUIT is sent without waiting for a reply, so it is still in the pipe.
    @memcpy(test_log[test_log_len..][0..link.to_server.len], link.to_server.bytes[0..link.to_server.len]);
    const log = test_log[0 .. test_log_len + link.to_server.len];
    // The announced name is the script's, not the host's, and the data is dot-stuffed.
    for ([_][]const u8{ "EHLO kraken.lab\r\n", "MAIL FROM:<a@example.test>", "RCPT TO:<c@example.test>", "\r\n..dot first\r\n", "QUIT" }) |expected| {
        if (std.mem.indexOf(u8, log, expected) == null) {
            std.debug.print("the client never sent {s}\n", .{expected});
            return error.TestUnexpectedResult;
        }
    }
}

test "smtp session ends when the server goes silent" {
    const state = lua.testState("protocols/smtp", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    test_link = &link;
    _ = link.to_client.transfer(.send, @constCast("220 mail.example.test ESMTP\r\n"), .{ .closed = -1, .want_read = -1, .failed = -1 });
    // The pipe holds the greeting only: EHLO's reply never comes.
    try std.testing.expect(!try testSession(state, "return {}"));
    try std.testing.expect(std.mem.indexOf(u8, lua.toBytes(state, -1).?, "SMTP connection failed") != null);
}

test "smtp reads the extensions of an EHLO with an empty AUTH line, as aiosmtpd sends it" {
    const state = lua.testState("protocols/smtp", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    test_link = &link;
    _ = link.to_client.transfer(.send, @constCast("220 lab ESMTP\r\n250-lab\r\n250-SIZE 33554432\r\n250-8BITMIME\r\n250-AUTH \r\n250 HELP\r\n"), .{ .closed = -1, .want_read = -1, .failed = -1 });
    try std.testing.expect(try testSession(state, "return {}"));
    c.lua_setglobal(state, "mail");
    try lua.expectScript(state,
        \\local info = mail:info()
        \\assert(info.extensions.size and info.extensions["8bitmime"] and info.size == 33554432, tostring(info.size))
    );
}
