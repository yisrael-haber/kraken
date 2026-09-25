const std = @import("std");
const c = @import("c");
const w = @import("wolfssl");
const lua = @import("../runtime/lua.zig");
const stream = @import("stream.zig");
const limits = @import("../limits.zig");

// wolfSSH runs one exec command per session over a Kraken TCP socket, through
// stream.zig's I/O callbacks. Client and server. No interactive shell: each
// session carries a single command's stdin, stdout and exit status.

const metatable = "kraken.ssh";

const codes: stream.Codes = .{ .closed = w.WS_CBIO_ERR_CONN_CLOSE, .want_read = w.WS_CBIO_ERR_WANT_READ, .failed = w.WS_CBIO_ERR_GENERAL };

fn Io(comptime Context: type) type {
    return stream.Callbacks(Context, ?*w.WOLFSSH, ?*anyopaque, w.word32, codes);
}

/// Called once before any script runs.
pub fn init() void {
    _ = w.wolfSSH_Init();
}

const Session = struct {
    transport: stream.Transport,
    role: stream.Role,
    ctx: ?*w.WOLFSSH_CTX = null,
    ssh: ?*w.WOLFSSH = null,
    /// Set while the handshake runs. wolfSSH's auth and host-key callbacks run
    /// inside that Lua call, and read the options table it holds on its stack.
    handshake: ?Handshake = null,
    /// Set when authorize or host_key_check refused the peer.
    rejected: bool = false,

    fn release(self: *Session) void {
        if (self.ssh) |ssh| w.wolfSSH_free(ssh);
        if (self.ctx) |ctx| w.wolfSSH_CTX_free(ctx);
        self.ssh = null;
        self.ctx = null;
    }

    /// Routes the session's I/O through `input` and `output`.
    fn attach(self: *Session, comptime Context: type, input: *Context, output: *Context) void {
        w.wolfSSH_SetIORecv(self.ctx, Io(Context).receive);
        w.wolfSSH_SetIOSend(self.ctx, Io(Context).send);
        w.wolfSSH_SetIOReadCtx(self.ssh, input);
        w.wolfSSH_SetIOWriteCtx(self.ssh, output);
    }
};

const Handshake = struct { state: ?*c.lua_State, options: c_int };

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "send", sendLua },        .{ "receive", receiveLua }, .{ "command", commandLua },
        .{ "exit_status", exitLua }, .{ "close", closeLua },
    }, collectLua);
    lua.pushFunctions(state, .{ .{ "connect", connectLua }, .{ "accept", acceptLua } });
    return 1;
}

fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    return open(state, .client);
}

fn acceptLua(state: ?*c.lua_State) callconv(.c) c_int {
    return open(state, .server);
}

/// `ssh.connect(tcp, options [, timeout_ms])` / `ssh.accept(tcp, options
/// [, timeout_ms])`: wraps a connected TCP socket, completes the SSH handshake,
/// and sets up the exec channel.
fn open(state: ?*c.lua_State, role: stream.Role) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const session = stream.new(state, metatable, Session{ .transport = transport, .role = role, .handshake = .{ .state = state, .options = 2 } });
    configure(state, session, role, 2);
    session.attach(stream.Transport, &session.transport, &session.transport);
    session.transport.begin(timeout);
    pump(state, session, if (role == .client) w.wolfSSH_connect else w.wolfSSH_accept);
    if (role == .server) awaitCommand(state, session);
    session.handshake = null;
    return 1;
}

fn configure(state: ?*c.lua_State, session: *Session, role: stream.Role, options: c_int) void {
    const endpoint: u8 = if (role == .client) w.WOLFSSH_ENDPOINT_CLIENT else w.WOLFSSH_ENDPOINT_SERVER;
    const ctx = w.wolfSSH_CTX_new(endpoint, null) orelse lua.raise(state, "SSH context allocation failed", .{});
    session.ctx = ctx;
    w.wolfSSH_SetUserAuth(ctx, if (role == .client) clientAuth else serverAuth);
    if (role == .server) {
        const host_key = lua.requiredString(state, options, "host_key");
        // wolfSSH loads DER private keys; PEM host keys are not supported.
        if (w.wolfSSH_CTX_UsePrivateKey_buffer(ctx, host_key.ptr, @intCast(host_key.len), w.WOLFSSH_FORMAT_ASN1) != w.WS_SUCCESS)
            lua.raise(state, "invalid host_key (must be a DER private key)", .{});
        expect(state, options, "authorize", c.LUA_TFUNCTION, true);
    } else {
        w.wolfSSH_CTX_SetPublicKeyCheck(ctx, hostKeyCheck);
        expect(state, options, "host_key_check", c.LUA_TFUNCTION, false);
        expect(state, options, "password", c.LUA_TSTRING, true);
    }
    const ssh = w.wolfSSH_new(ctx) orelse lua.raise(state, "SSH session allocation failed", .{});
    session.ssh = ssh;
    w.wolfSSH_SetUserAuthCtx(ssh, session);
    w.wolfSSH_SetPublicKeyCheckCtx(ssh, session);
    if (role == .client) {
        if (w.wolfSSH_SetUsername(ssh, lua.requiredString(state, options, "username").ptr) != w.WS_SUCCESS)
            lua.raise(state, "invalid username", .{});
        // wolfSSH copies the command.
        const command = lua.requiredString(state, options, "command");
        if (w.wolfSSH_SetChannelType(ssh, w.WOLFSSH_SESSION_EXEC, @constCast(command.ptr), @intCast(command.len)) != w.WS_SUCCESS)
            lua.raise(state, "could not set the command", .{});
    }
}

/// Runs `step` (connect or accept) until success, blocking in the socket
/// callbacks; a rejected peer or timeout raises.
fn pump(state: ?*c.lua_State, session: *Session, step: *const fn (?*w.WOLFSSH) callconv(.c) c_int) void {
    while (step(session.ssh) != w.WS_SUCCESS) {
        if (session.rejected) lua.raise(state, "authentication rejected", .{});
        session.transport.checkTimeout(state);
        if (!retryable(w.wolfSSH_get_error(session.ssh))) fail(state, session, "handshake");
    }
}

/// The exec request may arrive just after accept; run the worker until it does.
fn awaitCommand(state: ?*c.lua_State, session: *Session) void {
    var attempts: usize = 0;
    while (w.wolfSSH_GetSessionType(session.ssh) != w.WOLFSSH_SESSION_EXEC) : (attempts += 1) {
        if (attempts > 64) lua.raise(state, "client did not request a command", .{});
        service(state, session, w.WS_WANT_READ, "handshake");
    }
}

/// Handles a stream call's non-positive `status`: a retryable one (flow control,
/// rekeying, or data not yet processed) runs the worker once, which blocks in the
/// socket callbacks until the peer makes progress; anything else raises.
fn service(state: ?*c.lua_State, session: *Session, status: c_int, stage: [*:0]const u8) void {
    session.transport.checkTimeout(state);
    // WS_ERROR carries the specific cause in the session's error field.
    if (!retryable(if (status == w.WS_ERROR) w.wolfSSH_get_error(session.ssh) else status)) fail(state, session, stage);
    var channel: u32 = 0;
    const result = w.wolfSSH_worker(session.ssh, &channel);
    session.transport.checkTimeout(state);
    if (result != w.WS_SUCCESS and !retryable(result)) fail(state, session, stage);
}

fn retryable(code: c_int) bool {
    return switch (code) {
        0, w.WS_WANT_READ, w.WS_WANT_WRITE, w.WS_WINDOW_FULL, w.WS_REKEYING, w.WS_CHAN_RXD => true,
        else => false,
    };
}

fn sendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const data = session.transport.beginSend(state);
    var sent: usize = 0;
    while (sent < data.len) {
        const result = w.wolfSSH_stream_send(session.ssh, @constCast(data[sent..].ptr), @intCast(data.len - sent));
        // A full peer window waits here for the peer to read and adjust it.
        if (result > 0) sent += @intCast(result) else service(state, session, result, "send");
    }
    return 0;
}

/// Up to `count` bytes of the command's data; nil at end of stream.
fn receiveLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const count = session.transport.beginReceive(state);
    var buffer: [limits.socket_receive_capacity]u8 = undefined;
    while (true) {
        const result = w.wolfSSH_stream_read(session.ssh, &buffer, @intCast(count));
        if (result > 0) {
            lua.pushBytes(state, buffer[0..@intCast(result)]);
            return 1;
        }
        // A read after end of stream returns WS_ERROR with the error set to WS_EOF.
        const code = w.wolfSSH_get_error(session.ssh);
        if (result == w.WS_EOF or code == w.WS_EOF or code == w.WS_CHANNEL_CLOSED) {
            c.lua_pushnil(state);
            return 1;
        }
        service(state, session, result, "receive");
    }
}

/// The command the client requested (server sessions only).
fn commandLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    if (session.role != .server) lua.raise(state, "command is only available on an accepted session", .{});
    const command = w.wolfSSH_GetSessionCommand(session.ssh);
    if (command == null) c.lua_pushnil(state) else _ = c.lua_pushstring(state, command);
    return 1;
}

/// The command's exit status (client sessions only), after the output has ended.
fn exitLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    if (session.role != .client) lua.raise(state, "exit_status is only available on a connected session", .{});
    c.lua_pushinteger(state, w.wolfSSH_GetExitStatus(session.ssh));
    return 1;
}

/// `session:close([exit_status])`: a server sends the exit status and closes the
/// channel, then both end the session and close the TCP socket.
fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ssh) |ssh| {
        session.transport.begin(stream.close_timeout);
        if (session.role == .server) {
            const status = c.luaL_optinteger(state, 2, 0);
            if (status < 0 or status > 255) lua.raise(state, "exit_status must be between 0 and 255", .{});
            _ = w.wolfSSH_stream_exit(ssh, @intCast(status));
        }
        _ = w.wolfSSH_shutdown(ssh);
    }
    session.release();
    session.transport.close();
    return 0;
}

fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

// Callbacks from wolfSSH, on the script's thread during the handshake.

fn sessionOf(ctx: ?*anyopaque) *Session {
    return @ptrCast(@alignCast(ctx.?));
}

const Accessor = *const fn (?*w.WS_UserAuthData, [*c]w.word32) callconv(.c) [*c]const u8;

/// Server user auth: calls the Lua `authorize(username, method, secret)`.
/// wolfSSH runs this callback before it verifies a public-key signature, so a
/// `true` return only authorizes the key as policy; wolfSSH still fails the
/// login when the signature does not verify. A client may offer a key twice (an
/// unsigned probe, then the signed request), so this can run more than once.
fn serverAuth(auth_type: w.byte, data: ?*w.WS_UserAuthData, ctx: ?*anyopaque) callconv(.c) c_int {
    const method: [*:0]const u8, const secret: Accessor, const refused: c_int = switch (auth_type) {
        w.WOLFSSH_USERAUTH_PASSWORD => .{ "password", &w.krakenSshAuthPassword, w.WOLFSSH_USERAUTH_INVALID_PASSWORD },
        w.WOLFSSH_USERAUTH_PUBLICKEY => .{ "publickey", &w.krakenSshAuthPublicKey, w.WOLFSSH_USERAUTH_INVALID_PUBLICKEY },
        else => return w.WOLFSSH_USERAUTH_INVALID_AUTHTYPE,
    };
    const session = sessionOf(ctx);
    const handshake = session.handshake.?;
    const state = handshake.state;
    _ = c.lua_getfield(state, handshake.options, "authorize");
    pushField(state, &w.krakenSshAuthUser, data);
    _ = c.lua_pushstring(state, method);
    pushField(state, secret, data);
    return if (ask(state, session, 3)) w.WOLFSSH_USERAUTH_SUCCESS else refused;
}

fn pushField(state: ?*c.lua_State, accessor: Accessor, data: ?*w.WS_UserAuthData) void {
    var length: w.word32 = 0;
    const bytes = accessor(data, &length);
    lua.pushBytes(state, bytes[0..length]);
}

/// Calls the Lua callback pushed below its `arguments`. A false result or an
/// error refuses the peer and marks the session rejected.
fn ask(state: ?*c.lua_State, session: *Session, arguments: c_int) bool {
    const allowed = c.lua_pcallk(state, arguments, 1, 0, 0, null) == c.LUA_OK and c.lua_toboolean(state, -1) != 0;
    c.lua_pop(state, 1);
    if (!allowed) session.rejected = true;
    return allowed;
}

/// Client user auth: supplies the password.
fn clientAuth(auth_type: w.byte, data: ?*w.WS_UserAuthData, ctx: ?*anyopaque) callconv(.c) c_int {
    if (auth_type != w.WOLFSSH_USERAUTH_PASSWORD) return w.WOLFSSH_USERAUTH_FAILURE;
    const handshake = sessionOf(ctx).handshake.?;
    // Read without raising: a Lua error must not unwind through wolfSSH. The
    // options table keeps the string alive for the whole handshake.
    defer c.lua_pop(handshake.state, 1);
    if (c.lua_getfield(handshake.state, handshake.options, "password") != c.LUA_TSTRING) return w.WOLFSSH_USERAUTH_FAILURE;
    const password = lua.toBytes(handshake.state, -1).?;
    w.krakenSshSetAuthPassword(data, password.ptr, @intCast(password.len));
    return w.WOLFSSH_USERAUTH_SUCCESS;
}

/// Client host-key check: calls the optional Lua `host_key_check(der)`.
fn hostKeyCheck(key: [*c]const w.byte, key_size: w.word32, ctx: ?*anyopaque) callconv(.c) c_int {
    const session = sessionOf(ctx);
    const handshake = session.handshake.?;
    const state = handshake.state;
    if (c.lua_getfield(state, handshake.options, "host_key_check") == c.LUA_TNIL) {
        c.lua_pop(state, 1);
        return 0; // no check: accept any
    }
    lua.pushBytes(state, key[0..key_size]);
    return if (ask(state, session, 1)) 0 else -1;
}

// Helpers.

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ssh == null) lua.raise(state, "SSH session is closed", .{});
    return session;
}

fn fail(state: ?*c.lua_State, session: *Session, stage: [*:0]const u8) noreturn {
    session.transport.checkTimeout(state);
    lua.raise(state, "SSH %s failed: %s", .{ stage, w.wolfSSH_ErrorToName(w.wolfSSH_get_error(session.ssh)) });
}

/// Checks the type of an option that the handshake callbacks read later.
fn expect(state: ?*c.lua_State, options: c_int, name: [*:0]const u8, kind: c_int, required: bool) void {
    if (lua.field(state, options, name, kind)) c.lua_pop(state, 1) else if (required) lua.raise(state, "%s is required", .{name});
}

// The tests run real Lua sessions end to end over stream.Pipe, through every
// option and method of the module, and a send larger than the peer's window.

/// A connected client and server, as the Lua globals `client` and `server`, and
/// the pipes between them.
const Pair = struct {
    to_server: stream.Pipe = .{},
    to_client: stream.Pipe = .{},
    client: *Session = undefined,
    server: *Session = undefined,

    // A session userdata configured from the option table at `options`, wired to
    // the pipes, as the Lua global `name`.
    fn session(state: ?*c.lua_State, role: stream.Role, options: c_int, input: *stream.Pipe, output: *stream.Pipe, name: [*:0]const u8) *Session {
        const value = stream.new(state, metatable, Session{
            .transport = .{ .vm = undefined, .socket = &stream.test_socket },
            .role = role,
            .handshake = .{ .state = state, .options = options },
        });
        configure(state, value, role, options);
        value.attach(stream.Pipe, input, output);
        c.lua_setglobal(state, name);
        return value;
    }

    /// Configures both ends from the option tables at stack indices 1 (client)
    /// and 2 (server), and runs the handshake through the client's exec request.
    fn open(self: *Pair, state: ?*c.lua_State) !void {
        const top = c.lua_gettop(state);
        self.client = session(state, .client, 1, &self.to_client, &self.to_server, "client");
        self.server = session(state, .server, 2, &self.to_server, &self.to_client, "server");
        try std.testing.expectEqual(top, c.lua_gettop(state));
        try std.testing.expect(stream.handshake(w.wolfSSH_connect, self.client.ssh, w.wolfSSH_accept, self.server.ssh, w.WS_SUCCESS));
        for (0..64) |_| {
            if (w.wolfSSH_GetSessionType(self.server.ssh) == w.WOLFSSH_SESSION_EXEC) break;
            var channel: u32 = 0;
            _ = w.wolfSSH_worker(self.server.ssh, &channel);
        }
        try std.testing.expect(w.wolfSSH_GetSessionType(self.server.ssh) == w.WOLFSSH_SESSION_EXEC);
        // Mirror open(): the options are only on the stack during the handshake.
        self.client.handshake = null;
        self.server.handshake = null;
    }
};

/// A Lua state with the module and the two option tables at indices 1 and 2.
fn testOptions() !*c.lua_State {
    init();
    const state = lua.testState("protocols/ssh", module);
    errdefer c.lua_close(state);
    lua.pushBytes(state, @embedFile("testdata/ssh_host.der"));
    c.lua_setglobal(state, "host_key");
    try std.testing.expect(c.LUA_OK == c.luaL_loadstring(state,
        \\return { username = "user", command = "echo hi", password = "pass",
        \\         host_key_check = function(der) return type(der) == "string" and #der > 0 end },
        \\       { host_key = host_key, authorize = function(user, method, secret)
        \\             return user == "user" and method == "password" and secret == "pass" end }
    ));
    try std.testing.expect(c.LUA_OK == c.lua_pcallk(state, 0, 2, 0, 0, null));
    return state;
}

test "ssh exec runs end to end over the full module API" {
    const state = try testOptions();
    defer c.lua_close(state);
    var pair: Pair = .{};
    try pair.open(state);
    try lua.expectScript(state,
        \\assert(server:command() == "echo hi")                           -- the server reads the requested command
        \\assert(not pcall(function() return client:command() end))       -- command is server-only
        \\assert(not pcall(function() return server:exit_status() end))   -- exit_status is client-only
        \\-- data flows both ways: the client sends stdin, the server reads it
        \\client:send("stdin data")
        \\assert(server:receive(64) == "stdin data")
        \\-- the server writes the command's output; the client reads it, with a timeout
        \\server:send("hi\n", 1000)
        \\assert(client:receive(64, 1000) == "hi\n")
        \\-- the server finishes with an exit status; the client drains to end of stream
        \\server:close(7)
        \\assert(client:receive(64) == nil)
        \\assert(client:receive(64) == nil)                                -- and stays there
        \\assert(client:exit_status() == 7)
        \\client:close()
        \\assert(not pcall(function() return client:send("x") end))       -- unusable after close
    );
}

// The flow-control test's reading peer: when the server waits on an empty pipe,
// the client reads everything sent so far, which adjusts the server's window.
var drain_client: ?*w.WOLFSSH = null;
var drained: usize = 0;

fn drainClient() void {
    var buffer: [4096]u8 = undefined;
    while (true) {
        const read = w.wolfSSH_stream_read(drain_client, &buffer, buffer.len);
        if (read <= 0) return;
        drained += @intCast(read);
    }
}

test "ssh send larger than the peer window waits for the peer to read" {
    const state = try testOptions();
    defer c.lua_close(state);
    var pair: Pair = .{};
    try pair.open(state);
    drain_client = pair.client.ssh;
    drained = 0;
    pair.to_server.on_empty = drainClient;
    // Over twice wolfSSH's 128 KiB default window, sent in one call.
    try lua.expectScript(state,
        \\server:send(string.rep("x", 300000))
    );
    drainClient();
    try std.testing.expectEqual(@as(usize, 300000), drained);
}
