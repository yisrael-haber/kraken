const std = @import("std");
const c = @import("c");
const w = @import("wolfssl");
const lua = @import("../runtime/lua.zig");
const stream = @import("stream.zig");
const limits = @import("../limits.zig");

// wolfSSL runs TLS over a Kraken TCP socket through stream.zig's I/O callbacks.

const metatable = "kraken.tls";

const codes: stream.Codes = .{ .closed = w.WOLFSSL_CBIO_ERR_CONN_CLOSE, .want_read = w.WOLFSSL_CBIO_ERR_WANT_READ, .failed = w.WOLFSSL_CBIO_ERR_GENERAL };

fn Io(comptime Context: type) type {
    return stream.Callbacks(Context, ?*w.WOLFSSL, [*c]u8, c_int, codes);
}

/// Called once before any script runs; wolfSSL's first-call locking is not
/// thread-safe on every platform.
pub fn init() void {
    _ = w.wolfSSL_Init();
}

const Session = struct {
    transport: stream.Transport,
    ctx: ?*w.WOLFSSL_CTX = null,
    ssl: ?*w.WOLFSSL = null,

    fn release(self: *Session) void {
        if (self.ssl) |ssl| w.wolfSSL_free(ssl);
        if (self.ctx) |ctx| w.wolfSSL_CTX_free(ctx);
        self.ssl = null;
        self.ctx = null;
    }

    /// Routes the session's I/O through `input` and `output`.
    fn attach(self: *Session, comptime Context: type, input: *Context, output: *Context) void {
        w.wolfSSL_SSLSetIORecv(self.ssl, Io(Context).receive);
        w.wolfSSL_SSLSetIOSend(self.ssl, Io(Context).send);
        w.wolfSSL_SetIOReadCtx(self.ssl, input);
        w.wolfSSL_SetIOWriteCtx(self.ssl, output);
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{ .{ "send", sendLua }, .{ "receive", receiveLua }, .{ "close", closeLua }, .{ "info", infoLua } }, collectLua);
    lua.pushFunctions(state, .{ .{ "connect", connectLua }, .{ "accept", acceptLua } });
    return 1;
}

fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    return open(state, .client);
}

fn acceptLua(state: ?*c.lua_State) callconv(.c) c_int {
    return open(state, .server);
}

/// `tls.connect(tcp [, options [, timeout_ms]])` / `tls.accept(tcp, options
/// [, timeout_ms])`: wraps a connected TCP socket and completes the handshake.
fn open(state: ?*c.lua_State, role: stream.Role) c_int {
    const transport, const timeout = stream.arguments(state, role == .server);
    const session = stream.new(state, metatable, Session{ .transport = transport });
    configure(state, session, role, 2);
    session.attach(stream.Transport, &session.transport, &session.transport);
    session.transport.begin(timeout);
    const result = if (role == .client) w.wolfSSL_connect(session.ssl) else w.wolfSSL_accept(session.ssl);
    if (result != w.WOLFSSL_SUCCESS) fail(state, session, result);
    return 1;
}

/// Builds the context and session from the options table at `options`.
fn configure(state: ?*c.lua_State, session: *Session, role: stream.Role, options: c_int) void {
    const Version = enum { @"1.2", @"1.3" };
    const version: ?Version = if (lua.optionalString(state, options, "version")) |value|
        std.meta.stringToEnum(Version, value) orelse lua.raise(state, "version must be \"1.2\" or \"1.3\"", .{})
    else
        null;
    const method = if (version) |pinned| switch (pinned) {
        .@"1.2" => if (role == .client) w.wolfTLSv1_2_client_method() else w.wolfTLSv1_2_server_method(),
        .@"1.3" => if (role == .client) w.wolfTLSv1_3_client_method() else w.wolfTLSv1_3_server_method(),
    } else if (role == .client) w.wolfSSLv23_client_method() else w.wolfSSLv23_server_method();
    const ctx = w.wolfSSL_CTX_new(method) orelse lua.raise(state, "TLS context allocation failed", .{});
    session.ctx = ctx;
    const verify = lua.optionalBoolean(state, options, "verify");
    w.wolfSSL_CTX_set_verify(ctx, if (verify) w.WOLFSSL_VERIFY_PEER else w.WOLFSSL_VERIFY_NONE, null);
    if (lua.optionalString(state, options, "ca")) |pem| {
        check(state, w.wolfSSL_CTX_load_verify_buffer(ctx, pem.ptr, @intCast(pem.len), w.WOLFSSL_FILETYPE_PEM), "ca");
    } else if (verify) lua.raise(state, "verify requires ca", .{});
    const certificate = lua.optionalString(state, options, "certificate");
    const key = lua.optionalString(state, options, "key");
    if (role == .server and (certificate == null or key == null)) lua.raise(state, "accept requires certificate and key", .{});
    if (certificate) |pem| check(state, w.wolfSSL_CTX_use_certificate_chain_buffer(ctx, pem.ptr, @intCast(pem.len)), "certificate");
    if (key) |pem| check(state, w.wolfSSL_CTX_use_PrivateKey_buffer(ctx, pem.ptr, @intCast(pem.len), w.WOLFSSL_FILETYPE_PEM), "key");
    const ssl = w.wolfSSL_new(ctx) orelse lua.raise(state, "TLS session allocation failed", .{});
    session.ssl = ssl;
    if (lua.optionalString(state, options, "server_name")) |name| {
        check(state, w.wolfSSL_UseSNI(ssl, w.WOLFSSL_SNI_HOST_NAME, name.ptr, @intCast(name.len)), "server_name");
        // The domain check applies to the peer's certificate, so only a client
        // checks the server's name; a server's server_name is the name it answers to.
        if (verify and role == .client) check(state, w.wolfSSL_check_domain_name(ssl, name.ptr), "server_name");
    }
    if (lua.tableField(state, options, "alpn")) |list| {
        defer c.lua_settop(state, list - 1);
        // wolfSSL takes a comma-separated protocol list, which it copies and bounds.
        var buffer: lua.Buffer = undefined;
        buffer.init(state);
        var index: c.lua_Integer = 1;
        while (index <= c.lua_rawlen(state, list)) : (index += 1) {
            if (index > 1) buffer.add(",");
            _ = c.lua_rawgeti(state, list, index);
            _ = lua.stringAt(state, -1, "alpn entries");
            buffer.addValue();
        }
        buffer.push();
        const protocols = lua.toBytes(state, -1).?;
        if (protocols.len > 0) check(state, w.wolfSSL_UseALPN(ssl, @constCast(protocols.ptr), @intCast(protocols.len), w.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), "alpn");
    }
}

fn sendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const data = session.transport.beginSend(state);
    if (data.len == 0) return 0;
    const result = w.wolfSSL_write(session.ssl, data.ptr, @intCast(data.len));
    if (result != data.len) fail(state, session, result);
    return 0;
}

/// Up to `count` decrypted bytes once any arrive; nil after the peer closes.
fn receiveLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const count = session.transport.beginReceive(state);
    var buffer: [limits.socket_receive_capacity]u8 = undefined;
    const result = w.wolfSSL_read(session.ssl, &buffer, @intCast(count));
    if (result > 0) {
        lua.pushBytes(state, buffer[0..@intCast(result)]);
        return 1;
    }
    const code = w.wolfSSL_get_error(session.ssl, result);
    if (code != w.WOLFSSL_ERROR_ZERO_RETURN and code != w.SOCKET_PEER_CLOSED_E) fail(state, session, result);
    c.lua_pushnil(state);
    return 1;
}

/// Sends close_notify, releases the session, and closes its TCP socket.
fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ssl) |ssl| {
        session.transport.begin(stream.close_timeout);
        _ = w.wolfSSL_shutdown(ssl);
    }
    session.release();
    session.transport.close();
    return 0;
}

/// Garbage collection releases the session without network I/O; the TCP socket's
/// own collector closes it.
fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

/// `{ version, cipher, alpn, server_name, peer_certificates }`; certificates are DER.
fn infoLua(state: ?*c.lua_State) callconv(.c) c_int {
    const ssl = checkSession(state).ssl;
    c.lua_createtable(state, 0, 5);
    lua.setString(state, "version", std.mem.span(w.wolfSSL_get_version(ssl)));
    lua.setString(state, "cipher", std.mem.span(w.wolfSSL_get_cipher_name(ssl)));
    var protocol: [*c]u8 = null;
    var protocol_length: c_ushort = 0;
    if (w.wolfSSL_ALPN_GetProtocol(ssl, &protocol, &protocol_length) == w.WOLFSSL_SUCCESS and protocol != null) {
        lua.setString(state, "alpn", protocol[0..protocol_length]);
    }
    var name: ?*anyopaque = null;
    const name_length = w.wolfSSL_SNI_GetRequest(ssl, w.WOLFSSL_SNI_HOST_NAME, &name);
    if (name_length > 0 and name != null) lua.setString(state, "server_name", @as([*]const u8, @ptrCast(name.?))[0..name_length]);
    const chain = w.wolfSSL_get_peer_chain(ssl);
    const count: c_int = if (chain == null) 0 else w.wolfSSL_get_chain_count(chain);
    c.lua_createtable(state, @max(count, 0), 0);
    var index: c_int = 0;
    while (index < count) : (index += 1) {
        lua.pushBytes(state, w.wolfSSL_get_chain_cert(chain, index)[0..@intCast(w.wolfSSL_get_chain_length(chain, index))]);
        c.lua_rawseti(state, -2, index + 1);
    }
    c.lua_setfield(state, -2, "peer_certificates");
    return 1;
}

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ssl == null) lua.raise(state, "TLS session is closed", .{});
    return session;
}

/// Raises the session's error; a timeout reads like a socket timeout.
fn fail(state: ?*c.lua_State, session: *Session, result: c_int) noreturn {
    session.transport.checkTimeout(state);
    raiseCode(state, "TLS failed", w.wolfSSL_get_error(session.ssl, result));
}

fn check(state: ?*c.lua_State, result: c_int, comptime option: []const u8) void {
    if (result != w.WOLFSSL_SUCCESS) raiseCode(state, "invalid " ++ option, result);
}

/// Raises "`what`: " followed by wolfSSL's description of `code`.
fn raiseCode(state: ?*c.lua_State, what: [*:0]const u8, code: c_int) noreturn {
    var buffer: [128]u8 = undefined;
    w.wolfSSL_ERR_error_string_n(@bitCast(@as(c_long, code)), &buffer, buffer.len);
    lua.raise(state, "%s: %s", .{ what, &buffer });
}

// The test runs real Lua sessions end to end over stream.Pipe, through every
// option and method of the module.

// A session userdata configured from the option table at `options`, wired to the
// pipes, as the Lua global `name`.
fn testSession(state: ?*c.lua_State, role: stream.Role, options: c_int, input: *stream.Pipe, output: *stream.Pipe, name: [*:0]const u8) *Session {
    const session = stream.new(state, metatable, Session{ .transport = .{ .vm = undefined, .socket = &stream.test_socket } });
    configure(state, session, role, options);
    session.attach(stream.Pipe, input, output);
    c.lua_setglobal(state, name);
    return session;
}

test "tls session round trip over the full module API" {
    init();
    const state = lua.testState("protocols/tls", module);
    defer c.lua_close(state);
    const certificate = @embedFile("testdata/lab_cert.pem");
    const key = @embedFile("testdata/lab_key.pem");
    lua.pushBytes(state, certificate);
    c.lua_setglobal(state, "certificate");
    lua.pushBytes(state, key);
    c.lua_setglobal(state, "key");
    // Option tables at stack indices 1-5. Every side presents the lab cert
    // (CN and SAN kraken.test) and verifies its peer against it:
    //   1: TLS 1.3 client          2: server answering to kraken.test
    //   3: TLS 1.2 client          4: server answering to other.test
    //   5: client sending no SNI (so it can reach server 4)
    try std.testing.expect(c.LUA_OK == c.luaL_loadstring(state,
        \\local both = { verify = true, ca = certificate, certificate = certificate, key = key, server_name = "kraken.test" }
        \\local function opts(extra) local t = {} for k, v in pairs(both) do t[k] = v end for k, v in pairs(extra) do t[k] = v end return t end
        \\local anonymous = opts({ alpn = { "h2", "http/1.1" } })
        \\anonymous.server_name = nil
        \\return opts({ alpn = { "h2", "http/1.1" } }),
        \\       opts({ alpn = { "http/1.1" } }),
        \\       opts({ alpn = { "h2", "http/1.1" }, version = "1.2" }),
        \\       opts({ alpn = { "http/1.1" }, server_name = "other.test" }),
        \\       anonymous
    ));
    try std.testing.expect(c.LUA_OK == c.lua_pcallk(state, 0, 5, 0, 0, null));
    const Scenario = struct { client: c_int, server: c_int, version: [:0]const u8, sni: ?[:0]const u8 };
    for ([_]Scenario{
        .{ .client = 1, .server = 2, .version = "TLSv1.3", .sni = "kraken.test" },
        .{ .client = 3, .server = 2, .version = "TLSv1.2", .sni = "kraken.test" },
        // A verifying server checks the client's certificate against its CA only,
        // never against its own server_name.
        .{ .client = 5, .server = 4, .version = "TLSv1.3", .sni = null },
    }) |scenario| {
        var to_server: stream.Pipe = .{};
        var to_client: stream.Pipe = .{};
        const top = c.lua_gettop(state);
        const client = testSession(state, .client, scenario.client, &to_client, &to_server, "client");
        const server = testSession(state, .server, scenario.server, &to_server, &to_client, "server");
        try std.testing.expectEqual(top, c.lua_gettop(state));
        try std.testing.expect(stream.handshake(w.wolfSSL_connect, client.ssl, w.wolfSSL_accept, server.ssl, w.WOLFSSL_SUCCESS));
        lua.pushBytes(state, scenario.version);
        c.lua_setglobal(state, "expected");
        if (scenario.sni) |name| lua.pushBytes(state, name) else c.lua_pushnil(state);
        c.lua_setglobal(state, "sni");
        try lua.expectScript(state,
            \\local ci, si = client:info(), server:info()
            \\assert(ci.version == expected and si.version == expected, ci.version)
            \\assert(ci.alpn == "http/1.1" and si.alpn == "http/1.1")
            \\assert(si.server_name == sni)                      -- the server reads the client's SNI, if any
            \\assert(#ci.peer_certificates == 1 and #si.peer_certificates == 1)  -- mutual auth
            \\assert(type(ci.cipher) == "string" and type(si.cipher) == "string")
            \\-- application data flows both ways, and the trailing timeout is accepted
            \\client:send("ping")
            \\assert(server:receive(4) == "ping")
            \\server:send("pong", 1000)
            \\assert(client:receive(64, 1000) == "pong")
            \\-- the server closes; the client reads end of stream as nil, then closes too
            \\server:close()
            \\assert(client:receive(1) == nil)
            \\client:close()
            \\-- the session is unusable after close
            \\assert(not pcall(function() return client:send("x") end))
            \\assert(not pcall(function() return client:info() end))
        );
    }
}
