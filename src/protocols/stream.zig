const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const w = @import("wolfssl");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const command = @import("../command.zig");
const tls = @import("tls.zig");

pub const Role = enum { client, server };
pub const close_timeout = 1000;
pub const Failure = error{ Closed, Timeout, Failed };

/// Borrows the socket or TLS session retained by the Lua user value. Every
/// protocol operation shares one deadline with all library I/O it triggers.
pub const Stream = struct {
    source: union(enum) {
        tcp: struct { vm: *lua.VM, socket: *command.Socket },
        tls: *tls.Session,
        pipes: if (builtin.is_test) Ends else noreturn,
    },
    deadline: ?i64 = null,
    /// First I/O failure in this operation. Libraries cannot overwrite a timeout
    /// with a secondary error; release sets Failed to suppress protocol I/O.
    failure: ?Failure = null,

    pub fn fromLua(state: ?*c.lua_State) Stream {
        if (tls.fromLua(state, 1)) |session| {
            if (session.ssl == null) lua.raise(state, "TLS session is closed", .{});
            return .{ .source = .{ .tls = session } };
        }
        const tcp = socket.check(state, 1);
        if (tcp.endpoint.kind != .tcp or tcp.endpoint.handle == null)
            lua.raise(state, "connected TCP socket expected", .{});
        return .{ .source = .{ .tcp = .{ .vm = lua.vm(state), .socket = tcp } } };
    }

    pub fn begin(self: *Stream, timeout: ?u64) void {
        self.deadline = socket.deadline(timeout);
        self.failure = null;
        if (self.source == .tls) {
            self.source.tls.transport.deadline = self.deadline;
            self.source.tls.transport.failure = null;
        }
    }

    pub fn timedOut(self: *const Stream) bool {
        return (self.failure orelse return false) == error.Timeout;
    }

    pub fn beginSend(self: *Stream, state: ?*c.lua_State) []const u8 {
        const data = lua.checkBytes(state, 2);
        self.begin(socket.luaTimeout(state, 3));
        return data;
    }

    pub fn beginReceive(self: *Stream, state: ?*c.lua_State) usize {
        const count = socket.receiveCount(state, 2);
        self.begin(socket.luaTimeout(state, 3));
        return count;
    }

    /// Sends the entire buffer or fails; receives return once any bytes arrive.
    pub fn transfer(self: *Stream, action: command.SocketAction, bytes: []u8) Failure!usize {
        if (bytes.len == 0) return 0;
        const result: Failure!usize = switch (self.source) {
            .tcp => |*tcp| switch (socket.perform(tcp.vm, action, tcp.socket, null, bytes, self.deadline)) {
                .success => |count| count,
                .closed => error.Closed,
                .would_block => error.Timeout,
                else => error.Failed,
            },
            .tls => |session| blk: {
                const ssl = session.ssl orelse break :blk error.Failed;
                const result = if (action == .send)
                    w.wolfSSL_write(ssl, bytes.ptr, @intCast(bytes.len))
                else
                    w.wolfSSL_read(ssl, bytes.ptr, @intCast(bytes.len));
                if (result > 0 and (action == .receive or result == bytes.len)) break :blk @intCast(result);
                if (session.transport.timedOut()) break :blk error.Timeout;
                const code = w.wolfSSL_get_error(ssl, result);
                break :blk if (code == w.WOLFSSL_ERROR_ZERO_RETURN or code == w.SOCKET_PEER_CLOSED_E) error.Closed else error.Failed;
            },
            .pipes => |ends| if (builtin.is_test)
                (if (action == .send) ends.output else ends.input).transfer(action, bytes)
            else
                unreachable,
        };
        return result catch |err| {
            self.failure = self.failure orelse err;
            return err;
        };
    }

    pub fn close(self: *Stream) void {
        switch (self.source) {
            .tcp => |tcp| if (tcp.socket.endpoint.handle != null) {
                _ = socket.perform(tcp.vm, .close, tcp.socket, null, &.{}, null);
            },
            .tls => |session| session.close(),
            .pipes => {},
        }
    }
};

/// Adapts the shared stream result only at the TLS/SSH callback ABI boundary.
pub fn Callbacks(comptime Handle: type, comptime Buffer: type, comptime Size: type, comptime codes: struct { closed: c_int, want_read: c_int, failed: c_int }) type {
    return struct {
        pub fn receive(_: Handle, buffer: Buffer, size: Size, context: ?*anyopaque) callconv(.c) c_int {
            return forward(.receive, buffer, size, context);
        }

        pub fn send(_: Handle, buffer: Buffer, size: Size, context: ?*anyopaque) callconv(.c) c_int {
            return forward(.send, buffer, size, context);
        }

        fn forward(action: command.SocketAction, buffer: Buffer, size: Size, context: ?*anyopaque) c_int {
            const target: *Stream = @ptrCast(@alignCast(context.?));
            const bytes: [*c]u8 = @ptrCast(buffer);
            const count = target.transfer(action, bytes[0..@intCast(size)]) catch |err| return switch (err) {
                error.Closed => codes.closed,
                error.Timeout => if (action == .receive) codes.want_read else codes.failed,
                error.Failed => codes.failed,
            };
            return @intCast(count);
        }
    };
}

/// Reads `(tcp, options [, timeout_ms])` for TLS, SSH, SMB and DCERPC.
pub fn arguments(state: ?*c.lua_State, options_required: bool) struct { Stream, ?u64 } {
    const transport = Stream.fromLua(state);
    if (transport.source != .tcp) lua.raise(state, "connected TCP socket expected", .{});
    const timeout = socket.luaTimeout(state, 3);
    optionsTable(state, options_required);
    return .{ transport, timeout };
}

pub fn optionsTable(state: ?*c.lua_State, required: bool) void {
    if (!required and c.lua_isnoneornil(state, 2)) {
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 0);
    }
    c.luaL_checktype(state, 2, c.LUA_TTABLE);
    c.lua_settop(state, 2);
}

/// The user value retains the underlying socket or TLS session.
pub fn new(state: ?*c.lua_State, metatable: [*:0]const u8, value: anytype) *@TypeOf(value) {
    const session: *@TypeOf(value) = @ptrCast(@alignCast(c.lua_newuserdatauv(state, @sizeOf(@TypeOf(value)), 1).?));
    session.* = value;
    _ = c.luaL_setmetatable(state, metatable);
    c.lua_pushvalue(state, 1);
    _ = c.lua_setiuservalue(state, -2, 1);
    return session;
}

// Test support: the same stream and library callbacks over in-memory pipes.

/// Steps both ends of a handshake until each returns `success`. One thread
/// cannot block in both constructors at once, so each step returns when its
/// pipe runs dry.
pub fn handshake(connect: anytype, client: anytype, accept: anytype, server: anytype, success: c_int) bool {
    var connected = false;
    var accepted = false;
    for (0..100) |_| {
        if (!connected) connected = connect(client) == success;
        if (!accepted) accepted = accept(server) == success;
        if (connected and accepted) return true;
    }
    return false;
}

/// One direction of an in-memory connection.
pub const Pipe = struct {
    bytes: [262144]u8 = undefined,
    len: usize = 0,
    read_limit: usize = std.math.maxInt(usize),
    /// Runs when a read finds the pipe empty, standing in for a peer that makes
    /// progress while this end waits.
    on_empty: ?*const fn () void = null,

    pub fn transfer(self: *Pipe, action: command.SocketAction, bytes: []u8) Failure!usize {
        if (action == .send) {
            // Tests build without safety checks, so bound the copy explicitly.
            if (bytes.len > self.bytes.len - self.len) return error.Failed;
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
        if (self.len == 0) if (self.on_empty) |hook| hook();
        if (self.len == 0) return error.Timeout;
        const count = @min(self.read_limit, @min(self.len, bytes.len));
        @memcpy(bytes[0..count], self.bytes[0..count]);
        std.mem.copyForwards(u8, self.bytes[0 .. self.len - count], self.bytes[count..self.len]);
        self.len -= count;
        return count;
    }
};

/// What one end of a test connection receives from and sends to.
pub const Ends = struct { input: *Pipe, output: *Pipe };

/// The two directions of a protocol test connection.
pub const Duplex = struct {
    to_server: Pipe = .{},
    to_client: Pipe = .{},
    served: usize = 0,

    /// What the client has sent since the last call. It stays in the transcript.
    pub fn take(self: *Duplex) []const u8 {
        const request = self.to_server.bytes[self.served..self.to_server.len];
        self.served = self.to_server.len;
        return request;
    }

    /// Fails the test unless each string of `expected` is somewhere in what the client sent.
    pub fn expectSent(self: *const Duplex, expected: []const []const u8) !void {
        const sent = self.to_server.bytes[0..self.to_server.len];
        for (expected) |text| if (std.mem.indexOf(u8, sent, text) == null) {
            std.debug.print("the client never sent {s}; it sent:\n{s}\n", .{ text, sent });
            return error.TestUnexpectedResult;
        };
    }

    pub fn client(self: *Duplex) Ends {
        return .{ .input = &self.to_client, .output = &self.to_server };
    }

    pub fn server(self: *Duplex) Ends {
        return .{ .input = &self.to_server, .output = &self.to_client };
    }
};
