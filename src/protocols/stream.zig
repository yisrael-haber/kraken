const std = @import("std");
const c = @import("c");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const command = @import("../command.zig");

// The part of protocols/tls and protocols/ssh that is not the library: a session
// userdata over a connected Kraken TCP socket, whose library I/O callbacks move
// bytes with the same socket operations as tcp:send / tcp:receive, on the script's
// thread. Each Lua call sets one deadline that every callback it triggers shares.

pub const Role = enum { client, server };

/// close() sends a final message (close_notify, the exit status) best effort: a
/// peer that stops reading must not stall it.
pub const close_timeout = 1000;

/// The session's socket and the deadline of the Lua call in progress.
pub const Transport = struct {
    vm: *lua.VM,
    socket: *command.Socket,
    deadline: ?u64 = null,
    timed_out: bool = false,

    pub fn begin(self: *Transport, timeout: ?u64) void {
        self.deadline = socket.deadline(timeout);
        self.timed_out = false;
    }

    /// `session:send(data [, timeout_ms])`: the data, with the call's deadline started.
    pub fn beginSend(self: *Transport, state: ?*c.lua_State) []const u8 {
        const data = lua.checkBytes(state, 2);
        self.begin(socket.luaTimeout(state, 3));
        return data;
    }

    /// `session:receive(count [, timeout_ms])`: the count, with the call's deadline started.
    pub fn beginReceive(self: *Transport, state: ?*c.lua_State) usize {
        const count = socket.receiveCount(state, 2);
        self.begin(socket.luaTimeout(state, 3));
        return count;
    }

    /// One library I/O callback: the byte count, or the library's code for a closed
    /// peer, a timeout or a failure. A receive timeout is retryable, so the session
    /// stays usable; a send timeout is not, since a partial record cannot be resumed.
    pub fn transfer(self: *Transport, action: command.SocketAction, bytes: []u8, codes: Codes) c_int {
        const result = socket.perform(self.vm, action, self.socket, null, bytes, self.deadline);
        if (result > 0 or (result == 0 and action == .send)) return result;
        if (result == 0) return codes.closed;
        self.timed_out = result == -c.WOLFIP_EAGAIN;
        return if (self.timed_out and action == .receive) codes.want_read else codes.failed;
    }

    /// Raises the socket timeout error when the call ran out of time.
    pub fn checkTimeout(self: *const Transport, state: ?*c.lua_State) void {
        if (self.timed_out) socket.raiseTimeout(state);
    }

    pub fn close(self: *Transport) void {
        if (self.socket.descriptor >= 0) _ = socket.perform(self.vm, .close, self.socket, null, &.{}, null);
    }
};

/// A library's I/O callback return codes.
pub const Codes = struct { closed: c_int, want_read: c_int, failed: c_int };

/// A library's C I/O callbacks, `fn (handle, buffer, size, context) c_int`,
/// forwarding to `Context.transfer`: a Transport, or a Pipe in tests.
pub fn Callbacks(comptime Context: type, comptime Handle: type, comptime Buffer: type, comptime Size: type, comptime codes: Codes) type {
    return struct {
        pub fn receive(_: Handle, buffer: Buffer, size: Size, context: ?*anyopaque) callconv(.c) c_int {
            return forward(.receive, buffer, size, context);
        }

        pub fn send(_: Handle, buffer: Buffer, size: Size, context: ?*anyopaque) callconv(.c) c_int {
            return forward(.send, buffer, size, context);
        }

        fn forward(action: command.SocketAction, buffer: Buffer, size: Size, context: ?*anyopaque) c_int {
            const target: *Context = @ptrCast(@alignCast(context.?));
            const bytes: [*c]u8 = @ptrCast(buffer);
            return target.transfer(action, bytes[0..@intCast(size)], codes);
        }
    };
}

/// Reads a constructor's `(tcp, options [, timeout_ms])`, leaving the socket at 1
/// and the options table at 2 (an empty one when optional and omitted). Returns
/// the transport over the socket and the handshake timeout.
pub fn arguments(state: ?*c.lua_State, options_required: bool) struct { Transport, ?u64 } {
    const tcp = socket.check(state, 1);
    if (tcp.kind != .tcp or tcp.descriptor < 0) {
        _ = c.luaL_argerror(state, 1, "connected TCP socket expected");
        unreachable;
    }
    const timeout = socket.luaTimeout(state, 3);
    if (!options_required and c.lua_isnoneornil(state, 2)) {
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 0);
    }
    c.luaL_checktype(state, 2, c.LUA_TTABLE);
    c.lua_settop(state, 2);
    return .{ .{ .vm = lua.vm(state), .socket = tcp }, timeout };
}

/// A new session userdata holding `value`, with `metatable`, on the stack top.
/// Its user value keeps the value at 1, the TCP socket, alive.
pub fn new(state: ?*c.lua_State, metatable: [*:0]const u8, value: anytype) *@TypeOf(value) {
    const session: *@TypeOf(value) = @ptrCast(@alignCast(c.lua_newuserdatauv(state, @sizeOf(@TypeOf(value)), 1).?));
    session.* = value;
    _ = c.luaL_setmetatable(state, metatable);
    c.lua_pushvalue(state, 1);
    _ = c.lua_setiuservalue(state, -2, 1);
    return session;
}

// Test support: sessions run end to end over in-memory pipes instead of sockets.

/// A socket that is already closed, so Transport.close() does nothing.
pub var test_socket: command.Socket = .{ .identity = undefined, .kind = .tcp };

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
    /// Runs when a read finds the pipe empty, standing in for a peer that makes
    /// progress while this end waits.
    on_empty: ?*const fn () void = null,

    pub fn transfer(self: *Pipe, action: command.SocketAction, bytes: []u8, codes: Codes) c_int {
        if (action == .send) {
            // Tests build without safety checks, so bound the copy explicitly.
            if (bytes.len > self.bytes.len - self.len) return codes.failed;
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return @intCast(bytes.len);
        }
        if (self.len == 0) if (self.on_empty) |hook| hook();
        if (self.len == 0) return codes.want_read;
        const count = @min(self.len, bytes.len);
        @memcpy(bytes[0..count], self.bytes[0..count]);
        std.mem.copyForwards(u8, self.bytes[0 .. self.len - count], self.bytes[count..self.len]);
        self.len -= count;
        return @intCast(count);
    }
};
