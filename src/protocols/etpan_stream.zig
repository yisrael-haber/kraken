const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const tls = @import("tls.zig");
const command = @import("../command.zig");

// libetpan (SMTP, POP3 and IMAP) reads and writes its connection through a mailstream_low
// driver, its own seam for a caller-supplied transport. The driver forwards to a connected
// TCP socket or a protocols/tls session with the same socket operations as tcp:send and
// tcp:receive, on the script's thread. Each Lua call sets one deadline that every transfer
// it triggers shares. A timeout or failed transfer leaves a protocol exchange half done, so
// it ends the session, like the other protocol sessions.

/// Called once before any script runs. libetpan guards its global string table with a lock;
/// a pthread mutex needs no setup, but the Windows critical section does.
pub fn init() void {
    if (builtin.os.tag == .windows) etpan.mmapstring_init_lock();
}

const buffer_size = 8192;
const codes: stream.Codes = .{ .closed = -1, .want_read = -1, .failed = -1 };

/// A connected stream: the session's Transport, or a TLS session, or in tests a pipe.
const Link = struct {
    context: *anyopaque,
    transfer: *const fn (*anyopaque, command.SocketAction, []u8) c_int,
};

/// What a libetpan session keeps beside its library object: its connection.
pub const Wire = struct {
    /// The transport whose deadline each call sets: this session's own over a TCP
    /// socket, or the TLS session's over a secured connection.
    transport: *stream.Transport = undefined,
    own: stream.Transport = undefined,
    tls: ?*tls.Session = null,
    link: Link = undefined,
    /// A transfer failed or timed out: the session cannot continue.
    broken: bool = false,
    /// Set while releasing without protocol I/O (garbage collection).
    mute: bool = false,

    pub fn attach(self: *Wire, comptime Context: type, context: *Context) void {
        self.link = .{ .context = context, .transfer = struct {
            fn call(opaque_context: *anyopaque, action: command.SocketAction, bytes: []u8) c_int {
                const target: *Context = @ptrCast(@alignCast(opaque_context));
                return target.transfer(action, bytes, codes);
            }
        }.call };
    }

    /// Starts the call's deadline at the timeout argument.
    pub fn begin(self: *Wire, state: ?*c.lua_State, index: c_int) void {
        self.transport.begin(socket.luaTimeout(state, index));
    }

    /// Closes the connection under the session: the TLS session (with close_notify), or the socket.
    pub fn closeConnection(self: *Wire) void {
        if (self.tls) |layer| layer.close() else self.transport.close();
    }

    /// The libetpan stream over this wire, which the protocol's connect call takes over.
    pub fn open(self: *Wire, state: ?*c.lua_State) *etpan.mailstream {
        const low = etpan.mailstream_low_new(self, &driver) orelse lua.raise(state, "stream allocation failed", .{});
        return etpan.mailstream_new(low, buffer_size) orelse lua.raise(state, "stream allocation failed", .{});
    }

    /// Raises for a failed call on a broken wire, after ending the session with `release`
    /// (which the caller supplies, since the library object is the session's).
    pub fn raiseBroken(self: *Wire, state: ?*c.lua_State, what: [*:0]const u8) noreturn {
        if (self.transport.timed_out) socket.raiseTimeout(state);
        lua.raise(state, "%s connection failed", .{what});
    }
};

/// A new session userdata of `Session` (which has a `wire: Wire` field) on the stack top,
/// over the TCP socket or TLS session at index 1. Nothing is sent: the protocol's connect
/// call reads the greeting. A TLS session is how SMTPS, POP3S and IMAPS work.
pub fn create(state: ?*c.lua_State, comptime Session: type, metatable: [*:0]const u8) *Session {
    if (tls.fromLua(state, 1)) |layer| {
        if (layer.ssl == null) lua.raise(state, "TLS session is closed", .{});
        const session = stream.new(state, metatable, Session{});
        session.wire.tls = layer;
        session.wire.transport = &layer.transport;
        session.wire.attach(tls.Session, layer);
        return session;
    }
    const transport, _ = stream.arguments(state, false);
    const session = stream.new(state, metatable, Session{});
    session.wire.own = transport;
    session.wire.transport = &session.wire.own;
    session.wire.attach(stream.Transport, &session.wire.own);
    return session;
}

// The driver. libetpan treats a read or write of -1 as a stream error.

fn wireOf(low: [*c]etpan.mailstream_low) *Wire {
    return @ptrCast(@alignCast(low.?.*.data));
}

fn read(low: [*c]etpan.mailstream_low, buffer: ?*anyopaque, count: usize) callconv(.c) isize {
    const wire = wireOf(low);
    if (wire.mute or wire.broken) return -1;
    const bytes: [*]u8 = @ptrCast(buffer.?);
    const received = wire.link.transfer(wire.link.context, .receive, bytes[0..count]);
    if (received <= 0) {
        wire.broken = true;
        return -1;
    }
    return received;
}

fn write(low: [*c]etpan.mailstream_low, buffer: ?*const anyopaque, count: usize) callconv(.c) isize {
    const wire = wireOf(low);
    if (wire.mute or wire.broken) return -1;
    const bytes: [*]u8 = @ptrCast(@constCast(buffer.?));
    var sent: usize = 0;
    while (sent < count) {
        const result = wire.link.transfer(wire.link.context, .send, bytes[sent..count]);
        if (result <= 0) {
            wire.broken = true;
            return -1;
        }
        sent += @intCast(result);
    }
    return @intCast(count);
}

fn close(_: [*c]etpan.mailstream_low) callconv(.c) c_int {
    return 0;
}

fn descriptor(_: [*c]etpan.mailstream_low) callconv(.c) c_int {
    return -1;
}

fn release(_: [*c]etpan.mailstream_low) callconv(.c) void {}

fn cancel(_: [*c]etpan.mailstream_low) callconv(.c) void {}

fn cancelOf(_: [*c]etpan.mailstream_low) callconv(.c) ?*anyopaque {
    return null;
}

fn certificates(_: [*c]etpan.mailstream_low) callconv(.c) [*c]etpan.carray {
    return null;
}

fn idle(_: [*c]etpan.mailstream_low) callconv(.c) c_int {
    return 0;
}

var driver: etpan.mailstream_low_driver = .{
    .mailstream_read = read,
    .mailstream_write = write,
    .mailstream_close = close,
    .mailstream_get_fd = descriptor,
    .mailstream_free = release,
    .mailstream_cancel = cancel,
    .mailstream_get_cancel = @ptrCast(&cancelOf),
    .mailstream_get_certificate_chain = certificates,
    .mailstream_setup_idle = idle,
    .mailstream_unsetup_idle = idle,
    .mailstream_interrupt_idle = idle,
};
