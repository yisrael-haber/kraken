const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const Connection = @import("connection.zig").Connection;

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

/// What a libetpan session keeps beside its library object: its connection.
pub const Wire = struct {
    connection: Connection = undefined,
    /// A transfer failed or timed out: the session cannot continue.
    broken: bool = false,
    /// Set while releasing without protocol I/O (garbage collection).
    mute: bool = false,

    /// Starts the call's deadline at the timeout argument.
    pub fn begin(self: *Wire, state: ?*c.lua_State, index: c_int) void {
        self.connection.begin(socket.luaTimeout(state, index));
    }

    /// The libetpan stream over this wire, which the protocol's connect call takes over.
    pub fn open(self: *Wire, state: ?*c.lua_State) *etpan.mailstream {
        const low = etpan.mailstream_low_new(self, &driver) orelse lua.raise(state, "stream allocation failed", .{});
        return etpan.mailstream_new(low, buffer_size) orelse {
            etpan.mailstream_low_free(low);
            lua.raise(state, "stream allocation failed", .{});
        };
    }

    /// Closes the connection and raises after the caller releases its library session.
    pub fn raiseBroken(self: *Wire, state: ?*c.lua_State, what: [*:0]const u8) noreturn {
        const timed_out = self.connection.timedOut();
        self.connection.close();
        if (timed_out) socket.raiseTimeout(state);
        lua.raise(state, "%s connection failed", .{what});
    }
};

/// A new session userdata of `Session` (which has a `wire: Wire` field) on the stack top,
/// over the TCP socket or TLS session at index 1. Nothing is sent: the protocol's connect
/// call reads the greeting. A TLS session is how SMTPS, POP3S and IMAPS work.
pub fn create(state: ?*c.lua_State, comptime Session: type, metatable: [*:0]const u8) *Session {
    return stream.new(state, metatable, Session{ .wire = .{ .connection = Connection.fromLua(state) } });
}

// The driver. libetpan treats a read or write of -1 as a stream error.

fn wireOf(low: [*c]etpan.mailstream_low) *Wire {
    return @ptrCast(@alignCast(low.?.*.data));
}

fn read(low: [*c]etpan.mailstream_low, buffer: ?*anyopaque, count: usize) callconv(.c) isize {
    const wire = wireOf(low);
    if (wire.mute or wire.broken) return -1;
    const bytes: [*]u8 = @ptrCast(buffer.?);
    const received = wire.connection.transfer(.receive, bytes[0..count]);
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
        const result = wire.connection.transfer(.send, bytes[sent..count]);
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

fn release(low: [*c]etpan.mailstream_low) callconv(.c) void {
    std.c.free(low);
}

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
