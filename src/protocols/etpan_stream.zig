const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const command = @import("../command.zig");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");

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

/// libetpan owns the returned stream and frees it through the driver.
pub fn open(state: ?*c.lua_State, wire: *stream.Stream) *etpan.mailstream {
    const low = etpan.mailstream_low_new(wire, &driver) orelse lua.raise(state, "stream allocation failed", .{});
    return etpan.mailstream_new(low, buffer_size) orelse {
        etpan.mailstream_low_free(low);
        lua.raise(state, "stream allocation failed", .{});
    };
}

pub fn fail(state: ?*c.lua_State, wire: *stream.Stream, what: [*:0]const u8) noreturn {
    const timed_out = wire.timedOut();
    wire.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "%s connection failed", .{what});
}

// The driver. libetpan treats a read or write of -1 as a stream error.

fn wireOf(low: [*c]etpan.mailstream_low) *stream.Stream {
    return @ptrCast(@alignCast(low.?.*.data));
}

/// One transfer of up to `count` bytes; libetpan loops on partial ones.
fn transfer(low: [*c]etpan.mailstream_low, action: command.SocketAction, buffer: ?*anyopaque, count: usize) isize {
    const wire = wireOf(low);
    if (wire.failure != null) return -1;
    const bytes: [*]u8 = @ptrCast(buffer.?);
    const result = wire.transfer(action, bytes[0..count]) catch return -1;
    return @intCast(result);
}

fn read(low: [*c]etpan.mailstream_low, buffer: ?*anyopaque, count: usize) callconv(.c) isize {
    return transfer(low, .receive, buffer, count);
}

fn write(low: [*c]etpan.mailstream_low, buffer: ?*const anyopaque, count: usize) callconv(.c) isize {
    return transfer(low, .send, @constCast(buffer), count);
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

// libetpan checks the cancel, certificate and idle slots for null, and Kraken uses none of them.
var driver: etpan.mailstream_low_driver = .{
    .mailstream_read = read,
    .mailstream_write = write,
    .mailstream_close = close,
    .mailstream_get_fd = descriptor,
    .mailstream_free = release,
};

/// `session:close()` for a libetpan session: runs the protocol's goodbye command `quit` on its
/// library object `field_name`, then ends the session and closes the connection.
pub fn closer(comptime Session: type, comptime metatable: [*:0]const u8, comptime field_name: []const u8, comptime quit: anytype) c.lua_CFunction {
    return struct {
        fn close(state: ?*c.lua_State) callconv(.c) c_int {
            const session = lua.checkUserdata(state, 1, Session, metatable);
            if (@field(session, field_name)) |library| {
                session.wire.begin(stream.close_timeout);
                _ = quit(library);
                session.release();
            }
            session.wire.close();
            return 0;
        }
    }.close;
}
