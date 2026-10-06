const builtin = @import("builtin");
const c = @import("c");
const lua = @import("../runtime/lua.zig");
const command = @import("../command.zig");
const stream = @import("stream.zig");
const tls = @import("tls.zig");

const codes: stream.Codes = .{ .closed = -1, .want_read = -1, .failed = -1 };

/// A protocol owns its TCP transport or borrows the TLS session retained by its
/// Lua user value. Pipe connections exist only in test builds.
pub const Connection = union(enum) {
    tcp: stream.Transport,
    tls: *tls.Session,
    pipes: if (builtin.is_test) *stream.Duplex else noreturn,

    pub fn fromLua(state: ?*c.lua_State) Connection {
        if (tls.fromLua(state, 1)) |layer| {
            if (layer.ssl == null) lua.raise(state, "TLS session is closed", .{});
            return .{ .tls = layer };
        }
        const transport, _ = stream.arguments(state, false);
        return .{ .tcp = transport };
    }

    pub fn begin(self: *Connection, timeout: ?u64) void {
        switch (self.*) {
            .tcp => |*transport| transport.begin(timeout),
            .tls => |layer| layer.transport.begin(timeout),
            .pipes => {},
        }
    }

    pub fn timedOut(self: *const Connection) bool {
        return switch (self.*) {
            .tcp => |transport| transport.timed_out,
            .tls => |layer| layer.transport.timed_out,
            .pipes => false,
        };
    }

    pub fn transfer(self: *Connection, action: command.SocketAction, bytes: []u8) c_int {
        return switch (self.*) {
            .tcp => |*transport| transport.transfer(action, bytes, codes),
            .tls => |layer| layer.transfer(action, bytes, codes),
            .pipes => |pipes| if (builtin.is_test) pipes.transfer(action, bytes, codes) else unreachable,
        };
    }

    pub fn close(self: *Connection) void {
        switch (self.*) {
            .tcp => |*transport| transport.close(),
            .tls => |layer| layer.close(),
            .pipes => {},
        }
    }
};
