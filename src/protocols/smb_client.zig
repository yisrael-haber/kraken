const c = @import("c");
const std = @import("std");
const smb = @import("libsmb2");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const command = @import("../command.zig");

pub const Completion = struct {
    done: bool = false,
    status: c_int = 0,
    data: ?*anyopaque = null,
};

// Keep SMB read replies within one Ethernet frame for Kraken's packet transport.
pub const read_chunk_capacity: usize = 1024;
// Named-pipe reads need room for a complete RPC message, as in libsmb2's DCE/RPC path.
pub const pipe_read_capacity: usize = 65536;

pub const Client = struct {
    transport: stream.Transport,
    context: ?*smb.smb2_context = null,
    operation: Completion = .{},

    pub fn init(self: *Client, state: ?*c.lua_State, share: [*c]const u8) bool {
        const context = smb.smb2_init_context() orelse return false;
        self.context = context;
        var channel: smb.smb2_transport = .{
            .readv = readv,
            .writev = writev,
            .@"opaque" = self,
        };
        if (smb.smb2_set_transport(context, &channel) != 0) return false;
        if (lua.optionalString(state, 2, "username")) |value| smb.smb2_set_user(context, value.ptr);
        if (lua.optionalString(state, 2, "password")) |value| smb.smb2_set_password(context, value.ptr);
        if (lua.optionalString(state, 2, "domain")) |value| smb.smb2_set_domain(context, value.ptr);
        if (lua.field(state, 2, "sign", c.LUA_TBOOLEAN)) {
            smb.smb2_set_sign(context, c.lua_toboolean(state, -1));
            c.lua_pop(state, 1);
        }
        if (lua.field(state, 2, "seal", c.LUA_TBOOLEAN)) {
            smb.smb2_set_seal(context, c.lua_toboolean(state, -1));
            c.lua_pop(state, 1);
        }
        const server = lua.requiredString(state, 2, "server");
        self.operation = .{};
        if (smb.smb2_connect_share_transport_async(context, server.ptr, share, null, complete, &self.operation) != 0) return false;
        return self.pump() and self.operation.status == 0;
    }

    pub fn begin(self: *Client, state: ?*c.lua_State, index: c_int) void {
        self.transport.begin(socket.luaTimeout(state, index));
        self.operation = .{};
    }

    pub fn pump(self: *Client) bool {
        while (!self.operation.done and !self.transport.timed_out) {
            if (smb.smb2_service_transport(self.context, smb.smb2_which_events(self.context)) != 0) return false;
        }
        return self.operation.done and !self.transport.timed_out;
    }

    pub fn success(self: *Client) bool {
        return self.pump() and self.operation.status >= 0;
    }

    pub fn closeShare(self: *Client) void {
        if (self.context == null) return;
        self.transport.begin(stream.close_timeout);
        self.operation = .{};
        if (smb.smb2_disconnect_share_async(self.context, complete, &self.operation) == 0) _ = self.pump();
    }

    pub fn release(self: *Client) void {
        if (self.context) |context| smb.smb2_destroy_context(context);
        self.context = null;
    }

    pub fn errorText(self: *Client) [*c]const u8 {
        return if (self.context) |context| smb.smb2_get_error(context) else "SMB context allocation failed";
    }

    pub fn pipe(self: *Client, action: command.SocketAction, handle: ?*smb.smb2fh, buffer: *anyopaque, len: usize, transferred: [*c]usize) c_int {
        if (len == 0) return -1;
        const count: c_uint = @intCast(@min(len, if (action == .receive) pipe_read_capacity else 32768));
        self.operation = .{};
        const result = if (action == .receive)
            smb.smb2_read_async(self.context, handle, @ptrCast(buffer), count, complete, &self.operation)
        else
            smb.smb2_write_async(self.context, handle, @ptrCast(buffer), count, complete, &self.operation);
        if (result != 0 or !self.success() or self.operation.status == 0 or self.operation.status > count) return -1;
        transferred[0] = @intCast(self.operation.status);
        return 0;
    }
};

pub fn complete(_: ?*smb.smb2_context, status: c_int, data: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    const completion: *Completion = @ptrCast(@alignCast(context.?));
    completion.* = .{ .done = true, .status = status, .data = data };
}

fn readv(context: ?*anyopaque, iov: [*c]smb.smb2_iovec, count: c_int, transferred: [*c]usize) callconv(.c) smb.smb2_transport_result {
    return transfer(.receive, context, iov, count, transferred);
}

fn writev(context: ?*anyopaque, iov: [*c]smb.smb2_iovec, count: c_int, transferred: [*c]usize) callconv(.c) smb.smb2_transport_result {
    return transfer(.send, context, iov, count, transferred);
}

fn transfer(action: command.SocketAction, context: ?*anyopaque, iov: [*c]smb.smb2_iovec, count: c_int, transferred: [*c]usize) smb.smb2_transport_result {
    const self: *Client = @ptrCast(@alignCast(context.?));
    transferred[0] = 0;
    // libsmb2 drains reads until EAGAIN. Its completion callback may run during
    // that drain; do not block on another socket read after our reply is done.
    if (action == .receive and self.operation.done) return smb.SMB2_TRANSPORT_AGAIN;
    if (count <= 0) return smb.SMB2_TRANSPORT_ERROR;
    for (0..@intCast(count)) |index| {
        if (iov[index].len == 0) continue;
        const result = self.transport.transfer(action, iov[index].buf[0..iov[index].len], .{
            .closed = -2,
            .want_read = -3,
            .failed = -1,
        });
        if (result > 0) {
            transferred[0] += @intCast(result);
            if (result < iov[index].len) break;
        } else if (transferred[0] != 0) {
            return smb.SMB2_TRANSPORT_OK;
        } else return switch (result) {
            -2 => smb.SMB2_TRANSPORT_CLOSED,
            -3 => smb.SMB2_TRANSPORT_AGAIN,
            else => smb.SMB2_TRANSPORT_ERROR,
        };
    }
    return smb.SMB2_TRANSPORT_OK;
}

test "completed SMB operation ends the receive drain" {
    var client: Client = .{ .transport = undefined, .operation = .{ .done = true } };
    var buffer: [4]u8 = undefined;
    var iov: smb.smb2_iovec = .{ .buf = &buffer, .len = buffer.len, .free = null };
    var transferred: usize = 1;
    try std.testing.expectEqual(@as(smb.smb2_transport_result, smb.SMB2_TRANSPORT_AGAIN), readv(&client, &iov, 1, &transferred));
    try std.testing.expectEqual(@as(usize, 0), transferred);
}

test "SMB completion does not hide a transport timeout" {
    var client: Client = .{
        .transport = .{ .vm = undefined, .socket = undefined, .timed_out = true },
        .operation = .{ .done = true },
    };
    try std.testing.expect(!client.pump());
}
