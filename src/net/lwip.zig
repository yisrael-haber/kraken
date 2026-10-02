const std = @import("std");
const c = @import("lwip_c");
const net = @import("net_types");

const Interface = struct {
    raw: *c.struct_kraken_lwip_interface,
    ip: [4]u8,
    frame_mtu: u16,
    sockets: std.ArrayList(c_int) = .empty,
};

pub const Output = struct { context: *anyopaque, length: usize };

pub const Stack = struct {
    allocator: std.mem.Allocator,

    pub fn init(self: *Stack, allocator: std.mem.Allocator, context: *anyopaque, wake: *const fn (?*anyopaque) callconv(.c) void) net.Error!void {
        if (c.kraken_lwip_init(context, wake) != 0) return error.RuntimeUnavailable;
        self.* = .{ .allocator = allocator };
    }

    pub fn deinit(_: *Stack) void {
        c.kraken_lwip_finish();
    }

    pub fn addInterface(self: *Stack, config: net.Config, context: *anyopaque) net.Error!net.InterfaceHandle {
        const iface = self.allocator.create(Interface) catch return error.RuntimeUnavailable;
        errdefer self.allocator.destroy(iface);
        const raw = c.kraken_lwip_add(&config.ip, config.prefix,
            if (config.gateway) |*gateway| gateway else null, &config.mac, config.mtu, context) orelse return error.RuntimeUnavailable;
        iface.* = .{ .raw = raw, .ip = config.ip, .frame_mtu = config.mtu + 14 };
        return @enumFromInt(@intFromPtr(iface));
    }

    pub fn removeInterface(self: *Stack, handle: net.InterfaceHandle) void {
        const iface = interface(handle);
        for (iface.sockets.items) |fd| {
            _ = c.kraken_lwip_call(fd, @intFromEnum(net.SocketAction.close), null, null, 0);
        }
        iface.sockets.deinit(self.allocator);
        c.kraken_lwip_remove(iface.raw);
        self.allocator.destroy(iface);
    }

    pub fn frameMtu(_: *Stack, handle: net.InterfaceHandle) u16 {
        return interface(handle).frame_mtu;
    }

    pub fn input(_: *Stack, handle: net.InterfaceHandle, frame: []const u8) bool {
        const iface = interface(handle);
        if (frame.len == 0 or frame.len > iface.frame_mtu) return false;
        return c.kraken_lwip_input(iface.raw, frame.ptr, frame.len) == 0;
    }

    pub fn output(_: *Stack, bytes: []u8) ?Output {
        var context: ?*anyopaque = null;
        const length = c.kraken_lwip_output(&context, bytes.ptr, bytes.len);
        return if (length > 0) .{ .context = context.?, .length = @intCast(length) } else null;
    }

    pub fn socket(self: *Stack, handle: net.InterfaceHandle, action: net.SocketAction, value: *net.Socket, address: ?*net.Address, bytes: []u8) net.SocketResult {
        const iface = interface(handle);
        if ((action == .connect or action == .bind) and value.handle == null) {
            const fd = c.kraken_lwip_open(iface.raw, switch (value.kind) {
                .tcp => 1,
                .udp => 2,
                .raw => 3,
            }, value.protocol);
            if (fd < 0) return .failed;
            iface.sockets.append(self.allocator, fd) catch {
                _ = c.kraken_lwip_call(fd, @intFromEnum(net.SocketAction.close), null, null, 0);
                return .failed;
            };
            value.handle = encode(fd);
        }
        const socket_handle = value.handle orelse return .failed;
        const fd = decode(socket_handle);
        var raw_address: c.struct_kraken_lwip_address = undefined;
        const has_address = address != null;
        if (address) |a| {
            raw_address = .{ .ip = a.ip, .port = a.port };
            if (action == .bind and value.kind != .raw and std.mem.eql(u8, &raw_address.ip, &.{ 0, 0, 0, 0 }))
                raw_address.ip = iface.ip;
        }
        if (action == .send and value.kind == .raw and value.header) {
            const result = c.kraken_lwip_send_header(iface.raw, bytes.ptr, bytes.len);
            return if (result >= 0) .{ .success = @intCast(result) } else .failed;
        }
        const result = c.kraken_lwip_call(fd, @intFromEnum(action), if (has_address) &raw_address else null,
            bytes.ptr, if (action == .listen) value.backlog else bytes.len);
        if (result == -2) return .would_block;
        if (result < 0) return .failed;
        if (address) |a| if (action == .accept or action == .receive) {
            a.* = .{ .ip = raw_address.ip, .port = raw_address.port };
        };
        if (action == .accept) {
            iface.sockets.append(self.allocator, result) catch {
                _ = c.kraken_lwip_call(result, @intFromEnum(net.SocketAction.close), null, null, 0);
                return .failed;
            };
            return .{ .accepted = encode(result) };
        }
        if (action == .close) {
            for (iface.sockets.items, 0..) |registered, index| {
                if (registered == fd) {
                    _ = iface.sockets.swapRemove(index);
                    break;
                }
            }
            value.handle = null;
        }
        if (action == .receive and result == 0 and value.kind == .tcp) return .closed;
        return .{ .success = @intCast(result) };
    }
};

fn encode(fd: c_int) net.SocketHandle {
    return @enumFromInt(@as(usize, @intCast(fd)));
}

fn interface(handle: net.InterfaceHandle) *Interface {
    return @ptrFromInt(@intFromEnum(handle));
}

fn decode(handle: net.SocketHandle) c_int {
    return @intCast(@intFromEnum(handle));
}
