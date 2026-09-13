const std = @import("std");
const c = @import("c");
const identity = @import("../identities/identity.zig");
const command = @import("../command.zig");

pub const Error = error{
    InterfaceRequired,
    InvalidIpAddress,
    InvalidPrefixLength,
    InvalidGatewayAddress,
    InvalidMacAddress,
    InvalidMtu,
};

pub const Egress = *const fn (device: ?*c.struct_wolfIP_ll_dev, frame: ?*anyopaque, length: u32) callconv(.c) c_int;

/// One worker-owned wolfIP instance. wolfIP remains a C library, but all
/// application state, configuration, timekeeping, and callback routing stay
/// in Zig.
pub const Stack = struct {
    allocator: std.mem.Allocator,
    storage: []align(16) u8,
    frame_mtu: u16,

    pub fn init(self: *Stack, allocator: std.mem.Allocator, value: *const identity.Identity, context: *anyopaque, egress: Egress) Error!bool {
        if (value.interface.value().len == 0) return error.InterfaceRequired;
        const address = parseIpv4(value.ip.value()) catch return error.InvalidIpAddress;
        const prefix_length = parsePrefix(value.prefix.value()) catch return error.InvalidPrefixLength;
        const gateway = if (value.gateway.value().len == 0) null else parseIpv4(value.gateway.value()) catch return error.InvalidGatewayAddress;
        const mac = parseMac(value.mac.value()) orelse return error.InvalidMacAddress;
        const mtu = parseMtu(value.mtu.value()) catch return error.InvalidMtu;
        const storage = allocator.alignedAlloc(u8, .@"16", c.wolfIP_instance_size()) catch return false;
        errdefer allocator.free(storage);
        @memset(storage, 0);
        const instance: *c.struct_wolfIP = @ptrCast(storage.ptr);
        c.wolfIP_init(instance);
        const device = c.wolfIP_getdev(instance) orelse return false;

        @memcpy(device[0].mac[0..6], &mac);
        @memcpy(device[0].ifname[0..3], "cg0");
        const frame_mtu = mtu + ethernet_header_size;
        device[0].mtu = frame_mtu;
        device[0].send = egress;
        self.* = .{ .allocator = allocator, .storage = storage, .frame_mtu = frame_mtu };
        device[0].priv = context;
        c.wolfIP_ipconfig_set(instance, ip4(address), prefixMask(prefix_length), if (gateway) |value_gateway| ip4(value_gateway) else 0);
        return true;
    }

    pub fn input(self: *Stack, frame: []const u8) bool {
        if (frame.len == 0 or frame.len > self.frame_mtu) return false;
        c.wolfIP_recv(@ptrCast(self.storage.ptr), @constCast(frame.ptr), @intCast(frame.len));
        return true;
    }

    pub fn tick(self: *Stack) ?u32 {
        const timeout = c.wolfIP_poll(@ptrCast(self.storage.ptr), now());
        return if (timeout < 0) null else @intCast(timeout);
    }

    pub fn deinit(self: *Stack) void {
        self.allocator.free(self.storage);
    }

    pub fn socket(self: *Stack, call: *command.SocketCall) c_int {
        const instance: *c.struct_wolfIP = @ptrCast(self.storage.ptr);
        var address_length: c.socklen_t = @sizeOf(c.struct_wolfIP_sockaddr_in);
        const bytes = call.bytes;
        if (call.action == .connect or call.action == .bind) {
            if (call.socket.descriptor < 0) {
                call.socket.descriptor = c.wolfIP_sock_socket(instance, c.AF_INET, @intFromEnum(call.socket.kind), call.socket.protocol);
                if (call.socket.kind == .raw and call.socket.descriptor >= 0) {
                    const header: c_int = @intFromBool(call.socket.header);
                    const result = c.wolfIP_sock_setsockopt(instance, call.socket.descriptor, c.WOLFIP_SOL_IP, c.WOLFIP_IP_HDRINCL, &header, @sizeOf(c_int));
                    if (result < 0) return result;
                }
            }
            if (call.socket.descriptor < 0) return -1;
        }
        return switch (call.action) {
            .connect => c.wolfIP_sock_connect(instance, call.socket.descriptor, @ptrCast(call.address), address_length),
            .bind => c.wolfIP_sock_bind(instance, call.socket.descriptor, @ptrCast(call.address), address_length),
            .listen => c.wolfIP_sock_listen(instance, call.socket.descriptor, 1),
            .accept => c.wolfIP_sock_accept(instance, call.socket.descriptor, @ptrCast(call.address), &address_length),
            .send => c.wolfIP_sock_sendto(instance, call.socket.descriptor, bytes.ptr, bytes.len, 0, if (call.address.sin_family == c.AF_INET) @ptrCast(call.address) else null, address_length),
            .receive => c.wolfIP_sock_recvfrom(instance, call.socket.descriptor, bytes.ptr, bytes.len, 0, @ptrCast(call.address), &address_length),
            .close => c.wolfIP_sock_close(instance, call.socket.descriptor),
        };
    }
};

var random_state = std.atomic.Value(u32).init(0x9e3779b9);

test "raw sockets send both header modes and receive IPv4 packets" {
    const Capture = struct {
        bytes: [1514]u8 = undefined,
        len: usize = 0,

        fn send(device: ?*c.struct_wolfIP_ll_dev, data: ?*anyopaque, len: u32) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(device.?.priv));
            @memcpy(self.bytes[0..len], @as([*]const u8, @ptrCast(data))[0..len]);
            self.len = len;
            return @intCast(len);
        }
    };
    var capture: Capture = .{};
    var value: identity.Identity = .{};
    try value.interface.set("test");
    try value.ip.set("192.0.2.1");
    try value.mac.set("02:00:00:00:00:01");
    var stack: Stack = undefined;
    try std.testing.expect(try stack.init(std.testing.allocator, &value, &capture, Capture.send));
    defer stack.deinit();
    var packet: [25]u8 = undefined;
    for ([_]bool{ false, true }) |header| {
        var socket_value: command.Socket = .{ .identity = .{}, .kind = .raw, .protocol = 253, .header = header };
        var address: c.struct_wolfIP_sockaddr_in = .{ .sin_family = c.AF_INET };
        var call: command.SocketCall = .{ .action = .bind, .socket = &socket_value, .address = &address, .bytes = &.{} };
        try std.testing.expectEqual(0, stack.socket(&call));
        address.sin_addr.s_addr = 0xffffffff;
        call.action = .send;
        call.bytes = if (header) &packet else @constCast("probe");
        try std.testing.expectEqual(@as(c_int, @intCast(call.bytes.len)), stack.socket(&call));
        _ = stack.tick();
        try std.testing.expectEqual(39, capture.len);
        try std.testing.expectEqualSlices(u8, "probe", capture.bytes[34..39]);
        if (header) try std.testing.expectEqualSlices(u8, &packet, capture.bytes[14..39]);
        @memcpy(&packet, capture.bytes[14..39]);
        try std.testing.expect(stack.input(capture.bytes[0..capture.len]));
        var received: [64]u8 = undefined;
        call.action = .receive;
        call.bytes = &received;
        try std.testing.expectEqual(@as(c_int, packet.len), stack.socket(&call));
        try std.testing.expectEqualSlices(u8, &packet, received[0..packet.len]);
        call.action = .close;
        try std.testing.expectEqual(0, stack.socket(&call));
    }
}

pub export fn wolfIP_getrandom() callconv(.c) u32 {
    return random_state.fetchAdd(0x9e3779b9, .monotonic);
}

const ethernet_header_size = 14;

fn parseIpv4(value: []const u8) ![4]u8 {
    return (try std.Io.net.Ip4Address.parse(value, 0)).bytes;
}

fn parsePrefix(value: []const u8) !u8 {
    const prefix = if (value.len == 0) 24 else std.fmt.parseInt(u8, value, 10) catch return error.InvalidPrefix;
    return if (prefix <= 32) prefix else error.InvalidPrefix;
}

fn parseMac(value: []const u8) ?[6]u8 {
    if (value.len != 17) return null;
    var result: [6]u8 = undefined;
    for (&result, 0..) |*octet, index| {
        if (index < 5 and value[index * 3 + 2] != ':') return null;
        octet.* = std.fmt.parseInt(u8, value[index * 3 .. index * 3 + 2], 16) catch return null;
    }
    return result;
}

fn parseMtu(value: []const u8) !u16 {
    const mtu = if (value.len == 0) 1500 else std.fmt.parseInt(u16, value, 10) catch return error.InvalidMtu;
    return if (mtu >= 68 and mtu <= 1500) mtu else error.InvalidMtu;
}

fn ip4(value: [4]u8) c.ip4 {
    return (@as(c.ip4, value[0]) << 24) | (@as(c.ip4, value[1]) << 16) | (@as(c.ip4, value[2]) << 8) | value[3];
}

fn prefixMask(prefix_length: u8) c.ip4 {
    if (prefix_length == 0) return 0;
    return ~@as(c.ip4, 0) << @intCast(32 - prefix_length);
}

fn now() u64 {
    return @intCast(std.Io.Clock.awake.now(std.Io.Threaded.global_single_threaded.io()).toMilliseconds());
}
