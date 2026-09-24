const std = @import("std");
const c = @import("c");
const identity = @import("../identities/identity.zig");
const command = @import("../command.zig");

pub const Error = error{
    InvalidIpAddress,
    InvalidPrefixLength,
    InvalidGatewayAddress,
    InvalidMacAddress,
    InvalidMtu,
    RuntimeUnavailable,
};

pub const Stack = struct {
    storage: []align(16) u8,
    frame_mtu: u16,

    pub fn init(self: *Stack, allocator: std.mem.Allocator, value: *const identity.Identity, context: *anyopaque, egress: *const fn (?*c.struct_wolfIP_ll_dev, ?*anyopaque, u32) callconv(.c) c_int) Error!void {
        const address = parseIpv4(value.ip.value()) catch return error.InvalidIpAddress;
        const prefix_length = if (value.prefix.value().len == 0) 24 else std.fmt.parseInt(u8, value.prefix.value(), 10) catch return error.InvalidPrefixLength;
        if (prefix_length > 32) return error.InvalidPrefixLength;
        const gateway = if (value.gateway.value().len == 0) null else parseIpv4(value.gateway.value()) catch return error.InvalidGatewayAddress;
        const mac = parseMac(value.mac.value()) orelse return error.InvalidMacAddress;
        const mtu = if (value.mtu.value().len == 0) 1500 else std.fmt.parseInt(u16, value.mtu.value(), 10) catch return error.InvalidMtu;
        if (mtu < 68 or mtu > 1500) return error.InvalidMtu;
        const storage = allocator.alignedAlloc(u8, .@"16", c.wolfIP_instance_size()) catch return error.RuntimeUnavailable;
        const instance: *c.struct_wolfIP = @ptrCast(storage.ptr);
        c.wolfIP_init(instance);
        const device = c.wolfIP_getdev(instance).?;

        @memcpy(device[0].mac[0..6], &mac);
        self.* = .{ .storage = storage, .frame_mtu = mtu + ethernet_header_size };
        device[0].mtu = self.frame_mtu;
        device[0].send = egress;
        device[0].priv = context;
        c.wolfIP_ipconfig_set(instance, address, if (prefix_length == 0) 0 else ~@as(c.ip4, 0) << @intCast(32 - prefix_length), gateway orelse 0);
    }

    pub fn input(self: *Stack, frame: []const u8) bool {
        if (frame.len == 0 or frame.len > self.frame_mtu) return false;
        c.wolfIP_recv(@ptrCast(self.storage.ptr), @constCast(frame.ptr), @intCast(frame.len));
        return true;
    }

    pub fn tick(self: *Stack, now: u64) ?u64 {
        const timeout = c.wolfIP_poll(@ptrCast(self.storage.ptr), now);
        return if (timeout < 0) null else now + @as(u64, @intCast(timeout));
    }

    pub fn deinit(self: *Stack, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }

    pub fn socket(self: *Stack, action: command.SocketAction, socket_value: *command.Socket, address: *c.struct_wolfIP_sockaddr_in, bytes: []u8) c_int {
        const instance: *c.struct_wolfIP = @ptrCast(self.storage.ptr);
        var address_length: c.socklen_t = @sizeOf(c.struct_wolfIP_sockaddr_in);
        if ((action == .connect or action == .bind) and socket_value.descriptor < 0) {
            socket_value.descriptor = c.wolfIP_sock_socket(instance, c.AF_INET, @intFromEnum(socket_value.kind), socket_value.protocol);
            if (socket_value.descriptor < 0) return -1;
            if (socket_value.kind == .raw) {
                const header: c_int = @intFromBool(socket_value.header);
                const result = c.wolfIP_sock_setsockopt(instance, socket_value.descriptor, c.WOLFIP_SOL_IP, c.WOLFIP_IP_HDRINCL, &header, @sizeOf(c_int));
                if (result < 0) return result;
            }
        }
        return switch (action) {
            .connect => c.wolfIP_sock_connect(instance, socket_value.descriptor, @ptrCast(address), address_length),
            .bind => c.wolfIP_sock_bind(instance, socket_value.descriptor, @ptrCast(address), address_length),
            .listen => c.wolfIP_sock_listen(instance, socket_value.descriptor, 1),
            .accept => c.wolfIP_sock_accept(instance, socket_value.descriptor, @ptrCast(address), &address_length),
            .send => c.wolfIP_sock_sendto(instance, socket_value.descriptor, bytes.ptr, bytes.len, 0, if (address.sin_family == c.AF_INET) @ptrCast(address) else null, address_length),
            .receive => c.wolfIP_sock_recvfrom(instance, socket_value.descriptor, bytes.ptr, bytes.len, 0, @ptrCast(address), &address_length),
            .close => c.wolfIP_sock_close(instance, socket_value.descriptor),
        };
    }
};

var random_state: u32 = 0x9e3779b9;

pub export fn wolfIP_getrandom() callconv(.c) u32 {
    defer random_state +%= 0x9e3779b9;
    return random_state;
}

const ethernet_header_size = 14;

fn parseIpv4(value: []const u8) !c.ip4 {
    const bytes = (try std.Io.net.Ip4Address.parse(value, 0)).bytes;
    return std.mem.readInt(c.ip4, &bytes, .big);
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
