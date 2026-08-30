const std = @import("std");
const identity = @import("identity.zig");
const stack = @import("../runtime/stack.zig");

pub const Error = error{
    InterfaceRequired,
    InvalidIpAddress,
    InvalidPrefixLength,
    InvalidGatewayAddress,
    InvalidMacAddress,
    InvalidMtu,
};

pub fn network(value: *const identity.Identity) Error!stack.Config {
    if (value.interface.value().len == 0) return error.InterfaceRequired;
    return .{
        .address = parseIpv4(value.ip.value()) catch return error.InvalidIpAddress,
        .prefix_length = parsePrefix(value.prefix.value()) catch return error.InvalidPrefixLength,
        .gateway = if (value.gateway.value().len == 0) null else parseIpv4(value.gateway.value()) catch return error.InvalidGatewayAddress,
        .mac = parseMac(value.mac.value()) orelse return error.InvalidMacAddress,
        .mtu = parseMtu(value.mtu.value()) catch return error.InvalidMtu,
    };
}

fn parseIpv4(value: []const u8) ![4]u8 {
    return (try std.Io.net.Ip4Address.parse(value, 0)).bytes;
}

fn parsePrefix(value: []const u8) !u8 {
    if (value.len == 0) return 24;
    const prefix = std.fmt.parseInt(u8, value, 10) catch return error.InvalidPrefix;
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
    if (value.len == 0) return 1500;
    const mtu = std.fmt.parseInt(u16, value, 10) catch return error.InvalidMtu;
    if (mtu < 68 or mtu > 1500) return error.InvalidMtu;
    return mtu;
}

test "identity produces typed network configuration" {
    var value: identity.Identity = .{};
    try value.interface.set("eth0");
    try value.ip.set("192.168.122.50");
    try value.prefix.set("25");
    try value.gateway.set("192.168.122.1");
    try value.mac.set("02:11:22:33:44:55");
    try value.mtu.set("1400");

    const network_config = try network(&value);
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 50 }, network_config.address);
    try std.testing.expectEqual(@as(u8, 25), network_config.prefix_length);
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 1 }, network_config.gateway.?);
    try std.testing.expectEqual([6]u8{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, network_config.mac);
    try std.testing.expectEqual(@as(u16, 1400), network_config.mtu);
}

test "blank prefix, gateway, and mtu use defaults" {
    var value: identity.Identity = .{};
    try value.interface.set("eth0");
    try value.ip.set("10.0.0.8");
    try value.mac.set("02:11:22:33:44:55");

    const network_config = try network(&value);
    try std.testing.expectEqual(@as(u8, 24), network_config.prefix_length);
    try std.testing.expectEqual(@as(?[4]u8, null), network_config.gateway);
    try std.testing.expectEqual(@as(u16, 1500), network_config.mtu);
}

test "invalid network fields are rejected before runtime start" {
    var value: identity.Identity = .{};
    try value.interface.set("eth0");
    try value.ip.set("192.168.1.999");
    try std.testing.expectError(error.InvalidIpAddress, network(&value));

    try value.ip.set("192.168.1.8");
    try value.mac.set("");
    try std.testing.expectError(error.InvalidMacAddress, network(&value));
}
