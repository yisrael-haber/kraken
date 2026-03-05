const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const ph = @import("protocol_headers.zig");
const ArpManager = @import("Managers/ArpManager.zig").ArpManager;
const EthernetManager = @import("Managers/EthernetManager.zig").EthernetManager;
const libpcap_handler = @import("Handlers/libpcap_handler.zig");

pub const pcap = @import("pcap.zig").pcap;

const program_parameters = struct {
    ip: u32 = 0xC0A801F0, // 192.168.1.240
    mac: u48 = 0xf068e373866e, // f0:68:e3:73:86:6e
};

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();

    const devices = try get_device_list(arena);

    for (devices) |device| {
        device.print();
    }

    // const query_ip: u32 = @bitCast([4]u8{ 192, 168, 1, 247 });
    const query_ip: u32 = @bitCast([4]u8{ 247, 1, 168, 192 });

    const iface_name: []const u8 = pickInterface(devices) orelse return error.NoSuitableInterface;

    std.debug.print("Using interface: {s}\n", .{iface_name});
    var handler = try libpcap_handler.PcapHandler.init(arena, iface_name);
    defer handler.close();

    const params = program_parameters{};
    var eth_mgr = EthernetManager.init(arena, &handler);
    defer eth_mgr.deinit();

    var mgr = ArpManager.init(arena, &eth_mgr, params.ip, params.mac);
    defer mgr.deinit();

    try eth_mgr.registerHandler(0x0806, mgr.protocolHandler());

    std.debug.print("performing ARP query for 10.10.10.10 on {s}...\n", .{iface_name});
    try mgr.queryNetwork(query_ip);
    try eth_mgr.run();
}

fn hasIpv4Address(device: Device) bool {
    for (device.addresses) |address| {
        if (address.addr) |addr| {
            if (addr.family == posix.AF.INET) return true;
        }
    }
    return false;
}

fn pickInterface(devices: []Device) ?[]const u8 {
    // Prefer non-wireless interfaces: most WiFi drivers on Windows do not
    // support raw packet injection (pcap_sendpacket) in infrastructure mode.
    var wireless_fallback: ?[]const u8 = null;
    for (devices) |device| {
        const is_loopback = device.flags & pcap.PCAP_IF_LOOPBACK != 0;
        const is_up = device.flags & pcap.PCAP_IF_UP != 0;
        const is_running = device.flags & pcap.PCAP_IF_RUNNING != 0;
        const is_disconnected = (device.flags & pcap.PCAP_IF_CONNECTION_STATUS) ==
            pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
        const is_wireless = device.flags & pcap.PCAP_IF_WIRELESS != 0;
        if (!is_loopback and is_up and is_running and !is_disconnected and hasIpv4Address(device)) {
            if (!is_wireless) return device.name;
            if (wireless_fallback == null) wireless_fallback = device.name;
        }
    }
    return wireless_fallback;
}

fn get_device_list(allocator: std.mem.Allocator) ![]Device {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: ?*pcap.pcap_if_t = null;

    const errVal: c_int = pcap.pcap_findalldevs(&alldevs, &errbuf);

    if (errVal == -1) {
        std.debug.print("Error: {s}\n", .{errbuf});
        return error.PcapFindAllDevsFailed;
    }

    defer pcap.pcap_freealldevs(alldevs);

    var device_list = std.array_list.Managed(Device).init(allocator);
    defer {
        device_list.deinit();
    }

    var current_dev: ?*pcap.struct_pcap_if = alldevs;

    while (current_dev) |dev| {
        var addr_list = std.array_list.Managed(Address).init(allocator);
        var current_addr = dev.addresses;

        while (current_addr != null) {
            const ca = current_addr.*;

            try addr_list.append(.{
                .addr = if (ca.addr != null) @bitCast(ca.addr.*) else null,
                .netmask = if (ca.netmask != null) @bitCast(ca.netmask.*) else null,
                .broadaddr = if (ca.broadaddr != null) @bitCast(ca.broadaddr.*) else null,
                .dstaddr = if (ca.dstaddr != null) @bitCast(ca.dstaddr.*) else null,
            });

            current_addr = ca.next;
        }

        try device_list.append(.{
            .name = try allocator.dupe(u8, std.mem.span(dev.name)),
            .description = if (dev.description != null)
                try allocator.dupe(u8, std.mem.span(dev.description))
            else
                null,
            .flags = dev.flags,
            .addresses = try addr_list.toOwnedSlice(),
        });

        current_dev = dev.next;
    }

    return device_list.toOwnedSlice();
}

fn ip_to_bytes(ip: u32) [4]u8 {
    return @as(*const [4]u8, @ptrCast(&ip))[0..4].*;
}

fn mac_to_bytes(mac: u48) [6]u8 {
    return @as(*const [6]u8, @ptrCast(&mac))[0..6].*;
}

pub const Device = struct {
    name: []const u8,
    description: ?[]const u8,
    flags: u32,
    addresses: []Address,

    pub fn print(self: Device) void {
        if (self.addresses.len == 0) {
            return;
        }

        std.debug.print("Device: \"{s}\":\n", .{self.name});

        if (self.description != null) {
            std.debug.print("\tDescription: \"{s}\"\n", .{self.description.?});
        }

        std.debug.print("\tFlags: {d}\n", .{self.flags});
        std.debug.print("\tAddressing Information\n", .{});
        for (self.addresses) |address| {
            if (address.addr == null) {
                continue;
            }

            switch (address.addr.?.family) {
                posix.AF.INET => {
                    const addr_as_ipv4: posix.sockaddr.in = @bitCast(address.addr.?);
                    const netmask_as_ipv4: posix.sockaddr.in = @bitCast(address.netmask.?);
                    const broadcast_as_ipv4: posix.sockaddr.in = if (address.broadaddr != null) @bitCast(address.broadaddr.?) else std.mem.zeroes(posix.sockaddr.in);

                    const addr_ip_bytes = ip_to_bytes(addr_as_ipv4.addr);
                    const netmask_ip_bytes = ip_to_bytes(netmask_as_ipv4.addr);
                    const broadcast_ip_bytes = ip_to_bytes(broadcast_as_ipv4.addr);

                    std.debug.print("\t\tIPv4 address: {}.{}.{}.{}, ", .{ addr_ip_bytes[0], addr_ip_bytes[1], addr_ip_bytes[2], addr_ip_bytes[3] });
                    std.debug.print("\tNetmask: {}.{}.{}.{}", .{ netmask_ip_bytes[0], netmask_ip_bytes[1], netmask_ip_bytes[2], netmask_ip_bytes[3] });
                    if (address.broadaddr != null) {
                        std.debug.print("\tBroadcast: {}.{}.{}.{}", .{ broadcast_ip_bytes[0], broadcast_ip_bytes[1], broadcast_ip_bytes[2], broadcast_ip_bytes[3] });
                    }

                    std.debug.print("\n", .{});
                },
                else => {
                    continue;
                },
            }
        }
        std.debug.print("\n", .{});
    }
};

pub const Address = struct {
    addr: ?posix.sockaddr,
    netmask: ?posix.sockaddr,
    broadaddr: ?posix.sockaddr,
    dstaddr: ?posix.sockaddr,
};
