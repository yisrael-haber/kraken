const std = @import("std");
const posix = std.posix;
const ph = @import("protocol_headers.zig");
const ArpManager = @import("Managers/ArpManager.zig").ArpManager;
const libpcap_handler = @import("Handlers/libpcap_handler.zig");

pub const pcap = @import("pcap.zig").pcap;

const program_parameters = struct {
    ip: u32 = 0xAC181744, // 172.24.23.68
    mac: u48 = 0x00155DCE6CC8, // 00:15:5d:ce:6c:c8
};

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();

    const devices = try get_device_list(arena);

    for (devices) |device| {
        device.print();
    }

    // open a handler on the first interface (explicitly "eth0" for now)
    // and perform a single ARP query for 10.10.10.10 as requested.
    const query_ip: u32 = @bitCast([4]u8{ 10, 10, 10, 10 });
    var handler = try libpcap_handler.PcapHandler.init(arena, "eth0");
    defer handler.close();

    const params = program_parameters{};
    var local_mgr = ArpManager.init(arena, &handler, params.ip, params.mac);
    defer local_mgr.deinit();

    std.debug.print("performing ARP query for 10.10.10.10...\n", .{});
    try local_mgr.queryNetwork(query_ip);
}

fn listen_on(allocator: std.mem.Allocator, ifa_name: []const u8, ip: u32, mac: u48) !void {
    std.debug.print("Listening on: {s}\n", .{ifa_name});

    var handler = try libpcap_handler.PcapHandler.init(allocator, ifa_name);
    defer handler.close();

    var mgr = ArpManager.init(allocator, &handler, ip, mac);
    defer mgr.deinit();

    while (true) {
        const pkt_result = handler.receivePacket();
        if (pkt_result) |pkt_node| {
            defer handler.freeChain(pkt_node);

            const eth_node = pkt_node;
            const eh = switch (eth_node.header) {
                .Ethernet => |hdr| hdr.*,
                else => unreachable,
            };

            const inner_node = eth_node.next orelse null;

            if (eh.ether_type == 0x0806 and inner_node) {
                const ah = switch (inner_node.header) {
                    .Arp => |hdr| hdr.*,
                    else => unreachable,
                };

                eh.print();
                ah.print();

                if (ah.opcode == 0x0002) {
                    try mgr.cacheEntry(ah.sender_ip, ah.sender_mac);
                }
            }
        } else |err| {
            if (err == libpcap_handler.PcapHandler.Error.NoPacket) {
                continue; // timeout/keep listening
            }
            return err;
        }
    }
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
