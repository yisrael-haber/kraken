const std = @import("std");
const posix = std.posix;
const moto = @import("moto");

const pcap = @cImport({
    @cInclude("pcap.h");
});

const program_parameters = struct { ip: u32 = @bitCast([4]u8{ 172, 24, 23, 68 }), mac: u48 = @bitCast([6]u8{ 0, 21, 93, 206, 108, 200 }) };
const broadcast_mac: u48 = @bitCast([6]u8{ 255, 255, 255, 255, 255, 255 });

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();

    const devices = try get_device_list(arena);

    for (devices) |device| {
        device.print();
    }

    const a = program_parameters{};

    try listen_on(arena, "eth0", a.ip, a.mac);
}

fn listen_on(allocator: std.mem.Allocator, ifa_name: []const u8, ip: u32, mac: u48) !void {
    std.debug.print("Attempting to listen on: interface=\"{s}\", ", .{ifa_name});

    const ip_bytes = ip_to_bytes(ip);
    std.debug.print("with ip address {}.{}.{}.{} ", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] });

    const mac_bytes = mac_to_bytes(mac);
    std.debug.print("and with mac address {X}:{X}:{X}:{X}:{X}:{X}", .{ mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5] });

    std.debug.print("\n", .{});

    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    const device = try allocator.dupeZ(u8, ifa_name);
    defer allocator.free(device);

    const snaplen = 65535;
    const promisc = 1;
    const timeout_ms = 1000;

    const handle = pcap.pcap_open_live(device, snaplen, promisc, timeout_ms, &errbuf);

    if (handle == null) {
        std.debug.print("Error opening device: {s}\n", .{errbuf});
        return error.PcapOpenFailed;
    }

    defer pcap.pcap_close(handle);

    var header: [*c]pcap.pcap_pkthdr = undefined;
    var pkt_data: [*c]const u8 = undefined;

    while (true) {
        const res = pcap.pcap_next_ex(handle, &header, &pkt_data);

        switch (res) {
            1 => {
                const len = header.*.caplen;
                const data = pkt_data[0..len];

                const ethernet_header: EthernetHeader = @bitCast(data[0..14].*);

                if (ethernet_header.dest_mac == broadcast_mac) {
                    std.debug.print("Ethernet Header: {any}\n", .{ethernet_header});

                    const arp_header: ArpHeader = @bitCast(std.mem.readInt(u224, data[14..42], .big));

                    std.debug.print("Arp header: {any}, raw: {s}\n", .{ arp_header, std.fmt.bytesToHex(data[14..42], .upper) });

                    std.debug.print("sender MAC: {s}\n", .{std.fmt.bytesToHex(mac_to_bytes(arp_header.sender_mac), .upper)});
                }
            },
            0 => continue,
            -1 => {
                std.debug.print("Error: {s}\n", .{pcap.pcap_geterr(handle)});
                break;
            },
            -2 => break,
            else => break,
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
    const ip_bytes = @as(*const [4]u8, @ptrCast(&ip)).*;

    return ip_bytes;
}

fn mac_to_bytes(ip: u48) [6]u8 {
    const mac_bytes = @as(*const [6]u8, @ptrCast(&ip)).*;

    return mac_bytes;
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

pub const Address = struct { addr: ?posix.sockaddr, netmask: ?posix.sockaddr, broadaddr: ?posix.sockaddr, dstaddr: ?posix.sockaddr };

pub const EthernetHeader = packed struct(u112) {
    dest_mac: u48, // 6 bytes
    src_mac: u48, // 6 bytes
    ether_type: u16, // 2 bytes
};

pub const ArpHeader = packed struct(u224) {
    target_ip: u32,
    target_mac: u48,
    sender_ip: u32,
    sender_mac: u48,
    opcode: u16,
    proto_size: u8,
    hw_size: u8,
    proto_type: u16,
    hw_type: u16,
};
