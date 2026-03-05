const std = @import("std");
const ph = @import("../protocol_headers.zig");
const handler = @import("../Handlers/libpcap_handler.zig");

pub const ArpManager = struct {
    cache: std.AutoHashMap(u32, u48),
    allocator: std.mem.Allocator,
    handler: *handler.PcapHandler,
    our_ip: u32,
    our_mac: u48,

    pub fn init(allocator: std.mem.Allocator, h: *handler.PcapHandler, our_ip: u32, our_mac: u48) ArpManager {
        return ArpManager{
            .cache = std.AutoHashMap(u32, u48).init(allocator),
            .allocator = allocator,
            .handler = h,
            .our_ip = our_ip,
            .our_mac = our_mac,
        };
    }

    pub fn deinit(self: *ArpManager) void {
        self.cache.deinit();
    }

    pub fn getMacAddress(self: *ArpManager, ip: u32) !u48 {
        // Check if we have it cached
        if (self.cache.get(ip)) |mac| {
            return mac;
        }

        // Not in cache, query the network
        std.debug.print("ARP cache miss for IP {any}. Querying network...\n", .{ip_to_bytes(ip)});
        try self.queryNetwork(ip);

        // After querying, check cache again
        if (self.cache.get(ip)) |mac| {
            return mac;
        }

        return error.ArpQueryFailed;
    }

    pub fn cacheEntry(self: *ArpManager, ip: u32, mac: u48) !void {
        try self.cache.put(ip, mac);
        const ip_bytes = ip_to_bytes(ip);
        const mac_bytes = mac_to_bytes(mac);
        std.debug.print("ARP cache entry added: {}.{}.{}.{} -> {X}:{X}:{X}:{X}:{X}:{X}\n", .{
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        });
    }

    pub fn queryNetwork(self: *ArpManager, target_ip: u32) !void {
        const broadcast_mac: u48 = @bitCast([6]u8{ 255, 255, 255, 255, 255, 255 });

        // Build header node chain representing the packet we want to send.
        const eth_hdr = try self.allocator.create(ph.EthernetHeader);
        eth_hdr.* = ph.EthernetHeader{
            .ether_type = 0x0806, // ARP
            .src_mac = self.our_mac,
            .dest_mac = broadcast_mac,
        };

        const arp_hdr = try self.allocator.create(ph.ArpHeader);
        arp_hdr.* = ph.ArpHeader{
            .hw_type = 0x0001, // Ethernet
            .proto_type = 0x0800, // IPv4
            .hw_size = 6, // MAC address size
            .proto_size = 4, // IPv4 address size
            .opcode = 0x0001, // ARP Request
            .sender_mac = self.our_mac,
            // our_ip is already in network order; use directly
            .sender_ip = self.our_ip,
            .target_mac = 0, // Don't know yet
            .target_ip = target_ip,
        };

        const eth_node = try self.allocator.create(ph.HeaderNode);
        eth_node.* = ph.HeaderNode{
            .header = ph.Header{ .Ethernet = eth_hdr },
            .next = null,
            .prev = null,
        };

        const arp_node = try self.allocator.create(ph.HeaderNode);
        arp_node.* = ph.HeaderNode{
            .header = ph.Header{ .Arp = arp_hdr },
            .next = null,
            .prev = eth_node,
        };

        eth_node.next = arp_node;

        try self.handler.sendPacket(eth_node);
        self.handler.freeChain(eth_node);

        std.debug.print("ARP request sent for IP {any}\n", .{ip_to_bytes(target_ip)});
    }
};
fn ip_to_bytes(ip: u32) [4]u8 {
    return @as(*const [4]u8, @ptrCast(&ip))[0..4].*;
}

fn mac_to_bytes(mac: u48) [6]u8 {
    return @as(*const [6]u8, @ptrCast(&mac))[0..6].*;
}
