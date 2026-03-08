const std = @import("std");
const ph = @import("../protocol_headers.zig");
const em = @import("EthernetManager.zig");
const EthernetManager = em.EthernetManager;
const ProtocolHandler = em.ProtocolHandler;

pub const ArpManager = struct {
    cache: std.AutoHashMap(u32, u48),
    allocator: std.mem.Allocator,
    eth: *EthernetManager,
    our_ip: u32,
    our_mac: u48,

    pub fn init(allocator: std.mem.Allocator, eth: *EthernetManager, our_ip: u32, our_mac: u48) ArpManager {
        return ArpManager{
            .cache = std.AutoHashMap(u32, u48).init(allocator),
            .allocator = allocator,
            .eth = eth,
            .our_ip = our_ip,
            .our_mac = our_mac,
        };
    }

    pub fn deinit(self: *ArpManager) void {
        self.cache.deinit();
    }

    /// Returns a type-erased ProtocolHandler suitable for registering with an
    /// EthernetManager (ether_type 0x0806).
    pub fn protocolHandler(self: *ArpManager) ProtocolHandler {
        return .{
            .ptr = self,
            .handleFn = handlePacket,
        };
    }

    /// Called by EthernetManager when an ARP frame is received.
    fn handlePacket(ptr: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *ArpManager = @ptrCast(@alignCast(ptr));
        if (bytes.len < 28) return;
        const ah: ph.ArpHeader = @bitCast(std.mem.readInt(u224, bytes[0..28], .big));
        switch (ah.opcode) {
            0x0001 => { // request — cache the sender and respond if it's asking for our IP
                try self.cacheEntry(ah.sender_ip, ah.sender_mac);
                if (ah.target_ip == self.our_ip) {
                    try self.sendReply(ah.sender_mac, ah.sender_ip);
                }
            },
            0x0002 => { // reply — cache the sender
                try self.cacheEntry(ah.sender_ip, ah.sender_mac);
            },
            else => {},
        }
    }

    fn sendReply(self: *ArpManager, requester_mac: u48, requester_ip: u32) !void {
        const arp_hdr = try self.allocator.create(ph.ArpHeader);
        arp_hdr.* = .{
            .hw_type = 0x0001,
            .proto_type = 0x0800,
            .hw_size = 6,
            .proto_size = 4,
            .opcode = 0x0002,
            .sender_mac = self.our_mac,
            .sender_ip = self.our_ip,
            .target_mac = requester_mac,
            .target_ip = requester_ip,
        };
        const arp_node = try self.allocator.create(ph.HeaderNode);
        arp_node.* = .{ .header = .{ .Arp = arp_hdr }, .next = null, .prev = null };
        defer {
            self.allocator.destroy(arp_hdr);
            self.allocator.destroy(arp_node);
        }

        try self.eth.sendFrame(requester_mac, 0x0806, arp_node);

        const our_mac_bytes = ph.mac_to_be_bytes(self.our_mac);
        std.debug.print("ARP reply sent: {any} is at {X}:{X}:{X}:{X}:{X}:{X}\n", .{
            ph.ip_to_be_bytes(self.our_ip),
            our_mac_bytes[0],
            our_mac_bytes[1],
            our_mac_bytes[2],
            our_mac_bytes[3],
            our_mac_bytes[4],
            our_mac_bytes[5],
        });
    }

    pub fn getMacAddress(self: *ArpManager, ip: u32) !u48 {
        if (self.cache.get(ip)) |mac| {
            return mac;
        }

        std.debug.print("ARP cache miss for IP {any}. Querying network...\n", .{ph.ip_to_be_bytes(ip)});
        try self.queryNetwork(ip);

        if (self.cache.get(ip)) |mac| {
            return mac;
        }

        return error.ArpQueryFailed;
    }

    pub fn cacheEntry(self: *ArpManager, ip: u32, mac: u48) !void {
        try self.cache.put(ip, mac);
        const ip_bytes = ph.ip_to_be_bytes(ip);
        const mac_bytes = ph.mac_to_be_bytes(mac);
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

        const arp_hdr = try self.allocator.create(ph.ArpHeader);
        arp_hdr.* = .{
            .hw_type = 0x0001,
            .proto_type = 0x0800,
            .hw_size = 6,
            .proto_size = 4,
            .opcode = 0x0001,
            .sender_mac = self.our_mac,
            .sender_ip = self.our_ip,
            .target_mac = 0,
            .target_ip = target_ip,
        };
        const arp_node = try self.allocator.create(ph.HeaderNode);
        arp_node.* = .{ .header = .{ .Arp = arp_hdr }, .next = null, .prev = null };
        defer {
            self.allocator.destroy(arp_hdr);
            self.allocator.destroy(arp_node);
        }

        try self.eth.sendFrame(broadcast_mac, 0x0806, arp_node);

        std.debug.print("ARP request sent for IP {any}\n", .{ph.ip_to_be_bytes(target_ip)});
    }
};

