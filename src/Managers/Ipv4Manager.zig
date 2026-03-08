const std = @import("std");
const ph = @import("../protocol_headers.zig");
const em = @import("EthernetManager.zig");
const EthernetManager = em.EthernetManager;
const ProtocolHandler = em.ProtocolHandler;

/// Type-erased handler for IP-layer protocols. Receives both the parsed IPv4
/// header and the payload, allowing handlers to inspect source/destination IPs.
pub const Ipv4ProtocolHandler = struct {
    ptr: *anyopaque,
    handleFn: *const fn (ptr: *anyopaque, ip_hdr: ph.Ipv4Header, payload: []const u8) anyerror!void,

    pub fn handle(self: Ipv4ProtocolHandler, ip_hdr: ph.Ipv4Header, payload: []const u8) !void {
        return self.handleFn(self.ptr, ip_hdr, payload);
    }
};

pub const Ipv4Manager = struct {
    allocator: std.mem.Allocator,
    eth: *EthernetManager,
    handlers: std.AutoHashMap(u8, Ipv4ProtocolHandler),

    pub fn init(allocator: std.mem.Allocator, eth: *EthernetManager) Ipv4Manager {
        return .{
            .allocator = allocator,
            .eth = eth,
            .handlers = std.AutoHashMap(u8, Ipv4ProtocolHandler).init(allocator),
        };
    }

    pub fn deinit(self: *Ipv4Manager) void {
        self.handlers.deinit();
    }

    /// Register a handler for an IP protocol number (e.g. 1 for ICMP, 6 for TCP, 17 for UDP).
    pub fn registerHandler(self: *Ipv4Manager, protocol: u8, h: Ipv4ProtocolHandler) !void {
        try self.handlers.put(protocol, h);
    }

    /// Returns a type-erased ProtocolHandler suitable for registering with an
    /// EthernetManager (ether_type 0x0800).
    pub fn protocolHandler(self: *Ipv4Manager) ProtocolHandler {
        return .{
            .ptr = self,
            .handleFn = handlePacket,
        };
    }

    /// Send an IPv4 packet. Builds the IP header (with computed checksum), wraps
    /// `payload` in a HeaderNode chain, and sends via the EthernetManager.
    /// `payload` must remain valid for the duration of this call.
    pub fn sendPacket(
        self: *Ipv4Manager,
        dst_mac: u48,
        src_ip: u32,
        dst_ip: u32,
        protocol: u8,
        ttl: u8,
        payload: []const u8,
    ) !void {
        const total_length: u16 = @intCast(20 + payload.len);

        // Build the IP header with checksum = 0, then compute the checksum.
        var ip_hdr: ph.Ipv4Header = .{
            .version = 4,
            .ihl = 5,
            .tos = 0,
            .total_length = total_length,
            .identification = 0,
            .flags = 0,
            .fragment_offset = 0,
            .ttl = ttl,
            .protocol = protocol,
            .checksum = 0,
            .src_ip = src_ip,
            .dst_ip = dst_ip,
        };
        var hdr_buf: [20]u8 = undefined;
        std.mem.writeInt(u160, &hdr_buf, @bitCast(ip_hdr), .big);
        ip_hdr.checksum = ph.internetChecksum(&hdr_buf);

        const ip_pkt = try self.allocator.create(ph.Ipv4Packet);
        ip_pkt.* = .{ .header = ip_hdr, .options = &.{} };

        const payload_hdr = try self.allocator.create(ph.UnparsedHeader);
        payload_hdr.* = .{ .data = payload };

        const payload_node = try self.allocator.create(ph.HeaderNode);
        payload_node.* = .{ .header = .{ .Unparsed = payload_hdr }, .next = null, .prev = null };

        const ip_node = try self.allocator.create(ph.HeaderNode);
        ip_node.* = .{ .header = .{ .Ipv4 = ip_pkt }, .next = payload_node, .prev = null };

        defer {
            self.allocator.destroy(ip_pkt);
            self.allocator.destroy(payload_hdr);
            self.allocator.destroy(payload_node);
            self.allocator.destroy(ip_node);
        }

        try self.eth.sendFrame(dst_mac, 0x0800, ip_node);
    }

    /// Called by EthernetManager when an IPv4 frame is received.
    fn handlePacket(ptr: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *Ipv4Manager = @ptrCast(@alignCast(ptr));
        if (bytes.len < 20) return;
        const hdr: ph.Ipv4Header = @bitCast(std.mem.readInt(u160, bytes[0..20], .big));
        const ihl_bytes: usize = @as(usize, hdr.ihl) * 4;
        const payload_start = if (ihl_bytes >= 20 and ihl_bytes <= bytes.len) ihl_bytes else 20;
        if (self.handlers.get(hdr.protocol)) |h| {
            try h.handle(hdr, bytes[payload_start..]);
        }
    }
};
