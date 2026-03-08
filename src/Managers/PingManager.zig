const std = @import("std");
const ph = @import("../protocol_headers.zig");
const im = @import("Ipv4Manager.zig");
const am = @import("ArpManager.zig");
const Ipv4ProtocolHandler = im.Ipv4ProtocolHandler;

pub const PingManager = struct {
    allocator: std.mem.Allocator,
    ip: *im.Ipv4Manager,
    arp: *am.ArpManager,
    our_ip: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        ip: *im.Ipv4Manager,
        arp: *am.ArpManager,
        our_ip: u32,
    ) PingManager {
        return .{
            .allocator = allocator,
            .ip = ip,
            .arp = arp,
            .our_ip = our_ip,
        };
    }

    /// Returns an Ipv4ProtocolHandler for registering with Ipv4Manager (protocol 1 = ICMP).
    pub fn ipProtocolHandler(self: *PingManager) Ipv4ProtocolHandler {
        return .{
            .ptr = self,
            .handleFn = handlePacket,
        };
    }

    fn handlePacket(ptr: *anyopaque, ip_hdr: ph.Ipv4Header, bytes: []const u8) anyerror!void {
        const self: *PingManager = @ptrCast(@alignCast(ptr));

        // Ignore packets not addressed to us.
        if (ip_hdr.dst_ip != self.our_ip) return;
        if (bytes.len < 8) return;

        const icmp_type = bytes[0];
        const icmp_code = bytes[1];
        const identifier = (@as(u16, bytes[4]) << 8) | bytes[5];
        const sequence = (@as(u16, bytes[6]) << 8) | bytes[7];
        const data = bytes[8..];
        const src = ph.ip_to_be_bytes(ip_hdr.src_ip);

        switch (icmp_type) {
            8 => { // Echo Request
                if (icmp_code != 0) return;
                std.debug.print("ICMP Echo Request: id=0x{X:0>4} seq={d} from {}.{}.{}.{}\n", .{
                    identifier, sequence, src[0], src[1], src[2], src[3],
                });
                self.sendReply(ip_hdr.src_ip, identifier, sequence, data) catch |err| {
                    std.debug.print("ICMP reply failed: {}\n", .{err});
                };
            },
            0 => { // Echo Reply
                std.debug.print("ICMP Echo Reply: id=0x{X:0>4} seq={d} from {}.{}.{}.{}\n", .{
                    identifier, sequence, src[0], src[1], src[2], src[3],
                });
            },
            else => {},
        }
    }

    /// Send an ICMP echo request to `dst_ip` using a pre-resolved `dst_mac`.
    pub fn sendRequest(
        self: *PingManager,
        dst_ip: u32,
        dst_mac: u48,
        identifier: u16,
        sequence: u16,
    ) !void {
        const icmp = ph.IcmpEchoPacket{
            .icmp_type = 8, // Echo Request
            .code = 0,
            .checksum = 0,
            .identifier = identifier,
            .sequence = sequence,
            .data = &.{},
        };
        const icmp_bytes = icmp.serialize(self.allocator);
        defer self.allocator.free(icmp_bytes);
        try self.ip.sendPacket(dst_mac, self.our_ip, dst_ip, 1, 64, icmp_bytes);
        const dst = ph.ip_to_be_bytes(dst_ip);
        std.debug.print("ICMP Echo Request sent: id=0x{X:0>4} seq={d} to {}.{}.{}.{}\n", .{
            identifier, sequence, dst[0], dst[1], dst[2], dst[3],
        });
    }

    fn sendReply(
        self: *PingManager,
        dst_ip: u32,
        identifier: u16,
        sequence: u16,
        data: []const u8,
    ) !void {
        const dst_mac = try self.arp.getMacAddress(dst_ip);

        const icmp = ph.IcmpEchoPacket{
            .icmp_type = 0, // Echo Reply
            .code = 0,
            .checksum = 0,
            .identifier = identifier,
            .sequence = sequence,
            .data = data,
        };

        const icmp_bytes = icmp.serialize(self.allocator);
        defer self.allocator.free(icmp_bytes);

        try self.ip.sendPacket(dst_mac, self.our_ip, dst_ip, 1, 64, icmp_bytes);

        const dst = ph.ip_to_be_bytes(dst_ip);
        std.debug.print("ICMP Echo Reply sent: id=0x{X:0>4} seq={d} to {}.{}.{}.{}\n", .{
            identifier, sequence, dst[0], dst[1], dst[2], dst[3],
        });
    }
};
