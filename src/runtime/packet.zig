const std = @import("std");

pub const capacity = 2048;
pub const Direction = enum { inbound, outbound };

pub const Frame = struct {
    bytes: [capacity]u8 = [_]u8{0} ** capacity,
    len: u16 = 0,

    pub fn set(self: *Frame, value: []const u8) error{FrameTooLarge}!void {
        if (value.len > capacity) return error.FrameTooLarge;
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
    }
};

pub const Ipv4 = struct {
    offset: u16,
    header_length: u8,
};

pub const Tcp = struct { offset: u16, header_length: u8 };
pub const Transport = union(enum) { udp: u16, tcp: Tcp, icmp: u16 };

pub const Layout = struct {
    bytes: [capacity]u8 = [_]u8{0} ** capacity,
    len: u16 = 0,
    vlan_count: u16 = 0,
    arp: ?u16 = null,
    ipv4: ?Ipv4 = null,
    transport: ?Transport = null,

    pub fn init(value: Frame) Layout {
        var self: Layout = .{ .bytes = value.bytes, .len = value.len };
        self.parse();
        return self;
    }

    fn parse(self: *Layout) void {
        self.vlan_count = 0;
        self.arp = null;
        self.ipv4 = null;
        self.transport = null;
        const length: usize = self.len;
        if (length < 14) return;
        var network_type = readU16(self.bytes[12..14]);
        var offset: usize = 14;
        while (network_type == 0x8100 or network_type == 0x88a8) {
            if (offset + 4 > length) return;
            network_type = readU16(self.bytes[offset + 2 .. offset + 4]);
            offset += 4;
            self.vlan_count += 1;
        }
        if (network_type == 0x0806) {
            if (offset + 28 <= length) self.arp = @intCast(offset);
            return;
        }
        if (network_type != 0x0800 or offset + 20 > length) return;
        const version = self.bytes[offset] >> 4;
        const header_length: usize = @as(usize, self.bytes[offset] & 0x0f) * 4;
        if (version != 4 or header_length < 20 or offset + header_length > length) return;
        self.ipv4 = .{
            .offset = @intCast(offset),
            .header_length = @intCast(header_length),
        };
        if ((readU16(self.bytes[offset + 6 .. offset + 8]) & 0x1fff) != 0) return;
        const transport_offset = offset + header_length;
        const payload_length = length - transport_offset;
        switch (self.bytes[offset + 9]) {
            17 => self.transport = if (payload_length >= 8) .{ .udp = @intCast(transport_offset) } else null,
            6 => if (payload_length >= 20) {
                const tcp_header_length: usize = @as(usize, self.bytes[transport_offset + 12] >> 4) * 4;
                if (tcp_header_length >= 20 and tcp_header_length <= payload_length) {
                    self.transport = .{ .tcp = .{ .offset = @intCast(transport_offset), .header_length = @intCast(tcp_header_length) } };
                }
            },
            1 => self.transport = if (payload_length >= 8) .{ .icmp = @intCast(transport_offset) } else null,
            else => {},
        }
    }
};

pub fn readU16(value: []const u8) u16 {
    return std.mem.readInt(u16, value[0..2], .big);
}
