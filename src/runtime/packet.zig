const std = @import("std");

pub const frame_capacity = 2048;

pub const Direction = enum { inbound, outbound };
pub const Repair = enum { automatic, manual };

pub const SendOptions = struct {
    repair: Repair = .automatic,
};

pub const Ethernet = struct {
    destination: [6]u8,
    source: [6]u8,
    ether_type: u16,
};

pub const Vlan = struct {
    type_offset: u16,
    tci_offset: u16,
    inner_type_offset: u16,
};

pub const Arp = struct {
    offset: u16,
};

pub const Ipv4 = struct {
    offset: u16,
    header_length: u8,
    total_length: u16,
    protocol: u8,
    source: [4]u8,
    destination: [4]u8,
};

pub const Transport = union(enum) {
    udp: struct { offset: u16, length: u16 },
    tcp: struct { offset: u16, header_length: u8 },
    icmp: struct { offset: u16 },
};

/// A packet is always owned by exactly one identity worker. It intentionally
/// carries its bytes and parsed view together, so no packet view outlives data.
pub const Packet = struct {
    bytes: [frame_capacity]u8 = [_]u8{0} ** frame_capacity,
    len: u16 = 0,
    ethernet: ?Ethernet = null,
    vlans: [2]Vlan = undefined,
    vlan_count: u8 = 0,
    arp: ?Arp = null,
    ipv4: ?Ipv4 = null,
    transport: ?Transport = null,
    network_trailer_length: u16 = 0,

    pub fn clear(self: *Packet) void {
        self.* = .{};
    }

    pub fn setBytes(self: *Packet, value: []const u8) error{FrameTooLarge}!void {
        if (value.len > frame_capacity) return error.FrameTooLarge;
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
        self.parse();
    }

    pub fn parse(self: *Packet) void {
        self.ethernet = null;
        self.vlan_count = 0;
        self.arp = null;
        self.ipv4 = null;
        self.transport = null;
        self.network_trailer_length = 0;
        const length: usize = self.len;
        if (length < 14) return;
        const ether_type = readU16(self.bytes[12..14]);
        self.ethernet = .{
            .destination = self.bytes[0..6].*,
            .source = self.bytes[6..12].*,
            .ether_type = ether_type,
        };
        var network_type = ether_type;
        var offset: usize = 14;
        while ((network_type == 0x8100 or network_type == 0x88a8) and self.vlan_count < self.vlans.len) {
            if (offset + 4 > length) return;
            self.vlans[self.vlan_count] = .{
                .type_offset = @intCast(offset - 2),
                .tci_offset = @intCast(offset),
                .inner_type_offset = @intCast(offset + 2),
            };
            self.vlan_count += 1;
            network_type = readU16(self.bytes[offset + 2 .. offset + 4]);
            offset += 4;
        }
        if (network_type == 0x0806) {
            if (offset + 28 <= length) self.arp = .{ .offset = @intCast(offset) };
            return;
        }
        if (network_type != 0x0800 or offset + 20 > length) return;
        const version = self.bytes[offset] >> 4;
        const header_length: usize = @as(usize, self.bytes[offset] & 0x0f) * 4;
        if (version != 4 or header_length < 20 or offset + header_length > length) return;
        const wire_total_length = readU16(self.bytes[offset + 2 .. offset + 4]);
        // Keep a parsed view for malformed frames too. A transport hook may
        // repair or deliberately preserve those malformed wire values.
        const total_length: usize = if (wire_total_length >= header_length and offset + wire_total_length <= length)
            wire_total_length
        else
            length - offset;
        if (wire_total_length >= header_length and offset + wire_total_length <= length) {
            self.network_trailer_length = @intCast(length - offset - wire_total_length);
        }
        const ip = Ipv4{
            .offset = @intCast(offset),
            .header_length = @intCast(header_length),
            .total_length = @intCast(total_length),
            .protocol = self.bytes[offset + 9],
            .source = self.bytes[offset + 12 ..][0..4].*,
            .destination = self.bytes[offset + 16 ..][0..4].*,
        };
        self.ipv4 = ip;
        if ((readU16(self.bytes[offset + 6 .. offset + 8]) & 0x1fff) != 0) return;
        const transport_offset = offset + header_length;
        const payload_length = total_length - header_length;
        switch (ip.protocol) {
            17 => if (payload_length >= 8) {
                self.transport = .{ .udp = .{ .offset = @intCast(transport_offset), .length = readU16(self.bytes[transport_offset + 4 .. transport_offset + 6]) } };
            },
            6 => if (payload_length >= 20) {
                const tcp_header_length: usize = @as(usize, self.bytes[transport_offset + 12] >> 4) * 4;
                if (tcp_header_length >= 20 and tcp_header_length <= payload_length) {
                    self.transport = .{ .tcp = .{ .offset = @intCast(transport_offset), .header_length = @intCast(tcp_header_length) } };
                }
            },
            1 => if (payload_length >= 8) {
                self.transport = .{ .icmp = .{ .offset = @intCast(transport_offset) } };
            },
            else => {},
        }
    }

    pub fn payloadBounds(self: *const Packet) struct { offset: usize, length: usize } {
        const end: usize = if (self.ipv4) |ip| @min(@as(usize, self.len), @as(usize, ip.offset) + ip.total_length) else self.len;
        const offset: usize = if (self.transport) |transport| switch (transport) {
            .tcp => |tcp| @as(usize, tcp.offset) + tcp.header_length,
            .udp => |udp| @as(usize, udp.offset) + 8,
            .icmp => |icmp| @min(end, @as(usize, icmp.offset) + 8),
        } else if (self.ipv4) |ip| @as(usize, ip.offset) + ip.header_length else end;
        return .{ .offset = @min(offset, end), .length = end - @min(offset, end) };
    }

    pub fn replacePayload(self: *Packet, value: []const u8) error{FrameTooLarge}!void {
        const bounds = self.payloadBounds();
        try self.replaceRange(bounds.offset, bounds.length, value);
    }

    pub fn replaceRange(self: *Packet, offset: usize, old_length: usize, value: []const u8) error{FrameTooLarge}!void {
        if (offset > self.len or old_length > @as(usize, self.len) - offset) return error.FrameTooLarge;
        const old_end = offset + old_length;
        const new_length = @as(usize, self.len) - old_length + value.len;
        if (new_length > self.bytes.len) return error.FrameTooLarge;
        const tail = self.bytes[old_end..self.len];
        const destination = self.bytes[offset + value.len .. offset + value.len + tail.len];
        if (value.len > old_length)
            std.mem.copyBackwards(u8, destination, tail)
        else
            std.mem.copyForwards(u8, destination, tail);
        @memcpy(self.bytes[offset .. offset + value.len], value);
        self.len = @intCast(new_length);
        const network_trailer_length = self.network_trailer_length;
        self.parse();
        self.network_trailer_length = network_trailer_length;
    }

    pub fn repair(self: *Packet, options: SendOptions) void {
        if (options.repair == .manual) return;
        const ip = self.ipv4 orelse return;
        const offset: usize = ip.offset;
        const header_length: usize = ip.header_length;
        if (offset + header_length > self.len) return;
        const trailer_length: usize = self.network_trailer_length;
        if (trailer_length > @as(usize, self.len) - offset) return;
        const total_length = @as(usize, self.len) - offset - trailer_length;
        if (total_length > std.math.maxInt(u16)) return;
        writeU16(self.bytes[offset + 2 .. offset + 4], @intCast(total_length));
        self.bytes[offset + 10] = 0;
        self.bytes[offset + 11] = 0;
        writeU16(self.bytes[offset + 10 .. offset + 12], checksum(self.bytes[offset .. offset + header_length]));
        self.parse();
        const repaired_ip = self.ipv4 orelse return;
        switch (self.transport orelse return) {
            .udp => |udp| self.repairUdp(repaired_ip, udp),
            .tcp => |tcp| self.repairTcp(repaired_ip, tcp),
            .icmp => |icmp| self.repairIcmp(icmp),
        }
    }

    fn repairUdp(self: *Packet, ip: Ipv4, udp: anytype) void {
        const offset: usize = udp.offset;
        const ip_offset: usize = ip.offset;
        const length = @as(usize, ip.total_length) - (offset - ip_offset);
        if (length < 8 or ip_offset + @as(usize, ip.total_length) > self.len) return;
        writeU16(self.bytes[offset + 4 .. offset + 6], @intCast(length));
        self.bytes[offset + 6] = 0;
        self.bytes[offset + 7] = 0;
        var sum = pseudoHeaderSum(ip, 17, @intCast(length));
        sum = addBytes(sum, self.bytes[offset .. offset + length]);
        var result = finishChecksum(sum);
        if (result == 0) result = 0xffff;
        writeU16(self.bytes[offset + 6 .. offset + 8], result);
    }

    fn repairTcp(self: *Packet, ip: Ipv4, tcp: anytype) void {
        const offset: usize = tcp.offset;
        const ip_offset: usize = ip.offset;
        const length = @as(usize, ip.total_length) - (offset - ip_offset);
        if (length < 20) return;
        self.bytes[offset + 16] = 0;
        self.bytes[offset + 17] = 0;
        var sum = pseudoHeaderSum(ip, 6, @intCast(length));
        sum = addBytes(sum, self.bytes[offset .. offset + length]);
        writeU16(self.bytes[offset + 16 .. offset + 18], finishChecksum(sum));
    }

    fn repairIcmp(self: *Packet, icmp: anytype) void {
        const offset: usize = icmp.offset;
        const ip = self.ipv4 orelse return;
        const ip_offset: usize = ip.offset;
        const length = @as(usize, ip.total_length) - (offset - ip_offset);
        if (length < 4) return;
        self.bytes[offset + 2] = 0;
        self.bytes[offset + 3] = 0;
        writeU16(self.bytes[offset + 2 .. offset + 4], checksum(self.bytes[offset .. offset + length]));
    }
};

fn readU16(value: []const u8) u16 {
    return std.mem.readInt(u16, value[0..2], .big);
}

fn writeU16(value: []u8, integer: u16) void {
    std.mem.writeInt(u16, value[0..2], integer, .big);
}

fn addBytes(initial: u32, value: []const u8) u32 {
    var sum = initial;
    var index: usize = 0;
    while (index + 1 < value.len) : (index += 2) sum += readU16(value[index .. index + 2]);
    if (index < value.len) sum += @as(u32, value[index]) << 8;
    return sum;
}

fn finishChecksum(initial: u32) u16 {
    var sum = initial;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

fn checksum(value: []const u8) u16 {
    return finishChecksum(addBytes(0, value));
}

fn pseudoHeaderSum(ip: Ipv4, protocol: u8, length: u16) u32 {
    var sum: u32 = 0;
    sum = addBytes(sum, &ip.source);
    sum = addBytes(sum, &ip.destination);
    sum += protocol;
    sum += length;
    return sum;
}

test "automatic repair updates lengths and checksums" {
    var packet: Packet = .{};
    try packet.setBytes(&[_]u8{
        0,    1, 2,   3, 4, 5, 6, 7, 8,  9, 10, 11, 8,   0,
        0x45, 0, 0,   0, 0, 1, 0, 0, 64, 1, 0,  0,  192, 0,
        2,    1, 192, 0, 2, 2, 8, 0, 0,  0, 0,  1,  0,   1,
    });
    packet.repair(.{});
    try std.testing.expectEqual(@as(u16, 28), readU16(packet.bytes[16..18]));
    try std.testing.expectEqual(@as(u16, 0), checksum(packet.bytes[14..34]));
}

test "manual repair preserves supplied bytes" {
    var packet: Packet = .{};
    try packet.setBytes(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 1, 0, 1, 0, 0, 64, 1, 0xaa, 0xbb, 192, 0, 2, 1, 192, 0, 2, 2, 8, 0, 0, 0, 0, 1, 0, 1 });
    packet.repair(.{ .repair = .manual });
    try std.testing.expectEqual(@as(u8, 0), packet.bytes[16]);
    try std.testing.expectEqual(@as(u8, 1), packet.bytes[17]);
    try std.testing.expectEqual(@as(u8, 0xaa), packet.bytes[24]);
}
