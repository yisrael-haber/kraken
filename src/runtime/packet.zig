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
    tcp: struct { offset: u16 },
    icmp: struct { offset: u16 },
};

/// A packet is always owned by exactly one identity worker. It intentionally
/// carries its bytes and parsed view together, so no packet view outlives data.
pub const Packet = struct {
    bytes: [frame_capacity]u8 = [_]u8{0} ** frame_capacity,
    len: u16 = 0,
    direction: Direction = .inbound,
    dropped: bool = false,
    ethernet: ?Ethernet = null,
    ipv4: ?Ipv4 = null,
    transport: ?Transport = null,

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
        self.ipv4 = null;
        self.transport = null;
        const length: usize = self.len;
        if (length < 14) return;
        const ether_type = readU16(self.bytes[12..14]);
        self.ethernet = .{
            .destination = self.bytes[0..6].*,
            .source = self.bytes[6..12].*,
            .ether_type = ether_type,
        };
        if (ether_type != 0x0800 or length < 34) return;
        const offset: usize = 14;
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
        const ip = Ipv4{
            .offset = @intCast(offset),
            .header_length = @intCast(header_length),
            .total_length = @intCast(total_length),
            .protocol = self.bytes[offset + 9],
            .source = self.bytes[offset + 12 .. offset + 16].*,
            .destination = self.bytes[offset + 16 .. offset + 20].*,
        };
        self.ipv4 = ip;
        const transport_offset = offset + header_length;
        const payload_length = total_length - header_length;
        switch (ip.protocol) {
            17 => if (payload_length >= 8) {
                self.transport = .{ .udp = .{ .offset = @intCast(transport_offset), .length = readU16(self.bytes[transport_offset + 4 .. transport_offset + 6]) } };
            },
            6 => if (payload_length >= 20) {
                self.transport = .{ .tcp = .{ .offset = @intCast(transport_offset) } };
            },
            1 => if (payload_length >= 4) {
                self.transport = .{ .icmp = .{ .offset = @intCast(transport_offset) } };
            },
            else => {},
        }
    }

    pub fn repair(self: *Packet, options: SendOptions) void {
        if (options.repair == .manual) return;
        const ip = self.ipv4 orelse return;
        const offset: usize = ip.offset;
        const header_length: usize = ip.header_length;
        if (offset + header_length > self.len) return;
        writeU16(self.bytes[offset + 2 .. offset + 4], @intCast(self.len - offset));
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
        const length = @as(usize, self.len) - offset;
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
        const length = @as(usize, self.len) - offset;
        if (length < 20) return;
        self.bytes[offset + 16] = 0;
        self.bytes[offset + 17] = 0;
        var sum = pseudoHeaderSum(ip, 6, @intCast(length));
        sum = addBytes(sum, self.bytes[offset .. offset + length]);
        writeU16(self.bytes[offset + 16 .. offset + 18], finishChecksum(sum));
    }

    fn repairIcmp(self: *Packet, icmp: anytype) void {
        const offset: usize = icmp.offset;
        const length = @as(usize, self.len) - offset;
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

test "automatic repair updates ipv4 total length and checksum" {
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
