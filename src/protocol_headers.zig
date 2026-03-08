const std = @import("std");

pub const HeaderNode = struct {
    header: Header,
    next: ?*HeaderNode,
    prev: ?*HeaderNode,

    pub fn Serialize(self: HeaderNode, allocator: std.mem.Allocator) []u8 {
        const curr_bytes = switch (self.header) {
            inline else => |h| h.serialize(allocator),
        };

        if (self.next != null) {
            const next_bytes = self.next.?.Serialize(allocator);
            const combined_len = curr_bytes.len + next_bytes.len;
            const combined = allocator.alloc(u8, combined_len) catch unreachable;
            std.mem.copyForwards(u8, combined[0..curr_bytes.len], curr_bytes);
            std.mem.copyForwards(u8, combined[curr_bytes.len..], next_bytes);
            return combined;
        }

        return curr_bytes;
    }
};

/// IPv4 fixed header (20 bytes). Options are not represented; use ihl to
/// find where the payload begins.
///
/// Fields are declared LSB-first so that the struct can be cast to/from a
/// big-endian u160 integer directly:
///   header.* = @bitCast(std.mem.readInt(u160, bytes[0..20], .big));
pub const Ipv4Header = packed struct(u160) {
    dst_ip: u32,
    src_ip: u32,
    checksum: u16,
    protocol: u8,
    ttl: u8,
    fragment_offset: u13,
    flags: u3,
    identification: u16,
    total_length: u16,
    tos: u8,
    ihl: u4,
    version: u4,

    pub fn serialize(self: Ipv4Header, allocator: std.mem.Allocator) []u8 {
        const buf = allocator.alloc(u8, 20) catch unreachable;
        std.mem.writeInt(u160, buf[0..20], @bitCast(self), .big);
        return buf;
    }

    pub fn print(self: Ipv4Header) void {
        const src = ip_to_be_bytes(self.src_ip);
        const dst = ip_to_be_bytes(self.dst_ip);
        std.debug.print("IPv4 Header:\n", .{});
        std.debug.print("\tVersion: {d}  IHL: {d}  TOS: 0x{X:0>2}  Length: {d}\n", .{ self.version, self.ihl, self.tos, self.total_length });
        std.debug.print("\tID: 0x{X:0>4}  Flags: 0b{b:0>3}  FragOffset: {d}\n", .{ self.identification, self.flags, self.fragment_offset });
        std.debug.print("\tTTL: {d}  Protocol: {d}  Checksum: 0x{X:0>4}\n", .{ self.ttl, self.protocol, self.checksum });
        std.debug.print("\tSrc: {}.{}.{}.{}  Dst: {}.{}.{}.{}\n", .{ src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3] });
    }
};

/// IPv4 packet: the fixed 20-byte header paired with any trailing option bytes.
/// options is empty (len == 0) for the common case where ihl == 5.
/// Both header and options are populated from the same pcap-owned buffer and
/// do not need to be freed separately.
pub const Ipv4Packet = struct {
    header: Ipv4Header,
    options: []const u8,

    pub fn serialize(self: Ipv4Packet, allocator: std.mem.Allocator) []u8 {
        const buf = allocator.alloc(u8, 20 + self.options.len) catch unreachable;
        std.mem.writeInt(u160, buf[0..20], @bitCast(self.header), .big);
        @memcpy(buf[20..], self.options);
        return buf;
    }

    pub fn print(self: Ipv4Packet) void {
        self.header.print();
        if (self.options.len > 0) {
            std.debug.print("\tOptions: {d} bytes\n", .{self.options.len});
        }
    }
};

pub const Header = union(enum) {
    Ethernet: *EthernetHeader,
    Ipv4: *Ipv4Packet,
    Arp: *ArpHeader,
    Unparsed: *UnparsedHeader,
};

comptime {
    for (std.meta.fields(Header)) |field| {
        const T = @typeInfo(field.type).pointer.child;
        if (!@hasDecl(T, "serialize")) {
            @compileError("Header variant '" ++ field.name ++ "' is missing a serialize method");
        }
    }
}

pub const UnparsedHeader = struct {
    data: []const u8,

    pub fn serialize(self: UnparsedHeader, allocator: std.mem.Allocator) []u8 {
        const buf = allocator.alloc(u8, self.data.len) catch unreachable;
        std.mem.copyForwards(u8, buf, self.data);
        return buf;
    }
};

pub const EthernetHeader = packed struct(u112) {
    ether_type: u16,
    src_mac: u48,
    dest_mac: u48,

    pub fn serialize(self: EthernetHeader, allocator: std.mem.Allocator) []u8 {
        const buf = allocator.alloc(u8, 14) catch unreachable;
        const dest = mac_to_be_bytes(self.dest_mac);
        const src = mac_to_be_bytes(self.src_mac);
        std.mem.copyForwards(u8, buf[0..6], dest[0..]);
        std.mem.copyForwards(u8, buf[6..12], src[0..]);
        buf[12] = @intCast(self.ether_type >> 8);
        buf[13] = @intCast(self.ether_type & 0xFF);
        return buf;
    }

    pub fn print(self: EthernetHeader) void {
        const src_mac_bytes = mac_to_bytes(@byteSwap(self.src_mac));
        const dst_mac_bytes = mac_to_bytes(@byteSwap(self.dest_mac));
        std.debug.print("Ethernet Header: \n\tsrc: \t\t{s} \n\tdst: \t\t{s}\n\tether type: \t{X}\n", .{
            std.fmt.bytesToHex(src_mac_bytes, .upper),
            std.fmt.bytesToHex(dst_mac_bytes, .upper),
            self.ether_type,
        });
    }
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

    pub fn serialize(self: ArpHeader, allocator: std.mem.Allocator) []u8 {
        const buf = allocator.alloc(u8, 28) catch unreachable;
        var idx: usize = 0;
        buf[idx] = @intCast(self.hw_type >> 8);
        buf[idx + 1] = @intCast(self.hw_type & 0xFF);
        idx += 2;
        buf[idx] = @intCast(self.proto_type >> 8);
        buf[idx + 1] = @intCast(self.proto_type & 0xFF);
        idx += 2;
        buf[idx] = self.hw_size;
        idx += 1;
        buf[idx] = self.proto_size;
        idx += 1;
        buf[idx] = @intCast(self.opcode >> 8);
        buf[idx + 1] = @intCast(self.opcode & 0xFF);
        idx += 2;
        const smac = mac_to_be_bytes(self.sender_mac);
        std.mem.copyForwards(u8, buf[idx .. idx + 6], smac[0..]);
        idx += 6;
        const sip = ip_to_be_bytes(self.sender_ip);
        std.mem.copyForwards(u8, buf[idx .. idx + 4], sip[0..]);
        idx += 4;
        const tmac = mac_to_be_bytes(self.target_mac);
        std.mem.copyForwards(u8, buf[idx .. idx + 6], tmac[0..]);
        idx += 6;
        const tip = ip_to_be_bytes(self.target_ip);
        std.mem.copyForwards(u8, buf[idx .. idx + 4], tip[0..]);
        return buf;
    }

    pub fn print(self: ArpHeader) void {
        std.debug.print("\t\tARP Header: \n\t\t\tTarget IP: \t{any}\n", .{ip_to_be_bytes(self.target_ip)});
        std.debug.print("\t\t\tTarget MAC: \t0x{X}\n", .{mac_to_be_bytes(self.target_mac)});
        std.debug.print("\t\t\tSender IP: \t{any}\n", .{ip_to_be_bytes(self.sender_ip)});
        std.debug.print("\t\t\tSender MAC: \t0x{X}\n", .{mac_to_be_bytes(self.sender_mac)});
        std.debug.print("\t\t\tOpcode: \t0x{X}\n", .{self.opcode});
        std.debug.print("\t\t\tProto Size: \t{d}\n", .{self.proto_size});
        std.debug.print("\t\t\tHW Size: \t{d}\n", .{self.hw_size});
        std.debug.print("\t\t\tProto Type: \t0x{X}\n", .{self.proto_type});
        std.debug.print("\t\t\tHW Type: \t0x{X}\n", .{self.hw_type});
    }
};

/// Computes the Internet checksum (RFC 1071) over the given byte slice.
/// The checksum field in the header must be zeroed before calling this.
pub fn internetChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

/// ICMP echo request (type 8) / echo reply (type 0) packet.
/// The data slice points into a caller-managed buffer and is copied on serialize.
pub const IcmpEchoPacket = struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
    data: []const u8,

    pub fn serialize(self: IcmpEchoPacket, allocator: std.mem.Allocator) []u8 {
        const total_len = 8 + self.data.len;
        const buf = allocator.alloc(u8, total_len) catch unreachable;
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        buf[2] = 0; // checksum placeholder
        buf[3] = 0;
        buf[4] = @intCast(self.identifier >> 8);
        buf[5] = @intCast(self.identifier & 0xFF);
        buf[6] = @intCast(self.sequence >> 8);
        buf[7] = @intCast(self.sequence & 0xFF);
        @memcpy(buf[8..], self.data);
        const csum = internetChecksum(buf);
        buf[2] = @intCast(csum >> 8);
        buf[3] = @intCast(csum & 0xFF);
        return buf;
    }

    pub fn print(self: IcmpEchoPacket) void {
        const type_name = switch (self.icmp_type) {
            0 => "Echo Reply",
            8 => "Echo Request",
            else => "Unknown",
        };
        std.debug.print("ICMP {s}: id=0x{X:0>4} seq={d} data_len={d}\n", .{
            type_name, self.identifier, self.sequence, self.data.len,
        });
    }
};

/// Serialize a MAC address to its big-endian byte representation.
pub fn mac_to_be_bytes(mac: u48) [6]u8 {
    return .{
        @intCast((mac >> 40) & 0xFF),
        @intCast((mac >> 32) & 0xFF),
        @intCast((mac >> 24) & 0xFF),
        @intCast((mac >> 16) & 0xFF),
        @intCast((mac >> 8) & 0xFF),
        @intCast(mac & 0xFF),
    };
}

/// Serialize an IPv4 address to its big-endian byte representation.
pub fn ip_to_be_bytes(ip: u32) [4]u8 {
    return .{
        @intCast((ip >> 24) & 0xFF),
        @intCast((ip >> 16) & 0xFF),
        @intCast((ip >> 8) & 0xFF),
        @intCast(ip & 0xFF),
    };
}


pub fn ip_to_bytes(ip: u32) [4]u8 {
    return @as(*const [4]u8, @ptrCast(&ip))[0..4].*;
}

pub fn mac_to_bytes(mac: u48) [6]u8 {
    return @as(*const [6]u8, @ptrCast(&mac))[0..6].*;
}
