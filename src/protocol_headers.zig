const std = @import("std");

pub const HeaderNode = struct {
    header: Header,
    next: ?*HeaderNode,
    prev: ?*HeaderNode,

    pub fn Serialize(self: HeaderNode) []u8 {
        // allocate with the page allocator for simplicity
        const allocator = std.heap.page_allocator;
        var curr_bytes: []u8 = undefined;

        switch (self.header) {
            .Ethernet => |eh| {
                curr_bytes = serializeEthernetHeader(eh.*);
            },
            .Arp => |ah| {
                curr_bytes = serializeArpHeader(ah.*);
            },
            .Unparsed => |data| {
                // take ownership of the provided slice by copying
                curr_bytes = allocator.alloc(u8, data.len) catch unreachable;
                std.mem.copyForwards(u8, curr_bytes, data);
            },
        }

        if (self.next != null) {
            const next_bytes = self.next.?.Serialize();
            const combined_len = curr_bytes.len + next_bytes.len;
            const combined = allocator.alloc(u8, combined_len) catch unreachable;
            std.mem.copyForwards(u8, combined[0..curr_bytes.len], curr_bytes);
            std.mem.copyForwards(u8, combined[curr_bytes.len..], next_bytes);
            // optionally free old buffers if you want
            return combined;
        }

        return curr_bytes;
    }
};

pub const Header = union(enum) {
    Ethernet: *EthernetHeader,
    Arp: *ArpHeader,
    Unparsed: []const u8,
};

pub const EthernetHeader = packed struct(u112) {
    ether_type: u16,
    src_mac: u48,
    dest_mac: u48,

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

    pub fn print(self: ArpHeader) void {
        std.debug.print("\t\tARP Header: \n\t\t\tTarget IP: \t{any}\n", .{ip_to_bytes(@byteSwap(self.target_ip))});
        std.debug.print("\t\t\tTarget MAC: \t0x{X}\n", .{mac_to_bytes(@byteSwap(self.target_mac))});
        std.debug.print("\t\t\tSender IP: \t{any}\n", .{ip_to_bytes(@byteSwap(self.sender_ip))});
        std.debug.print("\t\t\tSender MAC: \t0x{X}\n", .{mac_to_bytes(@byteSwap(self.sender_mac))});
        std.debug.print("\t\t\tOpcode: \t0x{X}\n", .{self.opcode});
        std.debug.print("\t\t\tProto Size: \t{d}\n", .{self.proto_size});
        std.debug.print("\t\t\tHW Size: \t{d}\n", .{self.hw_size});
        std.debug.print("\t\t\tProto Type: \t0x{X}\n", .{self.proto_type});
        std.debug.print("\t\t\tHW Type: \t0x{X}\n", .{self.hw_type});
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

/// Serialise an Ethernet header exactly as it appears on the wire.
/// dest_mac (6) | src_mac (6) | ether_type (2)
pub fn serializeEthernetHeader(h: EthernetHeader) []u8 {
    const allocator = std.heap.page_allocator;
    const buf = allocator.alloc(u8, 14) catch unreachable;
    const dest = mac_to_be_bytes(h.dest_mac);
    const src = mac_to_be_bytes(h.src_mac);
    std.mem.copyForwards(u8, buf[0..6], dest[0..]);
    std.mem.copyForwards(u8, buf[6..12], src[0..]);
    buf[12] = @intCast(h.ether_type >> 8);
    buf[13] = @intCast(h.ether_type & 0xFF);
    return buf;
}

/// Serialise an ARP header in the correct field order and byte order.
/// See https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
pub fn serializeArpHeader(h: ArpHeader) []u8 {
    const allocator = std.heap.page_allocator;
    const buf = allocator.alloc(u8, 28) catch unreachable;
    var idx: usize = 0;
    buf[idx] = @intCast(h.hw_type >> 8);
    buf[idx + 1] = @intCast(h.hw_type & 0xFF);
    idx += 2;
    buf[idx] = @intCast(h.proto_type >> 8);
    buf[idx + 1] = @intCast(h.proto_type & 0xFF);
    idx += 2;
    buf[idx] = h.hw_size;
    idx += 1;
    buf[idx] = h.proto_size;
    idx += 1;
    buf[idx] = @intCast(h.opcode >> 8);
    buf[idx + 1] = @intCast(h.opcode & 0xFF);
    idx += 2;
    const smac = mac_to_be_bytes(h.sender_mac);
    std.mem.copyForwards(u8, buf[idx .. idx + 6], smac[0..]);
    idx += 6;
    const sip = ip_to_be_bytes(h.sender_ip);
    std.mem.copyForwards(u8, buf[idx .. idx + 4], sip[0..]);
    idx += 4;
    const tmac = mac_to_be_bytes(h.target_mac);
    std.mem.copyForwards(u8, buf[idx .. idx + 6], tmac[0..]);
    idx += 6;
    const tip = ip_to_be_bytes(h.target_ip);
    std.mem.copyForwards(u8, buf[idx .. idx + 4], tip[0..]);
    return buf;
}

pub fn ip_to_bytes(ip: u32) [4]u8 {
    return @as(*const [4]u8, @ptrCast(&ip))[0..4].*;
}

pub fn mac_to_bytes(mac: u48) [6]u8 {
    return @as(*const [6]u8, @ptrCast(&mac))[0..6].*;
}
