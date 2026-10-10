const std = @import("std");
const limits = @import("../limits.zig");
const c = @import("c");
const lua = @import("lua.zig");

pub const Frame = @import("../text.zig").FixedText(limits.frame_capacity);

// Packed fields run from low to high bits; headers are read and written as big-endian integers.
const ethernet = packed struct {
    type: u16,
    src: u48,
    dst: u48,
};

const vlan_tag = packed struct {
    etype: u16,
    id: u12,
    dei: u1,
    priority: u3,
};

const arp_header = packed struct {
    dst_proto_ipv4: u32,
    dst_hw_mac: u48,
    src_proto_ipv4: u32,
    src_hw_mac: u48,
    opcode: u16,
    proto_size: u8,
    hw_size: u8,
    proto_type: u16,
    hw_type: u16,
};

const ipv4_header = packed struct {
    dst: u32,
    src: u32,
    checksum: u16,
    proto: u8,
    ttl: u8,
    frag_offset: u13,
    flags: u3,
    id: u16,
    len: u16,
    dsfield: u8,
    hdr_len: u4,
    version: u4,
};

const tcp_header = packed struct {
    urgent_pointer: u16,
    checksum: u16,
    window_size_value: u16,
    flags: u12,
    hdr_len: u4,
    ack: u32,
    seq: u32,
    dstport: u16,
    srcport: u16,
};

const udp_header = packed struct {
    checksum: u16,
    length: u16,
    dstport: u16,
    srcport: u16,
};

const icmp_header = packed struct {
    checksum: u16,
    code: u8,
    type: u8,
};

/// Pushes a fixed header as a Lua table. Header lengths are exposed in bytes.
fn pushHeader(state: ?*c.lua_State, comptime Header: type, bytes: []const u8) void {
    const fields = std.meta.fields(Header);
    const header: Header = @bitCast(std.mem.readInt(std.meta.Int(.unsigned, @bitSizeOf(Header)), bytes[0 .. @bitSizeOf(Header) / 8], .big));
    c.lua_createtable(state, 0, fields.len);
    inline for (fields) |field| {
        const value: u64 = @field(header, field.name);
        lua.setInteger(state, field.name, if (comptime std.mem.eql(u8, field.name, "hdr_len")) value * 4 else value);
    }
}

fn pushTable(state: ?*c.lua_State, bytes: []const u8) void {
    c.lua_createtable(state, 0, 9);
    const table = c.lua_gettop(state);
    if (bytes.len < 14) return lua.setString(state, "data", bytes);
    pushHeader(state, ethernet, bytes);
    c.lua_setfield(state, table, "eth");
    var kind = readU16(bytes[12..14]);
    var offset: usize = 14;
    c.lua_createtable(state, 0, 0);
    var vlan_index: c_int = 1;
    while ((kind == 0x8100 or kind == 0x88a8) and offset + 4 <= bytes.len) : (vlan_index += 1) {
        pushHeader(state, vlan_tag, bytes[offset..]);
        c.lua_rawseti(state, -2, vlan_index);
        kind = readU16(bytes[offset + 2 .. offset + 4]);
        offset += 4;
    }
    c.lua_setfield(state, table, "vlan");
    if (kind == 0x0806 and offset + 28 <= bytes.len) {
        pushHeader(state, arp_header, bytes[offset..]);
        lua.setString(state, "data", bytes[offset + 28 ..]);
        return c.lua_setfield(state, table, "arp");
    }
    if (kind != 0x0800 or offset + 20 > bytes.len) return lua.setString(state, "data", bytes[offset..]);
    const header_length: usize = @as(usize, bytes[offset] & 0x0f) * 4;
    if (bytes[offset] >> 4 != 4 or header_length < 20 or offset + header_length > bytes.len) return lua.setString(state, "data", bytes[offset..]);
    pushHeader(state, ipv4_header, bytes[offset..]);
    lua.setString(state, "options", bytes[offset + 20 .. offset + header_length]);
    c.lua_setfield(state, table, "ip");
    const protocol = bytes[offset + 9];
    if ((readU16(bytes[offset + 6 .. offset + 8]) & 0x1fff) != 0) return pushIpData(state, table, bytes[offset + header_length ..]);
    offset += header_length;
    switch (protocol) {
        6 => if (offset + 20 <= bytes.len) {
            const tcp_length: usize = @as(usize, bytes[offset + 12] >> 4) * 4;
            if (tcp_length >= 20 and offset + tcp_length <= bytes.len) {
                pushHeader(state, tcp_header, bytes[offset..]);
                lua.setString(state, "options", bytes[offset + 20 .. offset + tcp_length]);
                lua.setString(state, "payload", bytes[offset + tcp_length ..]);
                return c.lua_setfield(state, table, "tcp");
            }
        },
        17 => if (offset + 8 <= bytes.len) {
            pushHeader(state, udp_header, bytes[offset..]);
            lua.setString(state, "payload", bytes[offset + 8 ..]);
            return c.lua_setfield(state, table, "udp");
        },
        1 => if (offset + 8 <= bytes.len) {
            pushHeader(state, icmp_header, bytes[offset..]);
            lua.setString(state, "rest_of_header", bytes[offset + 4 .. offset + 8]);
            lua.setString(state, "data", bytes[offset + 8 ..]);
            return c.lua_setfield(state, table, "icmp");
        },
        else => {},
    }
    pushIpData(state, table, bytes[offset..]);
}

fn pushIpData(state: ?*c.lua_State, table: c_int, bytes: []const u8) void {
    _ = c.lua_getfield(state, table, "ip");
    lua.setString(state, "data", bytes);
    c.lua_pop(state, 1);
}

fn fromLua(state: ?*c.lua_State) Frame {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    var output: Writer = .{};
    const eth = lua.tableField(state, 1, "eth") orelse {
        output.stringField(state, 1, "data");
        return output.value;
    };
    defer c.lua_pop(state, 1);
    output.write(state, ethernet, eth, .{});
    output.vlans(state);
    if (lua.tableField(state, 1, "arp")) |arp| {
        defer c.lua_pop(state, 1);
        output.write(state, arp_header, arp, .{"data"});
    } else if (lua.tableField(state, 1, "ip")) |ip| {
        defer c.lua_pop(state, 1);
        output.write(state, ipv4_header, ip, .{"options"});
        inline for (.{
            .{ "tcp", tcp_header, .{ "options", "payload" } },
            .{ "udp", udp_header, .{"payload"} },
            .{ "icmp", icmp_header, .{ "rest_of_header", "data" } },
        }) |protocol| {
            if (lua.tableField(state, 1, protocol[0])) |table| {
                defer c.lua_pop(state, 1);
                output.write(state, protocol[1], table, protocol[2]);
                return output.value;
            }
        }
        output.stringField(state, ip, "data");
    } else output.stringField(state, 1, "data");
    return output.value;
}

const Writer = struct {
    value: Frame = .{},

    fn append(self: *Writer, state: ?*c.lua_State, count: usize) []u8 {
        const start = self.value.len;
        if (count > Frame.capacity - start) lua.raise(state, std.fmt.comptimePrint("packet exceeds {d} bytes", .{Frame.capacity}), .{});
        self.value.len += count;
        return self.value.bytes[start..][0..count];
    }

    fn stringField(self: *Writer, state: ?*c.lua_State, table: c_int, name: [*:0]const u8) void {
        const bytes = lua.requiredString(state, table, name);
        @memcpy(self.append(state, bytes.len), bytes);
    }

    /// Writes a packed header in network byte order, followed by its string fields.
    fn write(self: *Writer, state: ?*c.lua_State, comptime Header: type, table: c_int, comptime strings: anytype) void {
        const bytes = self.append(state, @bitSizeOf(Header) / 8);
        var value: Header = undefined;
        inline for (std.meta.fields(Header)) |field| {
            const words = comptime std.mem.eql(u8, field.name, "hdr_len");
            var number = integerField(state, table, field.name, if (words) 60 else std.math.maxInt(field.type));
            if (words) {
                if (number % 4 != 0) lua.raise(state, "%s must be a multiple of 4", .{field.name.ptr});
                number /= 4;
            }
            @field(value, field.name) = @intCast(number);
        }
        std.mem.writeInt(std.meta.Int(.unsigned, @bitSizeOf(Header)), bytes[0 .. @bitSizeOf(Header) / 8], @bitCast(value), .big);
        inline for (strings) |name| self.stringField(state, table, name);
    }

    fn vlans(self: *Writer, state: ?*c.lua_State) void {
        const list = lua.tableField(state, 1, "vlan") orelse lua.raise(state, "vlan is required", .{});
        defer c.lua_pop(state, 1);
        for (0..c.lua_rawlen(state, list)) |index| {
            _ = c.lua_rawgeti(state, list, @intCast(index + 1));
            defer c.lua_pop(state, 1);
            if (c.lua_type(state, -1) != c.LUA_TTABLE) lua.raise(state, "vlan entries must be tables", .{});
            self.write(state, vlan_tag, c.lua_gettop(state), .{});
        }
    }
};

fn integerField(state: ?*c.lua_State, table: c_int, name: [:0]const u8, maximum: u64) u64 {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    return @intCast(lua.integerAt(state, -1, name.ptr, @intCast(maximum)));
}

fn readU16(value: []const u8) u16 {
    return std.mem.readInt(u16, value[0..2], .big);
}

/// The IPv4 header of an Ethernet frame and the lengths it declares, or null for another EtherType.
const Ipv4Header = struct { offset: usize, length: usize, total: usize };

fn ipv4Header(bytes: []const u8) error{InvalidPacketTable}!?Ipv4Header {
    if (bytes.len < 14) return null;
    var kind = readU16(bytes[12..14]);
    var offset: usize = 14;
    while (kind == 0x8100 or kind == 0x88a8) {
        if (offset + 4 > bytes.len) return error.InvalidPacketTable;
        kind = readU16(bytes[offset + 2 .. offset + 4]);
        offset += 4;
    }
    if (kind != 0x0800) return null;
    const ip = bytes[offset..];
    if (ip.len < 20) return error.InvalidPacketTable;
    const length = @as(usize, ip[0] & 0x0f) * 4;
    const total = readU16(ip[2..4]);
    if (ip[0] >> 4 != 4 or length < 20 or total < length or total > ip.len) return error.InvalidPacketTable;
    return .{ .offset = offset, .length = length, .total = total };
}

fn checksumSum(bytes: []const u8, initial: u32) u32 {
    var sum = initial;
    for (0..bytes.len / 2) |i| sum += readU16(bytes[i * 2 .. i * 2 + 2]);
    if (bytes.len % 2 != 0) sum += @as(u32, bytes[bytes.len - 1]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return sum;
}

fn writeChecksum(bytes: []u8, offset: usize, initial: u32) void {
    @memset(bytes[offset..][0..2], 0);
    std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(~checksumSum(bytes, initial) & 0xffff), .big);
}

fn recalculateChecksums(bytes: []u8) error{InvalidPacketTable}!void {
    const header = try ipv4Header(bytes) orelse return;
    const ip = bytes[header.offset..][0..header.total];
    writeChecksum(ip[0..header.length], 10, 0);
    // A fragment does not contain the complete transport checksum input.
    if (readU16(ip[6..8]) & 0x3fff != 0) return;
    var payload = ip[header.length..];
    const checksum_offset: usize = switch (ip[9]) {
        6 => 16,
        17 => 6,
        1 => 2,
        else => return,
    };
    const minimum_length: usize = if (ip[9] == 6) 20 else 8;
    if (payload.len < minimum_length) return error.InvalidPacketTable;
    if (ip[9] == 17) {
        const udp_length = readU16(payload[4..6]);
        if (udp_length < 8 or udp_length > payload.len) return error.InvalidPacketTable;
        payload = payload[0..udp_length];
    }
    const sum = if (ip[9] == 1) 0 else checksumSum(ip[12..20], @as(u32, ip[9]) + @as(u32, @intCast(payload.len)));
    writeChecksum(payload, checksum_offset, sum);
    if (ip[9] == 17 and readU16(payload[6..8]) == 0) @memset(payload[6..8], 0xff);
}

test "complete captured SYN-ACK checksum without changing other bytes" {
    const hex = "000022334455525400e9748e08004500003c000040004006c564c0a87a01c0a87a054a922e6580c5ae3da70481f18012fe8875860000020405b40402080ade125303000b165a01030307";
    var packet: Frame = .{};
    const original = try std.fmt.hexToBytes(packet.bytes[0 .. hex.len / 2], hex);
    packet.len = original.len;
    var expected = packet;
    expected.bytes[50] = 0xdb;
    expected.bytes[51] = 0xa3;
    try recalculateChecksums(packet.bytes[0..packet.len]);
    try std.testing.expectEqualSlices(u8, expected.value(), packet.value());
}

test "decoded packets encode back to their bytes" {
    const state = lua.testState("kraken/packet", packetModule);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local packet = require("kraken/packet")
        \\local function ether(kind, body) return string.rep("\1", 6) .. string.rep("\2", 6) .. string.pack(">I2", kind) .. body end
        \\local function ip(proto, options, body)
        \\    return string.pack(">BBI2I2I2BBI2", 0x45 + #options // 4, 0, 20 + #options + #body, 7, 0x4000, 64, proto, 0) .. "\10\0\0\1\10\0\0\2" .. options .. body
        \\end
        \\local udp = ether(0x0800, ip(17, "\1\1\1\0", string.pack(">I2I2I2I2", 5000, 53, 28, 0) .. string.rep("x", 20)))
        \\local tagged = string.rep("\1", 6) .. string.rep("\2", 6) .. string.pack(">I2I2I2", 0x8100, 0x6005, 0x0800) .. udp:sub(15)
        \\local tcp = ether(0x0800, ip(6, "", string.pack(">I2I2I4I4BBI2I2I2", 80, 4000, 1, 2, 0x60 | 1, 0x12, 512, 0, 0) .. "\2\4\5\180" .. "hi"))
        \\local icmp = ether(0x0800, ip(1, "", "\8\0\0\0\0\1\0\2ping"))
        \\local arp = ether(0x0806, string.pack(">I2I2BBI2", 1, 0x0800, 6, 4, 1) .. string.rep("\1", 6) .. "\10\0\0\1" .. string.rep("\0", 6) .. "\10\0\0\2")
        \\for _, bytes in ipairs({ udp, tagged, tcp, icmp, arp }) do
        \\    assert(packet.encode(packet.decode(bytes), false) == bytes)
        \\end
        \\local odd = packet.decode(icmp)
        \\odd.ip.hdr_len, odd.icmp.rest_of_header = 60, "ab"
        \\assert(packet.encode(odd, false):byte(15) == 0x4f)
        \\assert(packet.ipv4("10.0.0.1") == 0x0a000001)
        \\assert(packet.ipv4(0xffffffff) == "255.255.255.255")
        \\assert(packet.mac("ff-ff-ff-ff-ff-ff") == 0xffffffffffff)
        \\assert(packet.mac(0x010203040506) == "01:02:03:04:05:06")
        \\local changed = packet.decode(tcp)
        \\for _, header in ipairs({changed.eth, changed.ip, changed.tcp}) do
        \\    for field, value in pairs(header) do
        \\        if type(value) == "number" then header[field] = 0 end
        \\    end
        \\end
        \\assert(packet.encode(changed, false) == string.rep("\0", 54) .. tcp:sub(55))
        \\changed.eth.type = 0x0800
        \\assert(not pcall(packet.encode, changed))
    );
}

pub fn packetModule(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_createtable(state, 0, 5);
    lua.setFunction(state, -2, "decode", decodeLua);
    lua.setFunction(state, -2, "encode", encodeLua);
    lua.setFunction(state, -2, "ipv4", Ipv4Address.convert);
    lua.setFunction(state, -2, "mac", MacAddress.convert);
    lua.setFunction(state, -2, "fragment", fragmentLua);
    return 1;
}

fn decodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    pushTable(state, lua.checkBytes(state, 1));
    return 1;
}

fn fixChecksums(state: ?*c.lua_State, index: c_int) bool {
    if (c.lua_isnoneornil(state, index)) return true;
    c.luaL_checktype(state, index, c.LUA_TBOOLEAN);
    return c.lua_toboolean(state, index) != 0;
}

fn encodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const fix = fixChecksums(state, 2);
    var value = fromLua(state);
    if (fix) recalculateChecksums(value.bytes[0..value.len]) catch return c.luaL_error(state, "cannot recalculate checksums for malformed packet; use encode(frame, false) to preserve checksum fields");
    lua.pushBytes(state, value.value());
    return 1;
}

fn fragmentLua(state: ?*c.lua_State) callconv(.c) c_int {
    const mtu = c.luaL_checkinteger(state, 2);
    if (mtu < 20 or mtu > 65535) return c.luaL_argerror(state, 2, "MTU must be between 20 and 65535");
    const fix = fixChecksums(state, 3);
    var packet = fromLua(state);
    if (fix) recalculateChecksums(packet.bytes[0..packet.len]) catch return c.luaL_error(state, "invalid IPv4 packet");
    const header = (ipv4Header(packet.value()) catch return c.luaL_error(state, "invalid IPv4 packet")) orelse return c.luaL_error(state, "expected IPv4 packet");
    if (mtu < header.length) return c.luaL_error(state, "MTU leaves too little room for an IPv4 fragment");

    const ip_offset = header.offset;
    const payload = packet.bytes[ip_offset + header.length .. ip_offset + header.total];
    const flags_offset = readU16(packet.bytes[ip_offset + 6 .. ip_offset + 8]);
    const base_offset: usize = flags_offset & 0x1fff;
    if (base_offset * 8 + payload.len > 65535 - 20) return c.luaL_error(state, "fragment offsets exceed the IPv4 limit");
    var copied_options: [40]u8 = undefined;
    const copied = copiedOptions(packet.bytes[ip_offset + 20 .. ip_offset + header.length], &copied_options) catch return c.luaL_error(state, "invalid IPv4 options");

    c.lua_createtable(state, 0, 0);
    const output_table = c.lua_gettop(state);
    var cursor: usize = 0;
    var index: c.lua_Integer = 1;
    while (true) : (index += 1) {
        const options = if (cursor == 0) packet.bytes[ip_offset + 20 .. ip_offset + header.length] else copied;
        const fragment_header_len = 20 + options.len;
        const remaining = payload.len - cursor;
        var take = @min(remaining, @as(usize, @intCast(mtu)) - fragment_header_len);
        if (take < remaining) take -= take % 8;
        if (remaining > 0 and take == 0) return c.luaL_error(state, "MTU leaves too little room for an IPv4 fragment");
        const more = cursor + take < payload.len or (flags_offset & 0x2000) != 0;
        var value = packet;
        const fragment = value.bytes[ip_offset..];
        @memcpy(fragment[20..][0..options.len], options);
        @memcpy(fragment[fragment_header_len..][0..take], payload[cursor..][0..take]);
        value.len = ip_offset + fragment_header_len + take;
        fragment[0] = 0x40 | @as(u8, @intCast(fragment_header_len / 4));
        std.mem.writeInt(u16, fragment[2..4], @intCast(fragment_header_len + take), .big);
        std.mem.writeInt(u16, fragment[6..8], @intCast((flags_offset & 0xc000) | (@as(u16, @intFromBool(more)) << 13) | (base_offset + cursor / 8)), .big);
        if (fix) writeChecksum(fragment[0..fragment_header_len], 10, 0);
        pushTable(state, value.value());
        c.lua_rawseti(state, output_table, index);
        if (cursor + take == payload.len) return 1;
        cursor += take;
    }
}

fn copiedOptions(options: []const u8, output: *[40]u8) error{InvalidPacket}![]const u8 {
    var source: usize = 0;
    var length: usize = 0;
    while (source < options.len) {
        const kind = options[source];
        if (kind == 0) break;
        if (kind == 1) {
            source += 1;
            continue;
        }
        if (source + 2 > options.len) return error.InvalidPacket;
        const option_len = options[source + 1];
        if (option_len < 2 or source + option_len > options.len) return error.InvalidPacket;
        if (kind & 0x80 != 0) {
            @memcpy(output[length .. length + option_len], options[source .. source + option_len]);
            length += option_len;
        }
        source += option_len;
    }
    while (length % 4 != 0) : (length += 1) output[length] = 0;
    return output[0..length];
}
const AddressKind = enum { ipv4, mac };

fn Address(comptime length: usize, comptime kind: AddressKind) type {
    return struct {
        const address_name = if (kind == .ipv4) "IPv4 address" else "MAC address";

        /// Text converts to a wire integer; an integer converts to canonical text.
        fn convert(state: ?*c.lua_State) callconv(.c) c_int {
            const Int = std.meta.Int(.unsigned, length * 8);
            if (c.lua_type(state, 1) == c.LUA_TSTRING) {
                const bytes = parse(lua.checkBytes(state, 1)) orelse return c.luaL_error(state, "invalid " ++ address_name);
                c.lua_pushinteger(state, std.mem.readInt(Int, &bytes, .big));
            } else {
                const value: Int = @intCast(lua.integerAt(state, 1, address_name, std.math.maxInt(Int)));
                var bytes: [length]u8 = undefined;
                std.mem.writeInt(Int, &bytes, value, .big);
                var buffer: [17]u8 = undefined;
                lua.pushBytes(state, text(&bytes, &buffer));
            }
            return 1;
        }

        /// Dotted decimal or colon-separated hex.
        pub fn text(address: *const [length]u8, buffer: *[17]u8) []const u8 {
            return (switch (kind) {
                .ipv4 => std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{ address[0], address[1], address[2], address[3] }),
                .mac => std.fmt.bufPrint(buffer, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ address[0], address[1], address[2], address[3], address[4], address[5] }),
            }) catch unreachable;
        }

        /// IPv4 in canonical dotted decimal, or a MAC as six hex pairs separated by `:` or `-`.
        pub fn parse(source: []const u8) ?[length]u8 {
            if (kind == .ipv4) return (std.Io.net.Ip4Address.parse(source, 0) catch return null).bytes;
            if (source.len != 17 or (source[2] != ':' and source[2] != '-')) return null;
            var address: [length]u8 = undefined;
            for (&address, 0..) |*octet, position| {
                if (position > 0 and source[position * 3 - 1] != source[2]) return null;
                octet.* = std.fmt.parseInt(u8, source[position * 3 ..][0..2], 16) catch return null;
            }
            return address;
        }
    };
}

pub const Ipv4Address = Address(4, .ipv4);
pub const MacAddress = Address(6, .mac);
