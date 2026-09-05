const std = @import("std");
const limits = @import("../limits.zig");
const c = @import("c");

pub const Direction = enum { inbound, outbound };

pub const Frame = struct {
    bytes: [limits.frame_capacity]u8 = undefined,
    len: u16 = 0,

    pub fn set(self: *Frame, value: []const u8) error{FrameTooLarge}!void {
        if (value.len > self.bytes.len) return error.FrameTooLarge;
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
    }

    pub fn pushLua(self: *const Frame, state: ?*c.lua_State, send: c.lua_CFunction, context: *anyopaque) void {
        c.lua_createtable(state, 0, 9);
        const table = c.lua_gettop(state);
        c.lua_pushlightuserdata(state, context);
        c.lua_pushcclosure(state, send, 1);
        c.lua_setfield(state, table, "send");
        const bytes = self.bytes[0..self.len];
        if (bytes.len < 14) return pushBytes(state, "data", bytes);
        c.lua_createtable(state, 0, 3);
        MacAddress.pushField(state, "dst", bytes[0..6]);
        MacAddress.pushField(state, "src", bytes[6..12]);
        pushInteger(state, "type", readU16(bytes[12..14]));
        c.lua_setfield(state, table, "eth");
        var kind = readU16(bytes[12..14]);
        var offset: usize = 14;
        c.lua_createtable(state, 0, 0);
        var vlan_index: c_int = 1;
        while ((kind == 0x8100 or kind == 0x88a8) and offset + 4 <= bytes.len) : (vlan_index += 1) {
            const tci = readU16(bytes[offset .. offset + 2]);
            c.lua_createtable(state, 0, 5);
            pushInteger(state, "priority", tci >> 13);
            pushBoolean(state, "dei", (tci & 0x1000) != 0);
            pushInteger(state, "id", tci & 0x0fff);
            kind = readU16(bytes[offset + 2 .. offset + 4]);
            pushInteger(state, "etype", kind);
            c.lua_rawseti(state, -2, vlan_index);
            offset += 4;
        }
        c.lua_setfield(state, table, "vlan");
        if (kind == 0x0806 and offset + 28 <= bytes.len) return pushArp(state, table, bytes, offset);
        if (kind != 0x0800 or offset + 20 > bytes.len) return pushBytes(state, "data", bytes[offset..]);
        const header_length: usize = @as(usize, bytes[offset] & 0x0f) * 4;
        if (bytes[offset] >> 4 != 4 or header_length < 20 or offset + header_length > bytes.len) return pushBytes(state, "data", bytes[offset..]);
        pushIpv4(state, table, bytes, offset, header_length);
        if ((readU16(bytes[offset + 6 .. offset + 8]) & 0x1fff) != 0) return pushIpData(state, table, bytes[offset + header_length ..]);
        offset += header_length;
        switch (bytes[offset - header_length + 9]) {
            6 => if (offset + 20 <= bytes.len) {
                const tcp_length: usize = @as(usize, bytes[offset + 12] >> 4) * 4;
                if (tcp_length >= 20 and offset + tcp_length <= bytes.len) return pushTcp(state, table, bytes, offset, tcp_length);
            },
            17 => if (offset + 8 <= bytes.len) return pushUdp(state, table, bytes, offset),
            1 => if (offset + 8 <= bytes.len) return pushIcmp(state, table, bytes, offset),
            else => {},
        }
        pushIpData(state, table, bytes[offset..]);
    }

    pub fn fromLua(state: ?*c.lua_State) LuaError!Frame {
        if (c.lua_type(state, 1) != c.LUA_TTABLE) return error.InvalidPacketTable;
        var output: Writer = .{};
        const eth = tableField(state, 1, "eth") orelse {
            try output.stringField(state, 1, "data");
            return output.value;
        };
        defer c.lua_pop(state, 1);
        try output.ethernet(state, eth);
        try output.vlans(state);
        if (tableField(state, 1, "arp")) |arp| {
            defer c.lua_pop(state, 1);
            try output.arp(state, arp);
        } else if (tableField(state, 1, "ip")) |ip| {
            defer c.lua_pop(state, 1);
            try output.ipv4(state, ip);
        } else try output.stringField(state, 1, "data");
        return output.value;
    }
};

pub const LuaError = error{ InvalidPacketTable, FrameTooLarge };

fn pushArp(state: ?*c.lua_State, table: c_int, bytes: []const u8, offset: usize) void {
    c.lua_createtable(state, 0, 5);
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "type", readU16(bytes[offset .. offset + 2]));
    pushInteger(state, "size", bytes[offset + 4]);
    c.lua_setfield(state, -2, "hw");
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "type", readU16(bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "size", bytes[offset + 5]);
    c.lua_setfield(state, -2, "proto");
    pushInteger(state, "opcode", readU16(bytes[offset + 6 .. offset + 8]));
    c.lua_createtable(state, 0, 2);
    MacAddress.pushField(state, "hw_mac", bytes[offset + 8 .. offset + 14]);
    Ipv4Address.pushField(state, "proto_ipv4", bytes[offset + 14 .. offset + 18]);
    c.lua_setfield(state, -2, "src");
    c.lua_createtable(state, 0, 2);
    MacAddress.pushField(state, "hw_mac", bytes[offset + 18 .. offset + 24]);
    Ipv4Address.pushField(state, "proto_ipv4", bytes[offset + 24 .. offset + 28]);
    c.lua_setfield(state, -2, "dst");
    pushBytes(state, "data", bytes[offset + 28 ..]);
    c.lua_setfield(state, table, "arp");
}

fn pushIpv4(state: ?*c.lua_State, table: c_int, bytes: []const u8, offset: usize, header_length: usize) void {
    const flags_fragment = readU16(bytes[offset + 6 .. offset + 8]);
    c.lua_createtable(state, 0, 13);
    pushInteger(state, "version", bytes[offset] >> 4);
    pushInteger(state, "hdr_len", header_length);
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "dscp", bytes[offset + 1] >> 2);
    pushInteger(state, "ecn", bytes[offset + 1] & 3);
    c.lua_setfield(state, -2, "dsfield");
    pushInteger(state, "len", readU16(bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "id", readU16(bytes[offset + 4 .. offset + 6]));
    c.lua_createtable(state, 0, 3);
    pushBoolean(state, "rb", (flags_fragment & 0x8000) != 0);
    pushBoolean(state, "df", (flags_fragment & 0x4000) != 0);
    pushBoolean(state, "mf", (flags_fragment & 0x2000) != 0);
    c.lua_setfield(state, -2, "flags");
    pushInteger(state, "frag_offset", flags_fragment & 0x1fff);
    pushInteger(state, "ttl", bytes[offset + 8]);
    pushInteger(state, "proto", bytes[offset + 9]);
    pushInteger(state, "checksum", readU16(bytes[offset + 10 .. offset + 12]));
    Ipv4Address.pushField(state, "src", bytes[offset + 12 .. offset + 16]);
    Ipv4Address.pushField(state, "dst", bytes[offset + 16 .. offset + 20]);
    pushBytes(state, "options", bytes[offset + 20 .. offset + header_length]);
    c.lua_setfield(state, table, "ip");
}

fn pushTcp(state: ?*c.lua_State, table: c_int, bytes: []const u8, offset: usize, header_length: usize) void {
    const flags = bytes[offset + 13];
    c.lua_createtable(state, 0, 12);
    pushInteger(state, "srcport", readU16(bytes[offset .. offset + 2]));
    pushInteger(state, "dstport", readU16(bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "seq", readU32(bytes[offset + 4 .. offset + 8]));
    pushInteger(state, "ack", readU32(bytes[offset + 8 .. offset + 12]));
    pushInteger(state, "hdr_len", header_length);
    c.lua_createtable(state, 0, 10);
    pushBoolean(state, "ae", (bytes[offset + 12] & 1) != 0);
    pushInteger(state, "res", (bytes[offset + 12] >> 1) & 7);
    inline for (.{ .{ "fin", 0x01 }, .{ "syn", 0x02 }, .{ "reset", 0x04 }, .{ "push", 0x08 }, .{ "ack", 0x10 }, .{ "urg", 0x20 }, .{ "ece", 0x40 }, .{ "cwr", 0x80 } }) |field| pushBoolean(state, field[0], (flags & field[1]) != 0);
    c.lua_setfield(state, -2, "flags");
    pushInteger(state, "window_size_value", readU16(bytes[offset + 14 .. offset + 16]));
    pushInteger(state, "checksum", readU16(bytes[offset + 16 .. offset + 18]));
    pushInteger(state, "urgent_pointer", readU16(bytes[offset + 18 .. offset + 20]));
    pushBytes(state, "options", bytes[offset + 20 .. offset + header_length]);
    pushBytes(state, "payload", bytes[offset + header_length ..]);
    c.lua_setfield(state, table, "tcp");
}

fn pushUdp(state: ?*c.lua_State, table: c_int, bytes: []const u8, offset: usize) void {
    c.lua_createtable(state, 0, 5);
    pushInteger(state, "srcport", readU16(bytes[offset .. offset + 2]));
    pushInteger(state, "dstport", readU16(bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "length", readU16(bytes[offset + 4 .. offset + 6]));
    pushInteger(state, "checksum", readU16(bytes[offset + 6 .. offset + 8]));
    pushBytes(state, "payload", bytes[offset + 8 ..]);
    c.lua_setfield(state, table, "udp");
}

fn pushIcmp(state: ?*c.lua_State, table: c_int, bytes: []const u8, offset: usize) void {
    c.lua_createtable(state, 0, 5);
    pushInteger(state, "type", bytes[offset]);
    pushInteger(state, "code", bytes[offset + 1]);
    pushInteger(state, "checksum", readU16(bytes[offset + 2 .. offset + 4]));
    pushBytes(state, "rest_of_header", bytes[offset + 4 .. offset + 8]);
    pushBytes(state, "data", bytes[offset + 8 ..]);
    c.lua_setfield(state, table, "icmp");
}

fn pushIpData(state: ?*c.lua_State, table: c_int, bytes: []const u8) void {
    _ = c.lua_getfield(state, table, "ip");
    pushBytes(state, "data", bytes);
    c.lua_pop(state, 1);
}

const Writer = struct {
    value: Frame = .{},

    fn write(self: *Writer, bytes: []const u8) LuaError!void {
        const offset: usize = self.value.len;
        if (bytes.len > self.value.bytes.len - offset) return error.FrameTooLarge;
        @memcpy(self.value.bytes[offset .. offset + bytes.len], bytes);
        self.value.len += @intCast(bytes.len);
    }

    fn byte(self: *Writer, value: u8) LuaError!void {
        try self.write(&.{value});
    }

    fn writeU16(self: *Writer, value: u16) LuaError!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try self.write(&bytes);
    }

    fn writeU32(self: *Writer, value: u32) LuaError!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try self.write(&bytes);
    }

    fn stringField(self: *Writer, state: ?*c.lua_State, table: c_int, name: [*:0]const u8) LuaError!void {
        try self.write(try stringValue(state, table, name));
    }

    fn ethernet(self: *Writer, state: ?*c.lua_State, eth: c_int) LuaError!void {
        var address: [6]u8 = undefined;
        try MacAddress.readField(state, eth, "dst", &address);
        try self.write(&address);
        try MacAddress.readField(state, eth, "src", &address);
        try self.write(&address);
        try self.writeU16(@intCast(try readIntegerField(state, eth, "type", 0xffff)));
    }

    fn vlans(self: *Writer, state: ?*c.lua_State) LuaError!void {
        const list = try childTable(state, 1, "vlan");
        defer c.lua_pop(state, 1);
        for (0..c.lua_rawlen(state, list)) |index| {
            _ = c.lua_rawgeti(state, list, @intCast(index + 1));
            defer c.lua_pop(state, 1);
            if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
            const tag = c.lua_gettop(state);
            const priority = try readIntegerField(state, tag, "priority", 7);
            const dei = try readBooleanField(state, tag, "dei");
            const id = try readIntegerField(state, tag, "id", 0x0fff);
            try self.writeU16(@intCast((priority << 13) | (@as(u64, @intFromBool(dei)) << 12) | id));
            try self.writeU16(@intCast(try readIntegerField(state, tag, "etype", 0xffff)));
        }
    }

    fn arp(self: *Writer, state: ?*c.lua_State, index: c_int) LuaError!void {
        const hw = try childTable(state, index, "hw");
        defer c.lua_pop(state, 1);
        const proto = try childTable(state, index, "proto");
        defer c.lua_pop(state, 1);
        const src = try childTable(state, index, "src");
        defer c.lua_pop(state, 1);
        const dst = try childTable(state, index, "dst");
        defer c.lua_pop(state, 1);
        try self.writeU16(@intCast(try readIntegerField(state, hw, "type", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, proto, "type", 0xffff)));
        try self.byte(@intCast(try readIntegerField(state, hw, "size", 0xff)));
        try self.byte(@intCast(try readIntegerField(state, proto, "size", 0xff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "opcode", 0xffff)));
        var mac: [6]u8 = undefined;
        var ip: [4]u8 = undefined;
        try MacAddress.readField(state, src, "hw_mac", &mac);
        try self.write(&mac);
        try Ipv4Address.readField(state, src, "proto_ipv4", &ip);
        try self.write(&ip);
        try MacAddress.readField(state, dst, "hw_mac", &mac);
        try self.write(&mac);
        try Ipv4Address.readField(state, dst, "proto_ipv4", &ip);
        try self.write(&ip);
        try self.stringField(state, index, "data");
    }

    fn ipv4(self: *Writer, state: ?*c.lua_State, ip: c_int) LuaError!void {
        const dsfield = try childTable(state, ip, "dsfield");
        defer c.lua_pop(state, 1);
        const flags = try childTable(state, ip, "flags");
        defer c.lua_pop(state, 1);
        const header_length = try readIntegerField(state, ip, "hdr_len", 60);
        const options = try stringValue(state, ip, "options");
        if (header_length < 20 or header_length != 20 + options.len or options.len % 4 != 0) return error.InvalidPacketTable;
        try self.byte(@intCast((try readIntegerField(state, ip, "version", 0x0f)) << 4 | header_length / 4));
        try self.byte(@intCast((try readIntegerField(state, dsfield, "dscp", 63)) << 2 | try readIntegerField(state, dsfield, "ecn", 3)));
        try self.writeU16(@intCast(try readIntegerField(state, ip, "len", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, ip, "id", 0xffff)));
        try self.writeU16(@intCast((@as(u64, @intFromBool(try readBooleanField(state, flags, "rb"))) << 15) | (@as(u64, @intFromBool(try readBooleanField(state, flags, "df"))) << 14) | (@as(u64, @intFromBool(try readBooleanField(state, flags, "mf"))) << 13) | try readIntegerField(state, ip, "frag_offset", 0x1fff)));
        try self.byte(@intCast(try readIntegerField(state, ip, "ttl", 0xff)));
        try self.byte(@intCast(try readIntegerField(state, ip, "proto", 0xff)));
        try self.writeU16(@intCast(try readIntegerField(state, ip, "checksum", 0xffff)));
        var address: [4]u8 = undefined;
        try Ipv4Address.readField(state, ip, "src", &address);
        try self.write(&address);
        try Ipv4Address.readField(state, ip, "dst", &address);
        try self.write(&address);
        try self.write(options);
        if (tableField(state, 1, "tcp")) |transport| {
            defer c.lua_pop(state, 1);
            try self.tcp(state, transport);
        } else if (tableField(state, 1, "udp")) |transport| {
            defer c.lua_pop(state, 1);
            try self.udp(state, transport);
        } else if (tableField(state, 1, "icmp")) |transport| {
            defer c.lua_pop(state, 1);
            try self.icmp(state, transport);
        } else try self.stringField(state, ip, "data");
    }

    fn tcp(self: *Writer, state: ?*c.lua_State, index: c_int) LuaError!void {
        const flags = try childTable(state, index, "flags");
        defer c.lua_pop(state, 1);
        const header_length = try readIntegerField(state, index, "hdr_len", 60);
        const options = try stringValue(state, index, "options");
        if (header_length < 20 or header_length != 20 + options.len or options.len % 4 != 0) return error.InvalidPacketTable;
        try self.writeU16(@intCast(try readIntegerField(state, index, "srcport", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "dstport", 0xffff)));
        try self.writeU32(@intCast(try readIntegerField(state, index, "seq", 0xffffffff)));
        try self.writeU32(@intCast(try readIntegerField(state, index, "ack", 0xffffffff)));
        try self.byte(@intCast(header_length / 4 << 4 | (try readIntegerField(state, flags, "res", 7)) << 1 | @intFromBool(try readBooleanField(state, flags, "ae"))));
        var value: u8 = 0;
        inline for (.{ .{ "fin", 0x01 }, .{ "syn", 0x02 }, .{ "reset", 0x04 }, .{ "push", 0x08 }, .{ "ack", 0x10 }, .{ "urg", 0x20 }, .{ "ece", 0x40 }, .{ "cwr", 0x80 } }) |field| {
            if (try readBooleanField(state, flags, field[0])) value |= field[1];
        }
        try self.byte(value);
        try self.writeU16(@intCast(try readIntegerField(state, index, "window_size_value", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "checksum", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "urgent_pointer", 0xffff)));
        try self.write(options);
        try self.stringField(state, index, "payload");
    }

    fn udp(self: *Writer, state: ?*c.lua_State, index: c_int) LuaError!void {
        try self.writeU16(@intCast(try readIntegerField(state, index, "srcport", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "dstport", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "length", 0xffff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "checksum", 0xffff)));
        try self.stringField(state, index, "payload");
    }

    fn icmp(self: *Writer, state: ?*c.lua_State, index: c_int) LuaError!void {
        try self.byte(@intCast(try readIntegerField(state, index, "type", 0xff)));
        try self.byte(@intCast(try readIntegerField(state, index, "code", 0xff)));
        try self.writeU16(@intCast(try readIntegerField(state, index, "checksum", 0xffff)));
        const rest = try stringValue(state, index, "rest_of_header");
        if (rest.len != 4) return error.InvalidPacketTable;
        try self.write(rest);
        try self.stringField(state, index, "data");
    }
};

fn tableField(state: ?*c.lua_State, parent: c_int, name: [*:0]const u8) ?c_int {
    _ = c.lua_getfield(state, parent, name);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) {
        c.lua_pop(state, 1);
        return null;
    }
    return c.lua_gettop(state);
}

fn stringValue(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) LuaError![]const u8 {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TSTRING) return error.InvalidPacketTable;
    var length: usize = 0;
    const value = c.lua_tolstring(state, -1, &length) orelse return error.InvalidPacketTable;
    return value[0..length];
}

fn childTable(state: ?*c.lua_State, parent: c_int, name: [*:0]const u8) LuaError!c_int {
    _ = c.lua_getfield(state, parent, name);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
    return c.lua_gettop(state);
}

fn readIntegerField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, maximum: u64) LuaError!u64 {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    var is_number: c_int = 0;
    const value = c.lua_tointegerx(state, -1, &is_number);
    if (is_number == 0 or value < 0 or @as(u64, @intCast(value)) > maximum) return error.InvalidPacketTable;
    return @intCast(value);
}

fn readBooleanField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) LuaError!bool {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TBOOLEAN) return error.InvalidPacketTable;
    return c.lua_toboolean(state, -1) != 0;
}

fn pushInteger(state: ?*c.lua_State, name: [*:0]const u8, value: anytype) void {
    c.lua_pushinteger(state, @intCast(value));
    c.lua_setfield(state, -2, name);
}

fn pushBoolean(state: ?*c.lua_State, name: [*:0]const u8, value: bool) void {
    c.lua_pushboolean(state, @intFromBool(value));
    c.lua_setfield(state, -2, name);
}

fn pushBytes(state: ?*c.lua_State, name: [*:0]const u8, value: []const u8) void {
    _ = c.lua_pushlstring(state, value.ptr, value.len);
    c.lua_setfield(state, -2, name);
}

fn readU16(value: []const u8) u16 {
    return std.mem.readInt(u16, value[0..2], .big);
}

fn readU32(value: []const u8) u32 {
    return std.mem.readInt(u32, value[0..4], .big);
}

pub fn installLuaTypes(state: ?*c.lua_State) void {
    Ipv4Address.register(state);
    MacAddress.register(state);
    c.lua_createtable(state, 0, 2);
    setFunction(state, -2, "ipv4", Ipv4Address.construct);
    setFunction(state, -2, "mac", MacAddress.construct);
    c.lua_setglobal(state, "kraken");
}

fn setFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction) void {
    c.lua_pushcclosure(state, function, 0);
    c.lua_setfield(state, table, name);
}

const AddressKind = enum { ipv4, mac };

fn FixedAddress(comptime length: usize, comptime metatable_name: [:0]const u8, comptime kind: AddressKind) type {
    return struct {
        const Self = @This();
        const address_name = if (kind == .ipv4) "IPv4 address" else "MAC address";

        bytes: [length]u8,

        fn register(state: ?*c.lua_State) void {
            _ = c.luaL_newmetatable(state, metatable_name);
            setFunction(state, -2, "__index", index);
            setFunction(state, -2, "__newindex", newIndex);
            setFunction(state, -2, "__len", len);
            setFunction(state, -2, "__eq", equal);
            setFunction(state, -2, "__tostring", toString);
            _ = c.lua_pushstring(state, metatable_name);
            c.lua_setfield(state, -2, "__metatable");
            c.lua_pop(state, 1);
        }

        fn push(state: ?*c.lua_State, value: []const u8) void {
            const raw = c.lua_newuserdatauv(state, @sizeOf(Self), 0) orelse unreachable;
            const address: *Self = @ptrCast(@alignCast(raw));
            @memcpy(&address.bytes, value);
            _ = c.lua_getfield(state, c.LUA_REGISTRYINDEX, metatable_name);
            _ = c.lua_setmetatable(state, -2);
        }

        fn pushField(state: ?*c.lua_State, name: [*:0]const u8, value: []const u8) void {
            push(state, value);
            c.lua_setfield(state, -2, name);
        }

        fn read(state: ?*c.lua_State, index_value: c_int) ?*Self {
            const raw = c.luaL_testudata(state, index_value, metatable_name) orelse return null;
            return @ptrCast(@alignCast(raw));
        }

        fn readField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, destination: []u8) LuaError!void {
            _ = c.lua_getfield(state, table, name);
            defer c.lua_pop(state, 1);
            const address = read(state, -1) orelse return error.InvalidPacketTable;
            @memcpy(destination, &address.bytes);
        }

        fn construct(state: ?*c.lua_State) callconv(.c) c_int {
            if (c.lua_type(state, 1) != c.LUA_TSTRING) return c.luaL_error(state, address_name ++ " must be a string");
            var text_length: usize = 0;
            const raw = c.lua_tolstring(state, 1, &text_length) orelse return c.luaL_error(state, address_name ++ " must be a string");
            const parsed = parse(raw[0..text_length]) orelse return c.luaL_error(state, "invalid " ++ address_name);
            push(state, &parsed);
            return 1;
        }

        fn index(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            const array_index = checkedIndex(state, 2) orelse return c.luaL_error(state, address_name ++ " index must be between 1 and " ++ std.fmt.comptimePrint("{d}", .{length}));
            c.lua_pushinteger(state, address.bytes[array_index]);
            return 1;
        }

        fn newIndex(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            const array_index = checkedIndex(state, 2) orelse return c.luaL_error(state, address_name ++ " index must be between 1 and " ++ std.fmt.comptimePrint("{d}", .{length}));
            if (c.lua_isinteger(state, 3) == 0) return c.luaL_error(state, "address byte must be an integer");
            var is_number: c_int = 0;
            const value = c.lua_tointegerx(state, 3, &is_number);
            if (is_number == 0 or value < 0 or value > 255) return c.luaL_error(state, "address byte must be between 0 and 255");
            address.bytes[array_index] = @intCast(value);
            return 0;
        }

        fn len(state: ?*c.lua_State) callconv(.c) c_int {
            _ = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            c.lua_pushinteger(state, length);
            return 1;
        }

        fn equal(state: ?*c.lua_State) callconv(.c) c_int {
            const left = read(state, 1);
            const right = read(state, 2);
            c.lua_pushboolean(state, @intFromBool(left != null and right != null and std.mem.eql(u8, &left.?.bytes, &right.?.bytes)));
            return 1;
        }

        fn toString(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            var buffer: [17]u8 = undefined;
            const text = switch (kind) {
                .ipv4 => std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3] }),
                .mac => std.fmt.bufPrint(&buffer, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3], address.bytes[4], address.bytes[5] }),
            } catch return c.luaL_error(state, "invalid " ++ address_name);
            _ = c.lua_pushlstring(state, text.ptr, text.len);
            return 1;
        }

        fn checkedIndex(state: ?*c.lua_State, stack_index: c_int) ?usize {
            if (c.lua_isinteger(state, stack_index) == 0) return null;
            var is_number: c_int = 0;
            const value = c.lua_tointegerx(state, stack_index, &is_number);
            if (is_number == 0 or value < 1 or value > length) return null;
            return @intCast(value - 1);
        }

        fn parse(text: []const u8) ?[length]u8 {
            var address: [length]u8 = undefined;
            const separator: u8 = if (kind == .ipv4) '.' else if (std.mem.indexOfScalar(u8, text, ':') != null) ':' else '-';
            var parts = std.mem.splitScalar(u8, text, separator);
            for (&address) |*octet| {
                const part = parts.next() orelse return null;
                if (kind == .mac and part.len != 2) return null;
                octet.* = std.fmt.parseInt(u8, part, if (kind == .ipv4) 10 else 16) catch return null;
            }
            if (parts.next() != null) return null;
            return address;
        }
    };
}

const Ipv4Address = FixedAddress(4, "kraken.ipv4.address", .ipv4);
const MacAddress = FixedAddress(6, "kraken.mac.address", .mac);
