const c = @import("c");
const std = @import("std");
const lber = @import("ldap");
const lua = @import("../runtime/lua.zig");

// SNMP v1 and v2c messages as tables, like protocols/dns. liblber (OpenLDAP's BER
// codec, vendored for LDAP) builds the BER structure and converts object IDs; what
// SNMP puts in that structure is this file's. Scripts own the UDP sockets and the
// requests, walks and answers; nothing here limits what a packet may contain.

const pdu_names = [_][:0]const u8{ "get", "getnext", "response", "set", "trap", "getbulk", "inform", "trapv2", "report" };

const Kind = struct { name: [:0]const u8, tag: u8 };
const kinds = [_]Kind{
    .{ .name = "integer", .tag = 0x02 },        .{ .name = "octet_string", .tag = 0x04 },
    .{ .name = "null", .tag = 0x05 },           .{ .name = "oid", .tag = 0x06 },
    .{ .name = "ip_address", .tag = 0x40 },     .{ .name = "counter32", .tag = 0x41 },
    .{ .name = "gauge32", .tag = 0x42 },        .{ .name = "time_ticks", .tag = 0x43 },
    .{ .name = "opaque", .tag = 0x44 },         .{ .name = "counter64", .tag = 0x46 },
    .{ .name = "no_such_object", .tag = 0x80 }, .{ .name = "no_such_instance", .tag = 0x81 },
    .{ .name = "end_of_mib_view", .tag = 0x82 },
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    Scratch.register(state);
    lua.pushFunctions(state, .{ .{ "encode", encodeLua }, .{ "decode", decodeLua } });
    c.lua_createtable(state, 0, pdu_names.len);
    for (pdu_names, 0..) |name, number| lua.setInteger(state, name, number);
    c.lua_setfield(state, -2, "pdus");
    return 1;
}

/// The BER buffer of one encode call, in a to-be-closed stack slot, so __close frees it
/// when the call returns or raises.
const Scratch = struct {
    element: ?*lber.BerElement = null,

    const metatable = "kraken.snmp.scratch";

    fn register(state: ?*c.lua_State) void {
        _ = c.luaL_newmetatable(state, metatable);
        lua.setFunction(state, -2, "__close", close);
        c.lua_pop(state, 1);
    }

    fn push(state: ?*c.lua_State) *Scratch {
        const self: *Scratch = @ptrCast(@alignCast(c.lua_newuserdatauv(state, @sizeOf(Scratch), 0).?));
        self.* = .{};
        _ = c.luaL_setmetatable(state, metatable);
        c.lua_toclose(state, -1);
        return self;
    }

    fn close(state: ?*c.lua_State) callconv(.c) c_int {
        const self = lua.checkUserdata(state, 1, Scratch, metatable);
        if (self.element) |element| lber.ber_free(element, 1);
        self.* = .{};
        return 0;
    }
};

// Encoding. The message table is at index 1.

/// `snmp.encode(message)`: the message's bytes. A message has `version` ("v1", "v2c" by
/// default, "v3" or a number), `community` ("public"), `pdu` and the PDU's fields. When
/// `payload` is present it is everything after the version, as raw bytes.
fn encodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    c.lua_settop(state, 1);
    const scratch = Scratch.push(state);
    const element = lber.ber_alloc_t(lber.LBER_USE_DER) orelse lua.raise(state, "out of memory", .{});
    scratch.element = element;
    writeMessage(state, element);
    var packet: lber.struct_berval = undefined;
    if (lber.ber_flatten2(element, &packet, 0) != 0) lua.raise(state, "the packet could not be built", .{});
    lua.pushBytes(state, packet.bv_val[0..packet.bv_len]);
    return 1;
}

fn writeMessage(state: ?*c.lua_State, element: *lber.BerElement) void {
    begin(state, element, 0x30);
    putInteger(state, element, 0x02, versionOf(state), true);
    if (lua.optionalString(state, 1, "payload")) |payload| {
        raw(state, element, payload);
    } else {
        put(state, element, 0x04, lua.optionalString(state, 1, "community") orelse "public");
        const kind = pduOf(state);
        begin(state, element, 0xa0 | kind);
        if (kind == 4) {
            writeOid(state, element, 0x06, lua.requiredString(state, 1, "enterprise"));
            put(state, element, 0x40, ipv4(state, lua.requiredString(state, 1, "agent_address")));
            putInteger(state, element, 0x02, integer(state, 1, "generic_trap", 0), true);
            putInteger(state, element, 0x02, integer(state, 1, "specific_trap", 0), true);
            putInteger(state, element, 0x43, unsigned32(state, 1, "timestamp"), false);
        } else {
            putInteger(state, element, 0x02, integer(state, 1, "request_id", 0), true);
            putInteger(state, element, 0x02, integer(state, 1, if (kind == 5) "non_repeaters" else "error_status", 0), true);
            putInteger(state, element, 0x02, integer(state, 1, if (kind == 5) "max_repetitions" else "error_index", 0), true);
        }
        writeVarbinds(state, element);
        end(state, element);
    }
    end(state, element);
}

fn versionOf(state: ?*c.lua_State) u64 {
    if (c.lua_getfield(state, 1, "version") == c.LUA_TNUMBER) {
        defer c.lua_pop(state, 1);
        return @bitCast(c.lua_tointegerx(state, -1, null));
    }
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) == c.LUA_TNIL) return 1;
    if (c.lua_type(state, -1) != c.LUA_TSTRING) lua.raise(state, "version must be a name or a number", .{});
    const name = lua.stringAt(state, -1, "version");
    if (std.mem.eql(u8, name, "v1")) return 0;
    if (std.mem.eql(u8, name, "v2c")) return 1;
    if (std.mem.eql(u8, name, "v3")) return 3;
    lua.raise(state, "version must be v1, v2c, v3 or a number", .{});
}

/// The PDU type, 0 to 30: a name or a number.
fn pduOf(state: ?*c.lua_State) u8 {
    defer c.lua_pop(state, 1);
    if (c.lua_getfield(state, 1, "pdu") == c.LUA_TNUMBER) {
        const value = c.lua_tointegerx(state, -1, null);
        if (value < 0 or value > 30) lua.raise(state, "pdu must be 0 to 30", .{});
        return @intCast(value);
    }
    if (c.lua_type(state, -1) != c.LUA_TSTRING) lua.raise(state, "pdu is required: a name or a number", .{});
    const name = lua.stringAt(state, -1, "pdu");
    for (pdu_names, 0..) |known, number| if (std.mem.eql(u8, known, name)) return @intCast(number);
    lua.raise(state, "pdu must be get, getnext, response, set, trap, getbulk, inform, trapv2, report or a number", .{});
}

/// `table[name]` as an integer, or `default` when nil; the table is at stack `index`.
fn integer(state: ?*c.lua_State, index: c_int, name: [*:0]const u8, default: i64) u64 {
    if (!lua.field(state, index, name, c.LUA_TNUMBER)) return @bitCast(default);
    defer c.lua_pop(state, 1);
    var whole: c_int = 0;
    const value = c.lua_tointegerx(state, -1, &whole);
    if (whole == 0) lua.raise(state, "%s must be an integer", .{name});
    return @bitCast(value);
}

fn unsigned32(state: ?*c.lua_State, index: c_int, name: [*:0]const u8) u64 {
    const value = integer(state, index, name, 0);
    if (value > 0xffff_ffff) lua.raise(state, "%s must be 0 to 4294967295", .{name});
    return value;
}

fn ipv4(state: ?*c.lua_State, text: []const u8) []const u8 {
    const buffer = struct {
        var bytes: [4]u8 = undefined;
    };
    var parts = std.mem.splitScalar(u8, text, '.');
    for (0..4) |index| {
        const part = parts.next() orelse lua.raise(state, "an address must be a.b.c.d", .{});
        buffer.bytes[index] = std.fmt.parseInt(u8, part, 10) catch lua.raise(state, "an address must be a.b.c.d", .{});
    }
    if (parts.next() != null) lua.raise(state, "an address must be a.b.c.d", .{});
    return &buffer.bytes;
}

fn check(state: ?*c.lua_State, result: c_int) void {
    if (result < 0) lua.raise(state, "the packet could not be built", .{});
}

fn begin(state: ?*c.lua_State, element: *lber.BerElement, tag: u8) void {
    check(state, lber.ber_printf(element, "t{", @as(lber.ber_tag_t, tag)));
}

fn end(state: ?*c.lua_State, element: *lber.BerElement) void {
    check(state, lber.ber_printf(element, "}"));
}

/// An element with `tag` holding `bytes`.
fn put(state: ?*c.lua_State, element: *lber.BerElement, tag: u8, bytes: []const u8) void {
    check(state, lber.ber_printf(element, "to", @as(lber.ber_tag_t, tag), bytes.ptr, @as(lber.ber_len_t, @intCast(bytes.len))));
}

/// Bytes already encoded, appended as they are.
fn raw(state: ?*c.lua_State, element: *lber.BerElement, bytes: []const u8) void {
    check(state, @intCast(lber.ber_write(element, bytes.ptr, @intCast(bytes.len), 0)));
}

/// An INTEGER-shaped element: the shortest big-endian form, two's complement when
/// `signed`, otherwise unsigned with a leading zero when the top bit is set.
fn putInteger(state: ?*c.lua_State, element: *lber.BerElement, tag: u8, value: u64, signed: bool) void {
    var bytes: [9]u8 = @splat(0);
    std.mem.writeInt(u64, bytes[1..9], value, .big);
    var start: usize = 0;
    if (signed) {
        const pad: u8 = if (@as(i64, @bitCast(value)) < 0) 0xff else 0;
        bytes[0] = pad;
        while (start < 8 and bytes[start] == pad and (bytes[start + 1] >> 7) == (pad >> 7)) start += 1;
    } else {
        while (start < 8 and bytes[start] == 0 and bytes[start + 1] < 0x80) start += 1;
    }
    put(state, element, tag, bytes[start..]);
}

fn writeOid(state: ?*c.lua_State, element: *lber.BerElement, tag: u8, name: [:0]const u8) void {
    var buffer: [512]u8 = undefined;
    if (name.len > buffer.len) lua.raise(state, "oid is too long", .{});
    var text: lber.struct_berval = .{ .bv_len = @intCast(name.len), .bv_val = @constCast(name.ptr) };
    var encoded: lber.struct_berval = .{ .bv_len = @intCast(buffer.len), .bv_val = &buffer };
    if (lber.ber_encode_oid(&text, &encoded) != 0) lua.raise(state, "invalid oid \"%s\"", .{name.ptr});
    put(state, element, tag, buffer[0..encoded.bv_len]);
}

fn writeVarbinds(state: ?*c.lua_State, element: *lber.BerElement) void {
    begin(state, element, 0x30);
    if (lua.tableField(state, 1, "varbinds")) |list| {
        defer c.lua_pop(state, 1);
        const count: usize = @intCast(c.lua_rawlen(state, list));
        for (1..count + 1) |position| {
            if (c.lua_rawgeti(state, list, @intCast(position)) != c.LUA_TTABLE) lua.raise(state, "each varbind must be a table", .{});
            const varbind = c.lua_gettop(state);
            begin(state, element, 0x30);
            if (lua.optionalString(state, varbind, "oid_raw")) |bytes| {
                put(state, element, 0x06, bytes);
            } else writeOid(state, element, 0x06, lua.requiredString(state, varbind, "oid"));
            writeValue(state, element, varbind);
            end(state, element);
            c.lua_pop(state, 1);
        }
    }
    end(state, element);
}

/// The value of the varbind table at stack `varbind`: by `type`, else by its Lua type
/// (a number is an integer, a string an octet string, nothing a null). A `tag` writes
/// `value` (a string) as the raw content of that tag instead.
fn writeValue(state: ?*c.lua_State, element: *lber.BerElement, varbind: c_int) void {
    if (lua.field(state, varbind, "tag", c.LUA_TNUMBER)) {
        const tag = c.lua_tointegerx(state, -1, null);
        c.lua_pop(state, 1);
        if (tag < 0 or tag > 255) lua.raise(state, "tag must be 0 to 255", .{});
        return put(state, element, @intCast(tag), lua.optionalString(state, varbind, "value") orelse "");
    }
    const kind = kindOf(state, varbind);
    switch (kind.tag) {
        0x02 => putInteger(state, element, 0x02, integer(state, varbind, "value", 0), true),
        0x41, 0x42, 0x43 => putInteger(state, element, kind.tag, unsigned32(state, varbind, "value"), false),
        0x46 => putInteger(state, element, kind.tag, integer(state, varbind, "value", 0), false),
        0x04, 0x44 => put(state, element, kind.tag, lua.optionalString(state, varbind, "value") orelse ""),
        0x06 => writeOid(state, element, 0x06, lua.requiredString(state, varbind, "value")),
        0x40 => put(state, element, 0x40, ipv4(state, lua.requiredString(state, varbind, "value"))),
        else => put(state, element, kind.tag, ""),
    }
}

fn kindOf(state: ?*c.lua_State, varbind: c_int) Kind {
    if (lua.optionalString(state, varbind, "type")) |name| {
        for (kinds) |kind| if (std.mem.eql(u8, kind.name, name)) return kind;
        lua.raise(state, "unknown type \"%s\"", .{name.ptr});
    }
    defer c.lua_pop(state, 1);
    return switch (c.lua_getfield(state, varbind, "value")) {
        c.LUA_TNUMBER => kinds[0],
        c.LUA_TSTRING => kinds[1],
        else => kinds[2],
    };
}

// Decoding.

const Tlv = struct { tag: u8, content: []const u8, rest: []const u8 };

/// The element at the start of `bytes`: tag, content and what follows. Null when it is
/// truncated, has a multi-byte tag, or an indefinite or oversized length.
fn read(bytes: []const u8) ?Tlv {
    if (bytes.len < 2 or bytes[0] & 0x1f == 0x1f) return null;
    var length: usize = bytes[1];
    var offset: usize = 2;
    if (length & 0x80 != 0) {
        const count = length & 0x7f;
        if (count == 0 or count > 4 or bytes.len < 2 + count) return null;
        length = 0;
        for (bytes[2 .. 2 + count]) |byte| length = length << 8 | byte;
        offset = 2 + count;
    }
    if (bytes.len - offset < length) return null;
    return .{ .tag = bytes[0], .content = bytes[offset..][0..length], .rest = bytes[offset + length ..] };
}

fn signedValue(content: []const u8) ?i64 {
    if (content.len == 0 or content.len > 8) return null;
    var value: i64 = if (content[0] & 0x80 != 0) -1 else 0;
    for (content) |byte| value = value << 8 | byte;
    return value;
}

fn unsignedValue(content: []const u8) ?u64 {
    if (content.len == 0 or content.len > 9 or (content.len == 9 and content[0] != 0)) return null;
    var value: u64 = 0;
    for (content) |byte| value = value << 8 | byte;
    return value;
}

/// `snmp.decode(bytes)`: `{ version, community, pdu, request_id, error_status,
/// error_index, varbinds }`, where each varbind is `{ oid, type, value }`. `getbulk` has
/// `non_repeaters` and `max_repetitions`; a v1 `trap` has `enterprise`, `agent_address`,
/// `generic_trap`, `specific_trap` and `timestamp`. What does not parse stays in
/// `payload`: a v3 message after its version, or a PDU body, or a whole packet.
fn decodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    c.lua_settop(state, 1);
    if (!message(state, bytes)) {
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 1);
        lua.setString(state, "payload", bytes);
    }
    return 1;
}

fn message(state: ?*c.lua_State, bytes: []const u8) bool {
    const outer = read(bytes) orelse return false;
    if (outer.tag != 0x30) return false;
    const version = read(outer.content) orelse return false;
    if (version.tag != 0x02) return false;
    const number = signedValue(version.content) orelse return false;
    c.lua_createtable(state, 0, 8);
    setVersion(state, number);
    if (number != 0 and number != 1) return unparsed(state, version.rest);
    const community = read(version.rest) orelse return unparsed(state, version.rest);
    if (community.tag != 0x04) return unparsed(state, version.rest);
    lua.setString(state, "community", community.content);
    const pdu = read(community.rest) orelse return unparsed(state, community.rest);
    if (pdu.tag & 0xe0 != 0xa0) {
        lua.setInteger(state, "pdu", pdu.tag);
        return unparsed(state, pdu.content);
    }
    const kind: u8 = pdu.tag & 0x1f;
    if (kind < pdu_names.len) lua.setString(state, "pdu", pdu_names[kind]) else lua.setInteger(state, "pdu", kind);
    if (!pduFields(state, kind, pdu.content)) {
        // Only the header and the unparsed body.
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 4);
        setVersion(state, number);
        lua.setString(state, "community", community.content);
        if (kind < pdu_names.len) lua.setString(state, "pdu", pdu_names[kind]) else lua.setInteger(state, "pdu", kind);
        return unparsed(state, pdu.content);
    }
    return true;
}

fn unparsed(state: ?*c.lua_State, body: []const u8) bool {
    lua.setString(state, "payload", body);
    return true;
}

fn setVersion(state: ?*c.lua_State, number: i64) void {
    switch (number) {
        0 => lua.setString(state, "version", "v1"),
        1 => lua.setString(state, "version", "v2c"),
        3 => lua.setString(state, "version", "v3"),
        else => lua.setInteger(state, "version", number),
    }
}

fn pduFields(state: ?*c.lua_State, kind: u8, content: []const u8) bool {
    var rest = content;
    if (kind == 4) {
        const enterprise = read(rest) orelse return false;
        const agent = read(enterprise.rest) orelse return false;
        const generic = read(agent.rest) orelse return false;
        const specific = read(generic.rest) orelse return false;
        const stamp = read(specific.rest) orelse return false;
        if (enterprise.tag != 0x06 or agent.tag != 0x40 or agent.content.len != 4) return false;
        if (generic.tag != 0x02 or specific.tag != 0x02 or stamp.tag != 0x43) return false;
        var buffer: [4096]u8 = undefined;
        lua.setString(state, "enterprise", dotted(&buffer, enterprise.content) orelse return false);
        var address: [16]u8 = undefined;
        lua.setString(state, "agent_address", address4(&address, agent.content));
        lua.setInteger(state, "generic_trap", signedValue(generic.content) orelse return false);
        lua.setInteger(state, "specific_trap", signedValue(specific.content) orelse return false);
        lua.setInteger(state, "timestamp", unsignedValue(stamp.content) orelse return false);
        rest = stamp.rest;
    } else {
        const names = if (kind == 5) [_][:0]const u8{ "request_id", "non_repeaters", "max_repetitions" } else [_][:0]const u8{ "request_id", "error_status", "error_index" };
        for (names) |name| {
            const field = read(rest) orelse return false;
            if (field.tag != 0x02) return false;
            lua.setInteger(state, name, signedValue(field.content) orelse return false);
            rest = field.rest;
        }
    }
    const list = read(rest) orelse return false;
    if (list.tag != 0x30) return false;
    return varbinds(state, list.content);
}

fn varbinds(state: ?*c.lua_State, list: []const u8) bool {
    c.lua_createtable(state, 0, 0);
    var rest = list;
    var index: c_int = 0;
    while (rest.len > 0) {
        const item = read(rest) orelse return false;
        rest = item.rest;
        const name = read(item.content) orelse return false;
        const value = read(name.rest) orelse return false;
        if (item.tag != 0x30 or name.tag != 0x06) return false;
        var buffer: [4096]u8 = undefined;
        c.lua_createtable(state, 0, 3);
        lua.setString(state, "oid", dotted(&buffer, name.content) orelse return false);
        setValue(state, value);
        index += 1;
        c.lua_rawseti(state, -2, index);
    }
    c.lua_setfield(state, -2, "varbinds");
    return true;
}

/// The value as `type` and `value`; anything that does not fit its type is a `tag` and the raw `value`.
fn setValue(state: ?*c.lua_State, value: Tlv) void {
    var buffer: [4096]u8 = undefined;
    for (kinds) |kind| {
        if (kind.tag != value.tag) continue;
        const parsed = switch (kind.tag) {
            0x02 => if (signedValue(value.content)) |number| blk: {
                lua.setInteger(state, "value", number);
                break :blk true;
            } else false,
            0x41, 0x42, 0x43, 0x46 => if (unsignedValue(value.content)) |number| blk: {
                lua.setInteger(state, "value", @as(i64, @bitCast(number)));
                break :blk true;
            } else false,
            0x04, 0x44 => blk: {
                lua.setString(state, "value", value.content);
                break :blk true;
            },
            0x06 => if (dotted(&buffer, value.content)) |text| blk: {
                lua.setString(state, "value", text);
                break :blk true;
            } else false,
            0x40 => if (value.content.len == 4) blk: {
                lua.setString(state, "value", address4(buffer[0..16], value.content));
                break :blk true;
            } else false,
            else => value.content.len == 0,
        };
        if (parsed) return lua.setString(state, "type", kind.name);
        break;
    }
    lua.setInteger(state, "tag", value.tag);
    lua.setString(state, "value", value.content);
}

/// The dotted form of BER OID content in `buffer`, or null if it is not an OID.
fn dotted(buffer: *[4096]u8, content: []const u8) ?[:0]const u8 {
    if (content.len == 0 or content.len * 4 + 4 > buffer.len) return null;
    var encoded: lber.struct_berval = .{ .bv_len = @intCast(content.len), .bv_val = @constCast(content.ptr) };
    var text: lber.struct_berval = .{ .bv_len = @intCast(buffer.len), .bv_val = buffer };
    if (lber.ber_decode_oid(&encoded, &text) != 0) return null;
    buffer[text.bv_len] = 0;
    return buffer[0..text.bv_len :0];
}

fn address4(buffer: *[16]u8, content: []const u8) [:0]const u8 {
    return std.fmt.bufPrintZ(buffer, "{d}.{d}.{d}.{d}", .{ content[0], content[1], content[2], content[3] }) catch unreachable;
}

test "snmp encodes and decodes messages" {
    const state = lua.testState("protocols/snmp", module);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local snmp = require("protocols/snmp")
        \\assert(snmp.pdus.get == 0 and snmp.pdus.report == 8)
        \\-- a GetRequest for sysDescr.0, byte for byte
        \\local get = "\x30\x26\x02\x01\x01\x04\6public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        \\assert(snmp.encode{ version = "v2c", pdu = "get", request_id = 1, varbinds = { { oid = "1.3.6.1.2.1.1.1.0" } } } == get)
        \\local request = snmp.decode(get)
        \\assert(request.version == "v2c" and request.community == "public" and request.pdu == "get" and request.request_id == 1)
        \\assert(request.error_status == 0 and request.varbinds[1].oid == "1.3.6.1.2.1.1.1.0" and request.varbinds[1].type == "null")
        \\-- integers: the shortest two's complement, and unsigned types with a leading zero
        \\local function body(kind, number)
        \\    local bytes = snmp.encode{ pdu = "response", varbinds = { { oid = "1.3", type = kind, value = number } } }
        \\    local start = bytes:find("\x06\x01\x2b", 1, true) + 3
        \\    return bytes:sub(start)
        \\end
        \\assert(body("integer", 0) == "\x02\x01\x00" and body("integer", 127) == "\x02\x01\x7f" and body("integer", 128) == "\x02\x02\x00\x80")
        \\assert(body("integer", -1) == "\x02\x01\xff" and body("integer", -128) == "\x02\x01\x80" and body("integer", -129) == "\x02\x02\xff\x7f")
        \\assert(body("gauge32", 4294967295) == "\x42\x05\x00\xff\xff\xff\xff" and body("time_ticks", 256) == "\x43\x02\x01\x00")
        \\assert(body("counter32", 0) == "\x41\x01\x00" and body("counter64", -1) == "\x46\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff")
        \\assert(body("octet_string", "Linux") == "\x04\5Linux" and body("ip_address", "10.0.0.1") == "\x40\x04\x0a\x00\x00\x01")
        \\assert(body("oid", "1.3.6.1.2.1") == "\x06\x05\x2b\x06\x01\x02\x01" and body("end_of_mib_view") == "\x82\x00")
        \\-- values decode to what they were
        \\local response = snmp.decode(snmp.encode{ pdu = "response", request_id = 77, error_status = 2, error_index = 1, varbinds = {
        \\    { oid = "1.3.6.1.2.1.1.1.0", value = "Linux" }, { oid = "1.3.6.1.2.1.1.3.0", type = "time_ticks", value = 4000000000 },
        \\    { oid = "1.3.6.1.2.1.2.1.0", value = -5 }, { oid = "1.3.6.1.2.1.4.20.1.1", type = "ip_address", value = "192.0.2.7" },
        \\    { oid = "1.3.6.1.2.1.1.2.0", type = "oid", value = "1.3.6.1.4.1.8072.3.2.10" }, { oid = "1.3.6.1.9", type = "no_such_object" },
        \\    { oid = "1.3.6.1.2.1.31.1.1.1.6.1", type = "counter64", value = math.mininteger },
        \\} })
        \\assert(response.pdu == "response" and response.request_id == 77 and response.error_status == 2 and response.error_index == 1)
        \\local v = response.varbinds
        \\assert(v[1].type == "octet_string" and v[1].value == "Linux" and v[2].type == "time_ticks" and v[2].value == 4000000000)
        \\assert(v[3].type == "integer" and v[3].value == -5 and v[4].type == "ip_address" and v[4].value == "192.0.2.7")
        \\assert(v[5].type == "oid" and v[5].value == "1.3.6.1.4.1.8072.3.2.10" and v[6].type == "no_such_object" and v[6].value == nil)
        \\assert(v[7].type == "counter64" and v[7].value == math.mininteger)
        \\-- getbulk, v1 traps and the other PDU types
        \\local bulk = snmp.decode(snmp.encode{ pdu = "getbulk", request_id = 5, non_repeaters = 0, max_repetitions = 25, varbinds = { { oid = "1.3.6.1.2.1.2.2" } } })
        \\assert(bulk.pdu == "getbulk" and bulk.max_repetitions == 25 and bulk.non_repeaters == 0 and bulk.error_status == nil)
        \\local trap = snmp.decode(snmp.encode{ version = "v1", pdu = "trap", enterprise = "1.3.6.1.4.1.9", agent_address = "192.0.2.1",
        \\    generic_trap = 6, specific_trap = 42, timestamp = 12345, varbinds = { { oid = "1.3.6.1.4.1.9.1", value = 1 } } })
        \\assert(trap.version == "v1" and trap.pdu == "trap" and trap.enterprise == "1.3.6.1.4.1.9" and trap.agent_address == "192.0.2.1")
        \\assert(trap.generic_trap == 6 and trap.specific_trap == 42 and trap.timestamp == 12345 and trap.varbinds[1].value == 1)
        \\for name, number in pairs(snmp.pdus) do
        \\    if name ~= "trap" then assert(snmp.decode(snmp.encode{ pdu = number }).pdu == name) end
        \\end
        \\-- anything the wire allows: any tag, raw OIDs, odd versions and raw bodies
        \\assert(snmp.decode(snmp.encode{ pdu = 12, request_id = 1 }).pdu == 12)
        \\local odd = snmp.decode(snmp.encode{ pdu = "get", varbinds = { { oid_raw = "\x2b\x06", tag = 0x99, value = "xyz" } } })
        \\assert(odd.varbinds[1].oid == "1.3.6" and odd.varbinds[1].tag == 0x99 and odd.varbinds[1].value == "xyz")
        \\local v3 = snmp.decode(snmp.encode{ version = "v3", payload = "\x30\x00" })
        \\assert(v3.version == "v3" and v3.payload == "\x30\x00" and v3.community == nil)
        \\assert(snmp.encode{ version = 7, payload = "" } == "\x30\x03\x02\x01\x07")
        \\-- what does not parse comes back as payload
        \\assert(snmp.decode("garbage").payload == "garbage")
        \\local cut = snmp.decode(get:sub(1, 20))
        \\assert(cut.payload == get:sub(1, 20))
        \\local bad = snmp.decode("\x30\x10\x02\x01\x01\x04\6public\xa0\x03\x02\x01\x01")
        \\assert(bad.version == "v2c" and bad.community == "public" and bad.pdu == "get" and bad.payload == "\x02\x01\x01" and bad.request_id == nil)
        \\-- bad input raises
        \\assert(not pcall(snmp.encode, { pdu = "get", varbinds = { { oid = "3.1" } } }))
        \\assert(not pcall(snmp.encode, { pdu = "get", varbinds = { { oid = "1.3", type = "gauge32", value = -1 } } }))
        \\assert(not pcall(snmp.encode, { pdu = "get", varbinds = { { oid = "1.3", type = "nope" } } }))
        \\assert(not pcall(snmp.encode, { pdu = "nope" }))
        \\assert(not pcall(snmp.encode, {}))
        \\assert(not pcall(snmp.encode, { pdu = "get", varbinds = { "1.3" } }))
        \\assert(not pcall(snmp.encode, { pdu = "trap", enterprise = "1.3", agent_address = "1.2.3" }))
    );
}
