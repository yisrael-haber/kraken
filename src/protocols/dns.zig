const std = @import("std");
const c = @import("c");
const cares = @import("cares");
const lua = @import("../runtime/lua.zig");

// c-ares' record API does the wire work. Each record type is described by its
// keys and their datatypes, so one generic mapping covers every supported type.

const type_names = [_][:0]const u8{
    "A",     "NS",   "CNAME", "SOA",   "PTR", "HINFO", "MX",         "TXT",  "SIG",
    "AAAA",  "SRV",  "NAPTR", "OPT",   "DS",  "SSHFP", "RRSIG",      "NSEC", "DNSKEY",
    "NSEC3", "TLSA", "SVCB",  "HTTPS", "ANY", "URI",   "NSEC3PARAM", "CAA",
};

const Flag = struct { name: [*:0]const u8, value: c_ushort };
const header_flags = [_]Flag{
    .{ .name = "qr", .value = cares.ARES_FLAG_QR }, .{ .name = "aa", .value = cares.ARES_FLAG_AA },
    .{ .name = "tc", .value = cares.ARES_FLAG_TC }, .{ .name = "rd", .value = cares.ARES_FLAG_RD },
    .{ .name = "ra", .value = cares.ARES_FLAG_RA }, .{ .name = "ad", .value = cares.ARES_FLAG_AD },
    .{ .name = "cd", .value = cares.ARES_FLAG_CD },
};

const Section = struct { name: [*:0]const u8, value: cares.ares_dns_section_t };
const sections = [_]Section{
    .{ .name = "answers", .value = cares.ARES_SECTION_ANSWER },
    .{ .name = "authority", .value = cares.ARES_SECTION_AUTHORITY },
    .{ .name = "additional", .value = cares.ARES_SECTION_ADDITIONAL },
};

/// Parse every section as raw records.
const raw_sections = cares.ARES_DNS_PARSE_AN_BASE_RAW | cares.ARES_DNS_PARSE_NS_BASE_RAW | cares.ARES_DNS_PARSE_AR_BASE_RAW |
    cares.ARES_DNS_PARSE_AN_EXT_RAW | cares.ARES_DNS_PARSE_NS_EXT_RAW | cares.ARES_DNS_PARSE_AR_EXT_RAW;

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    Scratch.register(state);
    lua.pushFunctions(state, .{ .{ "encode", encodeLua }, .{ "decode", decodeLua } });
    c.lua_createtable(state, 0, type_names.len);
    inline for (type_names) |name| lua.setInteger(state, name, @field(cares, "ARES_REC_TYPE_" ++ name));
    c.lua_setfield(state, -2, "types");
    return 1;
}

/// The c-ares memory of one call, in a to-be-closed stack slot, so __close frees
/// it when the call returns or raises.
const Scratch = struct {
    record: ?*cares.ares_dns_record_t = null,
    buffer: [*c]u8 = null,

    const metatable = "kraken.dns.scratch";

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
        if (self.buffer != null) cares.ares_free_string(self.buffer);
        if (self.record) |record| cares.ares_dns_record_destroy(record);
        self.* = .{};
        return 0;
    }
};

// Encoding. The message table is at index 1.

fn encodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    c.lua_settop(state, 1);
    const scratch = Scratch.push(state);
    const message = 1;
    var flags: c_ushort = 0;
    if (lua.tableField(state, message, "flags")) |table| {
        for (header_flags) |flag| {
            _ = c.lua_getfield(state, table, flag.name);
            if (c.lua_toboolean(state, -1) != 0) flags |= flag.value;
            c.lua_pop(state, 1);
        }
    }
    check(state, cares.ares_dns_record_create(
        &scratch.record,
        @intCast(integerField(state, message, "id", 0, 0xffff)),
        flags,
        @intCast(integerField(state, message, "opcode", 0, 15)),
        @intCast(integerField(state, message, "rcode", 0, 4095)),
    ));
    const record = scratch.record.?;
    var questions = Entries.of(state, message, "questions");
    while (questions.next()) |entry| check(state, cares.ares_dns_record_query_add(
        record,
        lua.requiredString(state, entry, "name").ptr,
        @intCast(integerField(state, entry, "type", null, 0xffff)),
        @intCast(integerField(state, entry, "class", 1, 0xffff)),
    ));
    for (sections) |section| {
        var records = Entries.of(state, message, section.name);
        while (records.next()) |entry| encodeRecord(state, record, section.value, entry);
    }
    var length: usize = 0;
    check(state, cares.ares_dns_write(record, &scratch.buffer, &length));
    lua.pushBytes(state, scratch.buffer[0..length]);
    return 1;
}

fn encodeRecord(state: ?*c.lua_State, record: *cares.ares_dns_record_t, section: cares.ares_dns_section_t, entry: c_int) void {
    const name = lua.requiredString(state, entry, "name");
    const kind: u16 = @intCast(integerField(state, entry, "type", null, 0xffff));
    const class: u16 = @intCast(integerField(state, entry, "class", 1, 0xffff));
    const ttl: u32 = @intCast(integerField(state, entry, "ttl", 0, 0xffff_ffff));
    const raw = lua.optionalString(state, entry, "raw");
    var rr: ?*cares.ares_dns_rr_t = null;
    check(state, cares.ares_dns_record_rr_add(&rr, record, section, name.ptr, if (raw != null) cares.ARES_REC_TYPE_RAW_RR else kind, class, ttl));
    if (raw) |data| {
        check(state, cares.ares_dns_rr_set_u16(rr, cares.ARES_RR_RAW_RR_TYPE, kind));
        return check(state, cares.ares_dns_rr_set_bin(rr, cares.ARES_RR_RAW_RR_DATA, data.ptr, data.len));
    }
    var count: usize = 0;
    const keys = cares.ares_dns_rr_get_keys(kind, &count);
    for (0..count) |index| {
        c.luaL_checkstack(state, 4, "record too large");
        var buffer: [32]u8 = undefined;
        const field = keyName(state, keys[index], &buffer);
        if (c.lua_getfield(state, entry, field) == c.LUA_TNIL) continue;
        encodeKey(state, rr, keys[index], field);
    }
}

/// Sets one key from the value on top of the stack.
fn encodeKey(state: ?*c.lua_State, rr: ?*cares.ares_dns_rr_t, key: cares.ares_dns_rr_key_t, field: [*:0]const u8) void {
    switch (cares.ares_dns_rr_key_datatype(key)) {
        cares.ARES_DATATYPE_INADDR => {
            const parsed = std.Io.net.Ip4Address.parse(lua.stringAt(state, -1, field), 0) catch fieldError(state, field, "an IPv4 address");
            var address: cares.struct_in_addr = undefined;
            @memcpy(std.mem.asBytes(&address), &parsed.bytes);
            check(state, cares.ares_dns_rr_set_addr(rr, key, &address));
        },
        cares.ARES_DATATYPE_INADDR6 => {
            const parsed = std.Io.net.Ip6Address.parse(lua.stringAt(state, -1, field), 0) catch fieldError(state, field, "an IPv6 address");
            var address: cares.struct_ares_in6_addr = undefined;
            @memcpy(std.mem.asBytes(&address), &parsed.bytes);
            check(state, cares.ares_dns_rr_set_addr6(rr, key, &address));
        },
        cares.ARES_DATATYPE_U8 => check(state, cares.ares_dns_rr_set_u8(rr, key, @intCast(integerAt(state, -1, field, 0xff)))),
        cares.ARES_DATATYPE_U16 => check(state, cares.ares_dns_rr_set_u16(rr, key, @intCast(integerAt(state, -1, field, 0xffff)))),
        cares.ARES_DATATYPE_U32 => check(state, cares.ares_dns_rr_set_u32(rr, key, @intCast(integerAt(state, -1, field, 0xffff_ffff)))),
        cares.ARES_DATATYPE_NAME, cares.ARES_DATATYPE_STR => check(state, cares.ares_dns_rr_set_str(rr, key, lua.stringAt(state, -1, field).ptr)),
        cares.ARES_DATATYPE_BIN, cares.ARES_DATATYPE_BINP => {
            const data = lua.stringAt(state, -1, field);
            check(state, cares.ares_dns_rr_set_bin(rr, key, data.ptr, data.len));
        },
        cares.ARES_DATATYPE_ABINP => {
            const list = listAt(state, -1, field, "a list of strings");
            var index: c.lua_Integer = 1;
            while (c.lua_rawgeti(state, list, index) != c.LUA_TNIL) : (index += 1) {
                const data = lua.stringAt(state, -1, field);
                check(state, cares.ares_dns_rr_add_abin(rr, key, data.ptr, data.len));
                c.lua_pop(state, 1);
            }
        },
        cares.ARES_DATATYPE_OPT => {
            const list = listAt(state, -1, field, "a list of { code, value } pairs");
            var index: c.lua_Integer = 1;
            while (c.lua_rawgeti(state, list, index) != c.LUA_TNIL) : (index += 1) {
                if (c.lua_type(state, -1) != c.LUA_TTABLE) fieldError(state, field, "a list of { code, value } pairs");
                const pair = c.lua_gettop(state);
                _ = c.lua_rawgeti(state, pair, 1);
                const code = integerAt(state, -1, field, 0xffff);
                _ = c.lua_rawgeti(state, pair, 2);
                const value = lua.stringAt(state, -1, field);
                check(state, cares.ares_dns_rr_set_opt(rr, key, @intCast(code), value.ptr, value.len));
                c.lua_settop(state, pair - 1);
            }
        },
        else => fieldError(state, field, "a supported value"),
    }
}

// Decoding: `dns.decode(bytes [, raw])`.

fn decodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    const flags: c_uint = if (c.lua_toboolean(state, 2) != 0) raw_sections else 0;
    c.lua_settop(state, 2);
    const scratch = Scratch.push(state);
    check(state, cares.ares_dns_parse(bytes.ptr, bytes.len, flags, &scratch.record));
    const record = scratch.record.?;
    c.lua_createtable(state, 0, 8);
    lua.setInteger(state, "id", cares.ares_dns_record_get_id(record));
    lua.setInteger(state, "opcode", cares.ares_dns_record_get_opcode(record));
    lua.setInteger(state, "rcode", cares.ares_dns_record_get_rcode(record));
    const header = cares.ares_dns_record_get_flags(record);
    c.lua_createtable(state, 0, header_flags.len);
    for (header_flags) |flag| {
        c.lua_pushboolean(state, @intFromBool((header & flag.value) != 0));
        c.lua_setfield(state, -2, flag.name);
    }
    c.lua_setfield(state, -2, "flags");
    const questions = cares.ares_dns_record_query_cnt(record);
    c.lua_createtable(state, @intCast(questions), 0);
    for (0..questions) |index| {
        var name: [*c]const u8 = null;
        var kind: cares.ares_dns_rec_type_t = 0;
        var class: cares.ares_dns_class_t = 0;
        check(state, cares.ares_dns_record_query_get(record, index, &name, &kind, &class));
        c.lua_createtable(state, 0, 3);
        lua.setString(state, "name", std.mem.span(name));
        lua.setInteger(state, "type", kind);
        lua.setInteger(state, "class", class);
        c.lua_rawseti(state, -2, @intCast(index + 1));
    }
    c.lua_setfield(state, -2, "questions");
    for (sections) |section| {
        const count = cares.ares_dns_record_rr_cnt(record, section.value);
        c.lua_createtable(state, @intCast(count), 0);
        for (0..count) |index| {
            c.luaL_checkstack(state, 8, "message too large");
            decodeRecord(state, cares.ares_dns_record_rr_get_const(record, section.value, index).?);
            c.lua_rawseti(state, -2, @intCast(index + 1));
        }
        c.lua_setfield(state, -2, section.name);
    }
    return 1;
}

fn decodeRecord(state: ?*c.lua_State, rr: *const cares.ares_dns_rr_t) void {
    const kind = cares.ares_dns_rr_get_type(rr);
    c.lua_createtable(state, 0, 8);
    lua.setString(state, "name", std.mem.span(cares.ares_dns_rr_get_name(rr)));
    lua.setInteger(state, "class", cares.ares_dns_rr_get_class(rr));
    lua.setInteger(state, "ttl", cares.ares_dns_rr_get_ttl(rr));
    if (kind == cares.ARES_REC_TYPE_RAW_RR) {
        lua.setInteger(state, "type", cares.ares_dns_rr_get_u16(rr, cares.ARES_RR_RAW_RR_TYPE));
        var length: usize = 0;
        const data = cares.ares_dns_rr_get_bin(rr, cares.ARES_RR_RAW_RR_DATA, &length);
        return lua.setString(state, "raw", if (data == null) "" else data[0..length]);
    }
    lua.setInteger(state, "type", kind);
    var count: usize = 0;
    const keys = cares.ares_dns_rr_get_keys(kind, &count);
    for (0..count) |index| {
        var buffer: [32]u8 = undefined;
        const field = keyName(state, keys[index], &buffer);
        decodeKey(state, rr, keys[index]);
        c.lua_setfield(state, -2, field);
    }
}

/// Pushes one key's value.
fn decodeKey(state: ?*c.lua_State, rr: *const cares.ares_dns_rr_t, key: cares.ares_dns_rr_key_t) void {
    var length: usize = 0;
    switch (cares.ares_dns_rr_key_datatype(key)) {
        cares.ARES_DATATYPE_INADDR => {
            const bytes = std.mem.asBytes(@as(*const cares.struct_in_addr, @ptrCast(cares.ares_dns_rr_get_addr(rr, key).?)));
            _ = c.lua_pushfstring(state, "%d.%d.%d.%d", @as(c_int, bytes[0]), @as(c_int, bytes[1]), @as(c_int, bytes[2]), @as(c_int, bytes[3]));
        },
        cares.ARES_DATATYPE_INADDR6 => {
            var address: std.Io.net.Ip6Address.Unresolved = .{ .bytes = undefined, .interface_name = null };
            @memcpy(&address.bytes, std.mem.asBytes(@as(*const cares.struct_ares_in6_addr, @ptrCast(cares.ares_dns_rr_get_addr6(rr, key).?))));
            var text: [64]u8 = undefined;
            lua.pushBytes(state, std.fmt.bufPrint(&text, "{f}", .{address}) catch unreachable);
        },
        cares.ARES_DATATYPE_U8 => c.lua_pushinteger(state, cares.ares_dns_rr_get_u8(rr, key)),
        cares.ARES_DATATYPE_U16 => c.lua_pushinteger(state, cares.ares_dns_rr_get_u16(rr, key)),
        cares.ARES_DATATYPE_U32 => c.lua_pushinteger(state, cares.ares_dns_rr_get_u32(rr, key)),
        cares.ARES_DATATYPE_NAME, cares.ARES_DATATYPE_STR => {
            const value = cares.ares_dns_rr_get_str(rr, key);
            lua.pushBytes(state, if (value == null) "" else std.mem.span(value));
        },
        cares.ARES_DATATYPE_BIN, cares.ARES_DATATYPE_BINP => {
            const data = cares.ares_dns_rr_get_bin(rr, key, &length);
            lua.pushBytes(state, if (data == null) "" else data[0..length]);
        },
        cares.ARES_DATATYPE_ABINP => {
            const count = cares.ares_dns_rr_get_abin_cnt(rr, key);
            c.lua_createtable(state, @intCast(count), 0);
            for (0..count) |index| {
                const data = cares.ares_dns_rr_get_abin(rr, key, index, &length);
                lua.pushBytes(state, if (data == null) "" else data[0..length]);
                c.lua_rawseti(state, -2, @intCast(index + 1));
            }
        },
        cares.ARES_DATATYPE_OPT => {
            const count = cares.ares_dns_rr_get_opt_cnt(rr, key);
            c.lua_createtable(state, @intCast(count), 0);
            for (0..count) |index| {
                var value: [*c]const u8 = null;
                const code = cares.ares_dns_rr_get_opt(rr, key, index, &value, &length);
                c.lua_createtable(state, 2, 0);
                c.lua_pushinteger(state, code);
                c.lua_rawseti(state, -2, 1);
                lua.pushBytes(state, if (value == null) "" else value[0..length]);
                c.lua_rawseti(state, -2, 2);
                c.lua_rawseti(state, -2, @intCast(index + 1));
            }
        },
        else => c.lua_pushnil(state),
    }
}

// Helpers.

fn check(state: ?*c.lua_State, status: cares.ares_status_t) void {
    if (status != cares.ARES_SUCCESS) lua.raise(state, "%s", .{cares.ares_strerror(@intCast(status))});
}

fn keyName(state: ?*c.lua_State, key: cares.ares_dns_rr_key_t, buffer: *[32]u8) [:0]const u8 {
    const upper = std.mem.span(cares.ares_dns_rr_key_tostr(key));
    // The longest name c-ares 1.34.5 defines is 17 bytes; guard a future longer one.
    if (upper.len >= buffer.len) lua.raise(state, "record key name too long", .{});
    for (upper, 0..) |character, index| buffer[index] = std.ascii.toLower(character);
    buffer[upper.len] = 0;
    return buffer[0..upper.len :0];
}

fn fieldError(state: ?*c.lua_State, field: [*:0]const u8, expected: [*:0]const u8) noreturn {
    lua.raise(state, "%s must be %s", .{ field, expected });
}

/// The tables in the list `table[name]`, each left on the stack top in turn.
const Entries = struct {
    state: ?*c.lua_State,
    list: ?c_int,
    index: c.lua_Integer = 0,

    fn of(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) Entries {
        return .{ .state = state, .list = lua.tableField(state, table, name) };
    }

    /// The next entry's stack index, dropping whatever the previous one left.
    fn next(self: *Entries) ?c_int {
        const list = self.list orelse return null;
        c.lua_settop(self.state, list);
        self.index += 1;
        c.luaL_checkstack(self.state, 8, "message too large");
        return switch (c.lua_rawgeti(self.state, list, self.index)) {
            c.LUA_TNIL => null,
            c.LUA_TTABLE => c.lua_gettop(self.state),
            else => lua.raise(self.state, "entry %d must be a table", .{@as(c_int, @intCast(self.index))}),
        };
    }
};

fn listAt(state: ?*c.lua_State, index: c_int, field: [*:0]const u8, expected: [*:0]const u8) c_int {
    if (c.lua_type(state, index) != c.LUA_TTABLE) fieldError(state, field, expected);
    return c.lua_absindex(state, index);
}

fn integerField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, default: ?i64, maximum: i64) i64 {
    if (!lua.field(state, table, name, c.LUA_TNUMBER)) return default orelse lua.raise(state, "%s is required", .{name});
    defer c.lua_pop(state, 1);
    return integerAt(state, -1, name, maximum);
}

fn integerAt(state: ?*c.lua_State, index: c_int, field: [*:0]const u8, maximum: i64) i64 {
    var valid: c_int = 0;
    const value = c.lua_tointegerx(state, index, &valid);
    if (valid == 0 or value < 0 or value > maximum) lua.raise(state, "%s must be an integer from 0 to %I", .{ field, @as(c.lua_Integer, maximum) });
    return value;
}

test "dns encodes and decodes messages through c-ares" {
    const state = lua.testState("protocols/dns", module);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local dns = require("protocols/dns")
        \\local t = dns.types
        \\local bytes = dns.encode({
        \\    id = 0x1234, flags = { qr = true, rd = true, ra = true },
        \\    questions = { { name = "example.com", type = t.MX } },
        \\    answers = {
        \\        { name = "example.com", type = t.MX, ttl = 300, preference = 10, exchange = "mail.example.com" },
        \\        { name = "example.com", type = t.A, ttl = 60, addr = "192.0.2.7" },
        \\        { name = "example.com", type = t.AAAA, ttl = 60, addr = "2001:db8::7" },
        \\        { name = "example.com", type = t.TXT, ttl = 60, data = { "a", "bc" } },
        \\        { name = "_ldap._tcp.example.com", type = t.SRV, priority = 1, weight = 2, port = 389, target = "dc.example.com" },
        \\        { name = "example.com", type = 99, class = 1, ttl = 5, raw = "\1\2\3" },
        \\    },
        \\    additional = { { name = "", type = t.OPT, udp_size = 1232, version = 0, flags = 0, options = { { 10, "cookie00" } } } },
        \\})
        \\local m = dns.decode(bytes)
        \\assert(m.id == 0x1234 and m.flags.qr and m.flags.rd and m.flags.ra and not m.flags.aa and m.opcode == 0 and m.rcode == 0)
        \\assert(#m.questions == 1 and m.questions[1].name == "example.com" and m.questions[1].type == t.MX and m.questions[1].class == 1)
        \\local a = m.answers
        \\assert(#a == 6 and a[1].preference == 10 and a[1].exchange == "mail.example.com" and a[1].ttl == 300)
        \\assert(a[2].addr == "192.0.2.7" and a[3].addr == "2001:db8::7")
        \\assert(#a[4].data == 2 and a[4].data[1] == "a" and a[4].data[2] == "bc")
        \\assert(a[5].port == 389 and a[5].target == "dc.example.com")
        \\assert(a[6].type == 99 and a[6].raw == "\1\2\3")
        \\local opt = m.additional[1]
        \\assert(opt.type == t.OPT and opt.udp_size == 1232 and opt.options[1][1] == 10 and opt.options[1][2] == "cookie00")
        \\local raw = dns.decode(bytes, true)
        \\assert(raw.answers[1].type == t.MX and type(raw.answers[1].raw) == "string" and raw.answers[1].preference == nil)
        \\-- mDNS shapes: no questions, several questions, class top bits, NBT-NS opcode.
        \\local mdns = dns.decode(dns.encode({ flags = { qr = true, aa = true }, answers = {
        \\    { name = "host.local", type = t.A, class = 0x8001, ttl = 120, addr = "10.0.0.9" } } }))
        \\assert(#mdns.questions == 0 and mdns.answers[1].class == 0x8001)
        \\local many = dns.decode(dns.encode({ opcode = 5, questions = {
        \\    { name = "a.local", type = t.A, class = 0x8001 }, { name = "b.local", type = t.AAAA } } }))
        \\assert(many.opcode == 5 and #many.questions == 2 and many.questions[1].class == 0x8001)
        \\assert(not pcall(dns.decode, "\0\0"))
        \\assert(not pcall(dns.encode, { questions = { { name = "x" } } }))
        \\assert(not pcall(dns.encode, { answers = { { name = "x", type = t.A, addr = "not an address" } } }))
    );
}
