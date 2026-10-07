const c = @import("c");
const std = @import("std");
const lua = @import("../runtime/lua.zig");

// TFTP (RFC 1350, with the option extension of RFC 2347) is five small packet
// types over UDP. This module only turns packets into bytes and back, like
// protocols/dns; the sockets and the lock-step transfer are the script's. A
// packet is a table, and nothing in it is limited beyond what fits the wire.

const op_names = [_][:0]const u8{ "", "rrq", "wrq", "data", "ack", "error", "oack" };

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.pushFunctions(state, .{ .{ "encode", encodeLua }, .{ "decode", decodeLua } });
    c.lua_createtable(state, 0, op_names.len);
    for (op_names[1..], 1..) |name, value| lua.setInteger(state, name, value);
    c.lua_setfield(state, -2, "ops");
    return 1;
}

// Encoding. The packet table is at index 1.

/// The packet being built. It runs twice over the same packet: first measuring, which
/// is where a bad field raises, then filling memory that Lua owns, so an error never
/// leaks and the second pass cannot fail.
const Out = struct {
    bytes: [*]u8 = undefined,
    len: usize = 0,
    measuring: bool = true,

    fn add(self: *Out, data: []const u8) void {
        if (!self.measuring) @memcpy(self.bytes[self.len..][0..data.len], data);
        self.len += data.len;
    }

    fn number(self: *Out, value: u16) void {
        self.add(&.{ @intCast(value >> 8), @intCast(value & 0xff) });
    }

    fn string(self: *Out, data: []const u8) void {
        self.add(data);
        self.add(&.{0});
    }
};

/// `tftp.encode(packet)`: the packet's bytes. `op` is a name or a number, and the fields
/// are those of `decode`. `payload`, when present, is the whole body after the opcode.
fn encodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    c.lua_settop(state, 1);
    var out: Out = .{};
    write(state, &out);
    out = .{ .bytes = @ptrCast(c.lua_newuserdatauv(state, @max(out.len, 1), 0)), .measuring = false };
    write(state, &out);
    lua.pushBytes(state, out.bytes[0..out.len]);
    return 1;
}

fn write(state: ?*c.lua_State, out: *Out) void {
    const op = opcode(state);
    out.number(op);
    if (lua.optionalString(state, 1, "payload")) |payload| {
        out.add(payload);
    } else switch (op) {
        1, 2 => {
            out.string(lua.requiredString(state, 1, "filename"));
            out.string(lua.optionalString(state, 1, "mode") orelse "octet");
            writeOptions(state, out);
        },
        3 => {
            out.number(number(state, "block"));
            out.add(lua.optionalString(state, 1, "data") orelse "");
        },
        4 => out.number(number(state, "block")),
        5 => {
            out.number(number(state, "code"));
            out.string(lua.optionalString(state, 1, "message") orelse "");
        },
        6 => writeOptions(state, out),
        else => {},
    }
}

fn opcode(state: ?*c.lua_State) u16 {
    if (c.lua_getfield(state, 1, "op") == c.LUA_TNUMBER) {
        defer c.lua_pop(state, 1);
        return @intCast(lua.integerAt(state, -1, "op", 0xffff));
    }
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TSTRING) lua.raise(state, "op must be a name or a number", .{});
    const name = lua.stringAt(state, -1, "op");
    for (op_names[1..], 1..) |known, value| if (std.mem.eql(u8, known, name)) return @intCast(value);
    lua.raise(state, "op must be rrq, wrq, data, ack, error, oack or a number", .{});
}

fn number(state: ?*c.lua_State, name: [*:0]const u8) u16 {
    if (!lua.field(state, 1, name, c.LUA_TNUMBER)) lua.raise(state, "%s is required", .{name});
    defer c.lua_pop(state, 1);
    return @intCast(lua.integerAt(state, -1, name, 0xffff));
}

/// Writes `name NUL value NUL` for each option: from a table of names to values, or an
/// array of `{ name, value }` pairs, which keeps their order and any repeats.
fn writeOptions(state: ?*c.lua_State, out: *Out) void {
    const table = lua.tableField(state, 1, "options") orelse return;
    defer c.lua_pop(state, 1);
    const pairs: usize = @intCast(c.lua_rawlen(state, table));
    if (pairs > 0) {
        for (1..pairs + 1) |index| {
            _ = c.lua_rawgeti(state, table, @intCast(index));
            if (c.lua_type(state, -1) != c.LUA_TTABLE) lua.raise(state, "each option must be a { name, value } pair", .{});
            _ = c.lua_rawgeti(state, -1, 1);
            _ = c.lua_rawgeti(state, -2, 2);
            writeOption(state, out);
            c.lua_pop(state, 1);
        }
    } else {
        c.lua_pushnil(state);
        while (c.lua_next(state, table) != 0) {
            c.lua_pushvalue(state, -2);
            c.lua_insert(state, -2);
            writeOption(state, out);
        }
    }
}

/// Writes the name and value on the stack top (name below value) and pops both.
fn writeOption(state: ?*c.lua_State, out: *Out) void {
    if (c.lua_type(state, -2) != c.LUA_TSTRING) lua.raise(state, "option names must be strings", .{});
    var name_length: usize = 0;
    var value_length: usize = 0;
    const name = c.lua_tolstring(state, -2, &name_length);
    const value = c.lua_tolstring(state, -1, &value_length) orelse lua.raise(state, "option values must be strings or numbers", .{});
    out.string(name[0..name_length]);
    out.string(value[0..value_length]);
    c.lua_pop(state, 2);
}

// Decoding.

/// `tftp.decode(bytes)`: `{ op = "rrq" | "wrq", filename, mode, options }`,
/// `{ op = "data", block, data }`, `{ op = "ack", block }`, `{ op = "error", code, message }`
/// or `{ op = "oack", options }`, where `options` maps names to strings. A packet with an
/// unknown opcode, or a body that does not parse, is `{ op = name or number, payload }`.
fn decodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    if (bytes.len < 2) lua.raise(state, "a TFTP packet needs at least 2 bytes", .{});
    const op = std.mem.readInt(u16, bytes[0..2], .big);
    const body = bytes[2..];
    c.lua_createtable(state, 0, 4);
    if (op < 1 or op >= op_names.len) {
        lua.setInteger(state, "op", op);
        lua.setString(state, "payload", body);
        return 1;
    }
    lua.setString(state, "op", op_names[op]);
    const parsed = switch (op) {
        1, 2 => request(state, body),
        3 => body.len >= 2 and block(state, body),
        4 => body.len == 2 and block(state, body),
        5 => failure(state, body),
        6 => options(state, body),
        else => unreachable,
    };
    if (op == 3 and parsed) lua.setString(state, "data", body[2..]);
    if (!parsed) {
        // Only what was asked for: the opcode and the body, unparsed.
        c.lua_settop(state, 1);
        c.lua_createtable(state, 0, 2);
        lua.setString(state, "op", op_names[op]);
        lua.setString(state, "payload", body);
    }
    return 1;
}

fn block(state: ?*c.lua_State, body: []const u8) bool {
    lua.setInteger(state, "block", std.mem.readInt(u16, body[0..2], .big));
    return true;
}

fn failure(state: ?*c.lua_State, body: []const u8) bool {
    if (body.len < 2) return false;
    lua.setInteger(state, "code", std.mem.readInt(u16, body[0..2], .big));
    const text = body[2..];
    lua.setString(state, "message", text[0 .. std.mem.indexOfScalar(u8, text, 0) orelse text.len]);
    return true;
}

/// A read or write request: filename, mode, then option pairs, each ending in NUL.
fn request(state: ?*c.lua_State, body: []const u8) bool {
    var rest = body;
    const filename = next(&rest) orelse return false;
    const mode = next(&rest) orelse return false;
    lua.setString(state, "filename", filename);
    lua.setString(state, "mode", mode);
    return options(state, rest);
}

/// Pairs of NUL-terminated strings, set as `options`; false if one is unterminated or odd.
/// A failed parse leaves a half-built table on the stack for the caller to discard.
fn options(state: ?*c.lua_State, body: []const u8) bool {
    c.lua_createtable(state, 0, 4);
    var rest = body;
    while (rest.len > 0) {
        const name = next(&rest) orelse return false;
        const value = next(&rest) orelse return false;
        lua.setString(state, name.ptr, value);
    }
    c.lua_setfield(state, -2, "options");
    return true;
}

/// The NUL-terminated string at the start of `rest`, which moves past it; null when
/// there is no terminator.
fn next(rest: *[]const u8) ?[:0]const u8 {
    const end = std.mem.indexOfScalar(u8, rest.*, 0) orelse return null;
    const text: [:0]const u8 = rest.*[0..end :0];
    rest.* = rest.*[end + 1 ..];
    return text;
}

test "tftp encodes and decodes every packet type" {
    const state = lua.testState("protocols/tftp", module);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local tftp = require("protocols/tftp")
        \\assert(tftp.ops.rrq == 1 and tftp.ops.oack == 6)
        \\-- the wire bytes of each type
        \\assert(tftp.encode{ op = "rrq", filename = "boot.img" } == "\0\1boot.img\0octet\0")
        \\assert(tftp.encode{ op = "wrq", filename = "a", mode = "netascii", options = { { "blksize", 1024 }, { "tsize", "0" } } } == "\0\2a\0netascii\0blksize\0001024\0tsize\0000\0")
        \\assert(tftp.encode{ op = "data", block = 1, data = "abc" } == "\0\3\0\1abc")
        \\assert(tftp.encode{ op = "ack", block = 258 } == "\0\4\1\2")
        \\assert(tftp.encode{ op = "error", code = 1, message = "File not found" } == "\0\5\0\1File not found\0")
        \\assert(tftp.encode{ op = "oack", options = { blksize = 1024 } } == "\0\6blksize\0001024\0")
        \\-- anything the wire allows: other opcodes, raw bodies, odd sizes, repeated options
        \\assert(tftp.encode{ op = 9, payload = "xyz" } == "\0\9xyz")
        \\assert(tftp.encode{ op = "ack", payload = "" } == "\0\4")
        \\assert(#tftp.encode{ op = "data", block = 65535, data = string.rep("x", 70000) } == 70004)
        \\assert(tftp.encode{ op = "oack", options = { { "a", "1" }, { "a", "2" } } } == "\0\6a\0001\0a\0002\0")
        \\assert(tftp.encode{ op = "rrq", filename = "", mode = "" } == "\0\1\0\0")
        \\-- decoding
        \\local request = tftp.decode("\0\1boot.img\0octet\0blksize\0001024\0")
        \\assert(request.op == "rrq" and request.filename == "boot.img" and request.mode == "octet" and request.options.blksize == "1024")
        \\assert(tftp.decode("\0\1a\0octet\0").options.blksize == nil)
        \\local data = tftp.decode("\0\3\0\5")
        \\assert(data.op == "data" and data.block == 5 and data.data == "")
        \\assert(tftp.decode("\0\3\1\0" .. string.rep("z", 512)).data == string.rep("z", 512))
        \\assert(tftp.decode("\0\4\0\7").block == 7)
        \\local failure = tftp.decode("\0\5\0\2Access violation\0")
        \\assert(failure.op == "error" and failure.code == 2 and failure.message == "Access violation")
        \\assert(tftp.decode("\0\6tsize\0001500\0").options.tsize == "1500")
        \\-- what does not parse is returned as the opcode and the unparsed body
        \\local broken = tftp.decode("\0\1boot.img")
        \\assert(broken.op == "rrq" and broken.payload == "boot.img" and broken.filename == nil)
        \\assert(tftp.decode("\0\1a\0octet\0blksize").payload == "a\0octet\0blksize")
        \\assert(tftp.decode("\0\4\0").payload == "\0")
        \\assert(tftp.decode("\0\9xyz").op == 9 and tftp.decode("\0\9xyz").payload == "xyz")
        \\assert(tftp.decode("\0\0").op == 0)
        \\-- bad input raises
        \\assert(not pcall(tftp.decode, "\0"))
        \\assert(not pcall(tftp.encode, { op = "ack" }))
        \\assert(not pcall(tftp.encode, { op = "ack", block = 65536 }))
        \\assert(not pcall(tftp.encode, { op = "ack", block = 1.5 }))
        \\assert(not pcall(tftp.encode, { op = "rrq" }))
        \\assert(not pcall(tftp.encode, { op = "nope" }))
        \\assert(not pcall(tftp.encode, { op = 65536 }))
        \\assert(not pcall(tftp.encode, { op = "oack", options = { { "a" } } }))
        \\assert(not pcall(tftp.encode, { op = "oack", options = { a = {} } }))
    );
}
