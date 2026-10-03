const c = @import("c");
const std = @import("std");
const yaml = @import("yaml");

// libyaml's event parser builds Lua values directly on the Lua stack: a mapping
// is a table by key, a sequence an array, and a plain scalar that is an integer
// (decimal or 0x hex) a Lua integer; every other scalar is a string, and an empty
// value is absent. Anchors and aliases are not used by libdcerpc and not supported.

const max_depth = 64;

const Frame = struct {
    mapping: bool,
    /// A mapping's next scalar is a key, with that key on the Lua stack when false;
    /// for a sequence, the next array index.
    expect_key: bool = true,
    index: c_int = 1,
};

pub const Failure = struct { message: [160:0]u8 = @splat(0) };

/// Pushes the document's root value, or returns false with `failure` set and the
/// Lua stack unchanged.
pub fn push(state: ?*c.lua_State, text: []const u8, failure: *Failure) bool {
    const base = c.lua_gettop(state);
    var parser: yaml.yaml_parser_t = undefined;
    if (yaml.yaml_parser_initialize(&parser) == 0) return fail(state, base, failure, "out of memory", 0);
    defer yaml.yaml_parser_delete(&parser);
    yaml.yaml_parser_set_input_string(&parser, text.ptr, text.len);

    var frames: [max_depth]Frame = undefined;
    var depth: usize = 0;
    var done = false;
    while (!done) {
        var event: yaml.yaml_event_t = undefined;
        if (yaml.yaml_parser_parse(&parser, &event) == 0) {
            return fail(state, base, failure, if (parser.problem) |problem| std.mem.span(problem) else "invalid YAML", parser.problem_mark.line + 1);
        }
        defer yaml.yaml_event_delete(&event);
        switch (event.type) {
            yaml.YAML_MAPPING_START_EVENT, yaml.YAML_SEQUENCE_START_EVENT => {
                if (depth == max_depth) return fail(state, base, failure, "nested too deeply", event.start_mark.line + 1);
                c.lua_createtable(state, 0, 0);
                frames[depth] = .{ .mapping = event.type == yaml.YAML_MAPPING_START_EVENT };
                depth += 1;
            },
            yaml.YAML_MAPPING_END_EVENT, yaml.YAML_SEQUENCE_END_EVENT => {
                depth -= 1;
                if (depth == 0) done = true else store(state, &frames[depth - 1]);
            },
            yaml.YAML_SCALAR_EVENT => {
                const value = event.data.scalar;
                const bytes = value.value[0..value.length];
                if (depth > 0 and frames[depth - 1].mapping and frames[depth - 1].expect_key) {
                    _ = c.lua_pushlstring(state, bytes.ptr, bytes.len);
                    frames[depth - 1].expect_key = false;
                } else {
                    const plain = value.style == yaml.YAML_PLAIN_SCALAR_STYLE;
                    if (plain and bytes.len == 0) {
                        c.lua_pushnil(state);
                    } else if (plain and integer(bytes) != null) {
                        c.lua_pushinteger(state, integer(bytes).?);
                    } else {
                        _ = c.lua_pushlstring(state, bytes.ptr, bytes.len);
                    }
                    if (depth == 0) done = true else store(state, &frames[depth - 1]);
                }
            },
            yaml.YAML_ALIAS_EVENT => return fail(state, base, failure, "aliases are not supported", event.start_mark.line + 1),
            yaml.YAML_STREAM_END_EVENT => done = true,
            else => {},
        }
    }
    if (c.lua_gettop(state) != base + 1) c.lua_pushnil(state);
    return true;
}

/// Moves the value on the stack top into the table below it (and its key, for a
/// mapping); a nil value leaves the key absent.
fn store(state: ?*c.lua_State, frame: *Frame) void {
    if (frame.mapping) {
        if (c.lua_isnil(state, -1)) c.lua_pop(state, 2) else c.lua_rawset(state, -3);
        frame.expect_key = true;
    } else {
        c.lua_rawseti(state, -2, frame.index);
        frame.index += 1;
    }
}

fn fail(state: ?*c.lua_State, base: c_int, failure: *Failure, problem: []const u8, line: usize) bool {
    c.lua_settop(state, base);
    _ = std.fmt.bufPrintZ(&failure.message, "{s} at line {d}", .{ problem, line }) catch {};
    return false;
}

fn integer(bytes: []const u8) ?i64 {
    if (bytes.len > 2 and bytes[0] == '0' and (bytes[1] == 'x' or bytes[1] == 'X')) {
        return @bitCast(std.fmt.parseUnsigned(u64, bytes[2..], 16) catch return null);
    }
    const digits = if (bytes.len > 1 and bytes[0] == '-') bytes[1..] else bytes;
    if (digits.len == 0 or (digits.len > 1 and digits[0] == '0')) return null;
    for (digits) |digit| if (digit < '0' or digit > '9') return null;
    return std.fmt.parseInt(i64, bytes, 10) catch null;
}

test "YAML becomes Lua tables" {
    const state = c.luaL_newstate().?;
    defer c.lua_close(state);
    c.luaL_openlibs(state);
    var failure: Failure = .{};
    const text =
        \\Lookup:
        \\  InquiryType: 0x00000000 # RPC_C_EP_ALL_ELTS
        \\  EntryHandle:
        \\    UUID: d32023da-b225-42f6-b13d-d45656179472
        \\  NumEnts: 2
        \\  Share: 05001300
        \\  Entries:
        \\    - Annotation: Ngc Pop Key Service
        \\      Tower:
        \\        TowerLength: 75
        \\    - Annotation: IPC$
        \\  Empty:
        \\  Neg: -7
        \\  Name: "42"
        \\  Status: 0
        \\
    ;
    if (!push(state, text, &failure)) std.debug.print("{s}\n", .{std.mem.sliceTo(&failure.message, 0)});
    try std.testing.expect(c.lua_gettop(state) == 1);
    c.lua_setglobal(state, "doc");
    if (c.luaL_loadstring(state,
        \\local r = doc.Lookup
        \\assert(r.InquiryType == 0 and r.NumEnts == 2 and r.Status == 0 and r.Neg == -7)
        \\assert(r.EntryHandle.UUID == "d32023da-b225-42f6-b13d-d45656179472")
        \\assert(r.Share == "05001300" and r.Name == "42" and r.Empty == nil)
        \\assert(#r.Entries == 2 and r.Entries[1].Tower.TowerLength == 75 and r.Entries[2].Annotation == "IPC$")
    ) != c.LUA_OK or c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
        std.debug.print("{s}\n", .{std.mem.span(c.lua_tolstring(state, -1, null))});
        return error.TestUnexpectedResult;
    }
}

test "invalid YAML reports the problem and leaves the stack unchanged" {
    const state = c.luaL_newstate().?;
    defer c.lua_close(state);
    var failure: Failure = .{};
    try std.testing.expect(!push(state, "a: b\n  c: [d\n", &failure));
    try std.testing.expectEqual(@as(c_int, 0), c.lua_gettop(state));
    try std.testing.expect(std.mem.indexOf(u8, &failure.message, "line") != null);
}
