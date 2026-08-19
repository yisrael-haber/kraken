const std = @import("std");
const packet = @import("packet.zig");

const c = @import("c");

pub const transport_heap_size = 256 * 1024;
pub const global_heap_size = 512 * 1024;
pub const max_transport_instructions = 100_000;

/// Lua allocations never leave this fixed backing store. Freed allocations are
/// intentionally not recycled during one VM lifetime; closing and resetting a
/// VM returns the complete reservation before the next activation.
pub fn FixedLuaHeap(comptime size: usize) type {
    return struct {
        bytes: [size]u8 align(16) = [_]u8{0} ** size,
        used: usize = 0,
        exhausted: bool = false,

        pub fn reset(self: *@This()) void {
            self.used = 0;
            self.exhausted = false;
        }

        pub fn reallocate(self: *@This(), old: ?*anyopaque, old_size: usize, new_size: usize) ?*anyopaque {
            if (new_size == 0) return null;
            const start = std.mem.alignForward(usize, self.used, @alignOf(usize));
            if (start > self.bytes.len or new_size > self.bytes.len - start) {
                self.exhausted = true;
                return null;
            }
            const destination = self.bytes[start .. start + new_size];
            if (old) |old_pointer| {
                const source: [*]const u8 = @ptrCast(old_pointer);
                @memcpy(destination[0..@min(old_size, new_size)], source[0..@min(old_size, new_size)]);
            }
            self.used = start + new_size;
            return @ptrCast(destination.ptr);
        }
    };
}

pub const Transport = struct {
    heap: FixedLuaHeap(transport_heap_size) = .{},
    state: ?*c.lua_State = null,
    instruction_count: usize = 0,

    pub fn deinit(self: *Transport) void {
        if (self.state) |state| c.lua_close(state);
        self.state = null;
        self.heap.reset();
    }

    pub fn load(self: *Transport, source: []const u8, name: [*:0]const u8) Error!void {
        self.deinit();
        const state = c.lua_newstate(allocate, @ptrCast(self)) orelse return error.OutOfMemory;
        self.state = state;
        openLibraries(state);
        if (c.luaL_loadbufferx(state, source.ptr, source.len, name, null) != c.LUA_OK) {
            reportError(state, "Lua compilation error:");
            return error.LoadFailed;
        }
        if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
            reportError(state, "Lua runtime error:");
            return error.RuntimeFailed;
        }
    }

    /// Runs `transport(packet)` when the function exists. Lua can mutate only
    /// this call's packet through the deliberately small packet table.
    pub fn run(self: *Transport, value: *packet.Packet, options: *packet.SendOptions) Error!void {
        const state = self.state orelse return;
        _ = c.lua_getglobal(state, "transport");
        if (c.lua_type(state, -1) != c.LUA_TFUNCTION) {
            c.lua_pop(state, 1);
            return;
        }
        self.instruction_count = 0;
        active_transport = self;
        active_packet = value;
        active_options = options;
        defer {
            active_transport = null;
            active_packet = null;
            active_options = null;
        }
        c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
        defer c.lua_sethook(state, null, 0, 0);
        pushPacketTable(state);
        if (c.lua_pcallk(state, 1, 0, 0, 0, null) != c.LUA_OK) {
            reportError(state, "Lua runtime error:");
            return error.RuntimeFailed;
        }
    }
};

pub const Error = error{ OutOfMemory, LoadFailed, RuntimeFailed, InstructionBudgetExceeded };

threadlocal var active_transport: ?*Transport = null;
threadlocal var active_packet: ?*packet.Packet = null;
threadlocal var active_options: ?*packet.SendOptions = null;

fn allocate(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    const transport: *Transport = @ptrCast(@alignCast(user_data orelse return null));
    return transport.heap.reallocate(old, old_size, new_size);
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const transport = active_transport orelse return;
    transport.instruction_count += 1000;
    if (transport.instruction_count > max_transport_instructions) _ = c.luaL_error(state, "transport instruction budget exceeded");
}

fn pushPacketTable(state: ?*c.lua_State) void {
    c.lua_createtable(state, 0, 4);
    c.lua_pushcclosure(state, packetByte, 0);
    c.lua_setfield(state, -2, "byte");
    c.lua_pushcclosure(state, packetSetByte, 0);
    c.lua_setfield(state, -2, "set_byte");
    c.lua_pushcclosure(state, packetDrop, 0);
    c.lua_setfield(state, -2, "drop");
    c.lua_pushcclosure(state, packetRepair, 0);
    c.lua_setfield(state, -2, "set_repair");
}

fn packetByte(state: ?*c.lua_State) callconv(.c) c_int {
    const value = active_packet orelse return c.luaL_error(state, "packet unavailable");
    const index = luaIndex(state, 2) orelse return c.luaL_error(state, "invalid byte index");
    if (index >= value.len) return c.luaL_error(state, "byte index out of range");
    c.lua_pushinteger(state, value.bytes[index]);
    return 1;
}

fn packetSetByte(state: ?*c.lua_State) callconv(.c) c_int {
    const value = active_packet orelse return c.luaL_error(state, "packet unavailable");
    const index = luaIndex(state, 2) orelse return c.luaL_error(state, "invalid byte index");
    const byte = luaIndex(state, 3) orelse return c.luaL_error(state, "invalid byte value");
    if (index >= value.len or byte > 255) return c.luaL_error(state, "packet byte out of range");
    value.bytes[index] = @intCast(byte);
    value.parse();
    return 0;
}

fn packetDrop(state: ?*c.lua_State) callconv(.c) c_int {
    const value = active_packet orelse return c.luaL_error(state, "packet unavailable");
    value.dropped = true;
    return 0;
}

fn packetRepair(state: ?*c.lua_State) callconv(.c) c_int {
    const options = active_options orelse return c.luaL_error(state, "packet unavailable");
    var length: usize = 0;
    const raw = c.lua_tolstring(state, 2, &length) orelse return c.luaL_error(state, "repair must be a string");
    const value = raw[0..length];
    if (std.mem.eql(u8, value, "automatic")) options.repair = .automatic else if (std.mem.eql(u8, value, "manual")) options.repair = .manual else return c.luaL_error(state, "unknown repair mode");
    return 0;
}

fn luaIndex(state: ?*c.lua_State, index: c_int) ?usize {
    var is_number: c_int = 0;
    const value = c.lua_tointegerx(state, index, &is_number);
    if (is_number == 0 or value < 0) return null;
    return @intCast(value);
}

pub fn openLibraries(state: ?*c.lua_State) void {
    c.luaL_openlibs(state);
}

pub fn reportError(state: ?*c.lua_State, context: [*:0]const u8) void {
    c.kraken_log(context);
    const message = c.lua_tolstring(state, -1, null) orelse {
        c.kraken_log("Lua returned a non-string error value.");
        c.lua_pop(state, 1);
        return;
    };
    c.kraken_log(message);
    c.lua_pop(state, 1);
}

test "fixed Lua heap is bounded" {
    var heap: FixedLuaHeap(16) = .{};
    try std.testing.expect(heap.reallocate(null, 0, 8) != null);
    try std.testing.expect(heap.reallocate(null, 0, 32) == null);
    try std.testing.expect(heap.exhausted);
}

test "Lua runtime exposes the complete standard environment" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "local loaded_math = require('math'); assert(loaded_math == math); assert(io and os and package and debug)",
        "standard-environment-test",
    );
}

test "transport hook mutates its owned packet" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet) packet:set_byte(1, 123) end", "test");
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{ 1, 2, 3 });
    var options: packet.SendOptions = .{};
    try transport.run(&value, &options);
    try std.testing.expectEqual(@as(u8, 123), value.bytes[1]);
}

test "transport hook instruction budget aborts an infinite loop" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet) while true do end end", "test");
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{1});
    var options: packet.SendOptions = .{};
    try std.testing.expectError(error.RuntimeFailed, transport.run(&value, &options));
}
