const std = @import("std");
const frame = @import("frame.zig");
const limits = @import("../limits.zig");
const log = @import("../log.zig");
const c = @import("c");

const helpers_suffix = std.fs.path.sep_str ++ "scripts" ++ std.fs.path.sep_str ++ "helpers" ++ std.fs.path.sep_str ++ "?.lua";
const print_capacity = 8 * 1024;

pub fn FixedLuaHeap(comptime size: usize) type {
    return struct {
        bytes: [size]u8 align(16) = undefined,
        used: usize = 0,
        instructions: usize = 0,
        cancelled: std.Io.Event = .unset,

        pub fn begin(self: *@This()) void {
            self.used = 0;
            self.instructions = 0;
            self.cancelled.reset();
        }

        pub fn allocator(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
            const self: *@This() = @ptrCast(@alignCast(user_data.?));
            if (new_size == 0) return null;
            if (old) |pointer| {
                if (new_size <= old_size) return pointer;
                const replacement = self.allocate(new_size) orelse return null;
                const source: [*]const u8 = @ptrCast(pointer);
                const destination: [*]u8 = @ptrCast(replacement);
                @memcpy(destination[0..old_size], source[0..old_size]);
                return replacement;
            }
            return self.allocate(new_size);
        }

        fn allocate(self: *@This(), new_size: usize) ?*anyopaque {
            const start = std.mem.alignForward(usize, self.used, @alignOf(usize));
            if (start > self.bytes.len or new_size > self.bytes.len - start) return null;
            self.used = start + new_size;
            return @ptrCast(&self.bytes[start]);
        }

        pub fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
            var context: ?*anyopaque = null;
            _ = c.lua_getallocf(state, &context);
            const heap: *@This() = @ptrCast(@alignCast(context.?));
            if (heap.cancelled.isSet()) _ = c.luaL_error(state, "script cancelled");
            heap.instructions += 1000;
            if (heap.instructions > limits.lua_instruction_limit) _ = c.luaL_error(state, "instruction budget exceeded");
        }
    };
}

pub const TransportHeap = FixedLuaHeap(limits.transport_lua_heap_capacity);

pub fn initialize(state: ?*c.lua_State, scope: []const u8, config_dir: []const u8, cancelled: *std.Io.Event) void {
    c.luaL_openlibs(state);
    _ = c.lua_pushlstring(state, scope.ptr, scope.len);
    c.lua_pushcclosure(state, luaPrint, 1);
    c.lua_setglobal(state, "print");
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "path");
    _ = c.lua_pushstring(state, ";");
    _ = c.lua_pushlstring(state, config_dir.ptr, config_dir.len);
    _ = c.lua_pushlstring(state, helpers_suffix, helpers_suffix.len);
    c.lua_concat(state, 4);
    c.lua_setfield(state, -2, "path");
    _ = c.lua_getfield(state, -1, "preload");
    setFunction(state, -2, "kraken/packet", frame.packetModule);
    c.lua_pop(state, 2);
    c.lua_createtable(state, 0, 1);
    c.lua_pushlightuserdata(state, cancelled);
    c.lua_pushcclosure(state, sleepLua, 1);
    c.lua_setfield(state, -2, "sleep");
    c.lua_setglobal(state, "kraken");
}

pub fn preloadContext(state: ?*c.lua_State, name: [*:0]const u8, function: c.lua_CFunction, context: *anyopaque) void {
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "preload");
    c.lua_pushlightuserdata(state, context);
    c.lua_pushcclosure(state, function, 1);
    c.lua_setfield(state, -2, name);
    c.lua_pop(state, 2);
}

pub fn setFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction) void {
    c.lua_pushcclosure(state, function, 0);
    c.lua_setfield(state, table, name);
}

pub fn checkBytes(state: ?*c.lua_State, index: c_int) []const u8 {
    c.luaL_checktype(state, index, c.LUA_TSTRING);
    return toBytes(state, index).?;
}

pub fn toBytes(state: ?*c.lua_State, index: c_int) ?[]const u8 {
    var length: usize = 0;
    const bytes = c.lua_tolstring(state, index, &length) orelse return null;
    return bytes[0..length];
}

fn sleepLua(state: ?*c.lua_State) callconv(.c) c_int {
    const cancelled: *std.Io.Event = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    const milliseconds = c.luaL_checkinteger(state, 1);
    if (milliseconds < 0) return c.luaL_argerror(state, 1, "sleep duration must be non-negative");
    const io = std.Io.Threaded.global_single_threaded.io();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    while (!cancelled.isSet()) {
        if (std.Io.Clock.awake.now(io).nanoseconds >= deadline.raw.nanoseconds) return 0;
        cancelled.waitTimeout(io, .{ .deadline = deadline }) catch {};
    }
    return c.luaL_error(state, "script cancelled");
}

pub fn reportError(state: ?*c.lua_State, scope: []const u8, context: []const u8) void {
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: {s}: {s}", .{ scope, context, toBytes(state, -1) orelse "Lua returned a non-string error value" }) catch {};
    log.logger.err(.lua, output.buffered());
}

fn luaPrint(state: ?*c.lua_State) callconv(.c) c_int {
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: ", .{toBytes(state, c.lua_upvalueindex(1)).?}) catch {};
    const count = c.lua_gettop(state);
    var index: c_int = 1;
    while (index <= count) : (index += 1) {
        var value_len: usize = 0;
        const value = c.luaL_tolstring(state, index, &value_len).?;
        if (index > 1) output.writeByte('\t') catch {};
        output.writeAll(value[0..value_len]) catch {};
        c.lua_pop(state, 1);
    }
    log.logger.info(.lua, output.buffered());
    return 0;
}
