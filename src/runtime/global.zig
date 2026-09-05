const std = @import("std");
const c = @import("c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const command = @import("../command.zig");
const log = @import("../log.zig");

pub const Runner = struct {
    helpers_root: []const u8,
    logger: *log.Logger,
    commands: ring.SpscRing(command.Command, limits.runtime_command_capacity) = .{},
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    heap: lua.FixedLuaHeap(lua.global_heap_size) = .{},
    instruction_count: usize = 0,

    pub fn run(self: *Runner, source: text.FixedText(limits.source_capacity)) bool {
        self.stop();
        self.cancelled.store(false, .release);
        self.thread = std.Thread.spawn(.{}, execute, .{ self, source }) catch return false;
        return true;
    }

    pub fn stop(self: *Runner) void {
        self.cancelled.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        while (self.commands.pop()) |_| {}
    }
};

fn execute(runner: *Runner, source: text.FixedText(limits.source_capacity)) void {
    defer runner.heap.reset();
    runner.instruction_count = 0;
    const state = c.lua_newstate(allocate, @ptrCast(runner)) orelse return;
    defer c.lua_close(state);
    c.luaL_openlibs(state);
    lua.installPrint(state, runner.logger);
    lua.appendModulePath(state, runner.helpers_root);
    _ = c.lua_pushcclosure(state, globalStart, 0);
    c.lua_setglobal(state, "start_identity");
    _ = c.lua_pushcclosure(state, globalStop, 0);
    c.lua_setglobal(state, "stop_identity");
    _ = c.lua_pushcclosure(state, globalSendRaw, 0);
    c.lua_setglobal(state, "send_raw");
    const script = source.value();
    if (c.luaL_loadbufferx(state, script.ptr, script.len, "global", null) != c.LUA_OK) {
        lua.reportError(runner.logger, state, "Lua compilation error:");
        return;
    }
    c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
    if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK and !runner.cancelled.load(.acquire)) {
        lua.reportError(runner.logger, state, "Lua runtime error:");
    }
}

fn allocate(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    const runner: *Runner = @ptrCast(@alignCast(user_data.?));
    return runner.heap.reallocate(old, old_size, new_size);
}

fn globalStart(state: ?*c.lua_State) callconv(.c) c_int {
    return queueCommand(state, .start);
}

fn globalStop(state: ?*c.lua_State) callconv(.c) c_int {
    return queueCommand(state, .stop);
}

fn globalSendRaw(state: ?*c.lua_State) callconv(.c) c_int {
    const runner = runnerFor(state);
    const name = commandName(state) orelse return c.luaL_error(state, "identity name is required");
    var length: usize = 0;
    const raw = c.lua_tolstring(state, 2, &length) orelse return c.luaL_error(state, "packet must be a string");
    var value: frame.Frame = .{};
    value.set(raw[0..length]) catch return c.luaL_error(state, "packet exceeds fixed capacity");
    if (!runner.commands.push(.{ .send_packet = .{ .name = name, .value = value } })) return c.luaL_error(state, "global command queue is full");
    return 0;
}

fn queueCommand(state: ?*c.lua_State, tag: std.meta.Tag(command.Command)) c_int {
    const runner = runnerFor(state);
    const name = commandName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!runner.commands.push(switch (tag) {
        .start => .{ .start = name },
        .stop => .{ .stop = name },
        else => unreachable,
    })) return c.luaL_error(state, "global command queue is full");
    return 0;
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const runner = runnerFor(state);
    if (runner.cancelled.load(.acquire)) _ = c.luaL_error(state, "global script cancelled");
    runner.instruction_count += 1000;
    if (runner.instruction_count > lua.max_instructions) _ = c.luaL_error(state, "global instruction budget exceeded");
}

fn runnerFor(state: ?*c.lua_State) *Runner {
    var context: ?*anyopaque = undefined;
    _ = c.lua_getallocf(state, &context);
    return @ptrCast(@alignCast(context.?));
}

fn commandName(state: ?*c.lua_State) ?text.FieldText {
    var length: usize = 0;
    const value = c.lua_tolstring(state, 1, &length) orelse return null;
    var name: text.FieldText = .{};
    name.set(value[0..length]) catch return null;
    return name;
}
