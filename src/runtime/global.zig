const std = @import("std");
const c = @import("c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const log = @import("../log.zig");
const storage = @import("../storage/storage.zig");
const script_repository = @import("../storage/script_repository.zig");

pub const Runner = struct {
    helpers_root: []const u8,
    logger: *log.Logger,
    storage: *storage.Storage,
    storage_scratch: [limits.storage_scratch_capacity]u8 = undefined,
    display_name: text.FieldText = .{},
    commands: ring.SpscRing(command.Command, limits.runtime_command_capacity) = .{},
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    heap: lua.FixedLuaHeap(lua.global_heap_size) = .{},
    instruction_count: usize = 0,

    pub fn run(self: *Runner, name: text.FieldText, source: text.FixedText(limits.source_capacity)) bool {
        self.stop();
        self.display_name = name;
        self.cancelled.store(false, .release);
        self.thread = std.Thread.spawn(.{}, execute, .{ self, name, source }) catch return false;
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

fn execute(runner: *Runner, name: text.FieldText, source: text.FixedText(limits.source_capacity)) void {
    defer runner.heap.reset();
    runner.instruction_count = 0;
    var scope_buffer: [text.FieldText.capacity + 32]u8 = undefined;
    const scope = std.fmt.bufPrint(&scope_buffer, "Global script \"{s}\"", .{name.value()}) catch unreachable;
    runner.logger.formatted(.info, .global, "{s} started.", .{scope});
    const state = c.lua_newstate(allocate, @ptrCast(runner)) orelse {
        runner.logger.formatted(.err, .global, "{s} failed: Lua state allocation failed.", .{scope});
        return;
    };
    defer c.lua_close(state);
    c.luaL_openlibs(state);
    lua.installPrint(state, runner.logger, scope);
    lua.appendModulePath(state, runner.helpers_root);
    _ = c.lua_pushcclosure(state, globalStart, 0);
    c.lua_setglobal(state, "start_identity");
    _ = c.lua_pushcclosure(state, globalStop, 0);
    c.lua_setglobal(state, "stop_identity");
    _ = c.lua_pushcclosure(state, globalSendRaw, 0);
    c.lua_setglobal(state, "send_raw");
    _ = c.lua_pushcclosure(state, globalCreateIdentity, 0);
    c.lua_setglobal(state, "create_identity");
    _ = c.lua_pushcclosure(state, globalDeleteIdentity, 0);
    c.lua_setglobal(state, "delete_identity");
    _ = c.lua_pushcclosure(state, globalSetIdentityTransport, 0);
    c.lua_setglobal(state, "set_identity_transport");
    const script = source.value();
    if (c.luaL_loadbufferx(state, script.ptr, script.len, "global", null) != c.LUA_OK) {
        lua.reportError(runner.logger, state, scope, "compilation failed");
        return;
    }
    c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
    if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
        if (runner.cancelled.load(.acquire))
            runner.logger.formatted(.info, .global, "{s} stopped.", .{scope})
        else
            lua.reportError(runner.logger, state, scope, "runtime failed");
        return;
    }
    runner.logger.formatted(.info, .global, "{s} completed.", .{scope});
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

fn globalCreateIdentity(state: ?*c.lua_State) callconv(.c) c_int {
    const runner = runnerFor(state);
    const value = identityFromLua(state) orelse return c.luaL_error(state, "identity configuration requires a name and text fields");
    if (!runner.commands.push(.{ .save = value })) return c.luaL_error(state, "global command queue is full");
    return 0;
}

fn globalDeleteIdentity(state: ?*c.lua_State) callconv(.c) c_int {
    const runner = runnerFor(state);
    const name = commandName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!runner.commands.push(.{ .delete = name })) return c.luaL_error(state, "global command queue is full");
    return 0;
}

fn globalSetIdentityTransport(state: ?*c.lua_State) callconv(.c) c_int {
    const runner = runnerFor(state);
    const name = commandName(state) orelse return c.luaL_error(state, "identity name is required");
    const script = if (c.lua_type(state, 2) == c.LUA_TNIL)
        null
    else blk: {
        var script_name: text.FieldText = .{};
        if (!luaText(state, 2, &script_name)) return c.luaL_error(state, "transport script name is required");
        var source: text.FixedText(limits.source_capacity) = .{};
        const scripts: script_repository.Store = .{
            .scratch = &runner.storage_scratch,
            .config_dir = runner.storage.config_dir,
            .kind = .transport,
        };
        scripts.read(script_name.value(), &source) catch return c.luaL_error(state, "transport script is unavailable");
        break :blk command.Transport{ .name = script_name, .source = source };
    };
    if (!runner.commands.push(.{ .set_transport = .{ .name = name, .script = script } })) return c.luaL_error(state, "global command queue is full");
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
    var name: text.FieldText = .{};
    return if (luaText(state, 1, &name)) name else null;
}

fn identityFromLua(state: ?*c.lua_State) ?identity.Identity {
    if (c.lua_type(state, 1) != c.LUA_TTABLE) return null;
    var value: identity.Identity = .{};
    if (!tableText(state, "name", &value.label, true) or
        !tableText(state, "ip", &value.ip, false) or
        !tableText(state, "prefix", &value.prefix, false) or
        !tableText(state, "interface", &value.interface, false) or
        !tableText(state, "gateway", &value.gateway, false) or
        !tableText(state, "mac", &value.mac, false) or
        !tableText(state, "mtu", &value.mtu, false)) return null;
    return value;
}

fn tableText(state: ?*c.lua_State, field: [*:0]const u8, destination: *text.FieldText, required: bool) bool {
    _ = c.lua_getfield(state, 1, field);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) == c.LUA_TNIL) return !required;
    return luaText(state, -1, destination);
}

fn luaText(state: ?*c.lua_State, index: c_int, destination: *text.FieldText) bool {
    var length: usize = 0;
    const value = c.lua_tolstring(state, index, &length) orelse return false;
    destination.set(value[0..length]) catch return false;
    return true;
}
