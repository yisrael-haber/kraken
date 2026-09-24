const std = @import("std");
const runtime = @import("runtime.zig");
const command = @import("../command.zig");
const frame = @import("frame.zig");
const globals = @import("globals.zig");
const identities = @import("identities.zig");
const socket = @import("socket.zig");
const limits = @import("../limits.zig");
const log = @import("../log.zig");
const text = @import("../text.zig");
const c = @import("c");

const helpers_suffix = std.fs.path.sep_str ++ "scripts" ++ std.fs.path.sep_str ++ "helpers" ++ std.fs.path.sep_str ++ "?.lua";
const print_capacity = 8 * 1024;
pub const scope_capacity = limits.field_capacity + 16;

pub const Entry = union(enum) {
    /// Run the chunk only.
    chunk,
    /// Run the chunk, then call a global function with pushed arguments.
    call: struct {
        name: [*:0]const u8,
        arguments: *const fn (?*c.lua_State, *anyopaque) c_int,
        data: *anyopaque,
    },
};

/// One script run on its own thread. The Lua extra space points back here,
/// so every Kraken function reaches the VM without upvalues.
pub const VM = struct {
    manager: *runtime.Manager = undefined,
    arena: []align(16) u8 = &.{},
    used: usize = 0,
    instructions: usize = 0,
    cancelled: std.Io.Event = .unset,
    done: std.Io.Event = .unset,
    scope: text.FixedText(scope_capacity) = .{},
    source: text.FixedText(limits.source_capacity) = .{},
    entry: Entry = .chunk,
    thread: ?std.Thread = null,

    /// Copies scope and source, then builds and runs the state on its own thread.
    pub fn start(self: *VM, manager: *runtime.Manager, arena: []align(16) u8, scope: []const u8, source: []const u8, entry: Entry) (error{CapacityExceeded} || std.Thread.SpawnError)!void {
        std.debug.assert(!self.running());
        self.join();
        try self.scope.set(scope);
        try self.source.set(source);
        self.manager = manager;
        self.arena = arena;
        self.used = 0;
        self.instructions = 0;
        self.entry = entry;
        self.cancelled.reset();
        self.done.reset();
        self.thread = try std.Thread.spawn(.{}, main, .{self});
    }

    pub fn running(self: *const VM) bool {
        return self.thread != null and !self.done.isSet();
    }

    pub fn cancel(self: *VM) void {
        if (!self.running()) return;
        self.cancelled.set(io());
        self.manager.wake.signal();
    }

    pub fn join(self: *VM) void {
        const thread = self.thread orelse return;
        thread.join();
        self.thread = null;
    }

    fn main(self: *VM) void {
        defer self.done.set(io());
        const state = c.lua_newstate(allocate, self) orelse {
            log.logger.formatted(.err, .lua, "{s}: Lua state allocation failed.", .{self.scope.value()});
            return;
        };
        defer c.lua_close(state);
        install(state, self);
        execute(state, self.source.value(), self.entry);
    }

    /// Bump allocation from the arena; freed memory returns when the run ends.
    fn allocate(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
        const self: *VM = @ptrCast(@alignCast(user_data.?));
        if (new_size == 0) return null;
        if (old != null and new_size <= old_size) return old;
        const start_index = std.mem.alignForward(usize, self.used, @alignOf(usize));
        if (start_index > self.arena.len or new_size > self.arena.len - start_index) return null;
        self.used = start_index + new_size;
        const replacement = self.arena[start_index..self.used];
        if (old) |pointer| @memcpy(replacement[0..old_size], @as([*]const u8, @ptrCast(pointer))[0..old_size]);
        return replacement.ptr;
    }
};

pub fn vm(state: ?*c.lua_State) *VM {
    const slot: **VM = @ptrCast(@alignCast(c.lua_getextraspace(state)));
    return slot.*;
}

/// Installs the standard libraries, Kraken modules, and budget hook.
fn install(state: ?*c.lua_State, value: *VM) void {
    const slot: **VM = @ptrCast(@alignCast(c.lua_getextraspace(state)));
    slot.* = value;
    const config_dir = value.manager.storage.config_dir;
    c.luaL_openlibs(state);
    c.lua_pushcclosure(state, luaPrint, 0);
    c.lua_setglobal(state, "print");
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "path");
    _ = c.lua_pushstring(state, ";");
    _ = c.lua_pushlstring(state, config_dir.ptr, config_dir.len);
    _ = c.lua_pushlstring(state, helpers_suffix, helpers_suffix.len);
    c.lua_concat(state, 4);
    c.lua_setfield(state, -2, "path");
    c.lua_pop(state, 1);
    preload(state, "kraken/packet", frame.packetModule);
    preload(state, "kraken/std", stdModule);
    preload(state, "kraken/globals", globals.module);
    preload(state, "kraken/identities", identities.module);
    preload(state, "kraken/transmit", transmitModule);
    preload(state, "kraken/socket", socket.module);
    c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
}

/// Loads and runs the source, then the entry. Logs failures.
fn execute(state: ?*c.lua_State, source: []const u8, entry: Entry) void {
    if (c.luaL_loadbufferx(state, source.ptr, source.len, "=script", null) != c.LUA_OK) return reportError(state, "compilation failed");
    if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) return fail(state);
    switch (entry) {
        .chunk => {},
        .call => |call| {
            if (c.lua_getglobal(state, call.name) != c.LUA_TFUNCTION) {
                return log.logger.formatted(.err, .lua, "{s}: function {s} is missing.", .{ vm(state).scope.value(), call.name });
            }
            const count = call.arguments(state, call.data);
            if (c.lua_pcallk(state, count, 0, 0, 0, null) != c.LUA_OK) return fail(state);
        },
    }
}

fn fail(state: ?*c.lua_State) void {
    if (vm(state).cancelled.isSet())
        log.logger.formatted(.info, .lua, "{s}: stopped.", .{vm(state).scope.value()})
    else
        reportError(state, "runtime failed");
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const value = vm(state);
    if (value.cancelled.isSet()) _ = c.luaL_error(state, "script cancelled");
    value.instructions += 1000;
    if (value.instructions > limits.lua_instruction_limit) _ = c.luaL_error(state, "instruction budget exceeded");
}

fn preload(state: ?*c.lua_State, name: [*:0]const u8, function: c.lua_CFunction) void {
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "preload");
    c.lua_pushcclosure(state, function, 0);
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

pub fn checkText(state: ?*c.lua_State, index: c_int) text.FieldText {
    var value: text.FieldText = .{};
    value.set(checkBytes(state, index)) catch {
        _ = c.luaL_error(state, "text field exceeds capacity");
        unreachable;
    };
    return value;
}

pub fn toBytes(state: ?*c.lua_State, index: c_int) ?[]const u8 {
    var length: usize = 0;
    const bytes = c.lua_tolstring(state, index, &length) orelse return null;
    return bytes[0..length];
}

/// Runs a host command, raising its error name as a Lua error.
pub fn executeCommand(state: ?*c.lua_State, request: command.Command) c_int {
    vm(state).manager.execute(request) catch |err| return c.luaL_error(state, "%s", @errorName(err).ptr);
    return 0;
}

fn sleepLua(state: ?*c.lua_State) callconv(.c) c_int {
    const cancelled = &vm(state).cancelled;
    const milliseconds = c.luaL_checkinteger(state, 1);
    if (milliseconds < 0) return c.luaL_argerror(state, 1, "sleep duration must be non-negative");
    const deadline = std.Io.Clock.Timestamp.fromNow(io(), .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    while (!cancelled.isSet()) {
        if (std.Io.Clock.awake.now(io()).nanoseconds >= deadline.raw.nanoseconds) return 0;
        cancelled.waitTimeout(io(), .{ .deadline = deadline }) catch {};
    }
    return c.luaL_error(state, "script cancelled");
}

fn stdModule(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_createtable(state, 0, 1);
    setFunction(state, -2, "sleep", sleepLua);
    return 1;
}

fn transmitModule(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_pushcclosure(state, transmitLua, 0);
    return 1;
}

fn transmitLua(state: ?*c.lua_State) callconv(.c) c_int {
    const name = checkText(state, 1);
    var value: frame.Frame = .{};
    value.set(checkBytes(state, 2)) catch return c.luaL_argerror(state, 2, "packet exceeds fixed capacity");
    const direction = std.meta.stringToEnum(frame.Direction, checkBytes(state, 3)) orelse return c.luaL_argerror(state, 3, "direction must be inbound or outbound");
    return executeCommand(state, .{ .transmit = .{ .name = name, .value = value, .direction = direction } });
}

fn reportError(state: ?*c.lua_State, stage: []const u8) void {
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: {s}: {s}", .{ vm(state).scope.value(), stage, toBytes(state, -1) orelse "Lua returned a non-string error value" }) catch {};
    log.logger.err(.lua, output.buffered());
}

fn luaPrint(state: ?*c.lua_State) callconv(.c) c_int {
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: ", .{vm(state).scope.value()}) catch {};
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

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
