const std = @import("std");
const runtime = @import("runtime.zig");
const frame = @import("frame.zig");
const command = @import("../command.zig");
const io = @import("../io.zig");
const limits = @import("../limits.zig");
const log = @import("../log.zig");
const text = @import("../text.zig");
const c = @import("c");

const helpers_suffix = std.fs.path.sep_str ++ "scripts" ++ std.fs.path.sep_str ++ "helpers" ++ std.fs.path.sep_str ++ "?.lua";
const print_capacity = 8 * 1024;

/// A global script runs once, in a large arena with no instruction budget. A transport VM
/// runs once per frame in a small arena under a budget, building a fresh state after each run.
pub const Role = enum { global, transport };

/// What a transport script is called with.
pub const TransportArguments = struct { bytes: []const u8, direction: command.Direction };

/// Script runs on one thread. `spawn` builds a state ahead of time, then `run` hands it
/// a script.
/// The Lua extra space points back here, so every Kraken function reaches the VM without upvalues.
pub const VM = struct {
    manager: *runtime.Manager = undefined,
    role: Role = .global,
    instructions: usize = 0,
    work: std.Io.Event = .unset,
    cancelled: std.Io.Event = .unset,
    done: std.Io.Event = .unset,
    name: text.FieldText = .{},
    source: []const u8 = &.{},
    packet: frame.Frame = .{},
    direction: ?command.Direction = null,
    thread: ?std.Thread = null,

    /// Allocates the arena and starts the thread, which builds the state and waits for `run`.
    pub fn spawn(self: *VM, manager: *runtime.Manager, role: Role) std.Thread.SpawnError!void {
        std.debug.assert(!self.running());
        self.join();
        const arena_size: usize = if (role == .global) limits.global_lua_heap_capacity else limits.transport_lua_heap_capacity;
        const arena = try manager.allocator.alignedAlloc(u8, .@"16", arena_size);
        errdefer manager.allocator.free(arena);
        self.manager = manager;
        self.role = role;
        self.work.reset();
        self.cancelled.reset();
        self.done.reset();
        self.thread = try std.Thread.spawn(.{ .stack_size = limits.lua_thread_stack_size }, main, .{ self, arena });
    }

    /// Copies the script, name, and callback bytes before waking the VM.
    /// A global script has no callback arguments.
    pub fn run(self: *VM, name: []const u8, source: []const u8, arguments: ?TransportArguments) error{ CapacityExceeded, OutOfMemory }!void {
        std.debug.assert(self.running() and !self.work.isSet());
        try self.name.set(name);
        if (arguments) |call| try self.packet.set(call.bytes);
        self.source = try self.manager.allocator.dupe(u8, source);
        self.instructions = 0;
        self.direction = if (arguments) |call| call.direction else null;
        self.work.set(io.get());
    }

    /// Running covers both waiting for work and executing it.
    pub fn running(self: *const VM) bool {
        return self.thread != null and !self.done.isSet();
    }

    /// Ready for `run`: alive and not yet handed work.
    pub fn available(self: *const VM) bool {
        return self.running() and !self.work.isSet();
    }

    pub fn cancel(self: *VM) void {
        if (!self.running()) return;
        self.cancelled.set(io.get());
        self.work.set(io.get());
        self.manager.wake.signal();
    }

    pub fn join(self: *VM) void {
        const thread = self.thread orelse return;
        thread.join();
        self.thread = null;
    }

    fn main(self: *VM, arena: []align(16) u8) void {
        const allocator = self.manager.allocator;
        defer self.done.set(io.get());
        defer allocator.free(arena);
        while (true) {
            const state = c.lua_newstate(allocate, c.tlsf_create_with_pool(arena.ptr, arena.len)).?;
            install(state, self);
            self.work.waitUncancelable(io.get());
            if (!self.cancelled.isSet() and c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) reportError(state);
            c.lua_close(state);
            allocator.free(self.source);
            self.source = &.{};
            if (self.role == .global or self.cancelled.isSet()) return;
            self.work.reset();
            // A cancel that raced the reset must still wake the next wait.
            if (self.cancelled.isSet()) self.work.set(io.get());
            // Wake the manager so it can trim spares even when no further frame arrives.
            self.manager.wake.signal();
        }
    }

    /// TLSF allocation from the arena, so collected memory is reused within the run.
    fn allocate(pool: ?*anyopaque, old: ?*anyopaque, _: usize, new_size: usize) callconv(.c) ?*anyopaque {
        if (new_size == 0) {
            c.tlsf_free(pool, old);
            return null;
        }
        // Lua requires shrinking to succeed; TLSF always shrinks in place.
        return c.tlsf_realloc(pool, old, new_size);
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
    _ = c.lua_getfield(state, -1, "preload");
    inline for (.{
        .{ "kraken/packet", frame.packetModule },
        .{ "kraken/std", stdModule },
        .{ "kraken/globals", @import("globals.zig").module },
        .{ "kraken/identities", @import("identities.zig").module },
        .{ "kraken/transmit", transmitModule },
        .{ "kraken/socket", @import("socket.zig").module },
        .{ "protocols/http", @import("../protocols/http.zig").module },
        .{ "protocols/dns", @import("../protocols/dns.zig").module },
        .{ "protocols/tls", @import("../protocols/tls.zig").module },
        .{ "protocols/ssh", @import("../protocols/ssh.zig").module },
        .{ "protocols/dcerpc", @import("../protocols/dcerpc.zig").module },
        .{ "protocols/smb", @import("../protocols/smb.zig").module },
        .{ "protocols/ldap", @import("../protocols/ldap.zig").module },
        .{ "protocols/tftp", @import("../protocols/tftp.zig").module },
        .{ "protocols/snmp", @import("../protocols/snmp.zig").module },
        .{ "protocols/telnet", @import("../protocols/telnet.zig").module },
        .{ "protocols/sip", @import("../protocols/sip.zig").module },
        .{ "protocols/smtp", @import("../protocols/smtp.zig").module },
        .{ "protocols/pop3", @import("../protocols/pop3.zig").module },
        .{ "protocols/imap", @import("../protocols/imap.zig").module },
    }) |module| setFunction(state, -2, module[0], module[1]);
    c.lua_pop(state, 2);
    c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
    c.lua_pushcclosure(state, execute, 0);
}

/// Runs inside one protected call, including callback lookup and argument allocation.
fn execute(state: ?*c.lua_State) callconv(.c) c_int {
    const value = vm(state);
    if (c.luaL_loadbufferx(state, value.source.ptr, value.source.len, "=script", null) != c.LUA_OK) return c.lua_error(state);
    c.lua_callk(state, 0, 0, 0, null);
    const direction = value.direction orelse return 0;
    if (c.lua_getglobal(state, "transport") != c.LUA_TFUNCTION) return c.luaL_error(state, "function transport is missing");
    pushBytes(state, value.packet.value());
    pushBytes(state, value.name.value());
    pushBytes(state, @tagName(direction));
    c.lua_callk(state, 3, 0, 0, null);
    return 0;
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const value = vm(state);
    if (value.cancelled.isSet()) _ = c.luaL_error(state, "script cancelled");
    if (value.role == .global) return;
    value.instructions += 1000;
    if (value.instructions > limits.transport_instruction_limit) _ = c.luaL_error(state, "instruction budget exceeded");
}

/// Raises a Lua error. luaL_error longjmps out of the calling C function.
pub fn raise(state: ?*c.lua_State, comptime format: [*:0]const u8, arguments: anytype) noreturn {
    _ = @call(.auto, c.luaL_error, .{ state, format } ++ arguments);
    unreachable;
}

pub fn setFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction) void {
    c.lua_pushcclosure(state, function, 0);
    c.lua_setfield(state, table, name);
}

/// Pushes a table of named C functions: `.{ .{ "name", function }, ... }`.
pub fn pushFunctions(state: ?*c.lua_State, comptime functions: anytype) void {
    c.lua_createtable(state, 0, functions.len);
    inline for (functions) |entry| setFunction(state, -2, entry[0], entry[1]);
}

/// Registers the userdata metatable `name` with `methods` as __index and `collect`
/// as __gc, locked so scripts cannot replace it.
pub fn defineClass(state: ?*c.lua_State, name: [*:0]const u8, comptime methods: anytype, collect: c.lua_CFunction) void {
    _ = c.luaL_newmetatable(state, name);
    pushFunctions(state, methods);
    c.lua_setfield(state, -2, "__index");
    setFunction(state, -2, "__gc", collect);
    _ = c.lua_pushstring(state, name);
    c.lua_setfield(state, -2, "__metatable");
    c.lua_pop(state, 1);
}

/// The `__gc` of a session class: releases the session without network I/O.
pub fn collector(comptime T: type, comptime metatable: [*:0]const u8) c.lua_CFunction {
    return struct {
        fn collect(state: ?*c.lua_State) callconv(.c) c_int {
            checkUserdata(state, 1, T, metatable).release();
            return 0;
        }
    }.collect;
}

/// A function returning the session at argument 1, raising `closed` once its `field` is null.
pub fn liveChecker(comptime T: type, comptime metatable: [*:0]const u8, comptime field_name: []const u8, comptime closed: [*:0]const u8) *const fn (?*c.lua_State) *T {
    return &struct {
        fn check(state: ?*c.lua_State) *T {
            const session = checkUserdata(state, 1, T, metatable);
            if (@field(session, field_name) == null) raise(state, closed, .{});
            return session;
        }
    }.check;
}

/// Owns the library memory of one call in a to-be-closed Lua stack slot.
/// Construction installs its close handler, which runs on return or error.
pub fn pushScratch(state: ?*c.lua_State, comptime T: type) *T {
    const scratch: *T = @ptrCast(@alignCast(c.lua_newuserdatauv(state, @sizeOf(T), 0).?));
    scratch.* = .{};
    if (c.luaL_newmetatable(state, T.metatable) != 0) setFunction(state, -2, "__close", T.close);
    _ = c.lua_setmetatable(state, -2);
    c.lua_toclose(state, -1);
    return scratch;
}

pub fn checkUserdata(state: ?*c.lua_State, index: c_int, comptime T: type, metatable: [*:0]const u8) *T {
    return @ptrCast(@alignCast(c.luaL_checkudata(state, index, metatable)));
}

pub fn checkBytes(state: ?*c.lua_State, index: c_int) []const u8 {
    c.luaL_checktype(state, index, c.LUA_TSTRING);
    return toBytes(state, index).?;
}

pub fn checkText(state: ?*c.lua_State, index: c_int) text.FieldText {
    var value: text.FieldText = .{};
    value.set(checkBytes(state, index)) catch raise(state, "text field exceeds capacity", .{});
    return value;
}

/// Lua strings have a trailing zero, including binary strings with embedded zeros.
pub fn toBytes(state: ?*c.lua_State, index: c_int) ?[:0]const u8 {
    var length: usize = 0;
    const bytes = c.lua_tolstring(state, index, &length) orelse return null;
    return bytes[0..length :0];
}

/// The string at `index`, for table fields; raises "`name` must be a string".
pub fn stringAt(state: ?*c.lua_State, index: c_int, name: [*:0]const u8) [:0]const u8 {
    if (c.lua_type(state, index) != c.LUA_TSTRING) raise(state, "%s must be a string", .{name});
    return toBytes(state, index).?;
}

/// Pushes `table[name]` and returns true when it is set; returns false, leaving
/// the stack unchanged, when it is nil. Raises when it is set to another type.
pub fn field(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, kind: c_int) bool {
    c.luaL_checkstack(state, 1, "too many values");
    const actual = c.lua_getfield(state, table, name);
    if (actual == kind) return true;
    c.lua_pop(state, 1);
    if (actual == c.LUA_TNIL) return false;
    raise(state, "%s must be a %s", .{ name, c.lua_typename(state, kind) });
}

/// Pushes `table[name]` and returns its stack index, or null when it is nil.
pub fn tableField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) ?c_int {
    return if (field(state, table, name, c.LUA_TTABLE)) c.lua_gettop(state) else null;
}

/// `table[name]` as a string, or null when nil. It stays valid while the table holds it.
pub fn optionalString(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) ?[:0]const u8 {
    if (!field(state, table, name, c.LUA_TSTRING)) return null;
    defer c.lua_pop(state, 1);
    return toBytes(state, -1).?;
}

pub fn requiredString(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) [:0]const u8 {
    return optionalString(state, table, name) orelse raise(state, "%s is required", .{name});
}

/// `table[name]` as a boolean; false when nil.
pub fn optionalBoolean(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) bool {
    if (!field(state, table, name, c.LUA_TBOOLEAN)) return false;
    defer c.lua_pop(state, 1);
    return c.lua_toboolean(state, -1) != 0;
}

/// Appends bytes to a native Lua buffer, which must stay at a stable address.
/// Keep its stack placeholder on top between calls (except luaL_addvalue).
pub fn addBytes(buffer: *c.luaL_Buffer, bytes: []const u8) void {
    c.luaL_addlstring(buffer, bytes.ptr, bytes.len);
}

/// Adds `name: value\r\n` for each `{ name, value }` pair of the list at stack index
/// `list`, which must lie below the buffer's placeholder.
pub fn addHeaders(buffer: *c.luaL_Buffer, list: c_int) void {
    const state = buffer.L;
    var index: c.lua_Integer = 1;
    while (index <= c.lua_rawlen(state, list)) : (index += 1) {
        if (c.lua_rawgeti(state, list, index) != c.LUA_TTABLE) raise(state, "header %d must be a { name, value } pair", .{@as(c_int, @intCast(index))});
        const name = headerPart(state, 1, index);
        const value = headerPart(state, 2, index);
        c.lua_pop(state, 1);
        for ([_][]const u8{ name, ": ", value, "\r\n" }) |part| addBytes(buffer, part);
    }
}

/// Part 1 (name) or 2 (value) of the header pair on the stack top.
fn headerPart(state: ?*c.lua_State, part: c.lua_Integer, index: c.lua_Integer) []const u8 {
    defer c.lua_pop(state, 1);
    if (c.lua_rawgeti(state, -1, part) != c.LUA_TSTRING) raise(state, "header %d must be a { name, value } pair of strings", .{@as(c_int, @intCast(index))});
    return toBytes(state, -1).?;
}

/// Pops the value on the stack top and appends it to the array below it.
pub fn append(state: ?*c.lua_State) void {
    c.lua_rawseti(state, -2, @intCast(c.lua_rawlen(state, -2) + 1));
}

/// The whole number at `index`, from 0 to `maximum`; raises naming `field` otherwise.
pub fn integerAt(state: ?*c.lua_State, index: c_int, field_name: [*:0]const u8, maximum: i64) i64 {
    var valid: c_int = 0;
    const value = c.lua_tointegerx(state, index, &valid);
    if (valid == 0 or value < 0 or value > maximum) raise(state, "%s must be an integer from 0 to %I", .{ field_name, @as(c.lua_Integer, maximum) });
    return value;
}

pub fn pushBytes(state: ?*c.lua_State, bytes: []const u8) void {
    _ = c.lua_pushlstring(state, bytes.ptr, bytes.len);
}

/// Sets `name` on the table at the stack top.
pub fn setString(state: ?*c.lua_State, name: [*:0]const u8, bytes: []const u8) void {
    pushBytes(state, bytes);
    c.lua_setfield(state, -2, name);
}

/// Sets `name` on the table at the stack top.
pub fn setInteger(state: ?*c.lua_State, name: [*:0]const u8, value: anytype) void {
    c.lua_pushinteger(state, @intCast(value));
    c.lua_setfield(state, -2, name);
}

/// Test helper: a bare state with the standard libraries and `module` loaded as `name`.
pub fn testState(name: [*:0]const u8, module: c.lua_CFunction) *c.lua_State {
    const state = c.luaL_newstate().?;
    c.luaL_openlibs(state);
    c.luaL_requiref(state, name, module, 0);
    c.lua_pop(state, 1);
    return state;
}

/// Test helper: runs `script`, printing its Lua error on failure.
pub fn expectScript(state: *c.lua_State, script: [*:0]const u8) !void {
    if (c.luaL_loadstring(state, script) == c.LUA_OK and c.lua_pcallk(state, 0, 0, 0, 0, null) == c.LUA_OK) return;
    std.debug.print("{s}\n", .{toBytes(state, -1) orelse "unknown error"});
    return error.TestUnexpectedResult;
}

/// Runs a host command, raising its error name as a Lua error.
pub fn executeCommand(state: ?*c.lua_State, request: command.Command) c_int {
    vm(state).manager.execute(&request) catch |err| return c.luaL_error(state, "%s", @errorName(err).ptr);
    return 0;
}

fn sleepLua(state: ?*c.lua_State) callconv(.c) c_int {
    const cancelled = &vm(state).cancelled;
    const milliseconds = c.luaL_checkinteger(state, 1);
    if (milliseconds < 0) return c.luaL_argerror(state, 1, "sleep duration must be non-negative");
    const deadline = std.Io.Clock.Timestamp.fromNow(io.get(), .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    while (!cancelled.isSet()) {
        if (io.now().nanoseconds >= deadline.raw.nanoseconds) return 0;
        cancelled.waitTimeout(io.get(), .{ .deadline = deadline }) catch {};
    }
    return c.luaL_error(state, "script cancelled");
}

fn stdModule(state: ?*c.lua_State) callconv(.c) c_int {
    pushFunctions(state, .{.{ "sleep", sleepLua }});
    return 1;
}

fn transmitModule(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_pushcclosure(state, transmitLua, 0);
    return 1;
}

fn transmitLua(state: ?*c.lua_State) callconv(.c) c_int {
    const name = checkText(state, 1);
    const bytes = checkBytes(state, 2);
    const direction = std.meta.stringToEnum(command.Direction, checkBytes(state, 3)) orelse return c.luaL_argerror(state, 3, "direction must be inbound or outbound");
    return executeCommand(state, .{ .transmit = .{ .name = name, .bytes = bytes, .direction = direction } });
}

fn reportError(state: ?*c.lua_State) void {
    if (vm(state).cancelled.isSet()) return log.logger.formatted(.info, .lua, "{s} \"{s}\": stopped.", .{ @tagName(vm(state).role), vm(state).name.value() });
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    const message = if (c.lua_type(state, -1) == c.LUA_TSTRING) toBytes(state, -1).? else "Lua returned a non-string error value";
    output.print("{s} \"{s}\": failed: {s}", .{ @tagName(vm(state).role), vm(state).name.value(), message }) catch {};
    log.logger.err(.lua, output.buffered());
}

fn luaPrint(state: ?*c.lua_State) callconv(.c) c_int {
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s} \"{s}\": ", .{ @tagName(vm(state).role), vm(state).name.value() }) catch {};
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
