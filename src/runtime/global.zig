const std = @import("std");
const c = @import("c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const manager = @import("../identities/manager.zig");
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
    finished: std.Io.Event = .unset,
    sleep_cancelled: std.Io.Event = .unset,
    socket_count: usize = 0,

    pub fn run(self: *Runner, identities: *manager.Manager, name: text.FieldText, source: text.FixedText(limits.source_capacity)) bool {
        self.stop(identities);
        self.display_name = name;
        self.cancelled.store(false, .release);
        self.finished = .unset;
        self.sleep_cancelled.reset();
        self.thread = std.Thread.spawn(.{}, execute, .{ self, name, source }) catch return false;
        return true;
    }

    pub fn stop(self: *Runner, identities: *manager.Manager) void {
        self.cancelled.store(true, .release);
        self.sleep_cancelled.set(io());
        if (self.thread) |thread| {
            while (!self.finished.isSet()) {
                while (self.commands.pop()) |queued| if (queued == .socket) {
                    identities.execute(queued) catch unreachable;
                };
                self.finished.waitTimeout(io(), .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(1) } }) catch {};
            }
            thread.join();
            self.thread = null;
        }
        while (self.commands.pop()) |_| {}
    }

    pub fn isRunning(self: *const Runner) bool {
        return self.thread != null and !self.finished.isSet();
    }
};

fn execute(runner: *Runner, name: text.FieldText, source: text.FixedText(limits.source_capacity)) void {
    defer runner.finished.set(io());
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
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "preload");
    setFunction(state, -2, "kraken/socket", socketModule);
    c.lua_pop(state, 2);
    _ = c.lua_rawgeti(state, c.LUA_REGISTRYINDEX, c.LUA_RIDX_GLOBALS);
    setFunction(state, -2, "start_identity", globalStart);
    setFunction(state, -2, "stop_identity", globalStop);
    setFunction(state, -2, "send_raw", globalSendRaw);
    setFunction(state, -2, "create_identity", globalCreateIdentity);
    setFunction(state, -2, "delete_identity", globalDeleteIdentity);
    setFunction(state, -2, "set_identity_transport", globalSetIdentityTransport);
    c.lua_pop(state, 1);
    c.lua_createtable(state, 0, 1);
    setFunction(state, -2, "sleep", globalSleep);
    c.lua_setglobal(state, "kraken");
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

fn globalSleep(state: ?*c.lua_State) callconv(.c) c_int {
    const runner = runnerFor(state);
    const milliseconds = c.luaL_checkinteger(state, 1);
    if (milliseconds < 0) return c.luaL_argerror(state, 1, "sleep duration must be non-negative");
    const deadline = std.Io.Clock.Timestamp.fromNow(io(), .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    while (!runner.sleep_cancelled.isSet()) {
        if (std.Io.Clock.awake.now(io()).nanoseconds >= deadline.raw.nanoseconds) return 0;
        runner.sleep_cancelled.waitTimeout(io(), .{ .deadline = deadline }) catch {};
    }
    return c.luaL_error(state, "global script cancelled");
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

const socket_metatable = "kraken.socket";

fn socketModule(state: ?*c.lua_State) callconv(.c) c_int {
    _ = c.luaL_newmetatable(state, socket_metatable);
    c.lua_createtable(state, 0, 5);
    setFunction(state, -2, "send", socketSend);
    setFunction(state, -2, "receive", socketReceive);
    setFunction(state, -2, "close", socketClose);
    setFunction(state, -2, "listen", socketListen);
    setFunction(state, -2, "accept", socketAccept);
    c.lua_setfield(state, -2, "__index");
    setFunction(state, -2, "__gc", socketClose);
    _ = c.lua_pushstring(state, socket_metatable);
    c.lua_setfield(state, -2, "__metatable");
    c.lua_pop(state, 1);

    c.lua_createtable(state, 0, 2);
    inline for (.{ "tcp", "udp" }) |protocol| {
        c.lua_createtable(state, 0, 2);
        inline for (.{ command.SocketAction.connect, command.SocketAction.bind }) |action| {
            c.lua_pushboolean(state, @intFromBool(comptime std.mem.eql(u8, protocol, "tcp")));
            c.lua_pushinteger(state, @intFromEnum(action));
            c.lua_pushcclosure(state, socketOpen, 2);
            c.lua_setfield(state, -2, @tagName(action));
        }
        c.lua_setfield(state, -2, protocol);
    }
    return 1;
}

fn socketOpen(state: ?*c.lua_State) callconv(.c) c_int {
    const tcp = c.lua_toboolean(state, c.lua_upvalueindex(1)) != 0;
    const action: command.SocketAction = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(2), null));
    const identity_name = commandName(state) orelse return c.luaL_error(state, "identity name is required");
    var address = luaAddress(state, 2, 3) orelse return c.luaL_error(state, "IPv4 address and port are required");
    const timeout = if (tcp and action == .connect) luaTimeout(state, 4) else null;
    const value = newSocket(state);
    value.* = .{ .identity = identity_name, .tcp = tcp };
    _ = socketCall(state, action, value, &address, &.{}, timeout);
    return 1;
}

fn socketListen(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    var address: c.struct_wolfIP_sockaddr_in = .{};
    _ = socketCall(state, .listen, value, &address, &.{}, null);
    return 0;
}

fn socketAccept(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    const timeout = luaTimeout(state, 2);
    const peer = newSocket(state);
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const descriptor = socketCall(state, .accept, value, &address, &.{}, timeout);
    peer.* = value.*;
    peer.descriptor = descriptor;
    peer.handshaking = true;
    pushAddress(state, address);
    return 3;
}

fn socketSend(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    var length: usize = 0;
    const bytes = c.luaL_checklstring(state, 2, &length);
    var destination: c.struct_wolfIP_sockaddr_in = .{};
    var timeout_index: c_int = 3;
    if (!value.tcp and c.lua_type(state, 3) == c.LUA_TSTRING) {
        timeout_index = 5;
        destination = luaAddress(state, 3, 4) orelse return c.luaL_error(state, "UDP destination address and port are required");
    }
    const timeout = luaTimeout(state, timeout_index);
    _ = socketCall(state, .send, value, &destination, @constCast(bytes[0..length]), timeout);
    return 0;
}

fn socketReceive(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    const count = if (value.tcp) c.luaL_checkinteger(state, 2) else limits.socket_receive_capacity;
    if (count < 1 or count > limits.socket_receive_capacity) return c.luaL_error(state, "receive length must be between 1 and 32768");
    const timeout_index: c_int = if (value.tcp) 3 else 2;
    const timeout = luaTimeout(state, timeout_index);
    var received: [limits.socket_receive_capacity]u8 = undefined;
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const length = socketCall(state, .receive, value, &address, received[0..@intCast(count)], timeout);
    _ = c.lua_pushlstring(state, &received, @intCast(length));
    if (!value.tcp) {
        pushAddress(state, address);
        return 3;
    }
    return 1;
}

fn socketClose(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    if (value.descriptor < 0) return 0;
    var address: c.struct_wolfIP_sockaddr_in = .{};
    _ = socketCall(state, .close, value, &address, &.{}, null);
    return 0;
}

fn socketCall(state: ?*c.lua_State, action: command.SocketAction, value: *command.Socket, address: *c.struct_wolfIP_sockaddr_in, bytes: []u8, timeout: ?u64) c_int {
    const runner = runnerFor(state);
    var call: command.SocketCall = .{
        .cancelled = &runner.cancelled,
        .action = action,
        .socket = value,
        .address = address,
        .bytes = bytes,
        .deadline = if (timeout) |milliseconds| @as(u64, @intCast(std.Io.Clock.awake.now(io()).toMilliseconds())) + milliseconds else null,
    };
    while (!runner.commands.push(.{ .socket = &call })) std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    call.done.waitUncancelable(io());
    if (action == .close) {
        value.descriptor = -1;
        runner.socket_count -= 1;
    }
    if (call.result < 0) return c.luaL_error(state, if (call.result == -c.WOLFIP_EAGAIN) "socket call timed out" else "socket call failed");
    if (action == .connect or action == .bind or action == .accept) runner.socket_count += 1;
    return call.result;
}

fn newSocket(state: ?*c.lua_State) *command.Socket {
    if (runnerFor(state).socket_count == limits.global_socket_capacity) {
        _ = c.luaL_error(state, "global script socket limit reached");
        unreachable;
    }
    const raw = c.lua_newuserdatauv(state, @sizeOf(command.Socket), 0) orelse unreachable;
    const value: *command.Socket = @ptrCast(@alignCast(raw));
    value.descriptor = -1;
    _ = c.lua_getfield(state, c.LUA_REGISTRYINDEX, socket_metatable);
    _ = c.lua_setmetatable(state, -2);
    return value;
}

fn pushAddress(state: ?*c.lua_State, address: c.struct_wolfIP_sockaddr_in) void {
    const bytes: [4]u8 = @bitCast(address.sin_addr.s_addr);
    var buffer: [15]u8 = undefined;
    const output = std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch unreachable;
    _ = c.lua_pushlstring(state, output.ptr, output.len);
    c.lua_pushinteger(state, std.mem.bigToNative(u16, address.sin_port));
}

fn luaSocket(state: ?*c.lua_State) *command.Socket {
    const raw = c.luaL_checkudata(state, 1, socket_metatable);
    return @ptrCast(@alignCast(raw));
}

fn luaAddress(state: ?*c.lua_State, address_index: c_int, port_index: c_int) ?c.struct_wolfIP_sockaddr_in {
    var length: usize = 0;
    const value = c.lua_tolstring(state, address_index, &length) orelse return null;
    const port = c.luaL_checkinteger(state, port_index);
    if (port < 0 or port > 65535) return null;
    const address = std.Io.net.Ip4Address.parse(value[0..length], 0) catch return null;
    return .{ .sin_family = c.AF_INET, .sin_port = std.mem.nativeToBig(u16, @intCast(port)), .sin_addr = .{ .s_addr = @bitCast(address.bytes) } };
}

fn luaTimeout(state: ?*c.lua_State, index: c_int) ?u64 {
    if (c.lua_isnoneornil(state, index)) return null;
    const value = c.luaL_checkinteger(state, index);
    if (value < 0) {
        _ = c.luaL_argerror(state, index, "timeout must be non-negative");
        unreachable;
    }
    return @intCast(value);
}

fn setFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction) void {
    c.lua_pushcclosure(state, function, 0);
    c.lua_setfield(state, table, name);
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
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
