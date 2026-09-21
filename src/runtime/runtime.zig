const std = @import("std");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const globals = @import("globals.zig");
const stack = @import("stack.zig");
const pcap = @import("../platform/pcap.zig");
const wait = @import("../platform/wait.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const storage_module = @import("../storage/storage.zig");
const log = @import("../log.zig");
const c = @import("c");

const transport_vm_slots = 10;
const GlobalHeap = lua.FixedLuaHeap(limits.global_lua_heap_capacity);
const Request = struct {
    command: command.Command,
    done: std.Io.Event = .unset,
    result: ?Error = null,
};

pub const IdentityView = struct { value: identity.Identity, active: bool };

pub const Error = stack.Error || error{
    InterfaceRequired,
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    RuntimeUnavailable,
    StorageFailure,
    TransportScriptUnavailable,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    storage: *storage_module.Storage,
    globals: globals.Store = .{},
    global_heap: GlobalHeap = .{},
    global_thread: ?std.Thread = null,
    catalog: std.ArrayList(identity.Identity) = .empty,
    catalog_mutex: std.Io.Mutex = .init,
    commands: ring.MpscRing(*Request, limits.runtime_command_capacity) = .{},
    runtimes: std.StringArrayHashMapUnmanaged(*Runtime) = .empty,
    closing: std.Io.Event = .unset,
    thread: std.Thread = undefined,
    wake: wait.Wake = undefined,
    handles: std.ArrayList(wait.Handle) = .empty,
    next_run: u64 = 1,
    transport_heaps: ?*[transport_vm_slots]lua.TransportHeap = null,
    transport_depth: usize = 0,

    pub fn init(self: *Manager, allocator: std.mem.Allocator, storage: *storage_module.Storage) !void {
        self.* = .{ .allocator = allocator, .storage = storage };
        errdefer self.catalog.deinit(allocator);
        try storage.identities().load(allocator, &self.catalog);
        self.wake = try wait.Wake.init();
        errdefer self.wake.deinit();
        try self.handles.append(allocator, self.wake.handle);
        errdefer self.handles.deinit(allocator);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Manager) void {
        self.stopGlobal();
        self.closing.set(io());
        self.wake.signal();
        self.thread.join();
        self.wake.deinit();
        self.handles.deinit(self.allocator);
        for (self.runtimes.values()) |runtime| runtime.deinit();
        self.runtimes.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        if (self.transport_heaps) |heaps| self.allocator.destroy(heaps);
    }

    fn start(self: *Manager, value: *const identity.Identity) Error!void {
        if (self.runtimes.contains(value.label.value())) return error.IdentityInUse;
        if (@import("builtin").os.tag == .windows and self.runtimes.count() == 63) return error.RuntimeUnavailable;
        self.handles.ensureTotalCapacity(self.allocator, self.runtimes.count() + 2) catch return error.RuntimeUnavailable;
        if (value.interface.value().len == 0) return error.InterfaceRequired;
        const runtime = self.allocator.create(Runtime) catch return error.RuntimeUnavailable;
        errdefer self.allocator.destroy(runtime);
        runtime.* = .{ .manager = self, .name = value.label, .run_id = self.next_run, .transport = try self.transportSource(value.transport) };
        try runtime.stack.init(self.allocator, value, runtime, runtimeEgress);
        errdefer runtime.stack.deinit(self.allocator);
        runtime.pcap = pcap.Handle.open(value.interface.bytes[0..value.interface.len :0]) orelse return error.RuntimeUnavailable;
        errdefer runtime.pcap.close();
        if (applyIdentityFilter(&runtime.pcap, value) != null) return error.RuntimeUnavailable;
        self.runtimes.putNoClobber(self.allocator, runtime.name.value(), runtime) catch return error.RuntimeUnavailable;
        self.next_run +%= 1;
    }

    pub fn snapshot(self: *Manager, destination: *std.ArrayList(IdentityView)) !void {
        if (!self.catalog_mutex.tryLock()) return;
        defer self.catalog_mutex.unlock(io());
        try destination.resize(self.allocator, self.catalog.items.len);
        for (self.catalog.items, destination.items) |value, *entry| {
            entry.* = .{ .value = value, .active = self.runtimes.contains(value.label.value()) };
        }
    }

    pub fn runGlobal(self: *Manager, name: text.FieldText, source: text.FixedText(limits.source_capacity)) bool {
        self.global_heap.begin();
        self.global_thread = std.Thread.spawn(.{}, executeGlobal, .{ self, name, source }) catch return false;
        return true;
    }

    pub fn stopGlobal(self: *Manager) void {
        const thread = self.global_thread orelse return;
        self.global_heap.cancelled.set(io());
        self.wake.signal();
        thread.join();
        self.global_thread = null;
    }

    pub fn hasGlobalThread(self: *const Manager) bool {
        return self.global_thread != null;
    }

    pub fn execute(self: *Manager, request: command.Command) Error!void {
        var pending: Request = .{ .command = request };
        if (!self.commands.push(&pending)) return error.RuntimeUnavailable;
        self.wake.signal();
        pending.done.waitUncancelable(io());
        if (pending.result) |err| return err;
    }

    fn apply(self: *Manager, request: command.Command) Error!void {
        self.catalog_mutex.lockUncancelable(io());
        defer self.catalog_mutex.unlock(io());
        switch (request) {
            .save => |submitted| {
                var value = submitted;
                const updating = value.id.value().len > 0;
                if (updating) {
                    const current = for (self.catalog.items) |*candidate| {
                        if (std.mem.eql(u8, candidate.id.value(), value.id.value())) break candidate;
                    } else return error.IdentityNotFound;
                    if (self.runtimes.contains(current.label.value())) return error.IdentityInUse;
                    if (self.findName(value.label.value())) |named| if (named != current) return error.IdentityNameInUse;
                    value.transport = current.transport;
                } else if (self.findName(value.label.value()) != null) return error.IdentityNameInUse;
                self.storage.identities().save(value) catch return error.StorageFailure;
                self.storage.identities().load(self.allocator, &self.catalog) catch return error.StorageFailure;
                log.logger.formatted(.info, .ui, "Identity \"{s}\" {s}.", .{ value.label.value(), if (updating) "updated" else "created" });
            },
            .delete => |name| {
                const value = self.findName(name.value()) orelse return error.IdentityNotFound;
                if (self.runtimes.contains(value.label.value())) return error.IdentityInUse;
                self.storage.identities().delete(value.id.value()) catch return error.StorageFailure;
                self.storage.identities().load(self.allocator, &self.catalog) catch return error.StorageFailure;
                log.logger.formatted(.info, .ui, "Identity \"{s}\" deleted.", .{name.value()});
            },
            .start => |name| {
                const value = self.findName(name.value()) orelse return error.IdentityNotFound;
                try self.start(value);
                log.logger.formatted(.info, .runtime, "Identity \"{s}\" started.", .{value.label.value()});
            },
            .stop => |name| {
                (self.runtimes.fetchSwapRemove(name.value()) orelse return error.RuntimeUnavailable).value.deinit();
                log.logger.formatted(.info, .runtime, "Identity \"{s}\" stopped.", .{name.value()});
            },
            .set_transport => |selection| {
                const value = self.findName(selection.name.value()) orelse return error.IdentityNotFound;
                var updated = value.*;
                updated.transport = selection.script orelse .{};
                const source = try self.transportSource(updated.transport);
                self.storage.identities().save(updated) catch return error.StorageFailure;
                value.* = updated;
                if (self.runtimes.get(value.label.value())) |runtime| runtime.transport = source;
                log.logger.formatted(.info, .ui, "Identity \"{s}\" transport: {s}.", .{ value.label.value(), if (selection.script) |script| script.value() else "none" });
            },
            .send_packet => |packet| {
                const runtime = self.runtimes.get(packet.name.value()) orelse return error.RuntimeUnavailable;
                process(runtime, packet.value.bytes[0..packet.value.len], .outbound);
            },
            .set_bpf => |selection| {
                const runtime = self.runtimes.get(selection.name.value()) orelse return error.RuntimeUnavailable;
                const message = if (selection.expression.len == 0)
                    applyIdentityFilter(&runtime.pcap, self.findName(runtime.name.value()) orelse unreachable)
                else
                    runtime.pcap.setFilter(selection.expression.bytes[0..selection.expression.len :0]);
                if (message) |value|
                    log.logger.formatted(.warning, .runtime, "Identity \"{s}\" BPF rejected: {s}", .{ runtime.name.value(), value })
                else
                    log.logger.formatted(.info, .runtime, "Identity \"{s}\" BPF: {s}", .{ runtime.name.value(), if (selection.expression.len == 0) "default restored" else selection.expression.value() });
            },
            .socket => unreachable,
        }
    }

    fn findName(self: *Manager, name: []const u8) ?*identity.Identity {
        for (self.catalog.items) |*value| if (std.mem.eql(u8, value.label.value(), name)) return value;
        return null;
    }

    fn transportSource(self: *Manager, script: text.FieldText) Error!?text.FixedText(limits.source_capacity) {
        if (script.len == 0) return null;
        var source: text.FixedText(limits.source_capacity) = undefined;
        self.storage.scripts(.transport).read(script.value(), &source) catch return error.TransportScriptUnavailable;
        return source;
    }

    fn run(self: *Manager) void {
        var pending: ?*Request = null;
        while (!self.closing.isSet()) {
            self.wake.reset();
            while (self.commands.pop()) |request| {
                if (request.command == .socket) {
                    // Only the global script submits sockets, one synchronous call at a time.
                    std.debug.assert(pending == null);
                    request.command.socket.result = 0;
                    pending = request;
                    continue;
                }
                self.apply(request.command) catch |err| {
                    request.result = err;
                };
                request.done.set(io());
            }
            var deadline: u64 = std.math.maxInt(u64);
            self.handles.clearRetainingCapacity();
            self.handles.appendAssumeCapacity(self.wake.handle);
            for (self.runtimes.values()) |current| {
                self.handles.appendAssumeCapacity(current.pcap.ready);
                deadline = @min(deadline, current.stack.tick(now()) orelse std.math.maxInt(u64));
                var bytes: [limits.frame_capacity]u8 = undefined;
                const length = current.pcap.next(&bytes) catch blk: {
                    current.report("pcap receive failed");
                    break :blk null;
                };
                if (length) |len| {
                    process(current, bytes[0..len], .inbound);
                    deadline = 0; // Drain capture buffers without sleeping; service commands between frames.
                }
            }
            if (pending) |request| {
                const call = request.command.socket;
                const remaining = call.bytes.len;
                const descriptor = call.socket.descriptor;
                const completed = if (self.runtimes.get(call.socket.identity.value())) |runtime|
                    runtime.socket(call)
                else blk: {
                    call.result = -1;
                    break :blk true;
                };
                if (completed) {
                    pending = null;
                    deadline = 0; // Flush work queued by this socket operation.
                    request.done.set(io());
                } else if (call.bytes.len != remaining or call.socket.descriptor != descriptor) {
                    deadline = 0;
                } else deadline = @min(deadline, call.deadline orelse std.math.maxInt(u64));
            }
            if (self.closing.isSet()) break;
            wait.wait(self.handles.items, if (deadline == std.math.maxInt(u64)) null else deadline -| now()) catch |err| {
                log.logger.formatted(.err, .runtime, "Runtime wait failed: {s}.", .{@errorName(err)});
                std.process.exit(1);
            };
        }
    }
};

const socket_metatable = "kraken.socket";

fn executeGlobal(manager: *Manager, name: text.FieldText, source: text.FixedText(limits.source_capacity)) void {
    var scope_buffer: [text.FieldText.capacity + 16]u8 = undefined;
    const scope = std.fmt.bufPrint(&scope_buffer, "Global script \"{s}\"", .{name.value()}) catch unreachable;
    log.logger.formatted(.info, .global, "{s} started.", .{scope});
    const state = c.lua_newstate(GlobalHeap.allocator, @ptrCast(&manager.global_heap)) orelse {
        log.logger.formatted(.err, .global, "{s} failed: Lua state allocation failed.", .{scope});
        return;
    };
    defer c.lua_close(state);
    lua.initialize(state, scope, manager.storage.config_dir, &manager.global_heap.cancelled);
    globals.preload(state, &manager.globals);
    lua.preloadContext(state, "kraken/socket", socketModule, @ptrCast(manager));
    _ = c.lua_rawgeti(state, c.LUA_REGISTRYINDEX, c.LUA_RIDX_GLOBALS);
    inline for (.{ "start", "stop", "delete" }) |action| {
        setGlobalFunction(state, -2, action ++ "_identity", globalIdentityCommand(action), manager);
    }
    setGlobalFunction(state, -2, "send_raw", globalSendRaw, manager);
    setGlobalFunction(state, -2, "create_identity", globalCreateIdentity, manager);
    setGlobalFunction(state, -2, "set_identity_transport", globalSetIdentityTransport, manager);
    setGlobalFunction(state, -2, "set_identity_bpf", globalSetIdentityBpf, manager);
    c.lua_pop(state, 1);
    const script = source.value();
    if (c.luaL_loadbufferx(state, script.ptr, script.len, "global", null) != c.LUA_OK) {
        lua.reportError(state, scope, "compilation failed");
        return;
    }
    c.lua_sethook(state, GlobalHeap.budgetHook, c.LUA_MASKCOUNT, 1000);
    if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
        if (manager.global_heap.cancelled.isSet())
            log.logger.formatted(.info, .global, "{s} stopped.", .{scope})
        else
            lua.reportError(state, scope, "runtime failed");
        return;
    }
    log.logger.formatted(.info, .global, "{s} completed.", .{scope});
}

fn globalSendRaw(state: ?*c.lua_State) callconv(.c) c_int {
    const name = globalLuaText(state, 1);
    const raw = lua.toBytes(state, 2) orelse return c.luaL_error(state, "packet must be a string");
    var value: frame.Frame = .{};
    value.set(raw) catch return c.luaL_error(state, "packet exceeds fixed capacity");
    return queueGlobalCommand(state, .{ .send_packet = .{ .name = name, .value = value } });
}

fn globalCreateIdentity(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    var value: identity.Identity = .{};
    inline for (.{ "label", "ip", "prefix", "interface", "gateway", "mac", "mtu" }) |field| {
        const required = comptime std.mem.eql(u8, field, "label");
        _ = c.lua_getfield(state, 1, if (required) "name" else field);
        defer c.lua_pop(state, 1);
        if (required or !c.lua_isnil(state, -1)) @field(value, field) = globalLuaText(state, -1);
    }
    return queueGlobalCommand(state, .{ .save = value });
}

fn globalSetIdentityTransport(state: ?*c.lua_State) callconv(.c) c_int {
    const name = globalLuaText(state, 1);
    const script = if (c.lua_isnil(state, 2)) null else globalLuaText(state, 2);
    return queueGlobalCommand(state, .{ .set_transport = .{ .name = name, .script = script } });
}

fn globalSetIdentityBpf(state: ?*c.lua_State) callconv(.c) c_int {
    const name = globalLuaText(state, 1);
    const expression: text.FieldText = if (c.lua_isnoneornil(state, 2)) .{} else globalLuaText(state, 2);
    if (std.mem.indexOfScalar(u8, expression.value(), 0) != null) return c.luaL_error(state, "BPF cannot contain NUL bytes");
    return queueGlobalCommand(state, .{ .set_bpf = .{ .name = name, .expression = expression } });
}

fn socketModule(state: ?*c.lua_State) callconv(.c) c_int {
    const manager = globalManager(state, 1);
    _ = c.luaL_newmetatable(state, socket_metatable);
    c.lua_createtable(state, 0, 5);
    setGlobalFunction(state, -2, "send", socketSend, manager);
    setGlobalFunction(state, -2, "receive", socketReceive, manager);
    setGlobalFunction(state, -2, "close", socketClose, manager);
    setGlobalFunction(state, -2, "listen", socketListen, manager);
    setGlobalFunction(state, -2, "accept", socketAccept, manager);
    c.lua_setfield(state, -2, "__index");
    setGlobalFunction(state, -2, "__gc", socketClose, manager);
    _ = c.lua_pushstring(state, socket_metatable);
    c.lua_setfield(state, -2, "__metatable");
    c.lua_pop(state, 1);
    c.lua_createtable(state, 0, 3);
    inline for (comptime std.meta.tags(@FieldType(command.Socket, "kind"))) |kind| {
        c.lua_createtable(state, 0, 2);
        inline for (.{ command.SocketAction.connect, command.SocketAction.bind }) |action| {
            if (comptime kind == .raw and action == .connect) continue;
            c.lua_pushinteger(state, @intFromEnum(kind));
            c.lua_pushinteger(state, @intFromEnum(action));
            c.lua_pushlightuserdata(state, manager);
            c.lua_pushcclosure(state, socketOpen, 3);
            c.lua_setfield(state, -2, if (kind == .raw) "open" else @tagName(action));
        }
        c.lua_setfield(state, -2, @tagName(kind));
    }
    return 1;
}

fn socketOpen(state: ?*c.lua_State) callconv(.c) c_int {
    const kind: @FieldType(command.Socket, "kind") = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(1), null));
    const action: command.SocketAction = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(2), null));
    const name = globalLuaText(state, 1);
    var config: command.Socket = .{ .identity = name, .kind = kind };
    var address: c.struct_wolfIP_sockaddr_in = .{ .sin_family = c.AF_INET };
    if (kind == .raw) {
        const protocol = c.luaL_checkinteger(state, 2);
        if (protocol < 0 or protocol > 255) return c.luaL_error(state, "protocol must be between 0 and 255");
        config.protocol = @intCast(protocol);
        if (!c.lua_isnoneornil(state, 3)) {
            c.luaL_checktype(state, 3, c.LUA_TTABLE);
            _ = c.lua_getfield(state, 3, "header");
            if (!c.lua_isnil(state, -1)) c.luaL_checktype(state, -1, c.LUA_TBOOLEAN);
            config.header = c.lua_toboolean(state, -1) != 0;
            c.lua_pop(state, 1);
        }
    } else address = globalLuaAddress(state, 2, 3) orelse return c.luaL_error(state, "IPv4 address and port are required");
    const timeout = if (kind == .tcp and action == .connect) globalLuaTimeout(state, 4) else null;
    const value = newGlobalSocket(state);
    value.* = config;
    _ = socketCall(globalManager(state, 3), state, action, value, &address, &.{}, timeout);
    return 1;
}

fn socketListen(state: ?*c.lua_State) callconv(.c) c_int {
    const value = globalLuaSocket(state);
    _ = socketCall(globalManager(state, 1), state, .listen, value, null, &.{}, null);
    return 0;
}
fn socketAccept(state: ?*c.lua_State) callconv(.c) c_int {
    const value = globalLuaSocket(state);
    const peer = newGlobalSocket(state);
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const descriptor = socketCall(globalManager(state, 1), state, .accept, value, &address, &.{}, globalLuaTimeout(state, 2));
    peer.* = value.*;
    peer.descriptor = descriptor;
    peer.handshaking = true;
    pushGlobalAddress(state, address);
    return 3;
}
fn socketSend(state: ?*c.lua_State) callconv(.c) c_int {
    const value = globalLuaSocket(state);
    var length: usize = 0;
    const bytes = c.luaL_checklstring(state, 2, &length);
    var destination: c.struct_wolfIP_sockaddr_in = .{};
    var timeout_index: c_int = 3;
    if (value.kind == .raw or (value.kind == .udp and c.lua_type(state, 3) == c.LUA_TSTRING)) {
        timeout_index = if (value.kind == .raw) 4 else 5;
        destination = globalLuaAddress(state, 3, if (value.kind == .raw) null else 4) orelse return c.luaL_error(state, "invalid destination address or port");
    }
    _ = socketCall(globalManager(state, 1), state, .send, value, &destination, @constCast(bytes[0..length]), globalLuaTimeout(state, timeout_index));
    return 0;
}
fn socketReceive(state: ?*c.lua_State) callconv(.c) c_int {
    const value = globalLuaSocket(state);
    const count = if (value.kind == .tcp) c.luaL_checkinteger(state, 2) else limits.socket_receive_capacity;
    if (count < 1 or count > limits.socket_receive_capacity) return c.luaL_error(state, "receive length must be between 1 and 32768");
    var received: [limits.socket_receive_capacity]u8 = undefined;
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const length = socketCall(globalManager(state, 1), state, .receive, value, &address, received[0..@intCast(count)], globalLuaTimeout(state, if (value.kind == .tcp) 3 else 2));
    _ = c.lua_pushlstring(state, &received, @intCast(length));
    if (value.kind == .tcp) return 1;
    pushGlobalAddress(state, address);
    if (value.kind == .raw) {
        c.lua_pop(state, 1);
        return 2;
    }
    return 3;
}
fn socketClose(state: ?*c.lua_State) callconv(.c) c_int {
    const value = globalLuaSocket(state);
    if (value.descriptor < 0) return 0;
    _ = socketCall(globalManager(state, 1), state, .close, value, null, &.{}, null);
    return 0;
}

fn socketCall(manager: *Manager, state: ?*c.lua_State, action: command.SocketAction, value: *command.Socket, address: ?*c.struct_wolfIP_sockaddr_in, bytes: []u8, timeout: ?u64) c_int {
    var unused_address: c.struct_wolfIP_sockaddr_in = .{};
    var call: command.SocketCall = .{ .action = action, .socket = value, .address = address orelse &unused_address, .bytes = bytes, .deadline = if (timeout) |milliseconds| @as(u64, @intCast(std.Io.Clock.awake.now(io()).toMilliseconds())) + milliseconds else null };
    manager.execute(.{ .socket = &call }) catch return c.luaL_error(state, "socket call failed");
    if (action == .close) value.descriptor = -1;
    if (call.result < 0) return c.luaL_error(state, if (call.result == -c.WOLFIP_EAGAIN) "socket call timed out" else "socket call failed");
    return call.result;
}

fn globalIdentityCommand(comptime action: []const u8) c.lua_CFunction {
    return struct {
        fn call(state: ?*c.lua_State) callconv(.c) c_int {
            return queueGlobalCommand(state, @unionInit(command.Command, action, globalLuaText(state, 1)));
        }
    }.call;
}
fn globalManager(state: ?*c.lua_State, upvalue: c_int) *Manager {
    return @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(upvalue)).?));
}
fn queueGlobalCommand(state: ?*c.lua_State, request: command.Command) c_int {
    globalManager(state, 1).execute(request) catch |err| return c.luaL_error(state, @errorName(err));
    return 0;
}
fn setGlobalFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction, manager: *Manager) void {
    c.lua_pushlightuserdata(state, manager);
    c.lua_pushcclosure(state, function, 1);
    c.lua_setfield(state, table, name);
}
fn newGlobalSocket(state: ?*c.lua_State) *command.Socket {
    const raw = c.lua_newuserdatauv(state, @sizeOf(command.Socket), 0) orelse unreachable;
    const value: *command.Socket = @ptrCast(@alignCast(raw));
    value.descriptor = -1;
    _ = c.lua_getfield(state, c.LUA_REGISTRYINDEX, socket_metatable);
    _ = c.lua_setmetatable(state, -2);
    return value;
}
fn globalLuaSocket(state: ?*c.lua_State) *command.Socket {
    return @ptrCast(@alignCast(c.luaL_checkudata(state, 1, socket_metatable)));
}
fn pushGlobalAddress(state: ?*c.lua_State, address: c.struct_wolfIP_sockaddr_in) void {
    const bytes: [4]u8 = @bitCast(address.sin_addr.s_addr);
    var buffer: [15]u8 = undefined;
    const output = std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch unreachable;
    _ = c.lua_pushlstring(state, output.ptr, output.len);
    c.lua_pushinteger(state, std.mem.bigToNative(u16, address.sin_port));
}
fn globalLuaAddress(state: ?*c.lua_State, address_index: c_int, port_index: ?c_int) ?c.struct_wolfIP_sockaddr_in {
    const value = lua.toBytes(state, address_index) orelse return null;
    const port = if (port_index) |index| c.luaL_checkinteger(state, index) else 0;
    if (port < 0 or port > 65535) return null;
    const address = std.Io.net.Ip4Address.parse(value, 0) catch return null;
    return .{ .sin_family = c.AF_INET, .sin_port = std.mem.nativeToBig(u16, @intCast(port)), .sin_addr = .{ .s_addr = @bitCast(address.bytes) } };
}
fn globalLuaTimeout(state: ?*c.lua_State, index: c_int) ?u64 {
    if (c.lua_isnoneornil(state, index)) return null;
    const value = c.luaL_checkinteger(state, index);
    if (value < 0) {
        _ = c.luaL_argerror(state, index, "timeout must be non-negative");
        unreachable;
    }
    return @intCast(value);
}
fn globalLuaText(state: ?*c.lua_State, index: c_int) text.FieldText {
    var value: text.FieldText = .{};
    value.set(lua.checkBytes(state, index)) catch {
        _ = c.luaL_error(state, "text field exceeds capacity");
        unreachable;
    };
    return value;
}

fn applyIdentityFilter(handle: *pcap.Handle, value: *const identity.Identity) ?[]const u8 {
    var expression: [128]u8 = undefined;
    const filter = std.fmt.bufPrintZ(
        &expression,
        "ether dst {s} or ip dst host {s} or arp dst host {s}",
        .{ value.mac.value(), value.ip.value(), value.ip.value() },
    ) catch unreachable;
    return handle.setFilter(filter);
}

const Runtime = struct {
    manager: *Manager,
    name: text.FieldText,
    run_id: u64,
    transport: ?text.FixedText(limits.source_capacity),
    pcap: pcap.Handle = undefined,
    stack: stack.Stack = undefined,

    fn deinit(self: *Runtime) void {
        self.pcap.close();
        self.stack.deinit(self.manager.allocator);
        self.manager.allocator.destroy(self);
    }

    fn socket(self: *Runtime, call: *command.SocketCall) bool {
        const creating = call.action == .connect or call.action == .bind;
        if (creating and call.socket.run == 0) call.socket.run = self.run_id;
        if (call.socket.run != self.run_id) {
            call.result = -1;
            return true;
        }
        defer if (creating and call.result < 0) {
            _ = self.stack.socket(.close, call.socket, call.address, call.bytes);
            call.socket.descriptor = -1;
        };
        call.result = operation: while (true) {
            if (self.manager.global_heap.cancelled.isSet() and call.action != .close) break :operation -1;
            const result = self.stack.socket(call.action, call.socket, call.address, call.bytes);
            if (call.action == .close and result == -c.WOLFIP_EAGAIN) break :operation 0;
            const transferring = call.action == .send or call.action == .receive;
            if (result >= 0) {
                if (!transferring) break :operation result;
                if (result == 0 and call.socket.kind == .tcp) break :operation -1;
                call.bytes = call.bytes[@intCast(result)..];
                call.result += result;
                call.socket.handshaking = false;
                if (call.socket.kind != .tcp or call.bytes.len == 0) break :operation call.result;
                continue;
            } else if (result != -c.WOLFIP_EAGAIN and !(transferring and call.socket.handshaking and result == -1)) break :operation result;
            if (now() >= (call.deadline orelse std.math.maxInt(u64))) break :operation -c.WOLFIP_EAGAIN;
            return false;
        };
        return true;
    }

    fn inject(self: *Runtime, bytes: []const u8, direction: frame.Direction) bool {
        if (bytes.len > limits.frame_capacity) return false;
        return if (direction == .inbound) self.stack.input(bytes) else self.pcap.inject(bytes);
    }

    fn report(self: *Runtime, message: []const u8) void {
        log.logger.formatted(.err, .runtime, "Identity \"{s}\": {s}.", .{ self.name.value(), message });
    }
};

fn process(runtime: *Runtime, bytes: []const u8, direction: frame.Direction) void {
    const source = if (runtime.transport) |*value| value.value() else {
        if (!runtime.inject(bytes, direction) and direction == .outbound) runtime.report("pcap transmit failed");
        return;
    };
    const manager = runtime.manager;
    if (manager.transport_depth == transport_vm_slots) return runtime.report("transport VM slots exhausted");
    if (manager.transport_heaps == null) manager.transport_heaps = manager.allocator.create([transport_vm_slots]lua.TransportHeap) catch {
        return runtime.report("transport VM allocation failed");
    };
    // Callbacks nest on one thread: each depth owns one heap until it returns.
    const heap = &manager.transport_heaps.?[manager.transport_depth];
    manager.transport_depth += 1;
    defer manager.transport_depth -= 1;
    heap.begin();
    const state = c.lua_newstate(lua.TransportHeap.allocator, @ptrCast(heap)) orelse return runtime.report("transport VM allocation failed");
    defer c.lua_close(state);

    lua.initialize(state, runtime.name.value(), manager.storage.config_dir, &heap.cancelled);
    lua.preloadContext(state, "kraken/transmit", transmitModule, manager);
    globals.preload(state, &manager.globals);
    c.lua_sethook(state, lua.TransportHeap.budgetHook, c.LUA_MASKCOUNT, 1000);
    if (c.luaL_loadbufferx(state, source.ptr, source.len, "transport", null) != c.LUA_OK or c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
        lua.reportError(state, runtime.name.value(), "initialization failed");
        return;
    }
    _ = c.lua_getglobal(state, "transport");
    if (c.lua_type(state, -1) != c.LUA_TFUNCTION) return log.logger.formatted(.err, .lua, "{s}: function transport is missing.", .{runtime.name.value()});
    _ = c.lua_pushlstring(state, bytes.ptr, bytes.len);
    _ = c.lua_pushlstring(state, runtime.name.value().ptr, runtime.name.value().len);
    _ = c.lua_pushstring(state, if (direction == .inbound) "inbound" else "outbound");
    if (c.lua_pcallk(state, 3, 0, 0, 0, null) != c.LUA_OK) lua.reportError(state, runtime.name.value(), "runtime failed");
}

fn transmitModule(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_pushvalue(state, c.lua_upvalueindex(1));
    c.lua_pushcclosure(state, transmitLua, 1);
    return 1;
}

fn transmitLua(state: ?*c.lua_State) callconv(.c) c_int {
    const manager: *Manager = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    const name = lua.checkBytes(state, 1);
    const direction = std.meta.stringToEnum(frame.Direction, lua.checkBytes(state, 3)) orelse return c.luaL_argerror(state, 3, "direction must be inbound or outbound");
    const runtime = manager.runtimes.get(name) orelse return c.luaL_error(state, "identity is not running");
    if (!runtime.inject(lua.checkBytes(state, 2), direction)) return c.luaL_error(state, "packet transmission failed");
    return 0;
}

fn runtimeEgress(device: ?*c.struct_wolfIP_ll_dev, raw: ?*anyopaque, length: u32) callconv(.c) c_int {
    const runtime: *Runtime = @ptrCast(@alignCast(device.?.priv.?));
    const bytes: [*]const u8 = @ptrCast(raw.?);
    process(runtime, bytes[0..length], .outbound);
    return @intCast(length);
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn now() u64 {
    return @intCast(std.Io.Clock.awake.now(io()).toMilliseconds());
}
