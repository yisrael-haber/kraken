const std = @import("std");
const c = @import("c");
const packet = @import("packet.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const stack = @import("stack.zig");
const network_config = @import("network_config.zig");
const pcap = @import("../platform/pcap.zig");
const limits = @import("../limits.zig");

pub const max_identities = 5;
pub const text_capacity = limits.field_capacity;
pub const event_capacity = 64;
pub const command_capacity = 64;
pub const source_capacity = limits.source_capacity;

pub const State = enum(u8) { idle, starting, running, stopping, failed };
pub const LinkBackend = enum(u8) { pcap, memory };

pub const IdentityName = struct {
    bytes: [text_capacity]u8 = [_]u8{0} ** text_capacity,
    len: u8 = 0,

    pub fn init(raw: []const u8) error{NameTooLong}!IdentityName {
        if (raw.len == 0 or raw.len > text_capacity) return error.NameTooLong;
        var name: IdentityName = .{ .len = @intCast(raw.len) };
        @memcpy(name.bytes[0..raw.len], raw);
        return name;
    }

    pub fn value(self: *const IdentityName) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const IdentityName, value_: []const u8) bool {
        return std.mem.eql(u8, self.value(), value_);
    }
};

pub const IdentityConfig = struct {
    label: [text_capacity]u8 = [_]u8{0} ** text_capacity,
    label_len: u8 = 0,
    interface: [text_capacity]u8 = [_]u8{0} ** text_capacity,
    interface_len: u8 = 0,
    link_backend: LinkBackend = .pcap,
    network: ?network_config.Config = null,

    pub fn setLabel(self: *IdentityConfig, value: []const u8) void {
        self.label_len = @intCast(@min(value.len, self.label.len));
        @memcpy(self.label[0..self.label_len], value[0..self.label_len]);
    }

    pub fn setInterface(self: *IdentityConfig, value: []const u8) void {
        self.interface_len = @intCast(@min(value.len, self.interface.len));
        @memcpy(self.interface[0..self.interface_len], value[0..self.interface_len]);
    }

    pub fn interfaceZ(self: *const IdentityConfig, buffer: *[text_capacity + 1]u8) [:0]const u8 {
        @memcpy(buffer[0..self.interface_len], self.interface[0..self.interface_len]);
        buffer[self.interface_len] = 0;
        return buffer[0..self.interface_len :0];
    }
};

pub const EventKind = enum(u8) { started, stopped, failed, packet_dropped, queue_full };
pub const Event = struct {
    kind: EventKind,
    slot: u8,
    message: [text_capacity]u8 = [_]u8{0} ** text_capacity,
    message_len: u8 = 0,

    fn withMessage(kind: EventKind, slot: usize, message: []const u8) Event {
        var event: Event = .{ .kind = kind, .slot = @intCast(slot) };
        event.message_len = @intCast(@min(message.len, event.message.len));
        @memcpy(event.message[0..event.message_len], message[0..event.message_len]);
        return event;
    }
};

pub const StartRequest = struct {
    config: IdentityConfig,
    transport: ?Source = null,
};

const Command = union(enum) {
    start: StartRequest,
    stop,
    send_packet: struct { value: packet.Packet, options: packet.SendOptions },
    set_transport_source: Source,
    clear_transport,
};

const GlobalCommand = union(enum) {
    run: Source,
    stop,
};

const GlobalProgram = struct {
    heap: lua.FixedLuaHeap(lua.global_heap_size) = .{},
    state: ?*c.lua_State = null,
    thread: ?*c.lua_State = null,
    active: bool = false,
    instruction_count: usize = 0,

    fn deinit(self: *GlobalProgram) void {
        if (self.state) |state| c.lua_close(state);
        self.state = null;
        self.thread = null;
        self.active = false;
        self.heap.reset();
    }

    fn load(self: *GlobalProgram, source: Source) bool {
        self.deinit();
        const state = c.lua_newstate(allocateGlobal, @ptrCast(self)) orelse return false;
        self.state = state;
        lua.openLibraries(state);
        _ = c.lua_pushcclosure(state, globalStart, 0);
        c.lua_setglobal(state, "start_identity");
        _ = c.lua_pushcclosure(state, globalStop, 0);
        c.lua_setglobal(state, "stop_identity");
        _ = c.lua_pushcclosure(state, globalAwait, 0);
        c.lua_setglobal(state, "await");
        _ = c.lua_pushcclosure(state, globalSendRaw, 0);
        c.lua_setglobal(state, "send_raw");
        self.thread = c.lua_newthread(state);
        const thread = self.thread orelse return false;
        if (c.luaL_loadbufferx(thread, source.bytes[0..source.len].ptr, source.len, "global", null) != c.LUA_OK) {
            lua.reportError(thread, "Lua compilation error:");
            return false;
        }
        self.active = true;
        self.instruction_count = 0;
        c.lua_sethook(thread, globalBudgetHook, c.LUA_MASKCOUNT, 1000);
        return true;
    }
};

const GlobalScheduler = struct {
    runtime: *AppRuntime,
    shutdown: *std.atomic.Value(bool),
    thread: ?std.Thread = null,
    wake_mutex: std.Io.Mutex = .init,
    wake_condition: std.Io.Condition = .init,
    wake_requested: bool = false,
    producer_mutex: std.Io.Mutex = .init,
    commands: ring.SpscRing(GlobalCommand, command_capacity) = .{},
    program: GlobalProgram = .{},

    fn startThread(self: *GlobalScheduler) !void {
        self.thread = try std.Thread.spawn(.{}, globalMain, .{self});
    }

    fn request(self: *GlobalScheduler, command: GlobalCommand) bool {
        if (!self.commands.push(command)) return false;
        self.wake_mutex.lockUncancelable(io());
        self.wake_requested = true;
        self.wake_condition.signal(io());
        self.wake_mutex.unlock(io());
        return true;
    }
};

threadlocal var active_scheduler: ?*GlobalScheduler = null;
threadlocal var active_global_program: ?*GlobalProgram = null;

fn allocateGlobal(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    const program: *GlobalProgram = @ptrCast(@alignCast(user_data orelse return null));
    return program.heap.reallocate(old, old_size, new_size);
}

fn globalStart(state: ?*c.lua_State) callconv(.c) c_int {
    const scheduler = active_scheduler orelse return c.luaL_error(state, "global scheduler unavailable");
    const name = globalName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!scheduler.runtime.startStored(name)) return c.luaL_error(state, "identity is unavailable or all identity slots are active");
    return 0;
}

fn globalStop(state: ?*c.lua_State) callconv(.c) c_int {
    const scheduler = active_scheduler orelse return c.luaL_error(state, "global scheduler unavailable");
    const name = globalName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!scheduler.runtime.stopNamed(name)) return c.luaL_error(state, "identity is not running");
    return 0;
}

fn globalAwait(state: ?*c.lua_State) callconv(.c) c_int {
    return c.lua_yieldk(state, 0, 0, null);
}

fn globalSendRaw(state: ?*c.lua_State) callconv(.c) c_int {
    const scheduler = active_scheduler orelse return c.luaL_error(state, "global scheduler unavailable");
    const name = globalName(state) orelse return c.luaL_error(state, "identity name is required");
    var length: usize = 0;
    const raw = c.lua_tolstring(state, 2, &length) orelse return c.luaL_error(state, "packet must be a string");
    var value: packet.Packet = .{ .direction = .outbound };
    value.setBytes(raw[0..length]) catch return c.luaL_error(state, "packet exceeds fixed capacity");
    var options: packet.SendOptions = .{};
    if (c.lua_type(state, 3) == c.LUA_TSTRING) {
        var repair_length: usize = 0;
        const repair = c.lua_tolstring(state, 3, &repair_length)[0..repair_length];
        if (std.mem.eql(u8, repair, "manual")) options.repair = .manual else if (!std.mem.eql(u8, repair, "automatic")) return c.luaL_error(state, "unknown repair mode");
    }
    if (!scheduler.runtime.submitNamed(name, value, options)) return c.luaL_error(state, "identity is not running");
    return 0;
}

fn globalBudgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const program = active_global_program orelse return;
    program.instruction_count += 1000;
    if (program.instruction_count > lua.max_transport_instructions) _ = c.luaL_error(state, "global instruction budget exceeded");
}

fn globalName(state: ?*c.lua_State) ?[]const u8 {
    var length: usize = 0;
    const value = c.lua_tolstring(state, 1, &length) orelse return null;
    if (length == 0 or length > text_capacity) return null;
    return value[0..length];
}

pub const Source = struct {
    bytes: [source_capacity]u8 = [_]u8{0} ** source_capacity,
    len: u16 = 0,

    pub fn set(self: *Source, value: []const u8) error{SourceTooLarge}!void {
        if (value.len > source_capacity) return error.SourceTooLarge;
        self.len = @intCast(value.len);
        @memcpy(self.bytes[0..value.len], value);
    }
};

pub const StoredIdentity = struct {
    name: IdentityName,
    config: IdentityConfig,
};

const Worker = struct {
    runtime: *AppRuntime,
    index: usize,
    thread: ?std.Thread = null,
    wake_mutex: std.Io.Mutex = .init,
    wake_condition: std.Io.Condition = .init,
    wake_requested: bool = false,
    producer_mutex: std.Io.Mutex = .init,
    state: std.atomic.Value(State) = std.atomic.Value(State).init(.idle),
    commands: ring.SpscRing(Command, command_capacity) = .{},
    events: ring.SpscRing(Event, event_capacity) = .{},
    transport: lua.Transport = .{},
    config: IdentityConfig = .{},
    pcap: ?pcap.Handle = null,
    stack: stack.Stack = .{},
    memory_egress: ring.SpscRing(packet.Packet, event_capacity) = .{},
    transport_issue_reported: bool = false,
    link_issue_reported: bool = false,
    queue_full_reported: bool = false,

    fn startThread(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{}, workerMain, .{self});
    }

    fn request(self: *Worker, command: Command) bool {
        self.producer_mutex.lockUncancelable(io());
        const pushed = self.commands.push(command);
        self.producer_mutex.unlock(io());
        if (!pushed) return false;
        self.wake_mutex.lockUncancelable(io());
        self.wake_requested = true;
        self.wake_condition.signal(io());
        self.wake_mutex.unlock(io());
        return true;
    }

    fn emit(self: *Worker, event: Event) void {
        _ = self.events.push(event);
    }

    fn closeLink(self: *Worker) void {
        if (self.pcap) |*handle| handle.close();
        self.pcap = null;
    }
};

/// The only long-lived runtime allocation. Workers own all mutable stack,
/// packet, link, and Lua state for their slot; the UI owns dispatch and reads.
pub const AppRuntime = struct {
    allocator: std.mem.Allocator,
    workers: [max_identities]Worker = undefined,
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    scheduler: GlobalScheduler = undefined,
    workers_started: usize = 0,
    scheduler_started: bool = false,
    event_cursor: usize = 0,
    active_mutex: std.Io.Mutex = .init,
    active_names: [max_identities]?IdentityName = [_]?IdentityName{null} ** max_identities,
    stored_mutex: std.Io.Mutex = .init,
    stored_identities: []StoredIdentity = &.{},

    pub fn init(self: *AppRuntime, allocator: std.mem.Allocator) !void {
        self.* = .{ .allocator = allocator, .workers = undefined, .scheduler = undefined };
        self.scheduler = .{ .runtime = self, .shutdown = &self.shutdown };
        for (&self.workers, 0..) |*worker, index| {
            worker.* = .{ .runtime = self, .index = index };
        }
        errdefer self.deinit();
        for (&self.workers) |*worker| {
            try worker.startThread();
            self.workers_started += 1;
        }
        try self.scheduler.startThread();
        self.scheduler_started = true;
    }

    pub fn create(allocator: std.mem.Allocator) !*AppRuntime {
        const runtime = try allocator.create(AppRuntime);
        errdefer allocator.destroy(runtime);
        try runtime.init(allocator);
        return runtime;
    }

    pub fn deinit(self: *AppRuntime) void {
        self.shutdown.store(true, .release);
        self.scheduler.wake_mutex.lockUncancelable(io());
        self.scheduler.wake_requested = true;
        self.scheduler.wake_condition.signal(io());
        self.scheduler.wake_mutex.unlock(io());
        for (&self.workers) |*worker| {
            worker.wake_mutex.lockUncancelable(io());
            worker.wake_requested = true;
            worker.wake_condition.signal(io());
            worker.wake_mutex.unlock(io());
        }
        for (self.workers[0..self.workers_started]) |*worker| if (worker.thread) |thread| {
            thread.join();
            worker.thread = null;
        };
        if (self.scheduler_started) if (self.scheduler.thread) |thread| {
            thread.join();
            self.scheduler.thread = null;
        };
        self.scheduler.program.deinit();
        if (self.stored_identities.len > 0) self.allocator.free(self.stored_identities);
        self.stored_identities = &.{};
        self.active_names = [_]?IdentityName{null} ** max_identities;
        self.workers_started = 0;
        self.scheduler_started = false;
    }

    pub fn destroy(self: *AppRuntime, allocator: std.mem.Allocator) void {
        self.deinit();
        allocator.destroy(self);
    }

    pub fn state(self: *const AppRuntime, slot: usize) ?State {
        if (slot >= max_identities) return null;
        return self.workers[slot].state.load(.acquire);
    }

    pub fn start(self: *AppRuntime, slot: usize, config: IdentityConfig) bool {
        return self.startWithTransport(slot, .{ .config = config });
    }

    pub fn startWithTransport(self: *AppRuntime, slot: usize, request: StartRequest) bool {
        if (slot >= max_identities) return false;
        const current = self.workers[slot].state.load(.acquire);
        if (current != .idle and current != .failed) return false;
        if (self.workers[slot].state.cmpxchgStrong(current, .starting, .acq_rel, .acquire) != null) return false;
        if (self.workers[slot].request(.{ .start = request })) return true;
        _ = self.workers[slot].state.cmpxchgStrong(.starting, current, .release, .monotonic);
        return false;
    }

    pub fn startNamed(self: *AppRuntime, name: []const u8, request: StartRequest) bool {
        const owned_name = IdentityName.init(name) catch return false;
        self.active_mutex.lockUncancelable(io());
        defer self.active_mutex.unlock(io());
        for (self.active_names) |maybe_name| if (maybe_name) |active| {
            if (active.eql(name)) return false;
        };
        for (&self.active_names, 0..) |*maybe_name, slot| {
            if (maybe_name.* != null) continue;
            const current = self.workers[slot].state.load(.acquire);
            if (current != .idle and current != .failed) continue;
            maybe_name.* = owned_name;
            if (self.startWithTransport(slot, request)) return true;
            maybe_name.* = null;
        }
        return false;
    }

    pub fn startStored(self: *AppRuntime, name: []const u8) bool {
        self.stored_mutex.lockUncancelable(io());
        var config: ?IdentityConfig = null;
        for (self.stored_identities) |identity| if (identity.name.eql(name)) {
            config = identity.config;
            break;
        };
        self.stored_mutex.unlock(io());
        return self.startNamed(name, .{ .config = config orelse return false });
    }

    pub fn stop(self: *AppRuntime, slot: usize) bool {
        if (slot >= max_identities) return false;
        const current = self.workers[slot].state.load(.acquire);
        if (current != .running and current != .failed) return false;
        if (self.workers[slot].state.cmpxchgStrong(current, .stopping, .acq_rel, .acquire) != null) return false;
        if (self.workers[slot].request(.stop)) return true;
        _ = self.workers[slot].state.cmpxchgStrong(.stopping, current, .release, .monotonic);
        return false;
    }

    pub fn stopNamed(self: *AppRuntime, name: []const u8) bool {
        self.active_mutex.lockUncancelable(io());
        defer self.active_mutex.unlock(io());
        for (&self.active_names, 0..) |*maybe_name, slot| if (maybe_name.*) |active| {
            if (!active.eql(name)) continue;
            if (!self.stop(slot)) return false;
            maybe_name.* = null;
            return true;
        };
        return false;
    }

    pub fn slotForName(self: *AppRuntime, name: []const u8) ?usize {
        self.active_mutex.lockUncancelable(io());
        defer self.active_mutex.unlock(io());
        for (self.active_names, 0..) |maybe_name, slot| if (maybe_name) |active| {
            if (active.eql(name)) return slot;
        };
        return null;
    }

    pub fn setTransportSource(self: *AppRuntime, slot: usize, source: Source) bool {
        if (slot >= max_identities) return false;
        return self.workers[slot].request(.{ .set_transport_source = source });
    }

    pub fn injectMemory(self: *AppRuntime, slot: usize, value: packet.Packet) bool {
        return self.submitPacket(slot, value, .{});
    }

    pub fn submitPacket(self: *AppRuntime, slot: usize, value: packet.Packet, options: packet.SendOptions) bool {
        if (slot >= max_identities or self.workers[slot].state.load(.acquire) != .running) return false;
        return self.workers[slot].request(.{ .send_packet = .{ .value = value, .options = options } });
    }

    pub fn submitNamed(self: *AppRuntime, name: []const u8, value: packet.Packet, options: packet.SendOptions) bool {
        const slot = self.slotForName(name) orelse return false;
        return self.submitPacket(slot, value, options);
    }

    pub fn pollMemoryEgress(self: *AppRuntime, slot: usize) ?packet.Packet {
        if (slot >= max_identities) return null;
        return self.workers[slot].memory_egress.pop();
    }

    pub fn pollEvent(self: *AppRuntime) ?Event {
        for (0..max_identities) |offset| {
            const slot = (self.event_cursor + offset) % max_identities;
            if (self.workers[slot].events.pop()) |event| {
                self.event_cursor = (slot + 1) % max_identities;
                if (event.kind == .failed or event.kind == .stopped) self.releaseSlot(slot);
                return event;
            }
        }
        return null;
    }

    pub fn runGlobal(self: *AppRuntime, source: Source) bool {
        return self.scheduler.request(.{ .run = source });
    }

    pub fn stopGlobal(self: *AppRuntime) bool {
        return self.scheduler.request(.stop);
    }

    pub fn replaceStoredIdentities(self: *AppRuntime, identities: []const StoredIdentity) !void {
        const replacement: []StoredIdentity = if (identities.len == 0) &.{} else try self.allocator.dupe(StoredIdentity, identities);
        self.stored_mutex.lockUncancelable(io());
        const previous = self.stored_identities;
        self.stored_identities = replacement;
        self.stored_mutex.unlock(io());
        if (previous.len > 0) self.allocator.free(previous);
    }

    fn releaseSlot(self: *AppRuntime, slot: usize) void {
        if (slot >= max_identities) return;
        self.active_mutex.lockUncancelable(io());
        self.active_names[slot] = null;
        self.active_mutex.unlock(io());
    }
};

fn workerMain(worker: *Worker) void {
    defer worker.closeLink();
    defer worker.transport.deinit();
    defer worker.stack.deinit();
    while (!worker.runtime.shutdown.load(.acquire)) {
        var did_work = false;
        while (worker.commands.pop()) |command| {
            did_work = true;
            handleCommand(worker, command);
        }
        if (worker.state.load(.acquire) == .running) {
            did_work = pollPcap(worker) or did_work;
            worker.stack.tick();
        }
        if (!did_work) {
            if (worker.state.load(.acquire) == .running) {
                // A pcap backend has no command to wake this thread for the
                // next packet. Keep its polling and protocol time moving.
                std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
                continue;
            }
            worker.wake_mutex.lockUncancelable(io());
            while (!worker.wake_requested and !worker.runtime.shutdown.load(.acquire)) worker.wake_condition.waitUncancelable(io(), &worker.wake_mutex);
            worker.wake_requested = false;
            worker.wake_mutex.unlock(io());
        }
    }
}

fn globalMain(scheduler: *GlobalScheduler) void {
    defer scheduler.program.deinit();
    while (!scheduler.shutdown.load(.acquire)) {
        while (scheduler.commands.pop()) |command| switch (command) {
            .run => |source| if (!scheduler.program.load(source)) scheduler.program.deinit(),
            .stop => scheduler.program.deinit(),
        };
        const active = scheduler.program.active;
        if (active) {
            const program = &scheduler.program;
            const thread = program.thread orelse {
                program.deinit();
                continue;
            };
            var results: c_int = 0;
            active_scheduler = scheduler;
            active_global_program = program;
            program.instruction_count = 0;
            const result = c.lua_resume(thread, null, 0, &results);
            active_scheduler = null;
            active_global_program = null;
            if (result == c.LUA_OK) {
                program.deinit();
            } else if (result != c.LUA_YIELD) {
                lua.reportError(thread, "Lua runtime error:");
                program.deinit();
            }
        }
        if (active) {
            std.Io.sleep(io(), .fromMilliseconds(10), .awake) catch unreachable;
            continue;
        }
        scheduler.wake_mutex.lockUncancelable(io());
        while (!scheduler.wake_requested and !scheduler.shutdown.load(.acquire)) scheduler.wake_condition.waitUncancelable(io(), &scheduler.wake_mutex);
        scheduler.wake_requested = false;
        scheduler.wake_mutex.unlock(io());
    }
}

fn handleCommand(worker: *Worker, command: Command) void {
    switch (command) {
        .start => |request| startWorker(worker, request),
        .stop => stopWorker(worker),
        .set_transport_source => |source| {
            worker.transport.load(source.bytes[0..source.len], "transport") catch |err| {
                worker.emit(Event.withMessage(.failed, worker.index, @errorName(err)));
            };
        },
        .clear_transport => worker.transport.deinit(),
        .send_packet => |request| processPacket(worker, request.value, request.options),
    }
}

fn startWorker(worker: *Worker, request: StartRequest) void {
    const config = request.config;
    worker.closeLink();
    worker.transport.deinit();
    worker.config = config;
    worker.transport_issue_reported = false;
    worker.link_issue_reported = false;
    worker.queue_full_reported = false;
    if (request.transport) |source| {
        worker.transport.load(source.bytes[0..source.len], "transport") catch |err| {
            worker.state.store(.failed, .release);
            worker.emit(Event.withMessage(.failed, worker.index, @errorName(err)));
            return;
        };
    }
    if (config.link_backend == .pcap and config.interface_len == 0) {
        worker.state.store(.failed, .release);
        worker.emit(Event.withMessage(.failed, worker.index, "Select a discovered packet interface before starting."));
        return;
    }
    const network = config.network orelse network_config.Config.defaultForSlot(worker.index);
    if (!worker.stack.init(worker.index, network, @ptrCast(worker), workerEgress)) {
        worker.state.store(.failed, .release);
        worker.emit(Event.withMessage(.failed, worker.index, "wolfIP stack initialization failed"));
        return;
    }
    if (config.link_backend == .pcap) {
        var interface_name: [text_capacity + 1]u8 = undefined;
        var error_buffer: [text_capacity]u8 = [_]u8{0} ** text_capacity;
        worker.pcap = pcap.Handle.open(config.interfaceZ(&interface_name), &error_buffer) catch {
            worker.stack.deinit();
            worker.state.store(.failed, .release);
            worker.emit(Event.withMessage(.failed, worker.index, std.mem.sliceTo(&error_buffer, 0)));
            return;
        };
    }
    worker.state.store(.running, .release);
    worker.emit(.{ .kind = .started, .slot = @intCast(worker.index) });
}

fn stopWorker(worker: *Worker) void {
    worker.closeLink();
    worker.transport.deinit();
    worker.stack.deinit();
    worker.state.store(.idle, .release);
    worker.emit(.{ .kind = .stopped, .slot = @intCast(worker.index) });
}

fn pollPcap(worker: *Worker) bool {
    const handle = if (worker.pcap) |*value| value else return false;
    var buffer: [packet.frame_capacity]u8 = undefined;
    switch (handle.next(&buffer)) {
        .none => return false,
        .failed => return false,
        .frame => |length| {
            var value: packet.Packet = .{ .direction = .inbound };
            value.setBytes(buffer[0..length]) catch return false;
            processPacket(worker, value, .{});
            return true;
        },
    }
}

fn processPacket(worker: *Worker, value: packet.Packet, initial_options: packet.SendOptions) void {
    var current = value;
    var options: packet.SendOptions = initial_options;
    worker.transport.run(&current, &options) catch |err| {
        if (!worker.transport_issue_reported) {
            worker.transport_issue_reported = true;
            worker.emit(Event.withMessage(.packet_dropped, worker.index, @errorName(err)));
        }
        return;
    };
    if (current.dropped) return;
    current.repair(options);
    if (current.direction == .inbound) {
        switch (worker.stack.input(current.bytes[0..current.len])) {
            .accepted => {},
            .empty, .oversized => {},
            .inactive => {
                if (!worker.link_issue_reported) {
                    worker.link_issue_reported = true;
                    worker.emit(Event.withMessage(.failed, worker.index, "wolfIP ingress attempted while stack was inactive"));
                }
            },
        }
        return;
    }
    switch (worker.config.link_backend) {
        .pcap => if (worker.pcap) |*handle| {
            if (!handle.inject(current.bytes[0..current.len])) {
                if (!worker.link_issue_reported) {
                    worker.link_issue_reported = true;
                    worker.emit(Event.withMessage(.failed, worker.index, "pcap transmit failed"));
                }
                return;
            }
        },
        .memory => {
            if (!worker.memory_egress.push(current)) {
                if (!worker.queue_full_reported) {
                    worker.queue_full_reported = true;
                    worker.emit(.{ .kind = .queue_full, .slot = @intCast(worker.index) });
                }
                return;
            }
        },
    }
}

fn workerEgress(context: ?*anyopaque, frame: []const u8) c_int {
    const worker: *Worker = @ptrCast(@alignCast(context orelse return -1));
    var value: packet.Packet = .{ .direction = .outbound };
    value.setBytes(frame) catch return -1;
    processPacket(worker, value, .{});
    return 0;
}

test "memory-backed identity has deterministic lifecycle" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    var config: IdentityConfig = .{ .link_backend = .memory };
    config.setLabel("test");
    try std.testing.expect(runtime.start(0, config));
    var seen = false;
    var attempt: usize = 0;
    while (attempt < 200 and !seen) : (attempt += 1) {
        if (runtime.pollEvent()) |event| {
            if (event.kind == .started and event.slot == 0) seen = true;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    try std.testing.expect(seen);
    try std.testing.expect(runtime.stop(0));
}

test "pcap backend without an interface fails with a usable event" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);

    try std.testing.expect(runtime.start(0, .{}));
    var attempt: usize = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.pollEvent()) |event| {
            if (event.kind != .failed) continue;
            try std.testing.expectEqual(@as(u8, 0), event.slot);
            try std.testing.expectEqualStrings(
                "Select a discovered packet interface before starting.",
                event.message[0..event.message_len],
            );
            try std.testing.expectEqual(State.failed, runtime.state(0).?);
            return;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    return error.TestExpectedFailureEvent;
}

test "memory backend executes transport hook and exposes egress" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    var config: IdentityConfig = .{ .link_backend = .memory };
    config.setLabel("test");
    try std.testing.expect(runtime.start(0, config));
    var started = false;
    var attempt: usize = 0;
    while (attempt < 200 and !started) : (attempt += 1) {
        if (runtime.pollEvent()) |event| {
            if (event.kind == .started) started = true;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    try std.testing.expect(started);
    while (runtime.pollMemoryEgress(0)) |_| {}
    var source: Source = .{};
    try source.set("function transport(packet) packet:set_byte(1, 99) end");
    try std.testing.expect(runtime.setTransportSource(0, source));
    std.Io.sleep(io(), .fromMilliseconds(5), .awake) catch unreachable;
    var input: packet.Packet = .{ .direction = .outbound };
    try input.setBytes(&[_]u8{ 1, 2, 3 });
    try std.testing.expect(runtime.injectMemory(0, input));
    attempt = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.pollMemoryEgress(0)) |output| {
            if (output.len != 3) continue;
            try std.testing.expectEqual(@as(u8, 99), output.bytes[1]);
            return;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    return error.TestExpectedMemoryEgress;
}

test "five isolated wolfIP instances answer on their owned memory links" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    for (0..max_identities) |slot| {
        const host: u8 = @intCast(70 + slot);
        const config: IdentityConfig = .{
            .link_backend = .memory,
            .network = .{
                .address = .{ 10, 44, 0, host },
                .prefix_length = 24,
                .mac = .{ 0x02, 0x91, 0x82, 0x73, 0x64, host },
            },
        };
        try std.testing.expect(runtime.start(slot, config));
    }

    var attempt: usize = 0;
    while (attempt < 200) : (attempt += 1) {
        var running: usize = 0;
        for (0..max_identities) |slot| {
            if (runtime.state(slot) == .running) running += 1;
        }
        if (running == max_identities) break;
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    for (0..max_identities) |slot| try std.testing.expectEqual(State.running, runtime.state(slot).?);
    while (runtime.pollMemoryEgress(2)) |_| {}

    var request: packet.Packet = .{ .direction = .inbound };
    try request.setBytes(&[_]u8{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x08, 0x06,
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        10,   44,   0,    22,   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10,   44,   0,    72,
    });
    try std.testing.expect(runtime.injectMemory(2, request));

    attempt = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.pollMemoryEgress(2)) |reply| {
            if (reply.len != 42 or reply.bytes[12] != 0x08 or reply.bytes[13] != 0x06) continue;
            if (reply.bytes[20] != 0x00 or reply.bytes[21] != 0x02) continue;
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x91, 0x82, 0x73, 0x64, 72 }, reply.bytes[6..12]);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 44, 0, 72 }, reply.bytes[28..32]);
            return;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    return error.TestExpectedArpReply;
}

test "any stored name can claim one of five temporary runtime slots" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    const config: IdentityConfig = .{ .link_backend = .memory };

    for (0..max_identities) |index| {
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "identity-{d}", .{index});
        try std.testing.expect(runtime.startNamed(name, .{ .config = config }));
    }
    try std.testing.expect(!runtime.startNamed("identity-5", .{ .config = config }));

    var started: usize = 0;
    var attempt: usize = 0;
    while (attempt < 500 and started < max_identities) : (attempt += 1) {
        if (runtime.pollEvent()) |event| {
            if (event.kind == .started) started += 1;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    try std.testing.expectEqual(@as(usize, max_identities), started);
    try std.testing.expect(runtime.stopNamed("identity-2"));

    attempt = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.pollEvent()) |event| {
            if (event.kind == .stopped) break;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    try std.testing.expect(runtime.startNamed("identity-5", .{ .config = config }));
    try std.testing.expect(runtime.slotForName("identity-5") != null);
}

test "global program starts a configured identity without UI mediation" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    var config: IdentityConfig = .{ .link_backend = .memory };
    config.setLabel("global-test");
    const stored = [_]StoredIdentity{.{ .name = try IdentityName.init("global-test"), .config = config }};
    try runtime.replaceStoredIdentities(&stored);
    var source: Source = .{};
    try source.set("start_identity('global-test'); await()");
    try std.testing.expect(runtime.runGlobal(source));
    var attempt: usize = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.slotForName("global-test")) |slot| if (runtime.state(slot) == .running) return;
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    return error.TestExpectedRunningIdentity;
}

test "global program sends directly to a running worker" {
    const allocator = std.testing.allocator;
    const runtime = try AppRuntime.create(allocator);
    defer runtime.destroy(allocator);
    const config: IdentityConfig = .{ .link_backend = .memory };
    try std.testing.expect(runtime.startNamed("sender", .{ .config = config }));
    const slot = runtime.slotForName("sender").?;
    var started = false;
    var attempt: usize = 0;
    while (attempt < 200 and !started) : (attempt += 1) {
        if (runtime.pollEvent()) |event| started = event.kind == .started and event.slot == slot;
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    try std.testing.expect(started);
    var source: Source = .{};
    try source.set("send_raw('sender', string.char(1, 2, 3), 'manual'); await()");
    try std.testing.expect(runtime.runGlobal(source));
    attempt = 0;
    while (attempt < 200) : (attempt += 1) {
        if (runtime.pollMemoryEgress(slot)) |output| {
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, output.bytes[0..output.len]);
            return;
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
    }
    return error.TestExpectedMemoryEgress;
}

test "worker inbox serializes producers and full start rolls state back" {
    var runtime_instance: AppRuntime = .{ .allocator = std.testing.allocator, .workers = undefined, .scheduler = undefined };
    for (&runtime_instance.workers, 0..) |*worker, index| {
        worker.* = .{ .runtime = &runtime_instance, .index = index };
    }
    const Producer = struct {
        fn run(worker: *Worker) void {
            for (0..command_capacity / 2) |_| std.testing.expect(worker.request(.stop)) catch unreachable;
        }
    };
    const first = try std.Thread.spawn(.{}, Producer.run, .{&runtime_instance.workers[0]});
    const second = try std.Thread.spawn(.{}, Producer.run, .{&runtime_instance.workers[0]});
    first.join();
    second.join();
    try std.testing.expectEqual(@as(usize, command_capacity), runtime_instance.workers[0].commands.len());
    try std.testing.expect(!runtime_instance.start(0, .{}));
    try std.testing.expectEqual(State.idle, runtime_instance.state(0).?);
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
