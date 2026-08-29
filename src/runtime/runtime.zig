const std = @import("std");
const c = @import("c");
const packet = @import("packet.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const stack = @import("stack.zig");
const pcap = @import("../platform/pcap.zig");
const limits = @import("../limits.zig");
const storage_model = @import("../storage/model.zig");

pub const Identity = struct {
    name: storage_model.FixedText(limits.field_capacity),
    interface: storage_model.FixedText(limits.field_capacity),
    network: stack.Config,
    transport: ?storage_model.FixedText(limits.source_capacity) = null,
};

pub const Issue = struct {
    pub const Kind = enum(u8) { failed, transport_update_failed, packet_dropped };

    kind: Kind,
    identity: storage_model.FixedText(limits.field_capacity),
    message: storage_model.FixedText(limits.field_capacity) = .{},
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    helpers_root: []u8,
    workers: std.ArrayList(*Worker) = .empty,
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    scheduler: GlobalScheduler = undefined,
    issues: ring.SpscRing(Issue, limits.runtime_issue_capacity) = .{},
    issues_mutex: std.Io.Mutex = .init,
    workers_mutex: std.Io.Mutex = .init,
    identities_mutex: std.Io.Mutex = .init,
    identities: []Identity = &.{},

    pub fn create(allocator: std.mem.Allocator, helpers_root: []const u8) !*Runtime {
        const runtime = try allocator.create(Runtime);
        errdefer allocator.destroy(runtime);
        const owned_helpers_root = try allocator.dupe(u8, helpers_root);
        errdefer allocator.free(owned_helpers_root);
        runtime.* = .{ .allocator = allocator, .helpers_root = owned_helpers_root, .scheduler = undefined };
        runtime.scheduler = .{ .runtime = runtime };
        runtime.scheduler.thread = try std.Thread.spawn(.{}, globalMain, .{&runtime.scheduler});
        return runtime;
    }

    pub fn destroy(self: *Runtime) void {
        const allocator = self.allocator;
        self.shutdown.store(true, .release);
        self.scheduler.wake.set(io());
        self.scheduler.thread.join();
        for (self.workers.items) |worker| {
            worker.wake.set(io());
            worker.thread.join();
            allocator.destroy(worker);
        }
        self.workers.deinit(allocator);
        if (self.identities.len > 0) allocator.free(self.identities);
        allocator.free(self.helpers_root);
        allocator.destroy(self);
    }

    pub fn takeIdentities(self: *Runtime, replacement: []Identity) void {
        self.identities_mutex.lockUncancelable(io());
        const previous = self.identities;
        self.identities = replacement;
        self.identities_mutex.unlock(io());
        if (previous.len > 0) self.allocator.free(previous);
    }

    pub fn start(self: *Runtime, identity: Identity) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        if (self.workerNamedLocked(identity.name.value()) != null) return false;
        var worker: *Worker = for (self.workers.items) |candidate| {
            if (candidate.name == null) break candidate;
        } else blk: {
            self.workers.ensureUnusedCapacity(self.allocator, 1) catch return false;
            const created = self.allocator.create(Worker) catch return false;
            created.* = .{ .runtime = self };
            created.thread = std.Thread.spawn(.{}, workerMain, .{created}) catch {
                self.allocator.destroy(created);
                return false;
            };
            self.workers.appendAssumeCapacity(created);
            break :blk created;
        };
        worker.name = identity.name;
        if (worker.request(.{ .start = identity })) return true;
        worker.name = null;
        return false;
    }

    fn startNamed(self: *Runtime, name: []const u8) bool {
        self.identities_mutex.lockUncancelable(io());
        var configured: ?Identity = null;
        for (self.identities) |identity| if (identity.name.eql(name)) {
            configured = identity;
            break;
        };
        self.identities_mutex.unlock(io());
        return self.start(configured orelse return false);
    }

    pub fn stopNamed(self: *Runtime, name: []const u8) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        return requestStop(self.workerNamedLocked(name) orelse return false);
    }

    pub fn setTransport(self: *Runtime, name: []const u8, source: ?storage_model.FixedText(limits.source_capacity)) bool {
        return self.requestNamed(name, .{ .set_transport = source });
    }

    fn sendNamed(self: *Runtime, name: []const u8, value: packet.Frame) bool {
        return self.requestNamed(name, .{ .send_packet = value });
    }

    fn requestNamed(self: *Runtime, name: []const u8, command: Command) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        const worker = self.workerNamedLocked(name) orelse return false;
        if (!worker.running.load(.acquire)) return false;
        return worker.request(command);
    }

    pub fn isActive(self: *Runtime, name: []const u8) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        return self.workerNamedLocked(name) != null;
    }

    fn workerNamedLocked(self: *Runtime, name: []const u8) ?*Worker {
        for (self.workers.items) |worker| if (worker.name) |active| {
            if (active.eql(name)) return worker;
        };
        return null;
    }

    pub fn pollIssue(self: *Runtime) ?Issue {
        return self.issues.pop();
    }

    pub fn runGlobal(self: *Runtime, source: storage_model.FixedText(limits.source_capacity)) bool {
        return self.scheduler.request(.{ .run = source });
    }

    pub fn stopGlobal(self: *Runtime) bool {
        return self.scheduler.request(.stop);
    }

    fn pushIssue(self: *Runtime, issue: Issue) void {
        self.issues_mutex.lockUncancelable(io());
        _ = self.issues.push(issue);
        self.issues_mutex.unlock(io());
    }

    fn requestStop(worker: *Worker) bool {
        if (!worker.running.load(.acquire)) return false;
        worker.running.store(false, .release);
        if (worker.request(.stop)) return true;
        worker.running.store(true, .release);
        return false;
    }
};

const Command = union(enum) {
    start: Identity,
    stop,
    send_packet: packet.Frame,
    set_transport: ?storage_model.FixedText(limits.source_capacity),
};

const Worker = struct {
    runtime: *Runtime,
    name: ?storage_model.FixedText(limits.field_capacity) = null,
    thread: std.Thread = undefined,
    wake: std.Io.Event = .unset,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    commands: ring.SpscRing(Command, limits.runtime_command_capacity) = .{},
    transport: lua.Transport = .{},
    pcap: ?pcap.Handle = null,
    stack: stack.Stack = .{},

    fn request(self: *Worker, command: Command) bool {
        if (!self.commands.push(command)) return false;
        self.wake.set(io());
        return true;
    }

    fn reset(self: *Worker) void {
        self.running.store(false, .release);
        if (self.pcap) |*handle| handle.close();
        self.pcap = null;
        self.transport.deinit();
        self.stack.deinit();
    }
};

fn workerMain(worker: *Worker) void {
    defer worker.reset();
    while (true) {
        worker.wake.reset();
        if (worker.runtime.shutdown.load(.acquire)) return;
        while (worker.commands.pop()) |command| handleCommand(worker, command);
        if (worker.running.load(.acquire)) {
            const received = pollPcap(worker);
            worker.stack.tick();
            if (!received) std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch unreachable;
        } else worker.wake.waitUncancelable(io());
    }
}

fn handleCommand(worker: *Worker, command: Command) void {
    switch (command) {
        .start => |request| startWorker(worker, request),
        .stop => stopWorker(worker),
        .set_transport => |source| {
            if (source) |text| worker.transport.load(text.value(), "transport", worker.runtime.helpers_root) catch |err| {
                report(worker, .transport_update_failed, @errorName(err));
                return;
            } else worker.transport.deinit();
        },
        .send_packet => |value| processFrame(worker, value, .outbound),
    }
}

fn startWorker(worker: *Worker, identity: Identity) void {
    worker.reset();
    if (identity.transport) |source| {
        worker.transport.load(source.value(), "transport", worker.runtime.helpers_root) catch |err| {
            failWorker(worker, @errorName(err));
            return;
        };
    }
    const network = identity.network;
    if (!worker.stack.init(worker.runtime.allocator, network, @ptrCast(worker), workerEgress)) {
        failWorker(worker, "wolfIP stack initialization failed");
        return;
    }
    var error_buffer: [limits.field_capacity]u8 = [_]u8{0} ** limits.field_capacity;
    worker.pcap = pcap.Handle.open(identity.interface.valueZ(), network.mac, network.address, &error_buffer) catch {
        failWorker(worker, std.mem.sliceTo(&error_buffer, 0));
        return;
    };
    worker.running.store(true, .release);
}

fn stopWorker(worker: *Worker) void {
    worker.reset();
    clearName(worker);
}

fn failWorker(worker: *Worker, message: []const u8) void {
    worker.reset();
    report(worker, .failed, message);
    clearName(worker);
}

fn report(worker: *Worker, kind: Issue.Kind, message: []const u8) void {
    var issue: Issue = .{ .kind = kind, .identity = worker.name.? };
    issue.message.set(message) catch unreachable;
    worker.runtime.pushIssue(issue);
}

fn clearName(worker: *Worker) void {
    worker.runtime.workers_mutex.lockUncancelable(io());
    worker.name = null;
    worker.runtime.workers_mutex.unlock(io());
}

fn pollPcap(worker: *Worker) bool {
    const handle = if (worker.pcap) |*value| value else return false;
    var buffer: [packet.capacity]u8 = undefined;
    switch (handle.next(&buffer)) {
        .none => return false,
        .failed => {
            failWorker(worker, "pcap receive failed");
            return true;
        },
        .frame => |length| {
            var value: packet.Frame = .{};
            value.set(buffer[0..length]) catch unreachable;
            processFrame(worker, value, .inbound);
            return true;
        },
    }
}

fn processFrame(worker: *Worker, value: packet.Frame, direction: packet.Direction) void {
    if (worker.transport.loaded()) {
        worker.transport.run(&value, direction, @ptrCast(worker), transmitFromScript) catch |err| {
            report(worker, .packet_dropped, @errorName(err));
        };
        return;
    }
    _ = transmit(worker, direction, &value);
}

fn transmitFromScript(context: ?*anyopaque, direction: packet.Direction, value: *packet.Frame) bool {
    const worker: *Worker = @ptrCast(@alignCast(context orelse return false));
    return transmit(worker, direction, value);
}

fn transmit(worker: *Worker, direction: packet.Direction, current: *const packet.Frame) bool {
    if (direction == .inbound) {
        switch (worker.stack.input(current.bytes[0..current.len])) {
            .accepted => return true,
            .empty, .oversized => return false,
            .inactive => {
                report(worker, .packet_dropped, "wolfIP stack is inactive");
                return false;
            },
        }
    }
    const handle = if (worker.pcap) |*value| value else return false;
    if (handle.inject(current.bytes[0..current.len])) return true;
    report(worker, .packet_dropped, "pcap transmit failed");
    return false;
}

fn workerEgress(context: ?*anyopaque, raw: []const u8) c_int {
    const worker: *Worker = @ptrCast(@alignCast(context orelse return -1));
    var value: packet.Frame = .{};
    value.set(raw) catch return -1;
    processFrame(worker, value, .outbound);
    return 0;
}

const GlobalCommand = union(enum) {
    run: storage_model.FixedText(limits.source_capacity),
    stop,
};

const GlobalScheduler = struct {
    runtime: *Runtime,
    thread: std.Thread = undefined,
    wake: std.Io.Event = .unset,
    commands: ring.SpscRing(GlobalCommand, limits.runtime_command_capacity) = .{},
    heap: lua.FixedLuaHeap(lua.global_heap_size) = .{},
    lua_state: ?*c.lua_State = null,
    lua_thread: ?*c.lua_State = null,
    instruction_count: usize = 0,

    fn request(self: *GlobalScheduler, command: GlobalCommand) bool {
        if (!self.commands.push(command)) return false;
        self.wake.set(io());
        return true;
    }

    fn load(self: *GlobalScheduler, source: storage_model.FixedText(limits.source_capacity)) bool {
        self.deinit();
        const state = c.lua_newstate(allocateGlobal, @ptrCast(self)) orelse return false;
        self.lua_state = state;
        lua.openLibraries(state);
        lua.prependModulePath(state, self.runtime.helpers_root);
        _ = c.lua_pushcclosure(state, globalStart, 0);
        c.lua_setglobal(state, "start_identity");
        _ = c.lua_pushcclosure(state, globalStop, 0);
        c.lua_setglobal(state, "stop_identity");
        _ = c.lua_pushcclosure(state, globalAwait, 0);
        c.lua_setglobal(state, "await");
        _ = c.lua_pushcclosure(state, globalSendRaw, 0);
        c.lua_setglobal(state, "send_raw");
        self.lua_thread = c.lua_newthread(state);
        const thread = self.lua_thread orelse return false;
        const script = source.value();
        if (c.luaL_loadbufferx(thread, script.ptr, script.len, "global", null) != c.LUA_OK) {
            lua.reportError(thread, "Lua compilation error:");
            return false;
        }
        c.lua_sethook(thread, globalBudgetHook, c.LUA_MASKCOUNT, 1000);
        return true;
    }

    fn deinit(self: *GlobalScheduler) void {
        if (self.lua_state) |state| c.lua_close(state);
        self.lua_state = null;
        self.lua_thread = null;
        self.heap.reset();
    }
};

threadlocal var active_scheduler: ?*GlobalScheduler = null;

fn globalMain(scheduler: *GlobalScheduler) void {
    defer scheduler.deinit();
    while (true) {
        scheduler.wake.reset();
        if (scheduler.runtime.shutdown.load(.acquire)) return;
        while (scheduler.commands.pop()) |command| switch (command) {
            .run => |source| if (!scheduler.load(source)) scheduler.deinit(),
            .stop => scheduler.deinit(),
        };
        if (scheduler.lua_thread) |thread| {
            var results: c_int = 0;
            active_scheduler = scheduler;
            scheduler.instruction_count = 0;
            const result = c.lua_resume(thread, null, 0, &results);
            active_scheduler = null;
            if (result == c.LUA_YIELD) {
                std.Io.sleep(io(), .fromMilliseconds(10), .awake) catch unreachable;
                continue;
            }
            if (result != c.LUA_OK) lua.reportError(thread, "Lua runtime error:");
            scheduler.deinit();
        }
        scheduler.wake.waitUncancelable(io());
    }
}

fn allocateGlobal(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    const scheduler: *GlobalScheduler = @ptrCast(@alignCast(user_data orelse return null));
    return scheduler.heap.reallocate(old, old_size, new_size);
}

fn globalStart(state: ?*c.lua_State) callconv(.c) c_int {
    const scheduler = active_scheduler orelse return c.luaL_error(state, "global scheduler unavailable");
    const name = globalName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!scheduler.runtime.startNamed(name)) return c.luaL_error(state, "identity is unavailable or already running");
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
    var value: packet.Frame = .{};
    value.set(raw[0..length]) catch return c.luaL_error(state, "packet exceeds fixed capacity");
    if (!scheduler.runtime.sendNamed(name, value)) return c.luaL_error(state, "identity is not running");
    return 0;
}

fn globalBudgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const scheduler = active_scheduler orelse return;
    scheduler.instruction_count += 1000;
    if (scheduler.instruction_count > lua.max_transport_instructions) _ = c.luaL_error(state, "global instruction budget exceeded");
}

fn globalName(state: ?*c.lua_State) ?[]const u8 {
    var length: usize = 0;
    const value = c.lua_tolstring(state, 1, &length) orelse return null;
    if (length == 0 or length > limits.field_capacity) return null;
    return value[0..length];
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
