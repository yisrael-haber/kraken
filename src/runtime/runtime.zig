const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const pcap_c = @import("pcap_c");
const packet = @import("packet.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const stack = @import("stack.zig");
const pcap = @import("../platform/pcap.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const identity = @import("../identities/identity.zig");
const identity_config = @import("../identities/config.zig");

pub const Issue = struct {
    pub const Kind = enum(u8) { failed, transport_update_failed, packet_dropped };

    kind: Kind,
    identity: text.FixedText(limits.field_capacity),
    message: text.FixedText(limits.field_capacity) = .{},
};

pub const GlobalAction = union(enum) { start: []const u8, stop: []const u8, send_raw: struct { name: []const u8, frame: packet.Frame } };
pub const GlobalControl = struct { context: ?*anyopaque = null, invoke: ?*const fn (?*anyopaque, GlobalAction) bool = null };

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    helpers_root: []u8,
    workers: std.ArrayList(*Worker) = .empty,
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    scheduler: GlobalScheduler = undefined,
    issues: ring.SpscRing(Issue, limits.runtime_issue_capacity) = .{},
    issues_mutex: std.Io.Mutex = .init,
    workers_mutex: std.Io.Mutex = .init,

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
            worker.wake.signal();
            worker.thread.join();
            worker.wake.deinit();
            allocator.destroy(worker);
        }
        self.workers.deinit(allocator);
        allocator.free(self.helpers_root);
        allocator.destroy(self);
    }

    pub fn setGlobalControl(self: *Runtime, control: GlobalControl) void {
        self.scheduler.control = control;
    }

    pub fn start(self: *Runtime, value: identity.Identity, transport: ?text.FixedText(limits.source_capacity)) identity_config.Error!bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        const network = try identity_config.network(&value);
        if (self.workerNamedLocked(value.label.value()) != null) return false;
        var worker: *Worker = for (self.workers.items) |candidate| {
            if (candidate.name == null) break candidate;
        } else blk: {
            self.workers.ensureUnusedCapacity(self.allocator, 1) catch return false;
            const created = self.allocator.create(Worker) catch return false;
            created.* = .{ .runtime = self, .wake = Wake.init() catch {
                self.allocator.destroy(created);
                return false;
            } };
            created.thread = std.Thread.spawn(.{}, workerMain, .{created}) catch {
                created.wake.deinit();
                self.allocator.destroy(created);
                return false;
            };
            self.workers.appendAssumeCapacity(created);
            break :blk created;
        };
        worker.name = value.label;
        if (worker.request(.{ .start = .{ .identity = value, .network = network, .transport = transport } })) return true;
        worker.name = null;
        return false;
    }

    pub fn stopNamed(self: *Runtime, name: []const u8) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        return requestStop(self.workerNamedLocked(name) orelse return false);
    }

    pub fn setTransport(self: *Runtime, name: []const u8, source: ?text.FixedText(limits.source_capacity)) bool {
        self.workers_mutex.lockUncancelable(io());
        defer self.workers_mutex.unlock(io());
        return (self.workerNamedLocked(name) orelse return false).request(.{ .set_transport = source });
    }

    pub fn sendNamed(self: *Runtime, name: []const u8, value: packet.Frame) bool {
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
            if (std.mem.eql(u8, active.value(), name)) return worker;
        };
        return null;
    }

    pub fn pollIssue(self: *Runtime) ?Issue {
        return self.issues.pop();
    }

    pub fn runGlobal(self: *Runtime, source: text.FixedText(limits.source_capacity)) bool {
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
    start: struct { identity: identity.Identity, network: stack.Config, transport: ?text.FixedText(limits.source_capacity) },
    stop,
    send_packet: packet.Frame,
    set_transport: ?text.FixedText(limits.source_capacity),
};

const Wake = switch (builtin.os.tag) {
    .linux => struct {
        fd: std.posix.fd_t,

        fn init() !@This() {
            const fd = std.c.eventfd(0, std.os.linux.EFD.CLOEXEC | std.os.linux.EFD.NONBLOCK);
            if (fd < 0) return error.SystemResources;
            return .{ .fd = fd };
        }

        fn deinit(self: *@This()) void {
            _ = std.c.close(self.fd);
        }

        fn signal(self: *@This()) void {
            const value: u64 = 1;
            if (std.c.write(self.fd, std.mem.asBytes(&value).ptr, @sizeOf(u64)) != @sizeOf(u64)) unreachable;
        }

        fn reset(self: *@This()) void {
            var value: u64 = undefined;
            _ = std.posix.read(self.fd, std.mem.asBytes(&value)) catch |err| switch (err) {
                error.WouldBlock => {},
                else => unreachable,
            };
        }

        fn wait(self: *@This()) void {
            var fd = [_]std.posix.pollfd{.{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 }};
            _ = std.posix.poll(&fd, -1) catch unreachable;
        }
    },
    .windows => struct {
        handle: *anyopaque,

        fn init() !@This() {
            return .{ .handle = pcap_c.CreateEventA(null, 1, 0, null) orelse return error.SystemResources };
        }

        fn deinit(self: *@This()) void {
            if (pcap_c.CloseHandle(self.handle) == 0) unreachable;
        }

        fn signal(self: *@This()) void {
            if (pcap_c.SetEvent(self.handle) == 0) unreachable;
        }

        fn reset(self: *@This()) void {
            if (pcap_c.ResetEvent(self.handle) == 0) unreachable;
        }

        fn wait(self: *@This()) void {
            if (pcap_c.WaitForSingleObject(self.handle, std.math.maxInt(pcap_c.DWORD)) != pcap_c.WAIT_OBJECT_0) unreachable;
        }
    },
    else => @compileError("Kraken supports Linux and Windows"),
};

const Worker = struct {
    runtime: *Runtime,
    name: ?text.FixedText(limits.field_capacity) = null,
    thread: std.Thread = undefined,
    wake: Wake,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    commands: ring.SpscRing(Command, limits.runtime_command_capacity) = .{},
    transport: lua.Transport = .{},
    pcap: ?pcap.Handle = null,
    stack: stack.Stack = .{},

    fn request(self: *Worker, command: Command) bool {
        if (!self.commands.push(command)) return false;
        self.wake.signal();
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
        if (!worker.running.load(.acquire)) {
            worker.wake.wait();
            continue;
        }
        if (waitForWork(worker, worker.stack.tick()) catch {
            failWorker(worker, "pcap wait failed");
            continue;
        }) {
            _ = pollPcap(worker);
        }
    }
}

fn waitForWork(worker: *Worker, timeout: ?u32) error{WaitFailed}!bool {
    const handle = &worker.pcap.?;
    return switch (builtin.os.tag) {
        .linux => blk: {
            var fds = [_]std.posix.pollfd{
                .{ .fd = handle.ready, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = worker.wake.fd, .events = std.posix.POLL.IN, .revents = 0 },
            };
            _ = std.posix.poll(&fds, if (timeout) |milliseconds| @intCast(milliseconds) else -1) catch return error.WaitFailed;
            break :blk fds[1].revents == 0 and fds[0].revents != 0;
        },
        .windows => blk: {
            const handles = [_]pcap_c.HANDLE{ worker.wake.handle, handle.ready };
            break :blk switch (pcap_c.WaitForMultipleObjects(handles.len, &handles, 0, timeout orelse std.math.maxInt(pcap_c.DWORD))) {
                @as(pcap_c.DWORD, @intCast(pcap_c.WAIT_OBJECT_0)) => false,
                @as(pcap_c.DWORD, @intCast(pcap_c.WAIT_OBJECT_0 + 1)) => true,
                @as(pcap_c.DWORD, @intCast(pcap_c.WAIT_TIMEOUT)) => false,
                else => return error.WaitFailed,
            };
        },
        else => unreachable,
    };
}

fn handleCommand(worker: *Worker, command: Command) void {
    switch (command) {
        .start => |request| startWorker(worker, request.identity, request.network, request.transport),
        .stop => stopWorker(worker),
        .set_transport => |source| {
            if (!worker.running.load(.acquire)) return;
            if (source) |source_text| worker.transport.load(source_text.value(), "transport", worker.runtime.helpers_root) catch |err| {
                report(worker, .transport_update_failed, @errorName(err));
                return;
            } else worker.transport.deinit();
        },
        .send_packet => |value| processFrame(worker, value, .outbound),
    }
}

fn startWorker(worker: *Worker, value: identity.Identity, network: stack.Config, source: ?text.FixedText(limits.source_capacity)) void {
    worker.reset();
    if (source) |transport| {
        worker.transport.load(transport.value(), "transport", worker.runtime.helpers_root) catch |err| {
            failWorker(worker, @errorName(err));
            return;
        };
    }
    if (!worker.stack.init(worker.runtime.allocator, network, @ptrCast(worker), workerEgress)) {
        failWorker(worker, "wolfIP stack initialization failed");
        return;
    }
    var error_buffer: [limits.field_capacity]u8 = [_]u8{0} ** limits.field_capacity;
    worker.pcap = pcap.Handle.open(value.interface.bytes[0..value.interface.len :0], network.mac, network.address, &error_buffer) catch {
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
    var buffer: [limits.frame_capacity]u8 = undefined;
    const length = handle.next(&buffer) catch {
        failWorker(worker, "pcap receive failed");
        return true;
    } orelse return false;
    var value: packet.Frame = .{};
    value.set(buffer[0..length]) catch unreachable;
    processFrame(worker, value, .inbound);
    return true;
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
    run: text.FixedText(limits.source_capacity),
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
    control: GlobalControl = .{},

    fn request(self: *GlobalScheduler, command: GlobalCommand) bool {
        if (!self.commands.push(command)) return false;
        self.wake.set(io());
        return true;
    }

    fn load(self: *GlobalScheduler, source: text.FixedText(limits.source_capacity)) bool {
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
    if (!((scheduler.control.invoke orelse return c.luaL_error(state, "identity control unavailable"))(scheduler.control.context, .{ .start = name }))) return c.luaL_error(state, "identity is unavailable or already running");
    return 0;
}

fn globalStop(state: ?*c.lua_State) callconv(.c) c_int {
    const scheduler = active_scheduler orelse return c.luaL_error(state, "global scheduler unavailable");
    const name = globalName(state) orelse return c.luaL_error(state, "identity name is required");
    if (!((scheduler.control.invoke orelse return c.luaL_error(state, "identity control unavailable"))(scheduler.control.context, .{ .stop = name }))) return c.luaL_error(state, "identity is not running");
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
    if (!((scheduler.control.invoke orelse return c.luaL_error(state, "identity control unavailable"))(scheduler.control.context, .{ .send_raw = .{ .name = name, .frame = value } }))) return c.luaL_error(state, "identity is not running");
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
