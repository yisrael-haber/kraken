const std = @import("std");
const builtin = @import("builtin");
const pcap_c = @import("pcap_c");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const stack = @import("stack.zig");
const pcap = @import("../platform/pcap.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const identity = @import("../identities/identity.zig");
const identity_config = @import("../identities/config.zig");
const c = @import("c");

pub const Issue = struct {
    pub const Kind = enum(u8) { failed, packet_dropped };

    kind: Kind,
    identity: text.FieldText,
    message: text.FieldText = .{},
};

/// UI-thread-owned registry for per-identity network workers.
pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    transport_pool: lua.TransportPool,
    workers: std.ArrayList(*Worker) = .empty,

    pub fn init(self: *WorkerPool, allocator: std.mem.Allocator, helpers_root: []const u8) void {
        self.* = .{ .allocator = allocator, .transport_pool = .{ .helpers_root = helpers_root } };
    }

    pub fn deinit(self: *WorkerPool) void {
        for (self.workers.items) |worker| worker.deinit();
        self.workers.deinit(self.allocator);
    }

    pub fn start(self: *WorkerPool, value: identity.Identity, transport: ?text.FixedText(limits.source_capacity)) identity_config.Error!bool {
        const network = try identity_config.network(&value);
        if (self.workerNamed(value.label.value()) != null) return false;
        const worker = self.availableWorker() orelse return false;
        worker.name = value.label;
        worker.state.store(.starting, .release);
        if (worker.request(.{ .start = .{ .identity = value, .network = network, .transport = transport } })) return true;
        _ = worker.state.cmpxchgStrong(.starting, .idle, .release, .monotonic);
        return false;
    }

    pub fn stopNamed(self: *WorkerPool, name: []const u8) bool {
        return self.requestNamed(name, .stop);
    }

    pub fn setTransport(self: *WorkerPool, name: []const u8, source: ?text.FixedText(limits.source_capacity)) bool {
        return self.requestNamed(name, .{ .set_transport = source });
    }

    pub fn sendNamed(self: *WorkerPool, name: []const u8, value: frame.Frame) bool {
        return self.requestNamed(name, .{ .send_packet = value });
    }

    pub fn isInUse(self: *const WorkerPool, name: []const u8) bool {
        return self.workerNamed(name) != null;
    }

    pub fn pollIssue(self: *WorkerPool) ?Issue {
        for (self.workers.items) |worker| if (worker.issues.pop()) |issue| return issue;
        return null;
    }

    fn requestNamed(self: *WorkerPool, name: []const u8, command: Command) bool {
        const worker = self.workerNamed(name) orelse return false;
        return worker.request(command);
    }

    fn workerNamed(self: *const WorkerPool, name: []const u8) ?*Worker {
        for (self.workers.items) |worker| {
            if (worker.state.load(.acquire) == .idle) continue;
            if (std.mem.eql(u8, worker.name.value(), name)) return worker;
        }
        return null;
    }

    fn availableWorker(self: *WorkerPool) ?*Worker {
        for (self.workers.items) |worker| if (worker.state.load(.acquire) == .idle) return worker;
        self.workers.ensureUnusedCapacity(self.allocator, 1) catch return null;
        const worker = Worker.create(self.allocator, &self.transport_pool) orelse return null;
        self.workers.appendAssumeCapacity(worker);
        return worker;
    }
};

const Command = union(enum) {
    start: struct { identity: identity.Identity, network: stack.Config, transport: ?text.FixedText(limits.source_capacity) },
    stop,
    send_packet: frame.Frame,
    set_transport: ?text.FixedText(limits.source_capacity),
};

const State = enum(u8) { idle, starting, active, stopping };

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
    allocator: std.mem.Allocator,
    transport_pool: *lua.TransportPool,
    name: text.FieldText = .{},
    state: std.atomic.Value(State) = std.atomic.Value(State).init(.idle),
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: std.Thread = undefined,
    wake: Wake,
    commands: ring.SpscRing(Command, limits.runtime_command_capacity) = .{},
    issues: ring.SpscRing(Issue, limits.runtime_issue_capacity) = .{},
    transport: ?text.FixedText(limits.source_capacity) = null,
    pcap: ?pcap.Handle = null,
    stack: stack.Stack = .{},

    fn create(allocator: std.mem.Allocator, transport_pool: *lua.TransportPool) ?*Worker {
        const self = allocator.create(Worker) catch return null;
        errdefer allocator.destroy(self);
        self.* = .{ .allocator = allocator, .transport_pool = transport_pool, .wake = Wake.init() catch return null };
        self.thread = std.Thread.spawn(.{}, Worker.run, .{self}) catch {
            self.wake.deinit();
            return null;
        };
        return self;
    }

    fn deinit(self: *Worker) void {
        self.closing.store(true, .release);
        self.wake.signal();
        self.thread.join();
        self.wake.deinit();
        self.allocator.destroy(self);
    }

    fn request(self: *Worker, command: Command) bool {
        switch (command) {
            .start => if (self.state.load(.acquire) != .starting) return false,
            .stop => {
                if (self.state.cmpxchgStrong(.active, .stopping, .acq_rel, .acquire) != null) return false;
                if (self.enqueue(command)) return true;
                _ = self.state.cmpxchgStrong(.stopping, .active, .release, .monotonic);
                return false;
            },
            .send_packet => if (self.state.load(.acquire) != .active) return false,
            .set_transport => switch (self.state.load(.acquire)) {
                .starting, .active => {},
                else => return false,
            },
        }
        return self.enqueue(command);
    }

    fn enqueue(self: *Worker, command: Command) bool {
        if (!self.commands.push(command)) return false;
        self.wake.signal();
        return true;
    }

    fn reset(self: *Worker) void {
        if (self.pcap) |*pcap_handle| pcap_handle.close();
        self.pcap = null;
        self.transport = null;
        self.stack.deinit();
    }

    fn run(self: *Worker) void {
        defer self.reset();
        while (true) {
            self.wake.reset();
            if (self.closing.load(.acquire)) return;
            while (self.commands.pop()) |command| self.dispatch(command);
            if (self.closing.load(.acquire)) return;
            if (self.state.load(.acquire) != .active) {
                self.wake.wait();
                continue;
            }
            if (waitForWork(self, self.stack.tick()) catch {
                self.finish("pcap wait failed");
                continue;
            }) _ = pollPcap(self);
        }
    }

    fn dispatch(self: *Worker, command: Command) void {
        switch (command) {
            .start => |start_request| self.start(start_request.identity, start_request.network, start_request.transport),
            .stop => self.finish(null),
            .set_transport => |source| {
                if (self.state.load(.acquire) != .active) return;
                self.transport = source;
            },
            .send_packet => |value| if (self.state.load(.acquire) == .active) processFrame(self, value, .outbound),
        }
    }

    fn start(self: *Worker, value: identity.Identity, network: stack.Config, source: ?text.FixedText(limits.source_capacity)) void {
        self.reset();
        self.transport = source;
        if (!self.stack.init(self.allocator, network, @ptrCast(self), workerEgress)) return self.finish("wolfIP stack initialization failed");
        var error_buffer: [limits.field_capacity]u8 = [_]u8{0} ** limits.field_capacity;
        self.pcap = pcap.Handle.open(value.interface.bytes[0..value.interface.len :0], network.mac, network.address, &error_buffer) catch {
            self.finish(std.mem.sliceTo(&error_buffer, 0));
            return;
        };
        self.state.store(.active, .release);
    }

    fn finish(self: *Worker, failure: ?[]const u8) void {
        self.reset();
        if (failure) |message| self.report(.failed, message);
        self.state.store(.idle, .release);
    }

    fn report(self: *Worker, kind: Issue.Kind, message: []const u8) void {
        var issue: Issue = .{ .kind = kind, .identity = self.name };
        issue.message.set(message) catch unreachable;
        _ = self.issues.push(issue);
    }
};

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

fn pollPcap(worker: *Worker) bool {
    const handle = if (worker.pcap) |*value| value else return false;
    var buffer: [limits.frame_capacity]u8 = undefined;
    const length = handle.next(&buffer) catch {
        worker.finish("pcap receive failed");
        return true;
    } orelse return false;
    var value: frame.Frame = .{};
    value.set(buffer[0..length]) catch unreachable;
    processFrame(worker, value, .inbound);
    return true;
}

fn processFrame(worker: *Worker, value: frame.Frame, direction: frame.Direction) void {
    if (worker.transport) |source| {
        var invocation: ScriptInvocation = .{ .worker = worker, .direction = direction };
        const heap = worker.transport_pool.acquire() orelse {
            worker.report(.packet_dropped, "transport busy");
            return;
        };
        defer worker.transport_pool.release(heap);
        var lua_invocation: lua.Invocation = .{ .heap = heap, .script = source.value(), .helpers_root = worker.transport_pool.helpers_root, .packet = &value, .direction = direction };
        lua.runTransport(&lua_invocation, scriptSend, @ptrCast(&invocation)) catch |err| {
            worker.report(.packet_dropped, @errorName(err));
        };
        return;
    }
    _ = transmit(worker, direction, &value);
}

const ScriptInvocation = struct {
    worker: *Worker,
    direction: frame.Direction,
};

fn scriptSend(state: ?*c.lua_State) callconv(.c) c_int {
    const raw = c.lua_touserdata(state, c.lua_upvalueindex(1)) orelse return c.luaL_error(state, "packet is no longer active");
    const invocation: *ScriptInvocation = @ptrCast(@alignCast(raw));
    const value = frame.Frame.fromLua(state) catch return c.luaL_error(state, "packet table contains an invalid or oversized value");
    if (!transmit(invocation.worker, invocation.direction, &value)) return c.luaL_error(state, "packet transmission failed");
    return 0;
}

fn transmit(worker: *Worker, direction: frame.Direction, current: *const frame.Frame) bool {
    if (direction == .inbound) {
        switch (worker.stack.input(current.bytes[0..current.len])) {
            .accepted => return true,
            .empty, .oversized => return false,
            .inactive => {
                worker.report(.packet_dropped, "wolfIP stack is inactive");
                return false;
            },
        }
    }
    const handle = if (worker.pcap) |*value| value else return false;
    if (handle.inject(current.bytes[0..current.len])) return true;
    worker.report(.packet_dropped, "pcap transmit failed");
    return false;
}

fn workerEgress(context: ?*anyopaque, raw: []const u8) c_int {
    const worker: *Worker = @ptrCast(@alignCast(context orelse return -1));
    var value: frame.Frame = .{};
    value.set(raw) catch return -1;
    processFrame(worker, value, .outbound);
    return 0;
}
