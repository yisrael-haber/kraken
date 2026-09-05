const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const stack = @import("stack.zig");
const pcap = @import("../platform/pcap.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const log = @import("../log.zig");
const c = @import("c");

/// Manager-owned registry for per-identity network workers.
pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    helpers_root: []const u8,
    logger: *log.Logger,
    workers: std.StringArrayHashMapUnmanaged(*Worker) = .empty,

    pub fn init(self: *WorkerPool, allocator: std.mem.Allocator, helpers_root: []const u8, logger: *log.Logger) void {
        self.* = .{ .allocator = allocator, .helpers_root = helpers_root, .logger = logger };
    }

    pub fn deinit(self: *WorkerPool) void {
        for (self.workers.values()) |worker| worker.deinit(self.allocator);
        self.workers.deinit(self.allocator);
    }

    pub fn start(self: *WorkerPool, value: *const identity.Identity, transport: ?text.FixedText(limits.source_capacity)) stack.Error!bool {
        if (self.workers.get(value.label.value()) != null) return false;
        const worker = try Worker.create(self.allocator, self.helpers_root, self.logger, value, transport) orelse return false;
        self.workers.putNoClobber(self.allocator, worker.name.value(), worker) catch {
            worker.deinit(self.allocator);
            return false;
        };
        return true;
    }

    pub fn execute(self: *WorkerPool, request: command.Command) bool {
        switch (request) {
            .stop => |name| {
                const worker = self.workers.fetchSwapRemove(name.value()) orelse return false;
                worker.value.deinit(self.allocator);
                return true;
            },
            .set_transport => |selection| return self.admit(selection.name.value(), request),
            .send_packet => |packet| return self.admit(packet.name.value(), request),
            else => unreachable,
        }
    }

    pub fn isInUse(self: *const WorkerPool, name: []const u8) bool {
        return self.workers.contains(name);
    }

    fn admit(self: *WorkerPool, name: []const u8, request: command.Command) bool {
        const worker = self.workers.get(name) orelse return false;
        if (!worker.commands.push(request)) return false;
        worker.wake.signal();
        return true;
    }
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
    },
    .windows => struct {
        handle: windows.HANDLE,

        fn init() !@This() {
            return .{ .handle = CreateEventA(null, .TRUE, .FALSE, null) orelse return error.SystemResources };
        }

        fn deinit(self: *@This()) void {
            windows.CloseHandle(self.handle);
        }

        fn signal(self: *@This()) void {
            if (SetEvent(self.handle) == .FALSE) unreachable;
        }

        fn reset(self: *@This()) void {
            if (ResetEvent(self.handle) == .FALSE) unreachable;
        }
    },
    else => @compileError("Kraken supports Linux and Windows"),
};

const Worker = struct {
    name: text.FieldText,
    logger: *log.Logger,
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: std.Thread = undefined,
    wake: Wake,
    commands: ring.SpscRing(command.Command, limits.runtime_command_capacity) = .{},
    script: ?text.FixedText(limits.source_capacity) = null,
    transport: lua.Transport = .{},
    pcap: pcap.Handle = undefined,
    stack: stack.Stack = undefined,

    fn create(allocator: std.mem.Allocator, helpers_root: []const u8, logger: *log.Logger, value: *const identity.Identity, script: ?text.FixedText(limits.source_capacity)) stack.Error!?*Worker {
        const self = allocator.create(Worker) catch return null;
        errdefer allocator.destroy(self);
        self.* = .{
            .name = value.label,
            .logger = logger,
            .script = script,
            .transport = .{ .helpers_root = helpers_root, .logger = logger },
            .wake = Wake.init() catch return null,
        };
        errdefer self.wake.deinit();
        if (!try self.stack.init(allocator, value, @ptrCast(self), workerEgress)) return null;
        errdefer self.stack.deinit();
        self.pcap = pcap.Handle.open(value) catch return null;
        errdefer self.pcap.close();
        self.thread = std.Thread.spawn(.{}, Worker.run, .{self}) catch return null;
        return self;
    }

    fn deinit(self: *Worker, allocator: std.mem.Allocator) void {
        self.closing.store(true, .release);
        self.wake.signal();
        self.thread.join();
        self.wake.deinit();
        allocator.destroy(self);
    }

    fn run(self: *Worker) void {
        defer {
            self.transport.deinit();
            self.pcap.close();
            self.stack.deinit();
        }
        self.setTransport(self.script);
        while (true) {
            self.wake.reset();
            if (self.closing.load(.acquire)) return;
            while (self.commands.pop()) |queued| self.dispatch(queued);
            waitForWork(self) catch {
                self.report("pcap wait failed");
                return;
            };
            var buffer: [limits.frame_capacity]u8 = undefined;
            const length = self.pcap.next(&buffer) catch {
                self.report("pcap receive failed");
                return;
            } orelse continue;
            var value: frame.Frame = .{};
            value.set(buffer[0..length]) catch unreachable;
            processFrame(self, value, .inbound);
        }
    }

    fn dispatch(self: *Worker, request: command.Command) void {
        switch (request) {
            .set_transport => |selection| self.setTransport(if (selection.script) |script| script.source else null),
            .send_packet => |packet| processFrame(self, packet.value, .outbound),
            else => unreachable,
        }
    }

    fn setTransport(self: *Worker, script: ?text.FixedText(limits.source_capacity)) void {
        self.script = script;
        if (script) |source| self.transport.init(source.value()) catch |err| self.report(@errorName(err)) else self.transport.deinit();
    }

    fn report(self: *Worker, message: []const u8) void {
        var buffer: [2 * limits.field_capacity + 32:0]u8 = undefined;
        const output = std.fmt.bufPrintZ(&buffer, "{s}: {s}", .{ self.name.value(), message }) catch return;
        self.logger.err(.runtime, output);
    }
};

fn waitForWork(worker: *Worker) error{WaitFailed}!void {
    const timeout = worker.stack.tick();
    switch (builtin.os.tag) {
        .linux => {
            var fds = [_]std.posix.pollfd{
                .{ .fd = worker.pcap.ready, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = worker.wake.fd, .events = std.posix.POLL.IN, .revents = 0 },
            };
            _ = std.posix.poll(&fds, if (timeout) |milliseconds| @intCast(milliseconds) else -1) catch return error.WaitFailed;
        },
        .windows => {
            const handles = [_]windows.HANDLE{ worker.wake.handle, worker.pcap.ready };
            const result = WaitForMultipleObjects(handles.len, &handles, .FALSE, timeout orelse std.math.maxInt(windows.DWORD));
            if (result != 0 and result != 1 and result != 258) return error.WaitFailed;
        },
        else => unreachable,
    }
}

fn processFrame(worker: *Worker, value: frame.Frame, direction: frame.Direction) void {
    if (worker.script != null) {
        const invocation: lua.Invocation = .{ .packet = &value, .direction = direction, .send = scriptSend, .context = @ptrCast(worker) };
        worker.transport.run(&invocation) catch return;
    } else {
        _ = transmit(@ptrCast(worker), direction, &value);
    }
}

extern "kernel32" fn CreateEventA(security: ?*anyopaque, manual_reset: windows.BOOL, initial_state: windows.BOOL, name: ?[*:0]const u8) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn SetEvent(handle: windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ResetEvent(handle: windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn WaitForMultipleObjects(count: windows.DWORD, handles: [*]const windows.HANDLE, wait_all: windows.BOOL, timeout: windows.DWORD) callconv(.winapi) windows.DWORD;

fn scriptSend(state: ?*c.lua_State) callconv(.c) c_int {
    const invocation: *const lua.Invocation = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    const packet = frame.Frame.fromLua(state) catch return c.luaL_error(state, "packet table contains an invalid or oversized value");
    return if (transmit(invocation.context, invocation.direction, &packet)) 0 else c.luaL_error(state, "packet transmission failed");
}

fn transmit(context: *anyopaque, direction: frame.Direction, current: *const frame.Frame) bool {
    const worker: *Worker = @ptrCast(@alignCast(context));
    if (direction == .inbound) return worker.stack.input(current.bytes[0..current.len]);
    const sent = worker.pcap.inject(current.bytes[0..current.len]);
    if (!sent) worker.report("pcap transmit failed");
    return sent;
}

fn workerEgress(device: ?*c.struct_wolfIP_ll_dev, raw: ?*anyopaque, length: u32) callconv(.c) c_int {
    const worker: *Worker = @ptrCast(@alignCast(device.?.priv.?));
    const bytes: [*]const u8 = @ptrCast(raw.?);
    var value: frame.Frame = .{};
    value.set(bytes[0..length]) catch return -1;
    processFrame(worker, value, .outbound);
    return @intCast(length);
}
