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
    next_run: u64 = 1,

    pub fn init(self: *WorkerPool, allocator: std.mem.Allocator, helpers_root: []const u8, logger: *log.Logger) void {
        self.* = .{ .allocator = allocator, .helpers_root = helpers_root, .logger = logger };
    }

    pub fn deinit(self: *WorkerPool) void {
        for (self.workers.values()) |worker| worker.deinit(self.allocator);
        self.workers.deinit(self.allocator);
    }

    pub fn start(self: *WorkerPool, value: *const identity.Identity, transport: ?text.FixedText(limits.source_capacity)) stack.Error!bool {
        if (self.workers.get(value.label.value()) != null) return false;
        const run = self.next_run;
        self.next_run +%= 1;
        const worker = try Worker.create(self.allocator, self.helpers_root, self.logger, value, transport, run) orelse return false;
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
            .socket => |call| return self.admit(call.socket.identity.value(), request),
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
    run_id: u64,
    logger: *log.Logger,
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: std.Thread = undefined,
    wake: Wake,
    commands: ring.SpscRing(command.Command, limits.runtime_command_capacity) = .{},
    script_selected: bool = false,
    transport: lua.Transport = .{},
    pcap: pcap.Handle = undefined,
    stack: stack.Stack = undefined,

    fn create(allocator: std.mem.Allocator, helpers_root: []const u8, logger: *log.Logger, value: *const identity.Identity, script: ?text.FixedText(limits.source_capacity), run_id: u64) stack.Error!?*Worker {
        const self = allocator.create(Worker) catch return null;
        errdefer allocator.destroy(self);
        self.* = .{
            .name = value.label,
            .run_id = run_id,
            .logger = logger,
            .transport = .{ .helpers_root = helpers_root, .logger = logger },
            .wake = Wake.init() catch return null,
        };
        errdefer self.wake.deinit();
        if (!try self.stack.init(allocator, value, @ptrCast(self), workerEgress)) return null;
        errdefer self.stack.deinit();
        self.pcap = pcap.Handle.open(value) orelse return null;
        errdefer self.pcap.close();
        if (script) |source| _ = self.commands.push(.{ .set_transport = .{ .name = value.label, .script = .{ .name = .{}, .source = source } } });
        self.thread = std.Thread.spawn(.{}, Worker.run, .{self}) catch return null;
        return self;
    }

    fn deinit(self: *Worker, allocator: std.mem.Allocator) void {
        self.closing.store(true, .release);
        self.wake.signal();
        self.thread.join();
        while (self.commands.pop()) |request| if (request == .socket) request.socket.done.set(io());
        self.wake.deinit();
        allocator.destroy(self);
    }

    fn run(self: *Worker) void {
        defer {
            self.transport.deinit();
            self.pcap.close();
            self.stack.deinit();
        }
        while (!self.closing.load(.acquire)) {
            self.receive(null) catch return;
        }
    }

    fn receive(self: *Worker, maximum_wait: ?u32) !void {
        errdefer |err| self.report(@errorName(err));
        self.wake.reset();
        while (self.commands.pop()) |queued| self.dispatch(queued);
        if (self.closing.load(.acquire)) return;
        var timeout = self.stack.tick();
        if (maximum_wait) |limit| timeout = @min(timeout orelse limit, limit);
        switch (builtin.os.tag) {
            .linux => {
                var fds = [_]std.posix.pollfd{
                    .{ .fd = self.pcap.ready, .events = std.posix.POLL.IN, .revents = 0 },
                    .{ .fd = self.wake.fd, .events = std.posix.POLL.IN, .revents = 0 },
                };
                _ = std.posix.poll(&fds, if (timeout) |milliseconds| @intCast(milliseconds) else -1) catch return error.WaitFailed;
            },
            .windows => {
                const handles = [_]windows.HANDLE{ self.wake.handle, self.pcap.ready };
                const result = WaitForMultipleObjects(handles.len, &handles, .FALSE, timeout orelse std.math.maxInt(windows.DWORD));
                if (result != 0 and result != 1 and result != 258) return error.WaitFailed;
            },
            else => unreachable,
        }
        var value: frame.Frame = .{};
        const length = try self.pcap.next(&value.bytes) orelse return;
        value.len = @intCast(length);
        processFrame(self, value, .inbound);
    }

    fn dispatch(self: *Worker, request: command.Command) void {
        switch (request) {
            .set_transport => |selection| self.setTransport(if (selection.script) |script| script.source else null),
            .send_packet => |packet| processFrame(self, packet.value, .outbound),
            .socket => |call| self.socket(call),
            else => unreachable,
        }
    }

    fn socket(self: *Worker, call: *command.SocketCall) void {
        defer call.done.set(io());
        const creating = call.action == .connect or call.action == .bind;
        if (!creating and call.socket.run != self.run_id) return;
        if (creating) call.socket.run = self.run_id;
        const length = call.bytes.len;
        defer if (creating and call.result < 0) {
            call.action = .close;
            _ = self.stack.socket(call);
            call.socket.descriptor = -1;
        };
        call.result = operation: while (!self.closing.load(.acquire)) {
            if (call.cancelled.load(.acquire) and call.action != .close) break :operation -1;
            const result = self.stack.socket(call);
            if (call.action == .close and result == -c.WOLFIP_EAGAIN) break :operation 0;
            const transferring = call.action == .send or call.action == .receive;
            if (result >= 0) {
                if (!transferring) break :operation result;
                if (result == 0 and call.socket.tcp) break :operation -1;
                call.bytes = call.bytes[@intCast(result)..];
                call.socket.handshaking = false;
                if (!call.socket.tcp or call.bytes.len == 0) break :operation @intCast(length - call.bytes.len);
            } else if (result != -c.WOLFIP_EAGAIN and !(transferring and call.socket.handshaking and result == -1)) break :operation result;
            const now: u64 = @intCast(std.Io.Clock.awake.now(io()).toMilliseconds());
            const remaining = (call.deadline orelse std.math.maxInt(u64)) -| now;
            if (remaining == 0) break :operation -c.WOLFIP_EAGAIN;
            self.receive(@intCast(@min(remaining, 50))) catch break :operation -1;
        } else -1;
    }

    fn setTransport(self: *Worker, script: ?text.FixedText(limits.source_capacity)) void {
        self.script_selected = script != null;
        var scope_buffer: [text.FieldText.capacity + 32]u8 = undefined;
        const scope = std.fmt.bufPrint(&scope_buffer, "Identity \"{s}\" transport", .{self.name.value()}) catch unreachable;
        if (script) |source| self.transport.init(source.value(), scope) catch |err| switch (err) {
            error.ScriptFailed => {},
            error.OutOfMemory => self.report("transport Lua state allocation failed"),
        } else self.transport.deinit();
    }

    fn report(self: *Worker, message: []const u8) void {
        self.logger.formatted(.err, .runtime, "Identity \"{s}\": {s}.", .{ self.name.value(), message });
    }
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn processFrame(worker: *Worker, value: frame.Frame, direction: frame.Direction) void {
    if (worker.script_selected) {
        const invocation: lua.Invocation = .{ .packet = &value, .direction = direction, .send = scriptSend, .context = @ptrCast(worker) };
        worker.transport.run(&invocation) catch return;
    } else if (!transmit(@ptrCast(worker), direction, &value) and direction == .outbound) worker.report("pcap transmit failed");
}

extern "kernel32" fn CreateEventA(security: ?*anyopaque, manual_reset: windows.BOOL, initial_state: windows.BOOL, name: ?[*:0]const u8) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn SetEvent(handle: windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ResetEvent(handle: windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn WaitForMultipleObjects(count: windows.DWORD, handles: [*]const windows.HANDLE, wait_all: windows.BOOL, timeout: windows.DWORD) callconv(.winapi) windows.DWORD;

fn scriptSend(state: ?*c.lua_State) callconv(.c) c_int {
    const invocation: *const lua.Invocation = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    if (!c.lua_isnoneornil(state, 2) and c.lua_type(state, 2) != c.LUA_TBOOLEAN) return c.luaL_argerror(state, 2, "expected boolean");
    var packet = frame.Frame.fromLua(state) catch return c.luaL_error(state, "packet table contains an invalid or oversized value");
    if (c.lua_isnoneornil(state, 2) or c.lua_toboolean(state, 2) != 0) packet.recalculateChecksums() catch return c.luaL_error(state, "cannot recalculate checksums for malformed packet; use send(false) to preserve bytes");
    return if (transmit(invocation.context, invocation.direction, &packet)) 0 else c.luaL_error(state, "packet transmission failed");
}

fn transmit(context: *anyopaque, direction: frame.Direction, current: *const frame.Frame) bool {
    const worker: *Worker = @ptrCast(@alignCast(context));
    if (direction == .inbound) return worker.stack.input(current.bytes[0..current.len]);
    return worker.pcap.inject(current.bytes[0..current.len]);
}

fn workerEgress(device: ?*c.struct_wolfIP_ll_dev, raw: ?*anyopaque, length: u32) callconv(.c) c_int {
    const worker: *Worker = @ptrCast(@alignCast(device.?.priv.?));
    const bytes: [*]const u8 = @ptrCast(raw.?);
    var value: frame.Frame = .{};
    value.set(bytes[0..length]) catch return -1;
    processFrame(worker, value, .outbound);
    return @intCast(length);
}
