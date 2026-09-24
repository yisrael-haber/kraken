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
const Request = struct {
    command: command.Command,
    done: std.Io.Event = .unset,
    result: ?Error = null,
};

const TransportRun = struct {
    vm: lua.VM = .{},
    arena: [limits.transport_lua_heap_capacity]u8 align(16) = undefined,
    packet: frame.Frame = .{},
    identity: text.FieldText = .{},
    direction: frame.Direction = .inbound,
};

pub const IdentityView = struct { value: identity.Identity, active: bool };

pub const Error = stack.Error || error{
    InterfaceRequired,
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    RuntimeUnavailable,
    StorageFailure,
    TransmissionFailed,
    TransportScriptUnavailable,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    storage: *storage_module.Storage,
    globals: globals.Store = .{},
    global: lua.VM = .{},
    global_arena: [limits.global_lua_heap_capacity]u8 align(16) = undefined,
    catalog: std.ArrayList(identity.Identity) = .empty,
    catalog_mutex: std.Io.Mutex = .init,
    commands: ring.MpscRing(*Request, limits.runtime_command_capacity) = .{},
    runtimes: std.StringArrayHashMapUnmanaged(*Runtime) = .empty,
    closing: std.Io.Event = .unset,
    thread: std.Thread = undefined,
    wake: wait.Wake = undefined,
    handles: std.ArrayList(wait.Handle) = .empty,
    next_run: u64 = 1,
    transport_runs: *[transport_vm_slots]TransportRun = undefined,

    pub fn init(self: *Manager, allocator: std.mem.Allocator, storage: *storage_module.Storage) !void {
        self.* = .{ .allocator = allocator, .storage = storage };
        self.transport_runs = try allocator.create([transport_vm_slots]TransportRun);
        errdefer allocator.destroy(self.transport_runs);
        for (self.transport_runs) |*transport| transport.* = .{};
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
        for (self.transport_runs) |*transport| transport.vm.cancel();
        self.closing.set(io());
        self.wake.signal();
        self.thread.join();
        for (self.transport_runs) |*transport| transport.vm.join();
        self.wake.deinit();
        self.handles.deinit(self.allocator);
        for (self.runtimes.values()) |runtime| runtime.deinit();
        self.runtimes.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        self.allocator.destroy(self.transport_runs);
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

    // The global VM belongs to the UI thread: only it starts and stops it.
    pub fn runGlobal(self: *Manager, name: []const u8, source: []const u8) bool {
        if (self.global.running()) return false;
        var scope: [lua.scope_capacity]u8 = undefined;
        const value = std.fmt.bufPrint(&scope, "global \"{s}\"", .{name}) catch return false;
        self.global.start(self, &self.global_arena, value, source, .chunk) catch return false;
        log.logger.formatted(.info, .lua, "{s}: started.", .{value});
        return true;
    }

    pub fn stopGlobal(self: *Manager) void {
        self.global.cancel();
        self.global.join();
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
            .transmit => |packet| {
                const runtime = self.runtimes.get(packet.name.value()) orelse return error.RuntimeUnavailable;
                if (!runtime.inject(packet.value.bytes[0..packet.value.len], packet.direction)) return error.TransmissionFailed;
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
        var pending: std.ArrayList(*Request) = .empty;
        defer {
            self.commands.close();
            for (pending.items) |request| {
                request.command.socket.result = -1;
                request.done.set(io());
            }
            pending.deinit(self.allocator);
            while (self.commands.pop()) |request| {
                if (request.command == .socket) request.command.socket.result = -1;
                request.result = error.RuntimeUnavailable;
                request.done.set(io());
            }
        }
        while (!self.closing.isSet()) {
            self.wake.reset();
            while (self.commands.pop()) |request| {
                if (request.command == .socket) {
                    request.command.socket.result = 0;
                    pending.append(self.allocator, request) catch {
                        request.result = error.RuntimeUnavailable;
                        request.done.set(io());
                    };
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
            var pending_index: usize = 0;
            while (pending_index < pending.items.len) {
                const request = pending.items[pending_index];
                const call = request.command.socket;
                const remaining = call.bytes.len;
                const descriptor = call.socket.descriptor;
                // Cancellation never blocks close, so a cancelled VM still releases its sockets.
                const completed = if (call.cancelled.isSet() and call.action != .close) cancelled: {
                    call.result = -1;
                    break :cancelled true;
                } else if (self.runtimes.get(call.socket.identity.value())) |runtime|
                    runtime.socket(call)
                else blk: {
                    call.result = -1;
                    break :blk true;
                };
                if (completed) {
                    _ = pending.swapRemove(pending_index);
                    deadline = 0; // Flush work queued by this socket operation.
                    request.done.set(io());
                    continue;
                }
                if (call.bytes.len != remaining or call.socket.descriptor != descriptor) {
                    deadline = 0;
                } else {
                    deadline = @min(deadline, call.deadline orelse std.math.maxInt(u64));
                }
                pending_index += 1;
            }
            if (self.closing.isSet()) break;
            wait.wait(self.handles.items, if (deadline == std.math.maxInt(u64)) null else deadline -| now()) catch |err| {
                log.logger.formatted(.err, .runtime, "Runtime wait failed: {s}.", .{@errorName(err)});
                std.process.exit(1);
            };
        }
    }
};

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
            const result = self.stack.socket(call.action, call.socket, call.address, call.bytes);
            if (call.action == .close and result == -c.WOLFIP_EAGAIN) break :operation 0;
            const transferring = call.action == .send or call.action == .receive;
            if (result >= 0) {
                if (transferring) call.socket.handshaking = false;
                // A receive returns what is available; zero on TCP means the peer closed.
                if (call.action != .send) break :operation result;
                if (result == 0 and call.socket.kind == .tcp) break :operation -1;
                call.bytes = call.bytes[@intCast(result)..];
                call.result += result;
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
    const run = for (manager.transport_runs) |*candidate| {
        if (!candidate.vm.running()) break candidate;
    } else return runtime.report("transport VM slots exhausted");
    run.packet.set(bytes) catch return runtime.report("transport packet exceeds capacity");
    run.identity = runtime.name;
    run.direction = direction;
    var scope: [lua.scope_capacity]u8 = undefined;
    const value = std.fmt.bufPrint(&scope, "transport \"{s}\"", .{runtime.name.value()}) catch unreachable;
    run.vm.start(manager, &run.arena, value, source, .{ .call = .{
        .name = "transport",
        .arguments = pushTransportArguments,
        .data = run,
    } }) catch runtime.report("transport VM thread failed");
}

fn pushTransportArguments(state: ?*c.lua_State, data: *anyopaque) c_int {
    const run: *TransportRun = @ptrCast(@alignCast(data));
    _ = c.lua_pushlstring(state, &run.packet.bytes, run.packet.len);
    _ = c.lua_pushlstring(state, run.identity.value().ptr, run.identity.len);
    _ = c.lua_pushstring(state, @tagName(run.direction));
    return 3;
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

test "VMs cancel, run one global at a time, reuse slots, and call the transport entry" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    try log.logger.init(allocator, config_dir);
    defer log.logger.deinit();
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    var storage: storage_module.Storage = .{ .allocator = allocator, .config_dir = config_dir, .scratch = &scratch };
    const manager = try allocator.create(Manager);
    defer allocator.destroy(manager);
    try manager.init(allocator, &storage);
    defer manager.deinit();

    try std.testing.expect(manager.runGlobal("sleeper", "require('kraken/std').sleep(60000)"));
    try std.testing.expect(!manager.runGlobal("second", ""));
    manager.stopGlobal();
    try std.testing.expect(!manager.global.running());

    try std.testing.expect(manager.runGlobal("modules",
        \\for _, name in ipairs({ "packet", "transmit", "socket", "identities", "globals", "std" }) do
        \\    require("kraken/" .. name)
        \\end
        \\require("kraken/globals").set({ ok = true })
    ));
    manager.global.join();
    try std.testing.expect(manager.globals.len > 0);

    manager.globals.len = 0;
    const run = &manager.transport_runs[0];
    try run.packet.set("\x01\x02");
    try run.identity.set("researcher");
    run.direction = .outbound;
    try run.vm.start(manager, &run.arena, "transport test",
        \\function transport(bytes, identity, direction)
        \\    if bytes == "\1\2" and identity == "researcher" and direction == "outbound" then
        \\        require("kraken/globals").set({ ok = true })
        \\    end
        \\end
    , .{ .call = .{ .name = "transport", .arguments = pushTransportArguments, .data = run } });
    run.vm.join();
    try std.testing.expect(manager.globals.len > 0);
}

/// Test link: captures one stack's egress frames for delivery to the other.
const Link = struct {
    frames: [64]frame.Frame = undefined,
    count: usize = 0,

    fn egress(device: ?*c.struct_wolfIP_ll_dev, raw: ?*anyopaque, length: u32) callconv(.c) c_int {
        const link: *Link = @ptrCast(@alignCast(device.?.priv.?));
        const bytes: [*]const u8 = @ptrCast(raw.?);
        if (link.count == link.frames.len) return @intCast(length);
        link.frames[link.count].set(bytes[0..length]) catch unreachable;
        link.count += 1;
        return @intCast(length);
    }

    fn deliver(self: *Link, destination: *stack.Stack) void {
        const count = self.count;
        self.count = 0;
        for (self.frames[0..count]) |*value| _ = destination.input(value.bytes[0..value.len]);
    }
};

test "tcp receive returns available bytes, then nil after the peer closes" {
    const allocator = std.testing.allocator;
    var links: [2]Link = .{ .{}, .{} };
    var local: Runtime = .{ .manager = undefined, .name = .{}, .run_id = 1, .transport = null };
    var remote: stack.Stack = undefined;
    var configuration: identity.Identity = .{};
    try configuration.ip.set("10.0.0.1");
    try configuration.mac.set("02:00:00:00:00:01");
    try local.stack.init(allocator, &configuration, &links[0], Link.egress);
    defer local.stack.deinit(allocator);
    try configuration.ip.set("10.0.0.2");
    try configuration.mac.set("02:00:00:00:00:02");
    try remote.init(allocator, &configuration, &links[1], Link.egress);
    defer remote.deinit(allocator);
    const pump = struct {
        fn step(a: *stack.Stack, b: *stack.Stack, pair: *[2]Link) void {
            pair[0].deliver(b);
            pair[1].deliver(a);
            _ = a.tick(now());
            _ = b.tick(now());
            std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch {};
        }
    }.step;

    var address: c.struct_wolfIP_sockaddr_in = .{ .sin_family = c.AF_INET, .sin_port = std.mem.nativeToBig(u16, 7000), .sin_addr = .{ .s_addr = @bitCast([4]u8{ 10, 0, 0, 2 }) } };
    var none: c.struct_wolfIP_sockaddr_in = .{};
    var listener: command.Socket = .{ .identity = .{}, .kind = .tcp };
    try std.testing.expect(remote.socket(.bind, &listener, &address, &.{}) >= 0);
    try std.testing.expect(remote.socket(.listen, &listener, &address, &.{}) >= 0);

    var cancelled: std.Io.Event = .unset;
    var client: command.Socket = .{ .identity = .{}, .kind = .tcp };
    var buffer: [10]u8 = undefined;
    const Call = struct {
        fn run(runtime: *Runtime, remote_stack: *stack.Stack, pair: *[2]Link, call: command.SocketCall) c_int {
            var pending = call;
            while (!runtime.socket(&pending)) pump(&runtime.stack, remote_stack, pair);
            return pending.result;
        }
    };
    const base: command.SocketCall = .{ .action = .connect, .socket = &client, .address = &address, .bytes = &.{}, .deadline = now() + 2000, .cancelled = &cancelled, .result = 0 };
    try std.testing.expectEqual(@as(c_int, 0), Call.run(&local, &remote, &links, base));

    var peer: command.Socket = .{ .identity = .{}, .kind = .tcp };
    while (peer.descriptor < 0) : (pump(&local.stack, &remote, &links)) peer.descriptor = @max(-1, remote.socket(.accept, &listener, &none, &.{}));
    var hello = "hello".*;
    while (remote.socket(.send, &peer, &none, &hello) < 0) pump(&local.stack, &remote, &links);

    var receive = base;
    receive.action = .receive;
    receive.address = &none;
    receive.bytes = &buffer;
    receive.deadline = now() + 1000;
    try std.testing.expectEqual(@as(c_int, 5), Call.run(&local, &remote, &links, receive));
    try std.testing.expectEqualStrings("hello", buffer[0..5]);
    receive.deadline = now() + 50;
    try std.testing.expectEqual(@as(c_int, -c.WOLFIP_EAGAIN), Call.run(&local, &remote, &links, receive));

    var bye = "bye".*;
    while (remote.socket(.send, &peer, &none, &bye) < 0) pump(&local.stack, &remote, &links);
    _ = remote.socket(.close, &peer, &none, &.{});
    receive.deadline = now() + 1000;
    try std.testing.expectEqual(@as(c_int, 3), Call.run(&local, &remote, &links, receive));
    try std.testing.expectEqualStrings("bye", buffer[0..3]);
    try std.testing.expectEqual(@as(c_int, 0), Call.run(&local, &remote, &links, receive));
}
