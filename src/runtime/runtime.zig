const std = @import("std");
const frame = @import("frame.zig");
const ring = @import("ring.zig");
const lua = @import("lua.zig");
const globals = @import("globals.zig");
const stack = @import("net_backend");
const net = @import("net_types");
const pcap = @import("../platform/pcap.zig");
const wait = @import("../platform/wait.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const storage_module = @import("../storage/storage.zig");
const log = @import("../log.zig");
const tls = @import("../protocols/tls.zig");
const ssh = @import("../protocols/ssh.zig");
const ldap = @import("../protocols/ldap.zig");
const c = @import("c");

const Request = struct {
    command: command.Command,
    done: std.Io.Event = .unset,
    result: ?Error = null,
};

const TransportRun = struct {
    vm: lua.VM = .{},
    packet: frame.Frame = .{},
    identity: text.FieldText = .{},
    direction: frame.Direction = .inbound,
};

pub const IdentityView = struct { value: identity.Identity, active: bool };

pub const Error = net.Error || ConfigError || error{
    InterfaceRequired,
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    StorageFailure,
    TransmissionFailed,
    TransportScriptUnavailable,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    storage: *storage_module.Storage,
    globals: globals.Store = .{},
    global: lua.VM = .{},
    catalog: std.ArrayList(identity.Identity) = .empty,
    catalog_mutex: std.Io.Mutex = .init,
    commands: ring.MpscRing(*Request, limits.runtime_command_capacity) = .{},
    runtimes: std.StringArrayHashMapUnmanaged(*Runtime) = .empty,
    stack: stack.Stack = undefined,
    closing: std.Io.Event = .unset,
    thread: std.Thread = undefined,
    wake: wait.Wake = undefined,
    handles: std.ArrayList(wait.Handle) = .empty,
    next_run: u64 = 1,
    // Owned by the manager thread.
    transports: std.ArrayList(*TransportRun) = .empty,

    pub fn init(self: *Manager, allocator: std.mem.Allocator, storage: *storage_module.Storage) !void {
        self.* = .{ .allocator = allocator, .storage = storage };
        tls.init();
        ssh.init();
        ldap.init();
        errdefer self.catalog.deinit(allocator);
        try storage.identities().load(allocator, &self.catalog);
        self.wake = try wait.Wake.init();
        errdefer self.wake.deinit();
        try self.stack.init(allocator, self, stackWake);
        errdefer self.stack.deinit();
        try self.handles.append(allocator, self.wake.handle);
        errdefer self.handles.deinit(allocator);
        try self.transports.ensureTotalCapacity(allocator, limits.transport_vm_limit);
        errdefer self.releaseTransports();
        self.replenish();
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Manager) void {
        self.stopGlobal();
        self.closing.set(io());
        self.wake.signal();
        self.thread.join();
        self.releaseTransports();
        for (self.runtimes.values()) |runtime| runtime.deinit();
        self.stack.deinit();
        self.wake.deinit();
        self.handles.deinit(self.allocator);
        self.runtimes.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
    }

    fn releaseTransports(self: *Manager) void {
        for (self.transports.items) |transport| {
            transport.vm.cancel();
            transport.vm.join();
            self.allocator.destroy(transport);
        }
        self.transports.deinit(self.allocator);
    }

    /// Reaps exited transport VMs, cancels available ones beyond the spare count,
    /// and spawns new ones up to it within the limit.
    fn replenish(self: *Manager) void {
        var spare: usize = 0;
        var index: usize = 0;
        while (index < self.transports.items.len) {
            const transport = self.transports.items[index];
            if (!transport.vm.running()) {
                transport.vm.join();
                self.allocator.destroy(transport);
                _ = self.transports.swapRemove(index);
                continue;
            }
            if (transport.vm.available()) {
                spare += 1;
                if (spare > limits.transport_spare_vms) transport.vm.cancel();
            }
            index += 1;
        }
        while (spare < limits.transport_spare_vms and self.transports.items.len < limits.transport_vm_limit) : (spare += 1) {
            const transport = self.allocator.create(TransportRun) catch return;
            transport.* = .{};
            transport.vm.spawn(self, limits.transport_lua_heap_capacity, true) catch return self.allocator.destroy(transport);
            self.transports.appendAssumeCapacity(transport);
        }
    }

    fn available(self: *Manager) ?*TransportRun {
        for (self.transports.items) |transport| if (transport.vm.available()) return transport;
        return null;
    }

    fn start(self: *Manager, value: *const identity.Identity) Error!void {
        if (self.runtimes.contains(value.label.value())) return error.IdentityInUse;
        if (@import("builtin").os.tag == .windows and self.runtimes.count() == 63) return error.RuntimeUnavailable;
        self.handles.ensureTotalCapacity(self.allocator, self.runtimes.count() + 2) catch return error.RuntimeUnavailable;
        if (value.interface.value().len == 0) return error.InterfaceRequired;
        const runtime = self.allocator.create(Runtime) catch return error.RuntimeUnavailable;
        errdefer self.allocator.destroy(runtime);
        runtime.* = .{ .manager = self, .name = value.label, .run_id = self.next_run, .transport = try self.transportCode(value.transport) };
        errdefer if (runtime.transport) |code| self.allocator.free(code);
        runtime.iface = try self.stack.addInterface(try parseStackConfig(value), runtime);
        errdefer self.stack.removeInterface(runtime.iface);
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
        self.global.spawn(self, limits.global_lua_heap_capacity, false) catch return false;
        self.global.run(value, source, null, .chunk) catch {
            self.stopGlobal();
            return false;
        };
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
                const code = try self.transportCode(updated.transport);
                self.storage.identities().save(updated) catch {
                    if (code) |bytes| self.allocator.free(bytes);
                    return error.StorageFailure;
                };
                value.* = updated;
                if (self.runtimes.get(value.label.value())) |runtime| {
                    if (runtime.transport) |old| self.allocator.free(old);
                    runtime.transport = code;
                } else if (code) |bytes| self.allocator.free(bytes);
                log.logger.formatted(.info, .ui, "Identity \"{s}\" transport: {s}.", .{ value.label.value(), if (selection.script) |script| script.value() else "none" });
            },
            .transmit => |packet| {
                const runtime = self.runtimes.get(packet.name.value()) orelse return error.RuntimeUnavailable;
                const bytes = packet.value.bytes[0..packet.value.len];
                runtime.inject(bytes, packet.direction) catch |err| {
                    log.logger.formatted(.warning, .runtime, "Identity \"{s}\": transmit rejected a {d}-byte {s} frame: {s} (frame MTU {d}, capacity {d}).", .{
                        runtime.name.value(), bytes.len, @tagName(packet.direction), @errorName(err), self.stack.frameMtu(runtime.iface), limits.frame_capacity,
                    });
                    return error.TransmissionFailed;
                };
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

    /// Reads and compiles a transport script once, so each frame loads bytecode instead of parsing source.
    fn transportCode(self: *Manager, script: text.FieldText) Error!?[]u8 {
        if (script.len == 0) return null;
        var source: text.FixedText(limits.source_capacity) = undefined;
        self.storage.scripts(.transport).read(script.value(), &source) catch return error.TransportScriptUnavailable;
        return compile(self.allocator, script.value(), source.value()) catch error.TransportScriptUnavailable;
    }

    fn run(self: *Manager) void {
        var pending: std.ArrayList(*Request) = .empty;
        defer {
            for (self.transports.items) |transport| transport.vm.cancel();
            self.commands.close();
            for (pending.items) |request| {
                request.command.socket.result = .failed;
                request.done.set(io());
            }
            pending.deinit(self.allocator);
            while (self.commands.pop()) |request| {
                if (request.command == .socket) request.command.socket.result = .failed;
                request.result = error.RuntimeUnavailable;
                request.done.set(io());
            }
        }
        while (!self.closing.isSet()) {
            self.wake.reset();
            var output_bytes: [limits.frame_capacity]u8 = undefined;
            while (self.stack.output(&output_bytes)) |packet| {
                const runtime: *Runtime = @ptrCast(@alignCast(packet.context));
                process(runtime, output_bytes[0..packet.length], .outbound);
            }
            while (self.commands.pop()) |request| {
                if (request.command == .socket) {
                    request.command.socket.result = .{ .success = 0 };
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
            self.replenish();
            var deadline: u64 = std.math.maxInt(u64);
            self.handles.clearRetainingCapacity();
            self.handles.appendAssumeCapacity(self.wake.handle);
            for (self.runtimes.values()) |current| {
                self.handles.appendAssumeCapacity(current.pcap.ready);
                var bytes: [limits.frame_capacity]u8 = undefined;
                // A small batch per wake saves polls; commands are still serviced between batches.
                for (0..limits.capture_batch) |_| {
                    const length = (current.pcap.next(&bytes) catch |err| blk: {
                        current.report(switch (err) {
                            error.ReceiveFailed => "pcap receive failed",
                            error.TruncatedFrame => "pcap frame truncated",
                        });
                        break :blk null;
                    }) orelse break;
                    process(current, bytes[0..length], .inbound);
                    deadline = 0;
                }
            }
            var pending_index: usize = 0;
            while (pending_index < pending.items.len) {
                const request = pending.items[pending_index];
                const call = request.command.socket;
                const remaining = call.bytes.len;
                const handle = call.socket.endpoint.handle;
                // Cancellation never blocks close, so a cancelled VM still releases its sockets.
                const completed = if (call.cancelled.isSet() and call.action != .close) cancelled: {
                    call.result = .failed;
                    break :cancelled true;
                } else if (self.runtimes.get(call.socket.identity.value())) |runtime|
                    runtime.socket(call)
                else blk: {
                    call.result = .failed;
                    break :blk true;
                };
                if (completed) {
                    _ = pending.swapRemove(pending_index);
                    deadline = 0; // Flush work queued by this socket operation.
                    request.done.set(io());
                    continue;
                }
                if (call.bytes.len != remaining or call.socket.endpoint.handle != handle) {
                    deadline = 0;
                } else {
                    deadline = @min(deadline, @min(call.deadline orelse std.math.maxInt(u64), now() + 10));
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

/// Compiles Lua source to bytecode, keeping debug information for error line numbers.
fn compile(allocator: std.mem.Allocator, name: []const u8, source: []const u8) error{ CompileFailed, OutOfMemory }![]u8 {
    const state = c.luaL_newstate() orelse return error.OutOfMemory;
    defer c.lua_close(state);
    if (c.luaL_loadbufferx(state, source.ptr, source.len, "=script", "t") != c.LUA_OK) {
        log.logger.formatted(.err, .lua, "Transport script \"{s}\" failed to compile: {s}", .{ name, lua.toBytes(state, -1) orelse "unknown error" });
        return error.CompileFailed;
    }
    const Output = struct {
        allocator: std.mem.Allocator,
        bytes: std.ArrayList(u8) = .empty,

        fn write(_: ?*c.lua_State, data: ?*const anyopaque, size: usize, context: ?*anyopaque) callconv(.c) c_int {
            const output: *@This() = @ptrCast(@alignCast(context.?));
            output.bytes.appendSlice(output.allocator, @as([*]const u8, @ptrCast(data.?))[0..size]) catch return 1;
            return 0;
        }
    };
    var output: Output = .{ .allocator = allocator };
    errdefer output.bytes.deinit(allocator);
    if (c.lua_dump(state, Output.write, &output, 0) != 0) return error.OutOfMemory;
    return output.bytes.toOwnedSlice(allocator);
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
    transport: ?[]u8,
    pcap: pcap.Handle = undefined,
    iface: net.InterfaceHandle = undefined,

    fn deinit(self: *Runtime) void {
        if (self.transport) |code| self.manager.allocator.free(code);
        self.pcap.close();
        self.manager.stack.removeInterface(self.iface);
        self.manager.allocator.destroy(self);
    }

    fn socket(self: *Runtime, call: *command.SocketCall) bool {
        const creating = call.action == .connect or call.action == .bind;
        if (creating and call.socket.run == 0) call.socket.run = self.run_id;
        if (call.socket.run != self.run_id) {
            call.result = .failed;
            return true;
        }
        while (true) {
            const result = self.manager.stack.socket(self.iface, call.action, &call.socket.endpoint, call.address, call.bytes);
            switch (result) {
                .success => |count| {
                    if (call.action != .send) {
                        call.result = result;
                        break;
                    }
                    if (count == 0 and call.socket.endpoint.kind == .tcp) {
                        call.result = .failed;
                        break;
                    }
                    call.bytes = call.bytes[count..];
                    call.result.success += count;
                    if (call.socket.endpoint.kind != .tcp or call.bytes.len == 0) break;
                },
                .would_block => {
                    if (now() < (call.deadline orelse std.math.maxInt(u64))) return false;
                    call.result = .would_block;
                    break;
                },
                else => {
                    call.result = result;
                    break;
                },
            }
        }
        if (creating and (call.result == .failed or call.result == .would_block) and call.socket.endpoint.handle != null) {
            _ = self.manager.stack.socket(self.iface, .close, &call.socket.endpoint, null, &.{});
            call.socket.endpoint.handle = null;
        }
        return true;
    }

    fn inject(self: *Runtime, bytes: []const u8, direction: frame.Direction) error{ EmptyFrame, FrameExceedsCapacity, FrameExceedsMtu, CaptureSendFailed }!void {
        if (bytes.len == 0) return error.EmptyFrame;
        if (bytes.len > limits.frame_capacity) return error.FrameExceedsCapacity;
        if (direction == .inbound) {
            if (!self.manager.stack.input(self.iface, bytes)) return error.FrameExceedsMtu;
        } else if (!self.pcap.inject(bytes)) return error.CaptureSendFailed;
    }

    fn report(self: *Runtime, message: []const u8) void {
        log.logger.formatted(.err, .runtime, "Identity \"{s}\": {s}.", .{ self.name.value(), message });
    }
};

fn process(runtime: *Runtime, bytes: []const u8, direction: frame.Direction) void {
    const source = runtime.transport orelse {
        runtime.inject(bytes, direction) catch if (direction == .outbound) runtime.report("pcap transmit failed");
        return;
    };
    const manager = runtime.manager;
    const transport = manager.available() orelse blk: {
        manager.replenish();
        break :blk manager.available() orelse return runtime.report("transport VM limit reached");
    };
    transport.packet.set(bytes) catch return runtime.report("transport packet exceeds capacity");
    transport.identity = runtime.name;
    transport.direction = direction;
    var scope: [lua.scope_capacity]u8 = undefined;
    const value = std.fmt.bufPrint(&scope, "transport \"{s}\"", .{runtime.name.value()}) catch unreachable;
    transport.vm.run(value, source, limits.transport_instruction_limit, .{ .call = .{
        .name = "transport",
        .arguments = pushTransportArguments,
        .data = transport,
    } }) catch return runtime.report("transport VM hand-off failed");
    manager.replenish();
}

fn pushTransportArguments(state: ?*c.lua_State, data: *anyopaque) c_int {
    const run: *TransportRun = @ptrCast(@alignCast(data));
    _ = c.lua_pushlstring(state, &run.packet.bytes, run.packet.len);
    _ = c.lua_pushlstring(state, run.identity.value().ptr, run.identity.len);
    _ = c.lua_pushstring(state, @tagName(run.direction));
    return 3;
}

fn stackWake(context: ?*anyopaque) callconv(.c) void {
    const manager: *Manager = @ptrCast(@alignCast(context.?));
    manager.wake.signal();
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn now() u64 {
    return @intCast(std.Io.Clock.awake.now(io()).toMilliseconds());
}

const ConfigError = error{ InvalidIpAddress, InvalidPrefixLength, InvalidGatewayAddress, InvalidMacAddress, InvalidMtu };

fn parseStackConfig(value: *const identity.Identity) ConfigError!net.Config {
    const ip = (std.Io.net.Ip4Address.parse(value.ip.value(), 0) catch return error.InvalidIpAddress).bytes;
    const prefix = if (value.prefix.value().len == 0) 24 else std.fmt.parseInt(u8, value.prefix.value(), 10) catch return error.InvalidPrefixLength;
    if (prefix > 32) return error.InvalidPrefixLength;
    const gateway = if (value.gateway.value().len == 0) null else (std.Io.net.Ip4Address.parse(value.gateway.value(), 0) catch return error.InvalidGatewayAddress).bytes;
    const mac = parseMac(value.mac.value()) orelse return error.InvalidMacAddress;
    const mtu = if (value.mtu.value().len == 0) 1500 else std.fmt.parseInt(u16, value.mtu.value(), 10) catch return error.InvalidMtu;
    if (mtu < 68 or @as(usize, mtu) + 14 > limits.frame_capacity) return error.InvalidMtu;
    return .{ .ip = ip, .prefix = prefix, .gateway = gateway, .mac = mac, .mtu = mtu };
}

fn parseMac(value: []const u8) ?[6]u8 {
    if (value.len != 17) return null;
    var result: [6]u8 = undefined;
    for (&result, 0..) |*octet, index| {
        if (index < 5 and value[index * 3 + 2] != ':') return null;
        octet.* = std.fmt.parseInt(u8, value[index * 3 .. index * 3 + 2], 16) catch return null;
    }
    return result;
}

test "VMs cancel, run one global at a time, reclaim memory, and rearm transport VMs" {
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
    // No manager thread: the test owns the transports.
    manager.* = .{ .allocator = allocator, .storage = &storage };
    manager.wake = try wait.Wake.init();
    defer manager.wake.deinit();
    try manager.transports.ensureTotalCapacity(allocator, limits.transport_vm_limit);
    defer manager.releaseTransports();
    manager.replenish();

    try std.testing.expect(manager.runGlobal("sleeper", "require('kraken/std').sleep(60000)"));
    try std.testing.expect(!manager.runGlobal("second", ""));
    manager.stopGlobal();
    try std.testing.expect(!manager.global.running());

    try std.testing.expect(manager.runGlobal("modules",
        \\for _, name in ipairs({ "packet", "transmit", "socket", "identities", "globals", "std" }) do
        \\    require("kraken/" .. name)
        \\end
        \\require("protocols/http")
        \\require("protocols/dns")
        \\require("protocols/tls")
        \\require("protocols/ssh")
        \\require("kraken/globals").set({ ok = true })
    ));
    manager.global.join();
    try std.testing.expect(manager.globals.len > 0);

    // Each frame runs on an available VM, which rearms afterwards.
    var runtime: Runtime = .{ .manager = manager, .name = .{}, .run_id = 1, .transport = null };
    try runtime.name.set("researcher");
    runtime.transport = try compile(allocator, "test",
        \\function transport(bytes, identity, direction)
        \\    require("kraken/std").sleep(20)
        \\    if identity == "researcher" and direction == "outbound" then
        \\        require("kraken/globals").set({ bytes = bytes })
        \\    end
        \\end
    );
    defer allocator.free(runtime.transport.?);
    for ([_][]const u8{ "\x01\x02", "\x03" }) |bytes| {
        manager.globals.len = 0;
        const taken = manager.available().?;
        process(&runtime, bytes, .outbound);
        while (!taken.vm.available()) std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch {};
        try std.testing.expect(manager.globals.len > 0);
    }
    // A burst grows the pool; once idle it shrinks back to the spares.
    for (0..6) |_| process(&runtime, "\x04", .outbound);
    try std.testing.expect(manager.transports.items.len > limits.transport_spare_vms);
    for (0..2000) |_| {
        manager.replenish();
        if (manager.transports.items.len == limits.transport_spare_vms) break;
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch {};
    } else return error.TestUnexpectedResult;

    // Allocates four arenas' worth of strings and runs past the transport budget.
    manager.globals.len = 0;
    try std.testing.expect(manager.runGlobal("churn",
        \\for i = 1, 256 do local value = string.rep("x", 1024 * 1024 - 1) .. i end
        \\local count = 0
        \\for i = 1, 2000000 do count = count + 1 end
        \\require("kraken/globals").set({ ok = count })
    ));
    manager.global.join();
    try std.testing.expect(manager.globals.len > 0);
}

const Link = struct {
    manager: *Manager,
    local: *Runtime,
    remote: *Runtime,

    fn pump(self: *Link) void {
        var bytes: [limits.frame_capacity]u8 = undefined;
        while (self.manager.stack.output(&bytes)) |packet| {
            const source: *Runtime = @ptrCast(@alignCast(packet.context));
            const destination = if (source == self.local) self.remote.iface else self.local.iface;
            _ = self.manager.stack.input(destination, bytes[0..packet.length]);
        }
        std.Io.sleep(io(), .fromMilliseconds(1), .awake) catch {};
    }
};

test "virtual link carries TCP, UDP and raw sockets" {
    const allocator = std.testing.allocator;
    var manager: Manager = .{ .allocator = allocator, .storage = undefined };
    try manager.stack.init(allocator, &manager, testWake);
    defer manager.stack.deinit();
    var local: Runtime = .{ .manager = &manager, .name = .{}, .run_id = 1, .transport = null };
    var remote: Runtime = .{ .manager = &manager, .name = .{}, .run_id = 2, .transport = null };
    var configuration: identity.Identity = .{};
    try configuration.ip.set("10.0.0.1");
    try configuration.mac.set("02:00:00:00:00:01");
    local.iface = try manager.stack.addInterface(try parseStackConfig(&configuration), &local);
    defer manager.stack.removeInterface(local.iface);
    try configuration.ip.set("10.0.0.2");
    try configuration.mac.set("02:00:00:00:00:02");
    remote.iface = try manager.stack.addInterface(try parseStackConfig(&configuration), &remote);
    defer manager.stack.removeInterface(remote.iface);
    var link: Link = .{ .manager = &manager, .local = &local, .remote = &remote };
    var address: net.Address = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 };
    var bind_address: net.Address = .{ .port = 7000 };
    var listener: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    try std.testing.expect(manager.stack.socket(remote.iface, .bind, &listener.endpoint, &bind_address, &.{}) == .success);
    try std.testing.expect(manager.stack.socket(remote.iface, .listen, &listener.endpoint, null, &.{}) == .success);

    var cancelled: std.Io.Event = .unset;
    var client: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    var buffer: [10]u8 = undefined;
    const Call = struct {
        fn run(runtime: *Runtime, link_value: *Link, call: command.SocketCall) net.SocketResult {
            var pending = call;
            while (!runtime.socket(&pending)) link_value.pump();
            return pending.result;
        }
    };
    const base: command.SocketCall = .{ .action = .connect, .socket = &client, .address = &address, .bytes = &.{}, .deadline = now() + 2000, .cancelled = &cancelled, .result = .{ .success = 0 } };
    try std.testing.expectEqual(@as(usize, 0), Call.run(&local, &link, base).success);

    var peer: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    while (peer.endpoint.handle == null) : (link.pump()) {
        const result = manager.stack.socket(remote.iface, .accept, &listener.endpoint, null, &.{});
        if (result == .accepted) peer.endpoint.handle = result.accepted;
    }
    var hello = "hello".*;
    while (manager.stack.socket(remote.iface, .send, &peer.endpoint, null, &hello) == .would_block) link.pump();

    var receive = base;
    receive.action = .receive;
    receive.address = null;
    receive.bytes = &buffer;
    receive.deadline = now() + 1000;
    try std.testing.expectEqual(@as(usize, 5), Call.run(&local, &link, receive).success);
    try std.testing.expectEqualStrings("hello", buffer[0..5]);
    receive.deadline = now() + 50;
    try std.testing.expect(Call.run(&local, &link, receive) == .would_block);

    var bye = "bye".*;
    while (manager.stack.socket(remote.iface, .send, &peer.endpoint, null, &bye) == .would_block) link.pump();
    _ = manager.stack.socket(remote.iface, .close, &peer.endpoint, null, &.{});
    receive.deadline = now() + 1000;
    try std.testing.expectEqual(@as(usize, 3), Call.run(&local, &link, receive).success);
    try std.testing.expectEqualStrings("bye", buffer[0..3]);
    try std.testing.expect(Call.run(&local, &link, receive) == .closed);

    // Wildcard binds are scoped to an identity, so both can use the same port.
    var local_udp: net.Socket = .{ .kind = .udp };
    var remote_udp: net.Socket = .{ .kind = .udp };
    var udp_bind: net.Address = .{ .port = 7001 };
    try std.testing.expect(manager.stack.socket(local.iface, .bind, &local_udp, &udp_bind, &.{}) == .success);
    try std.testing.expect(manager.stack.socket(remote.iface, .bind, &remote_udp, &udp_bind, &.{}) == .success);
    var udp_data = "udp".*;
    var udp_destination: net.Address = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7001 };
    try std.testing.expect(manager.stack.socket(local.iface, .send, &local_udp, &udp_destination, &udp_data) == .success);
    var udp_source: net.Address = .{};
    var datagram: [16]u8 = undefined;
    var udp_result: net.SocketResult = .would_block;
    const udp_deadline = now() + 1000;
    while (udp_result == .would_block and now() < udp_deadline) {
        link.pump();
        udp_result = manager.stack.socket(remote.iface, .receive, &remote_udp, &udp_source, &datagram);
    }
    try std.testing.expect(udp_result == .success);
    try std.testing.expectEqualStrings("udp", datagram[0..udp_result.success]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &udp_source.ip);
    try std.testing.expect(manager.stack.socket(local.iface, .receive, &local_udp, &udp_source, &datagram) == .would_block);

    var raw_sender: net.Socket = .{ .kind = .raw, .protocol = 253 };
    var raw_receiver: net.Socket = .{ .kind = .raw, .protocol = 253 };
    var raw_bind: net.Address = .{};
    try std.testing.expect(manager.stack.socket(local.iface, .bind, &raw_sender, &raw_bind, &.{}) == .success);
    try std.testing.expect(manager.stack.socket(remote.iface, .bind, &raw_receiver, &raw_bind, &.{}) == .success);
    var raw_data = "raw".*;
    var raw_destination: net.Address = .{ .ip = .{ 10, 0, 0, 2 } };
    try std.testing.expect(manager.stack.socket(local.iface, .send, &raw_sender, &raw_destination, &raw_data) == .success);
    var packet: [64]u8 = undefined;
    var raw_result: net.SocketResult = .would_block;
    const raw_deadline = now() + 1000;
    while (raw_result == .would_block and now() < raw_deadline) {
        link.pump();
        raw_result = manager.stack.socket(remote.iface, .receive, &raw_receiver, &udp_source, &packet);
    }
    try std.testing.expect(raw_result == .success);
    try std.testing.expect(std.mem.endsWith(u8, packet[0..raw_result.success], "raw"));
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &udp_source.ip);
}

fn testWake(_: ?*anyopaque) callconv(.c) void {}
