const std = @import("std");
const frame = @import("frame.zig");
const lua = @import("lua.zig");
const globals = @import("globals.zig");
const io = @import("../io.zig");
const net = @import("net");
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
const sip = @import("../protocols/sip.zig");
const etpan_stream = @import("../protocols/etpan_stream.zig");
const c = @import("c");

const Request = struct {
    command: *const command.Command,
    done: std.Io.Event = .unset,
    // Pending TCP sends retain their completed byte count here.
    result: Error!net.SocketResult = .{ .success = 0 },
    node: std.DoublyLinkedList.Node = .{},

    fn fromNode(node: *std.DoublyLinkedList.Node) *Request {
        return @fieldParentPtr("node", node);
    }

    fn reject(self: *Request) void {
        self.result = error.RuntimeUnavailable;
        self.done.set(io.get());
    }
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
    commands: std.DoublyLinkedList = .{},
    commands_mutex: std.Io.Mutex = .init,
    runtimes: std.StringArrayHashMapUnmanaged(*Runtime) = .empty,
    stack: net.Stack = undefined,
    closing: std.Io.Event = .unset,
    thread: std.Thread = undefined,
    wake: wait.Wake = undefined,
    handles: std.ArrayList(wait.Handle) = .empty,
    next_run: u64 = 1,
    // Owned by the manager thread.
    transports: [limits.transport_vm_limit]lua.VM = @splat(.{}),

    pub fn init(self: *Manager, allocator: std.mem.Allocator, storage: *storage_module.Storage) !void {
        self.* = .{ .allocator = allocator, .storage = storage };
        tls.init();
        ssh.init();
        ldap.init();
        sip.init();
        etpan_stream.init();
        errdefer self.catalog.deinit(allocator);
        try storage.identities().load(allocator, &self.catalog);
        self.wake = try wait.Wake.init();
        errdefer self.wake.deinit();
        try self.stack.init(allocator, self, stackWake);
        try self.handles.append(allocator, self.wake.handle);
        errdefer self.handles.deinit(allocator);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Manager) void {
        self.stopGlobal();
        self.closing.set(io.get());
        self.wake.signal();
        self.thread.join();
        for (self.runtimes.values()) |runtime| runtime.deinit();
        self.wake.deinit();
        self.handles.deinit(self.allocator);
        self.runtimes.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
    }

    fn releaseTransports(self: *Manager) void {
        for (&self.transports) |*transport| transport.cancel();
        for (&self.transports) |*transport| transport.join();
    }

    /// Keeps two ready VMs; arenas and threads are created only as needed.
    fn replenish(self: *Manager) void {
        var spare: usize = 0;
        for (&self.transports) |*transport| {
            if (!transport.running()) transport.join();
            if (transport.available()) {
                spare += 1;
                if (spare > limits.transport_spare_vms) transport.cancel();
            }
        }
        if (spare >= limits.transport_spare_vms) return;
        for (&self.transports) |*transport| {
            if (transport.running()) continue;
            transport.spawn(self, .transport) catch return;
            spare += 1;
            if (spare == limits.transport_spare_vms) break;
        }
    }

    fn available(self: *Manager) ?*lua.VM {
        for (&self.transports) |*transport| if (transport.available()) return transport;
        return null;
    }

    fn start(self: *Manager, value: *const identity.Identity) Error!void {
        if (self.runtimes.contains(value.label.value())) return error.IdentityInUse;
        if (@import("builtin").os.tag == .windows and self.runtimes.count() == 63) return error.RuntimeUnavailable;
        self.handles.ensureTotalCapacity(self.allocator, self.runtimes.count() + 2) catch return error.RuntimeUnavailable;
        if (value.interface.value().len == 0) return error.InterfaceRequired;
        const config = try parseStackConfig(value);
        const runtime = self.allocator.create(Runtime) catch return error.RuntimeUnavailable;
        errdefer self.allocator.destroy(runtime);
        runtime.* = .{ .manager = self, .name = value.label, .run_id = self.next_run, .config = config, .transport = try self.transportCode(value.transport) };
        errdefer if (runtime.transport) |code| self.allocator.free(code);
        try runtime.iface.init(&self.stack, config);
        errdefer runtime.iface.deinit();
        runtime.pcap = pcap.Handle.open(value.interface.bytes[0..value.interface.len :0]) catch return error.RuntimeUnavailable;
        errdefer runtime.pcap.close();
        if (applyIdentityFilter(&runtime.pcap, config) != null) return error.RuntimeUnavailable;
        self.runtimes.putNoClobber(self.allocator, runtime.name.value(), runtime) catch return error.RuntimeUnavailable;
        self.next_run +%= 1;
    }

    pub fn snapshot(self: *Manager, destination: *std.ArrayList(IdentityView)) !void {
        if (!self.catalog_mutex.tryLock()) return;
        defer self.catalog_mutex.unlock(io.get());
        try destination.resize(self.allocator, self.catalog.items.len);
        for (self.catalog.items, destination.items) |value, *entry| {
            entry.* = .{ .value = value, .active = self.runtimes.contains(value.label.value()) };
        }
    }

    // The global VM belongs to the UI thread: only it starts and stops it.
    pub fn runGlobal(self: *Manager, name: []const u8, source: []const u8) bool {
        if (self.global.running()) return false;
        self.global.spawn(self, .global) catch return false;
        self.global.run(name, source, null) catch {
            self.stopGlobal();
            return false;
        };
        log.logger.formatted(.info, .lua, "global \"{s}\": started.", .{self.global.name.value()});
        return true;
    }

    pub fn stopGlobal(self: *Manager) void {
        self.global.cancel();
        self.global.join();
    }

    /// Borrows the command and its buffers until completion; submission blocks until then.
    /// Non-socket commands return zero-byte success.
    pub fn execute(self: *Manager, request: *const command.Command) Error!net.SocketResult {
        var pending: Request = .{ .command = request };
        {
            self.commands_mutex.lockUncancelable(io.get());
            defer self.commands_mutex.unlock(io.get());
            if (self.closing.isSet()) return error.RuntimeUnavailable;
            self.commands.append(&pending.node);
        }
        self.wake.signal();
        pending.done.waitUncancelable(io.get());
        return pending.result;
    }

    fn nextCommand(self: *Manager) ?*Request {
        self.commands_mutex.lockUncancelable(io.get());
        defer self.commands_mutex.unlock(io.get());
        return Request.fromNode(self.commands.popFirst() orelse return null);
    }

    fn apply(self: *Manager, request: *const command.Command) Error!void {
        self.catalog_mutex.lockUncancelable(io.get());
        defer self.catalog_mutex.unlock(io.get());
        switch (request.*) {
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
                updated.transport = selection.script;
                const code = try self.transportCode(updated.transport);
                errdefer if (code) |bytes| self.allocator.free(bytes);
                self.storage.identities().save(updated) catch return error.StorageFailure;
                value.* = updated;
                if (self.runtimes.get(value.label.value())) |runtime| {
                    if (runtime.transport) |old| self.allocator.free(old);
                    runtime.transport = code;
                } else if (code) |bytes| self.allocator.free(bytes);
                log.logger.formatted(.info, .ui, "Identity \"{s}\" transport: {s}.", .{ value.label.value(), if (selection.script.len == 0) "none" else selection.script.value() });
            },
            .transmit => |packet| {
                const runtime = self.runtimes.get(packet.name.value()) orelse return error.RuntimeUnavailable;
                runtime.inject(packet.bytes, packet.direction) catch |err| {
                    log.logger.formatted(.warning, .runtime, "Identity \"{s}\": transmit rejected a {d}-byte {s} frame: {s} (capacity {d}).", .{
                        runtime.name.value(), packet.bytes.len, @tagName(packet.direction), @errorName(err), limits.frame_capacity,
                    });
                    return error.TransmissionFailed;
                };
            },
            .set_bpf => |selection| {
                const runtime = self.runtimes.get(selection.name.value()) orelse return error.RuntimeUnavailable;
                const message = if (selection.expression.len == 0)
                    applyIdentityFilter(&runtime.pcap, runtime.config)
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
        var pending: std.DoublyLinkedList = .{};
        defer {
            while (pending.popFirst()) |node| Request.fromNode(node).reject();
            while (self.nextCommand()) |request| request.reject();
            self.releaseTransports();
        }
        while (!self.closing.isSet()) {
            self.wake.reset();
            var output_bytes: [limits.frame_capacity]u8 = undefined;
            while (self.stack.output(&output_bytes)) |packet| {
                const runtime: *Runtime = @fieldParentPtr("iface", packet.iface);
                process(runtime, output_bytes[0..packet.length], .outbound);
            }
            while (self.nextCommand()) |request| {
                if (request.command.* == .socket) {
                    pending.append(&request.node);
                    continue;
                }
                self.apply(request.command) catch |err| {
                    request.result = err;
                };
                request.done.set(io.get());
            }
            self.replenish();
            var deadline: i64 = std.math.maxInt(i64);
            self.handles.clearRetainingCapacity();
            self.handles.appendAssumeCapacity(self.wake.handle);
            for (self.runtimes.values()) |current| {
                self.handles.appendAssumeCapacity(current.pcap.ready);
                // A small batch per wake saves polls; commands are still serviced between batches.
                for (0..limits.capture_batch) |_| {
                    const bytes = (current.pcap.next() catch |err| blk: {
                        current.report(switch (err) {
                            error.ReceiveFailed => "pcap receive failed",
                            error.TruncatedFrame => "pcap frame truncated",
                        });
                        break :blk null;
                    }) orelse break;
                    process(current, bytes, .inbound);
                    deadline = 0;
                }
            }
            var next = pending.first;
            while (next) |node| {
                next = node.next;
                const request = Request.fromNode(node);
                const call = &request.command.socket;
                if (self.runtimes.get(call.socket.identity.value())) |runtime| {
                    if (!runtime.socket(request)) {
                        deadline = @min(deadline, @min(call.deadline orelse std.math.maxInt(i64), io.now().toMilliseconds() + 10));
                        continue;
                    }
                } else request.result = .failed;
                pending.remove(node);
                request.done.set(io.get());
            }
            if (self.closing.isSet()) break;
            wait.wait(self.handles.items, if (deadline == std.math.maxInt(i64)) null else @max(deadline - io.now().toMilliseconds(), 0)) catch |err| {
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
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    if (c.lua_dump(state, writeBytecode, &output.writer, 0) != 0) return error.OutOfMemory;
    return output.toOwnedSlice();
}

fn writeBytecode(_: ?*c.lua_State, data: ?*const anyopaque, size: usize, context: ?*anyopaque) callconv(.c) c_int {
    const output: *std.Io.Writer = @ptrCast(@alignCast(context.?));
    output.writeAll(@as([*]const u8, @ptrCast(data.?))[0..size]) catch return 1;
    return 0;
}

fn applyIdentityFilter(handle: *pcap.Handle, config: net.Config) ?[]const u8 {
    var mac: [17]u8 = undefined;
    var ip: [17]u8 = undefined;
    var expression: [128]u8 = undefined;
    const address = frame.Ipv4Address.text(&config.ip, &ip);
    const filter = std.fmt.bufPrintZ(
        &expression,
        "ether dst {s} or ip dst host {s} or arp dst host {s}",
        .{ frame.MacAddress.text(&config.mac, &mac), address, address },
    ) catch unreachable;
    return handle.setFilter(filter);
}

const Runtime = struct {
    manager: *Manager,
    name: text.FieldText,
    run_id: u64,
    transport: ?[]u8,
    config: net.Config = undefined,
    pcap: pcap.Handle = undefined,
    iface: net.Interface = undefined,

    fn deinit(self: *Runtime) void {
        if (self.transport) |code| self.manager.allocator.free(code);
        self.pcap.close();
        self.iface.deinit();
        self.manager.allocator.destroy(self);
    }

    fn socket(self: *Runtime, request: *Request) bool {
        const call = &request.command.socket;
        const creating = call.action == .connect or call.action == .bind;
        if (creating and call.socket.run == 0) call.socket.run = self.run_id;
        // Close still runs during cancellation; stale activations never touch the stack.
        if (call.socket.run != self.run_id or (call.cancelled.isSet() and call.action != .close)) {
            request.result = .failed;
            return true;
        }
        while (true) {
            const sent = (request.result catch unreachable).success;
            const result = self.iface.socket(call.action, &call.socket.endpoint, call.address, call.bytes[sent..]);
            if (result == .would_block and io.now().toMilliseconds() < (call.deadline orelse std.math.maxInt(i64))) return false;
            request.result = result;
            if (result != .success) break;
            request.result = .{ .success = sent + result.success };
            if (call.action != .send or call.socket.endpoint.kind != .tcp or sent + result.success == call.bytes.len) break;
        }
        const result = request.result catch unreachable;
        if (creating and (result == .failed or result == .would_block) and call.socket.endpoint.handle != null) {
            _ = self.iface.socket(.close, &call.socket.endpoint, null, &.{});
        }
        return true;
    }

    fn inject(self: *Runtime, bytes: []const u8, direction: command.Direction) (net.Error || error{ EmptyFrame, FrameExceedsCapacity, CaptureSendFailed })!void {
        if (bytes.len == 0) return error.EmptyFrame;
        if (bytes.len > limits.frame_capacity) return error.FrameExceedsCapacity;
        if (direction == .inbound) {
            try self.iface.input(bytes);
        } else if (!self.pcap.inject(bytes)) return error.CaptureSendFailed;
    }

    fn report(self: *Runtime, message: []const u8) void {
        log.logger.formatted(.err, .runtime, "Identity \"{s}\": {s}.", .{ self.name.value(), message });
    }
};

fn process(runtime: *Runtime, bytes: []const u8, direction: command.Direction) void {
    const source = runtime.transport orelse {
        runtime.inject(bytes, direction) catch if (direction == .outbound) runtime.report("pcap transmit failed");
        return;
    };
    const manager = runtime.manager;
    const transport = manager.available() orelse return runtime.report("transport VM limit reached");
    transport.run(runtime.name.value(), source, .{ .bytes = bytes, .direction = direction }) catch return runtime.report("transport VM hand-off failed");
    manager.replenish();
}

fn stackWake(context: ?*anyopaque) callconv(.c) void {
    const manager: *Manager = @ptrCast(@alignCast(context.?));
    manager.wake.signal();
}

const ConfigError = error{ InvalidIpAddress, InvalidPrefixLength, InvalidGatewayAddress, InvalidMacAddress, InvalidMtu };

fn parseStackConfig(value: *const identity.Identity) ConfigError!net.Config {
    const ip = (std.Io.net.Ip4Address.parse(value.ip.value(), 0) catch return error.InvalidIpAddress).bytes;
    const prefix = if (value.prefix.value().len == 0) 24 else std.fmt.parseInt(u8, value.prefix.value(), 10) catch return error.InvalidPrefixLength;
    if (prefix > 32) return error.InvalidPrefixLength;
    const gateway = if (value.gateway.value().len == 0) null else (std.Io.net.Ip4Address.parse(value.gateway.value(), 0) catch return error.InvalidGatewayAddress).bytes;
    const mac = frame.MacAddress.parse(value.mac.value()) orelse return error.InvalidMacAddress;
    const mtu = if (value.mtu.value().len == 0) 1500 else std.fmt.parseInt(u16, value.mtu.value(), 10) catch return error.InvalidMtu;
    if (mtu < limits.mtu_min or @as(usize, mtu) + 14 > limits.frame_capacity) return error.InvalidMtu;
    return .{ .ip = ip, .prefix = prefix, .gateway = gateway, .mac = mac, .mtu = mtu };
}

test "VMs cancel, run one global at a time, reclaim memory, and rearm transport VMs" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    try log.logger.init(allocator, config_dir);
    defer log.logger.deinit();
    var storage: storage_module.Storage = .{ .config_dir = config_dir };
    const manager = try allocator.create(Manager);
    defer allocator.destroy(manager);
    // No manager thread: the test owns the transports.
    manager.* = .{ .allocator = allocator, .storage = &storage };
    manager.wake = try wait.Wake.init();
    defer manager.wake.deinit();
    defer manager.releaseTransports();
    manager.replenish();

    try std.testing.expect(manager.runGlobal("sleeper", "require('kraken/std').sleep(60000)"));
    try std.testing.expect(!manager.runGlobal("second", ""));
    manager.stopGlobal();

    try std.testing.expect(manager.runGlobal("modules",
        \\for _, name in ipairs({ "packet", "transmit", "socket", "identities", "globals", "std" }) do
        \\    require("kraken/" .. name)
        \\end
        \\for _, name in ipairs({
        \\    "http", "dns", "tls", "ssh", "dcerpc", "smb", "ldap",
        \\    "tftp", "snmp", "telnet", "sip", "smtp", "pop3", "imap",
        \\}) do require("protocols/" .. name) end
        \\require("kraken/globals").set({ ok = true })
    ));
    manager.global.join();
    try std.testing.expect(manager.globals.len > 0);

    const failing = manager.available().?;
    try failing.run("lookup", "setmetatable(_G, {__index = function() error('lookup failed') end})", .{ .bytes = "", .direction = .outbound });
    while (!failing.available()) std.Io.sleep(io.get(), .fromMilliseconds(1), .awake) catch {};
    var errors: [1024]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, try log.logger.readTail(&errors), "lookup failed") != null);

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
        while (!taken.available()) std.Io.sleep(io.get(), .fromMilliseconds(1), .awake) catch {};
        try std.testing.expect(manager.globals.len > 0);
    }
    // A burst grows the pool; once idle it shrinks back to the spares.
    for (0..6) |_| process(&runtime, "\x04", .outbound);
    var allocated: usize = 0;
    for (&manager.transports) |*transport| allocated += @intFromBool(transport.thread != null);
    try std.testing.expect(allocated > limits.transport_spare_vms);
    for (0..2000) |_| {
        manager.replenish();
        allocated = 0;
        for (&manager.transports) |*transport| allocated += @intFromBool(transport.thread != null);
        if (allocated == limits.transport_spare_vms) break;
        std.Io.sleep(io.get(), .fromMilliseconds(1), .awake) catch {};
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
            const source: *Runtime = @fieldParentPtr("iface", packet.iface);
            const destination = if (source == self.local) &self.remote.iface else &self.local.iface;
            destination.input(bytes[0..packet.length]) catch {};
        }
        std.Io.sleep(io.get(), .fromMilliseconds(1), .awake) catch {};
    }
};

test "virtual link carries TCP, UDP and raw sockets" {
    const allocator = std.testing.allocator;
    var manager: Manager = .{ .allocator = allocator, .storage = undefined };
    try manager.stack.init(allocator, &manager, testWake);
    var local: Runtime = .{ .manager = &manager, .name = .{}, .run_id = 1, .transport = null };
    var remote: Runtime = .{ .manager = &manager, .name = .{}, .run_id = 2, .transport = null };
    var configuration: identity.Identity = .{};
    try configuration.ip.set("10.0.0.1");
    try configuration.mac.set("02:00:00:00:00:01");
    try local.iface.init(&manager.stack, try parseStackConfig(&configuration));
    defer local.iface.deinit();
    try configuration.ip.set("10.0.0.2");
    try configuration.mac.set("02:00:00:00:00:02");
    try configuration.mtu.set("2000");
    try remote.iface.init(&manager.stack, try parseStackConfig(&configuration));
    defer remote.iface.deinit();
    var link: Link = .{ .manager = &manager, .local = &local, .remote = &remote };
    var address: net.Address = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 };
    var bind_address: net.Address = .{ .port = 7000 };
    var listener: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    try std.testing.expect(remote.iface.socket(.bind, &listener.endpoint, &bind_address, &.{}) == .success);
    try std.testing.expect(remote.iface.socket(.listen, &listener.endpoint, null, &.{}) == .success);

    var cancelled: std.Io.Event = .unset;
    var client: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    var buffer: [10]u8 = undefined;
    const Call = struct {
        fn run(runtime: *Runtime, link_value: *Link, call: command.SocketCall) net.SocketResult {
            const operation: command.Command = .{ .socket = call };
            var pending: Request = .{ .command = &operation };
            while (!runtime.socket(&pending)) link_value.pump();
            return pending.result catch unreachable;
        }
    };
    const base: command.SocketCall = .{ .action = .connect, .socket = &client, .address = &address, .bytes = &.{}, .deadline = io.now().toMilliseconds() + 2000, .cancelled = &cancelled };
    try std.testing.expectEqual(@as(usize, 0), Call.run(&local, &link, base).success);

    var peer: command.Socket = .{ .identity = .{}, .endpoint = .{ .kind = .tcp } };
    while (peer.endpoint.handle == null) : (link.pump()) {
        const result = remote.iface.socket(.accept, &listener.endpoint, null, &.{});
        if (result == .accepted) peer.endpoint.handle = result.accepted;
    }
    var hello = "hello".*;
    while (remote.iface.socket(.send, &peer.endpoint, null, &hello) == .would_block) link.pump();

    var receive = base;
    receive.action = .receive;
    receive.address = null;
    receive.bytes = &buffer;
    receive.deadline = io.now().toMilliseconds() + 1000;
    try std.testing.expectEqual(@as(usize, 5), Call.run(&local, &link, receive).success);
    try std.testing.expectEqualStrings("hello", buffer[0..5]);
    receive.deadline = io.now().toMilliseconds() + 50;
    try std.testing.expect(Call.run(&local, &link, receive) == .would_block);

    // One command completes a send larger than lwIP's default TCP send buffer.
    var payload = [_]u8{0x5a} ** 2000;
    var send = base;
    send.action = .send;
    send.address = null;
    send.bytes = &payload;
    send.deadline = io.now().toMilliseconds() + 1000;
    try std.testing.expectEqual(payload.len, Call.run(&local, &link, send).success);
    var received_payload: [payload.len]u8 = undefined;
    var received_count: usize = 0;
    while (received_count < received_payload.len and io.now().toMilliseconds() < send.deadline.?) {
        link.pump();
        const result = remote.iface.socket(.receive, &peer.endpoint, null, received_payload[received_count..]);
        if (result == .success) received_count += result.success else try std.testing.expect(result == .would_block);
    }
    try std.testing.expectEqual(payload.len, received_count);
    try std.testing.expectEqualSlices(u8, &payload, &received_payload);

    var bye = "bye".*;
    while (remote.iface.socket(.send, &peer.endpoint, null, &bye) == .would_block) link.pump();
    _ = remote.iface.socket(.close, &peer.endpoint, null, &.{});
    receive.deadline = io.now().toMilliseconds() + 1000;
    try std.testing.expectEqual(@as(usize, 3), Call.run(&local, &link, receive).success);
    try std.testing.expectEqualStrings("bye", buffer[0..3]);
    try std.testing.expect(Call.run(&local, &link, receive) == .closed);

    // Wildcard binds are scoped to an identity, so both can use the same port.
    var local_udp: net.Socket = .{ .kind = .udp };
    var remote_udp: net.Socket = .{ .kind = .udp };
    var udp_bind: net.Address = .{ .port = 7001 };
    try std.testing.expect(local.iface.socket(.bind, &local_udp, &udp_bind, &.{}) == .success);
    try std.testing.expect(remote.iface.socket(.bind, &remote_udp, &udp_bind, &.{}) == .success);
    var udp_data = "udp".*;
    var udp_destination: net.Address = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7001 };
    try std.testing.expect(local.iface.socket(.send, &local_udp, &udp_destination, &udp_data) == .success);
    var udp_source: net.Address = .{};
    var datagram: [16]u8 = undefined;
    var udp_result: net.SocketResult = .would_block;
    const udp_deadline = io.now().toMilliseconds() + 1000;
    while (udp_result == .would_block and io.now().toMilliseconds() < udp_deadline) {
        link.pump();
        udp_result = remote.iface.socket(.receive, &remote_udp, &udp_source, &datagram);
    }
    try std.testing.expect(udp_result == .success);
    try std.testing.expectEqualStrings("udp", datagram[0..udp_result.success]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &udp_source.ip);
    try std.testing.expect(local.iface.socket(.receive, &local_udp, &udp_source, &datagram) == .would_block);

    var local_raw: net.Socket = .{ .kind = .raw, .protocol = 253 };
    var remote_raw: net.Socket = .{ .kind = .raw, .protocol = 253 };
    var raw_bind: net.Address = .{};
    try std.testing.expect(local.iface.socket(.bind, &local_raw, &raw_bind, &.{}) == .success);
    try std.testing.expect(remote.iface.socket(.bind, &remote_raw, &raw_bind, &.{}) == .success);
    // Receive a frame larger than the local MTU, within Kraken's buffer capacity.
    var raw_data = [_]u8{0xa5} ** 1800;
    var raw_destination: net.Address = .{ .ip = .{ 10, 0, 0, 1 } };
    try std.testing.expect(remote.iface.socket(.send, &remote_raw, &raw_destination, &raw_data) == .success);
    var packet: [limits.frame_capacity]u8 = undefined;
    var raw_result: net.SocketResult = .would_block;
    const raw_deadline = io.now().toMilliseconds() + 1000;
    while (raw_result == .would_block and io.now().toMilliseconds() < raw_deadline) {
        link.pump();
        raw_result = local.iface.socket(.receive, &local_raw, &udp_source, &packet);
    }
    try std.testing.expect(raw_result == .success);
    try std.testing.expect(std.mem.endsWith(u8, packet[0..raw_result.success], &raw_data));
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &udp_source.ip);

    try std.testing.expectError(error.FrameExceedsCapacity, local.inject(&([_]u8{0} ** (limits.frame_capacity + 1)), .inbound));
}

fn testWake(_: ?*anyopaque) callconv(.c) void {}
