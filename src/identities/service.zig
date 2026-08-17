const std = @import("std");
const limits = @import("../limits.zig");
const model = @import("model.zig");
const storage_module = @import("../storage/storage.zig");
const runtime = @import("../runtime/runtime.zig");
const pcap = @import("../platform/pcap.zig");

pub const Command = union(enum) {
    create: model.Draft,
    update: struct { id: model.IdentityId, draft: model.Draft },
    delete: model.IdentityId,
    start: struct { id: model.IdentityId, transport: ?runtime.Source = null },
    stop: model.IdentityId,
};

pub const Error = error{
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    RuntimeUnavailable,
    StorageFailure,
    InterfaceRequired,
    InvalidIpAddress,
    InvalidPrefixLength,
    InvalidGatewayAddress,
    InvalidMacAddress,
    InvalidMtu,
};

pub const Event = union(enum) {
    runtime: runtime.Event,
    overflow,
};

pub const Service = struct {
    storage: *storage_module.Storage,
    runtime_instance: *runtime.AppRuntime,
    catalog: storage_module.IdentityCatalog = .{},
    devices: [32]pcap.Device = undefined,
    device_count: usize = 0,
    events: [limits.identity_event_capacity]Event = undefined,
    event_read: usize = 0,
    event_len: usize = 0,
    event_overflow: bool = false,

    pub fn init(self: *Service, storage: *storage_module.Storage, runtime_instance: *runtime.AppRuntime) !void {
        self.* = .{ .storage = storage, .runtime_instance = runtime_instance };
        self.device_count = pcap.Handle.list(&self.devices);
        try self.reload();
    }

    pub fn deinit(self: *Service) void {
        self.catalog.deinit(self.storage.allocator);
    }

    pub fn snapshot(self: *const Service) []const model.Identity {
        return self.catalog.slice();
    }

    pub fn interfaces(self: *const Service) []const pcap.Device {
        return self.devices[0..self.device_count];
    }

    pub fn reload(self: *Service) !void {
        var loaded: storage_module.IdentityCatalog = .{};
        errdefer loaded.deinit(self.storage.allocator);
        try self.storage.identities().load(&loaded);
        self.catalog.deinit(self.storage.allocator);
        self.catalog = loaded;
        try self.syncRuntime();
    }

    pub fn execute(self: *Service, command: Command) Error!void {
        switch (command) {
            .create => |draft| {
                if (self.indexOfName(draft.label, null) != null) return error.IdentityNameInUse;
                self.storage.identities().save(draft, null) catch return error.StorageFailure;
                self.reload() catch |err| return mapReloadError(err);
            },
            .update => |update| {
                const index = self.indexOf(update.id) orelse return error.IdentityNotFound;
                const current_name = self.catalog.values[index].label.value();
                if (!std.mem.eql(u8, current_name, update.draft.label) and self.runtime_instance.slotForName(current_name) != null) return error.IdentityInUse;
                if (self.indexOfName(update.draft.label, update.id.value()) != null) return error.IdentityNameInUse;
                self.storage.identities().save(update.draft, update.id.value()) catch return error.StorageFailure;
                self.reload() catch |err| return mapReloadError(err);
            },
            .delete => |id| {
                const index = self.indexOf(id) orelse return error.IdentityNotFound;
                if (self.runtime_instance.slotForName(self.catalog.values[index].label.value()) != null) return error.IdentityInUse;
                self.storage.identities().delete(id.value()) catch return error.StorageFailure;
                self.reload() catch |err| return mapReloadError(err);
            },
            .start => |start| {
                const index = self.indexOf(start.id) orelse return error.IdentityNotFound;
                const identity = &self.catalog.values[index];
                if (self.indexOfName(identity.label.value(), identity.file_name.value()) != null) return error.IdentityNameInUse;
                const config = try buildRuntimeConfig(identity);
                if (!self.runtime_instance.startNamed(identity.label.value(), .{ .config = config, .transport = start.transport })) return error.RuntimeUnavailable;
            },
            .stop => |id| {
                const index = self.indexOf(id) orelse return error.IdentityNotFound;
                if (!self.runtime_instance.stopNamed(self.catalog.values[index].label.value())) return error.RuntimeUnavailable;
            },
        }
    }

    pub fn slotFor(self: *Service, id: []const u8) ?usize {
        const identity_id = model.IdentityId.init(id) catch return null;
        const index = self.indexOf(identity_id) orelse return null;
        return self.runtime_instance.slotForName(self.catalog.values[index].label.value());
    }

    pub fn pumpRuntimeEvents(self: *Service) void {
        var count: usize = 0;
        while (count < runtime.event_capacity) : (count += 1) {
            const value = self.runtime_instance.pollEvent() orelse break;
            self.emit(.{ .runtime = value });
        }
        if (self.event_overflow and self.event_len < self.events.len) {
            self.event_overflow = false;
            self.push(.overflow);
        }
    }

    pub fn nextEvent(self: *Service) ?Event {
        if (self.event_len == 0) return null;
        const result = self.events[self.event_read];
        self.event_read = (self.event_read + 1) % self.events.len;
        self.event_len -= 1;
        return result;
    }

    fn indexOf(self: *const Service, id: model.IdentityId) ?usize {
        for (self.catalog.slice(), 0..) |identity, index| if (id.eql(identity.file_name.value())) return index;
        return null;
    }

    fn indexOfName(self: *const Service, name: []const u8, excluding_file: ?[]const u8) ?usize {
        for (self.catalog.slice(), 0..) |identity, index| {
            if (!std.mem.eql(u8, identity.label.value(), name)) continue;
            if (excluding_file) |excluded| if (std.mem.eql(u8, identity.file_name.value(), excluded)) continue;
            return index;
        }
        return null;
    }

    fn syncRuntime(self: *Service) !void {
        if (self.catalog.len == 0) return self.runtime_instance.replaceStoredIdentities(&.{});
        const identities = try self.storage.allocator.alloc(runtime.StoredIdentity, self.catalog.len);
        defer self.storage.allocator.free(identities);
        var len: usize = 0;
        for (self.catalog.slice()) |*identity| {
            if (self.indexOfName(identity.label.value(), identity.file_name.value()) != null) continue;
            const config = buildRuntimeConfig(identity) catch continue;
            identities[len] = .{
                .name = runtime.IdentityName.init(identity.label.value()) catch continue,
                .config = config,
            };
            len += 1;
        }
        try self.runtime_instance.replaceStoredIdentities(identities[0..len]);
    }

    fn emit(self: *Service, value: Event) void {
        if (self.event_len == self.events.len) {
            self.event_overflow = true;
            return;
        }
        self.push(value);
    }

    fn push(self: *Service, value: Event) void {
        self.events[(self.event_read + self.event_len) % self.events.len] = value;
        self.event_len += 1;
    }
};

fn mapReloadError(_: anyerror) Error {
    return error.StorageFailure;
}

fn buildRuntimeConfig(identity: *const model.Identity) Error!runtime.IdentityConfig {
    if (identity.interface.value().len == 0) return error.InterfaceRequired;

    var config: runtime.IdentityConfig = .{};
    config.setLabel(identity.label.value());
    config.setInterface(identity.interface.value());
    config.network = .{
        .address = parseIpv4(identity.ip.value()) catch return error.InvalidIpAddress,
        .prefix_length = parsePrefix(identity.prefix.value()) catch return error.InvalidPrefixLength,
        .gateway = if (identity.gateway.value().len == 0)
            null
        else
            parseIpv4(identity.gateway.value()) catch return error.InvalidGatewayAddress,
        .mac = if (identity.mac.value().len == 0)
            defaultMac(identity.label.value())
        else
            parseMac(identity.mac.value()) catch return error.InvalidMacAddress,
        .mtu = parseMtu(identity.mtu.value()) catch return error.InvalidMtu,
    };
    return config;
}

fn defaultMac(name: []const u8) [6]u8 {
    const hash = std.hash.Wyhash.hash(0, name);
    return .{ 0x02, @truncate(hash >> 32), @truncate(hash >> 24), @truncate(hash >> 16), @truncate(hash >> 8), @truncate(hash) };
}

fn parseIpv4(value: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, value, '.');
    for (&result) |*octet| {
        const part = parts.next() orelse return error.InvalidAddress;
        if (part.len == 0) return error.InvalidAddress;
        octet.* = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
    }
    if (parts.next() != null) return error.InvalidAddress;
    return result;
}

fn parsePrefix(value: []const u8) !u8 {
    if (value.len == 0) return 24;
    const prefix = std.fmt.parseInt(u8, value, 10) catch return error.InvalidPrefix;
    if (prefix > 32) return error.InvalidPrefix;
    return prefix;
}

fn parseMac(value: []const u8) ![6]u8 {
    const separator: u8 = if (std.mem.indexOfScalar(u8, value, ':') != null) ':' else '-';
    var result: [6]u8 = undefined;
    var parts = std.mem.splitScalar(u8, value, separator);
    for (&result) |*octet| {
        const part = parts.next() orelse return error.InvalidMac;
        if (part.len != 2) return error.InvalidMac;
        octet.* = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMac;
    }
    if (parts.next() != null or (result[0] & 1) != 0) return error.InvalidMac;
    return result;
}

fn parseMtu(value: []const u8) !u16 {
    if (value.len == 0) return 1500;
    const mtu = std.fmt.parseInt(u16, value, 10) catch return error.InvalidMtu;
    if (mtu < 68 or mtu > 1500) return error.InvalidMtu;
    return mtu;
}

test "saved network fields produce typed runtime configuration" {
    var identity: model.Identity = .{};
    try identity.label.set("configured");
    try identity.interface.set("eth0");
    try identity.ip.set("192.168.122.50");
    try identity.prefix.set("25");
    try identity.gateway.set("192.168.122.1");
    try identity.mac.set("02:11:22:33:44:55");
    try identity.mtu.set("1400");

    const config = try buildRuntimeConfig(&identity);
    const network = config.network.?;
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 50 }, network.address);
    try std.testing.expectEqual(@as(u8, 25), network.prefix_length);
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 1 }, network.gateway.?);
    try std.testing.expectEqual([6]u8{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, network.mac);
    try std.testing.expectEqual(@as(u16, 1400), network.mtu);
}

test "blank optional network fields use deterministic defaults" {
    var identity: model.Identity = .{};
    try identity.interface.set("eth0");
    try identity.ip.set("10.0.0.8");

    const config = try buildRuntimeConfig(&identity);
    const network = config.network.?;
    try std.testing.expectEqual(@as(u8, 24), network.prefix_length);
    try std.testing.expectEqual(@as(?[4]u8, null), network.gateway);
    try std.testing.expectEqual(defaultMac(identity.label.value()), network.mac);
    try std.testing.expectEqual(@as(u16, 1500), network.mtu);
}

test "invalid network fields are rejected before runtime start" {
    var identity: model.Identity = .{};
    try identity.interface.set("eth0");
    try identity.ip.set("192.168.1.999");
    try std.testing.expectError(error.InvalidIpAddress, buildRuntimeConfig(&identity));

    try identity.ip.set("192.168.1.8");
    try identity.mac.set("ff:ff:ff:ff:ff:ff");
    try std.testing.expectError(error.InvalidMacAddress, buildRuntimeConfig(&identity));
}

test "stored identities do not reserve runtime slots" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    var storage: storage_module.Storage = .{ .allocator = allocator, .config_dir = config_dir, .scratch = &scratch };
    try storage.identities().save(.{ .label = "alpha" }, null);
    try storage.identities().save(.{ .label = "beta" }, null);

    var runtime_instance: runtime.AppRuntime = undefined;
    try runtime_instance.init(allocator);
    defer runtime_instance.deinit();
    var service: Service = undefined;
    try service.init(&storage, &runtime_instance);
    defer service.deinit();

    try std.testing.expectEqual(@as(usize, 2), service.snapshot().len);
    try std.testing.expect(service.slotFor(service.snapshot()[0].file_name.value()) == null);
    try std.testing.expect(service.slotFor(service.snapshot()[1].file_name.value()) == null);
    try std.testing.expectError(error.IdentityNameInUse, service.execute(.{ .create = .{ .label = "alpha" } }));
    try std.testing.expect(service.nextEvent() == null);
}
