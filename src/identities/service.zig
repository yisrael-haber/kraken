const std = @import("std");
const limits = @import("../limits.zig");
const model = @import("../storage/model.zig");
const storage_module = @import("../storage/storage.zig");
const runtime = @import("../runtime/runtime.zig");
const pcap = @import("../platform/pcap.zig");

pub const Command = union(enum) {
    create: model.IdentityDraft,
    update: struct { id: model.IdentityIdText, draft: model.IdentityDraft },
    delete: model.IdentityIdText,
    start: struct { id: model.IdentityIdText, transport: ?model.FixedText(limits.source_capacity) = null },
    stop: model.IdentityIdText,
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

pub const Service = struct {
    storage: *storage_module.Storage,
    runtime_instance: *runtime.Runtime,
    catalog: model.IdentityCatalog = .{},
    devices: [32]pcap.Device = undefined,
    device_count: usize = 0,

    pub fn init(self: *Service, storage: *storage_module.Storage, runtime_instance: *runtime.Runtime) !void {
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
        var loaded: model.IdentityCatalog = .{};
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
                if (!std.mem.eql(u8, current_name, update.draft.label) and self.runtime_instance.isActive(current_name)) return error.IdentityInUse;
                if (self.indexOfName(update.draft.label, update.id.value()) != null) return error.IdentityNameInUse;
                self.storage.identities().save(update.draft, update.id.value()) catch return error.StorageFailure;
                self.reload() catch |err| return mapReloadError(err);
            },
            .delete => |id| {
                const index = self.indexOf(id) orelse return error.IdentityNotFound;
                if (self.runtime_instance.isActive(self.catalog.values[index].label.value())) return error.IdentityInUse;
                self.storage.identities().delete(id.value()) catch return error.StorageFailure;
                self.reload() catch |err| return mapReloadError(err);
            },
            .start => |start| {
                const index = self.indexOf(start.id) orelse return error.IdentityNotFound;
                const identity = &self.catalog.values[index];
                if (self.indexOfName(identity.label.value(), identity.file_name.value()) != null) return error.IdentityNameInUse;
                var runtime_identity = try buildRuntimeIdentity(identity);
                runtime_identity.transport = start.transport;
                if (!self.runtime_instance.start(runtime_identity)) return error.RuntimeUnavailable;
            },
            .stop => |id| {
                const index = self.indexOf(id) orelse return error.IdentityNotFound;
                if (!self.runtime_instance.stopNamed(self.catalog.values[index].label.value())) return error.RuntimeUnavailable;
            },
        }
    }

    pub fn isActive(self: *Service, id: []const u8) bool {
        for (self.catalog.slice()) |identity| {
            if (identity.file_name.eql(id)) return self.runtime_instance.isActive(identity.label.value());
        }
        return false;
    }

    pub fn nextIssue(self: *Service) ?runtime.Issue {
        return self.runtime_instance.pollIssue();
    }

    fn indexOf(self: *const Service, id: model.IdentityIdText) ?usize {
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
        if (self.catalog.len == 0) return self.runtime_instance.takeIdentities(&.{});
        var identities = try self.runtime_instance.allocator.alloc(runtime.Identity, self.catalog.len);
        errdefer self.runtime_instance.allocator.free(identities);
        var len: usize = 0;
        for (self.catalog.slice()) |*identity| {
            if (self.indexOfName(identity.label.value(), identity.file_name.value()) != null) continue;
            identities[len] = buildRuntimeIdentity(identity) catch continue;
            len += 1;
        }
        if (len < identities.len) identities = try self.runtime_instance.allocator.realloc(identities, len);
        self.runtime_instance.takeIdentities(identities);
    }
};

fn mapReloadError(_: anyerror) Error {
    return error.StorageFailure;
}

fn buildRuntimeIdentity(identity: *const model.Identity) Error!runtime.Identity {
    if (identity.label.value().len == 0) return error.RuntimeUnavailable;
    if (identity.interface.value().len == 0) return error.InterfaceRequired;

    var runtime_identity: runtime.Identity = .{
        .name = .{},
        .interface = .{},
        .network = .{
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
        },
    };
    runtime_identity.name.set(identity.label.value()) catch return error.RuntimeUnavailable;
    runtime_identity.interface.set(identity.interface.value()) catch return error.RuntimeUnavailable;
    return runtime_identity;
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

    const config = try buildRuntimeIdentity(&identity);
    const network = config.network;
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 50 }, network.address);
    try std.testing.expectEqual(@as(u8, 25), network.prefix_length);
    try std.testing.expectEqual([4]u8{ 192, 168, 122, 1 }, network.gateway.?);
    try std.testing.expectEqual([6]u8{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, network.mac);
    try std.testing.expectEqual(@as(u16, 1400), network.mtu);
}

test "blank optional network fields use deterministic defaults" {
    var identity: model.Identity = .{};
    try identity.label.set("defaults");
    try identity.interface.set("eth0");
    try identity.ip.set("10.0.0.8");

    const config = try buildRuntimeIdentity(&identity);
    const network = config.network;
    try std.testing.expectEqual(@as(u8, 24), network.prefix_length);
    try std.testing.expectEqual(@as(?[4]u8, null), network.gateway);
    try std.testing.expectEqual(defaultMac(identity.label.value()), network.mac);
    try std.testing.expectEqual(@as(u16, 1500), network.mtu);
}

test "invalid network fields are rejected before runtime start" {
    var identity: model.Identity = .{};
    try identity.label.set("invalid");
    try identity.interface.set("eth0");
    try identity.ip.set("192.168.1.999");
    try std.testing.expectError(error.InvalidIpAddress, buildRuntimeIdentity(&identity));

    try identity.ip.set("192.168.1.8");
    try identity.mac.set("ff:ff:ff:ff:ff:ff");
    try std.testing.expectError(error.InvalidMacAddress, buildRuntimeIdentity(&identity));
}
