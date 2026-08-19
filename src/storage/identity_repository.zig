const std = @import("std");
const file_store = @import("file_store.zig");
const limits = @import("../limits.zig");
const model = @import("model.zig");

pub const Identity = model.Identity;
pub const Catalog = model.IdentityCatalog;

pub const Draft = model.IdentityDraft;

pub const Store = struct {
    allocator: std.mem.Allocator,
    scratch: *[limits.storage_scratch_capacity]u8,
    config_dir: []const u8,

    pub fn load(self: Store, catalog: *Catalog) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const identities_path = try directoryPath(self.config_dir, "identities", &path_buffer);
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, identities_path, .{
            .open_options = .{ .iterate = true },
        });
        defer dir.close(io);

        catalog.deinit(self.allocator);
        errdefer catalog.deinit(self.allocator);
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
            var transient = std.heap.FixedBufferAllocator.init(self.scratch);
            const allocator = transient.allocator();
            const contents = try dir.readFileAlloc(io, entry.name, allocator, .limited(64 * 1024));
            var parsed = std.json.parseFromSlice(Draft, allocator, contents, .{}) catch return error.MalformedIdentity;
            defer parsed.deinit();
            try append(catalog, self.allocator, fromDisk(entry.name, parsed.value) catch return error.MalformedIdentity);
            catalog.len += 1;
        }
        sortByLabel(catalog.values[0..catalog.len]);
    }

    pub fn save(self: Store, identity: Draft, previous_file_name: ?[]const u8) !void {
        if (identity.label.len == 0) return error.LabelRequired;

        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        const io = std.Io.Threaded.global_single_threaded.io();
        const identities_path = try std.fs.path.join(allocator, &.{ self.config_dir, "identities" });
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, identities_path, .{});
        defer dir.close(io);

        const file_name = if (previous_file_name) |previous|
            try allocator.dupe(u8, previous)
        else
            try fileNameForLabel(allocator, identity.label);
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        try std.json.fmt(identity, .{ .whitespace = .indent_2 }).format(&output.writer);
        try file_store.writeAtomic(dir, io, allocator, file_name, output.written());
    }

    pub fn delete(self: Store, file_name: []const u8) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const identities_path = try directoryPath(self.config_dir, "identities", &path_buffer);
        const dir = try std.Io.Dir.openDir(.cwd(), io, identities_path, .{});
        defer dir.close(io);
        try dir.deleteFile(io, file_name);
    }
};

fn append(catalog: *Catalog, allocator: std.mem.Allocator, value: Identity) !void {
    if (catalog.len == catalog.values.len) {
        const capacity = if (catalog.values.len == 0) 16 else catalog.values.len * 2;
        catalog.values = if (catalog.values.len == 0)
            try allocator.alloc(Identity, capacity)
        else
            try allocator.realloc(catalog.values, capacity);
    }
    catalog.values[catalog.len] = value;
}

fn fromDisk(file_name: []const u8, disk: Draft) !Identity {
    var identity: Identity = .{};
    try identity.file_name.set(file_name);
    try identity.label.set(disk.label);
    try identity.ip.set(disk.ip);
    try identity.prefix.set(disk.prefix);
    try identity.interface.set(disk.interface);
    try identity.gateway.set(disk.gateway);
    try identity.mac.set(disk.mac);
    try identity.mtu.set(disk.mtu);
    return identity;
}

fn directoryPath(config_dir: []const u8, child: []const u8, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{c}{s}", .{ config_dir, std.fs.path.sep, child });
}

fn fileNameForLabel(allocator: std.mem.Allocator, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{x}.json", .{std.hash.Wyhash.hash(0, label)});
}

fn sortByLabel(identities: []Identity) void {
    var i: usize = 1;
    while (i < identities.len) : (i += 1) {
        const identity = identities[i];
        var j = i;
        while (j > 0 and std.mem.order(u8, identities[j - 1].label.value(), identity.label.value()) == .gt) : (j -= 1) {
            identities[j] = identities[j - 1];
        }
        identities[j] = identity;
    }
}

test "store saves, reloads, and deletes identities" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const store = Store{ .allocator = allocator, .scratch = &scratch, .config_dir = config_dir };

    try store.save(.{
        .label = "base",
        .ip = "192.168.122.5",
        .prefix = "24",
        .interface = "eth0",
        .gateway = "192.168.122.1",
    }, null);

    var loaded: Catalog = .{};
    defer loaded.deinit(allocator);
    try store.load(&loaded);
    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expectEqualStrings("base", loaded.values[0].label.value());
    try std.testing.expectEqualStrings("192.168.122.5", loaded.values[0].ip.value());
    try std.testing.expectEqualStrings("24", loaded.values[0].prefix.value());

    try store.delete(loaded.values[0].file_name.value());
    var after_delete: Catalog = .{};
    defer after_delete.deinit(allocator);
    try store.load(&after_delete);
    try std.testing.expectEqual(@as(usize, 0), after_delete.len);
}

test "catalog grows beyond the former fixed identity limit" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const store = Store{ .allocator = allocator, .scratch = &scratch, .config_dir = config_dir };

    for (0..70) |index| {
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "identity-{d}", .{index});
        try store.save(.{ .label = name }, null);
    }

    var loaded: Catalog = .{};
    defer loaded.deinit(allocator);
    try store.load(&loaded);
    try std.testing.expectEqual(@as(usize, 70), loaded.len);
}

test "editing preserves the opaque identity filename" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const store = Store{ .allocator = allocator, .scratch = &scratch, .config_dir = config_dir };

    try store.save(.{ .label = "before" }, null);
    var before: Catalog = .{};
    defer before.deinit(allocator);
    try store.load(&before);
    try std.testing.expectEqual(@as(usize, 1), before.len);
    const original_file_name = try allocator.dupe(u8, before.values[0].file_name.value());
    defer allocator.free(original_file_name);

    try store.save(.{ .label = "after" }, original_file_name);
    var after: Catalog = .{};
    defer after.deinit(allocator);
    try store.load(&after);
    try std.testing.expectEqual(@as(usize, 1), after.len);
    try std.testing.expectEqualStrings(original_file_name, after.values[0].file_name.value());
    try std.testing.expectEqualStrings("after", after.values[0].label.value());
}

test "malformed identity is reported" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    const identities_path = try std.fs.path.join(allocator, &.{ config_dir, "identities" });
    defer allocator.free(identities_path);
    const io = std.Io.Threaded.global_single_threaded.io();
    const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, identities_path, .{});
    defer dir.close(io);
    try dir.writeFile(io, .{ .sub_path = "broken.json", .data = "{" });

    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const store = Store{ .allocator = allocator, .scratch = &scratch, .config_dir = config_dir };
    var catalog: Catalog = .{};
    try std.testing.expectError(error.MalformedIdentity, store.load(&catalog));
}
