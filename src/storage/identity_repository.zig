const std = @import("std");
const file_store = @import("file_store.zig");
const io = @import("../io.zig");
const identity = @import("../identities/identity.zig");
const log = @import("../log.zig");

/// Working memory for reading or writing one identity file; it also bounds the file's size.
const scratch_capacity = 16 * 1024;

pub const Store = struct {
    config_dir: []const u8,

    pub fn load(self: Store, allocator: std.mem.Allocator, catalog: *std.ArrayList(identity.Identity)) !void {
        const dir = try self.openDirectory(.{ .iterate = true });
        defer dir.close(io.get());

        catalog.clearRetainingCapacity();
        var scratch: [scratch_capacity]u8 = undefined;
        var iterator = dir.iterate();
        while (try iterator.next(io.get())) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
            var transient = std.heap.FixedBufferAllocator.init(&scratch);
            const parsed = read(dir, entry.name, transient.allocator()) catch |err| {
                log.logger.formatted(.warning, .app, "Identity file \"{s}\" skipped: {s}.", .{ entry.name, @errorName(err) });
                continue;
            };
            try catalog.append(allocator, parsed);
        }
        std.mem.sort(identity.Identity, catalog.items, {}, lessByLabel);
    }

    pub fn save(self: Store, value: identity.Identity) !void {
        var scratch: [scratch_capacity]u8 = undefined;
        var transient = std.heap.FixedBufferAllocator.init(&scratch);
        const allocator = transient.allocator();
        var saved = value;
        if (saved.id.value().len == 0) try saved.id.set(try std.fmt.allocPrint(allocator, "{x}.json", .{std.hash.Wyhash.hash(0, saved.label.value())}));
        const dir = try self.openDirectory(.{});
        defer dir.close(io.get());
        try file_store.writeAtomic(dir, saved.id.value(), try std.json.Stringify.valueAlloc(allocator, saved, .{}));
    }

    pub fn delete(self: Store, file_name: []const u8) !void {
        const dir = try self.openDirectory(.{});
        defer dir.close(io.get());
        try dir.deleteFile(io.get(), file_name);
    }

    fn openDirectory(self: Store, options: std.Io.Dir.OpenOptions) !std.Io.Dir {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, "{s}" ++ std.fs.path.sep_str ++ "identities", .{self.config_dir});
        return std.Io.Dir.createDirPathOpen(.cwd(), io.get(), path, .{ .open_options = options });
    }
};

fn read(dir: std.Io.Dir, file_name: []const u8, allocator: std.mem.Allocator) !identity.Identity {
    const contents = try dir.readFileAlloc(io.get(), file_name, allocator, .unlimited);
    return std.json.parseFromSliceLeaky(identity.Identity, allocator, contents, .{});
}

fn lessByLabel(_: void, lhs: identity.Identity, rhs: identity.Identity) bool {
    return std.mem.order(u8, lhs.label.value(), rhs.label.value()) == .lt;
}

test "store persists, updates, and deletes identities" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    const store = Store{ .config_dir = config_dir };

    var value: identity.Identity = .{};
    try value.label.set("base");
    try value.ip.set("192.168.122.5");
    try value.transport.set("filter.lua");
    try store.save(value);

    var loaded: std.ArrayList(identity.Identity) = .empty;
    defer loaded.deinit(allocator);
    try store.load(allocator, &loaded);
    try std.testing.expectEqual(@as(usize, 1), loaded.items.len);
    try std.testing.expectEqualStrings("base", loaded.items[0].label.value());
    try std.testing.expectEqualStrings("192.168.122.5", loaded.items[0].ip.value());
    try std.testing.expectEqualStrings("filter.lua", loaded.items[0].transport.value());

    const id = loaded.items[0].id;
    value = loaded.items[0];
    try value.label.set("after");
    try store.save(value);
    try store.load(allocator, &loaded);
    try std.testing.expectEqual(@as(usize, 1), loaded.items.len);
    try std.testing.expectEqualStrings(id.value(), loaded.items[0].id.value());
    try std.testing.expectEqualStrings("after", loaded.items[0].label.value());

    try store.delete(loaded.items[0].id.value());
    try store.load(allocator, &loaded);
    try std.testing.expectEqual(@as(usize, 0), loaded.items.len);
}
