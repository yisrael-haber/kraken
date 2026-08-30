const std = @import("std");
const file_store = @import("file_store.zig");
const limits = @import("../limits.zig");
const identity = @import("../identities/identity.zig");

pub const Store = struct {
    scratch: *[limits.storage_scratch_capacity]u8,
    config_dir: []const u8,

    pub fn load(self: Store, allocator: std.mem.Allocator, catalog: *std.ArrayList(identity.Identity)) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, true, .{ .iterate = true });
        defer dir.close(io);

        catalog.clearRetainingCapacity();
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
            var transient = std.heap.FixedBufferAllocator.init(self.scratch);
            const scratch_allocator = transient.allocator();
            const contents = try dir.readFileAlloc(io, entry.name, scratch_allocator, .limited(64 * 1024));
            var parsed = std.json.parseFromSliceLeaky(identity.Identity, scratch_allocator, contents, .{}) catch return error.MalformedIdentity;
            parsed.id.set(entry.name) catch return error.MalformedIdentity;
            try catalog.append(allocator, parsed);
        }
        std.mem.sort(identity.Identity, catalog.items, {}, lessByLabel);
    }

    pub fn save(self: Store, value: identity.Identity) !void {
        if (value.label.value().len == 0) return error.LabelRequired;

        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        var saved = value;
        if (saved.id.value().len == 0) try saved.id.set(try fileNameForLabel(allocator, saved.label.value()));
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, true, .{});
        defer dir.close(io);
        const file_name = saved.id.value();
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        try std.json.fmt(saved, .{}).format(&output.writer);
        try file_store.writeAtomic(dir, io, file_name, output.written());
    }

    pub fn delete(self: Store, file_name: []const u8) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, false, .{});
        defer dir.close(io);
        try dir.deleteFile(io, file_name);
    }

    fn openDirectory(self: Store, io: std.Io, create: bool, options: std.Io.Dir.OpenOptions) !std.Io.Dir {
        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        const path = try std.fs.path.join(allocator, &.{ self.config_dir, "identities" });
        return if (create)
            std.Io.Dir.createDirPathOpen(.cwd(), io, path, .{ .open_options = options })
        else
            std.Io.Dir.openDir(.cwd(), io, path, options);
    }
};

fn fileNameForLabel(allocator: std.mem.Allocator, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{x}.json", .{std.hash.Wyhash.hash(0, label)});
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
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const store = Store{ .scratch = &scratch, .config_dir = config_dir };

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
