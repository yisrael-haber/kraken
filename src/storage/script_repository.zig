const std = @import("std");
const file_store = @import("file_store.zig");
const limits = @import("../limits.zig");
const text = @import("../text.zig");

pub const Kind = enum {
    global,
    transport,
    helpers,
};

pub const Store = struct {
    scratch: *[limits.storage_scratch_capacity]u8,
    config_dir: []const u8,
    kind: Kind,

    pub fn load(self: Store, allocator: std.mem.Allocator, catalog: *std.ArrayList(text.FieldText)) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, true, .{ .iterate = true });
        defer dir.close(io);

        catalog.clearRetainingCapacity();
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".lua")) continue;
            var file_name: text.FieldText = .{};
            try file_name.set(entry.name);
            try catalog.append(allocator, file_name);
        }
        std.mem.sort(text.FieldText, catalog.items, {}, lessByName);
    }

    pub fn read(self: Store, file_name: []const u8, source: *text.FixedText(limits.source_capacity)) !void {
        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, false, .{});
        defer dir.close(io);
        const contents = try dir.readFileAlloc(io, file_name, allocator, .limited(limits.source_capacity));
        try source.set(contents);
    }

    pub fn save(self: Store, name: []const u8, source: []const u8, previous_file_name: ?[]const u8) !text.FieldText {
        if (source.len > limits.source_capacity) return error.SourceTooLarge;
        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        var saved_file_name: text.FieldText = .{};
        try saved_file_name.set(try fileNameForName(allocator, name));

        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, true, .{});
        defer dir.close(io);
        try file_store.writeAtomic(dir, io, saved_file_name.value(), source);

        if (previous_file_name) |previous| {
            if (!std.mem.eql(u8, previous, saved_file_name.value())) {
                dir.deleteFile(io, previous) catch |err| if (err != error.FileNotFound) return err;
            }
        }
        return saved_file_name;
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
        const path = try std.fs.path.join(allocator, &.{ self.config_dir, "scripts", @tagName(self.kind) });
        return if (create)
            std.Io.Dir.createDirPathOpen(.cwd(), io, path, .{ .open_options = options })
        else
            std.Io.Dir.openDir(.cwd(), io, path, options);
    }
};

fn fileNameForName(allocator: std.mem.Allocator, raw_name: []const u8) ![]u8 {
    const name = std.mem.cutSuffix(u8, raw_name, ".lua") orelse raw_name;
    if (name.len == 0) return error.NameRequired;
    if (std.mem.indexOfAny(u8, name, "/\\\x00") != null) return error.InvalidName;
    return std.fmt.allocPrint(allocator, "{s}.lua", .{name});
}

fn lessByName(_: void, lhs: text.FieldText, rhs: text.FieldText) bool {
    return std.mem.order(u8, lhs.value(), rhs.value()) == .lt;
}

test "script kinds are isolated below the scripts root" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var scratch: [limits.storage_scratch_capacity]u8 = undefined;
    const global_store = Store{ .scratch = &scratch, .config_dir = config_dir, .kind = .global };
    const transport_store = Store{ .scratch = &scratch, .config_dir = config_dir, .kind = .transport };

    _ = try global_store.save("bootstrap", "print('global')", null);
    _ = try transport_store.save("bootstrap.lua", "print('transport')", null);

    var global_scripts: std.ArrayList(text.FieldText) = .empty;
    try global_store.load(allocator, &global_scripts);
    var transport_scripts: std.ArrayList(text.FieldText) = .empty;
    try transport_store.load(allocator, &transport_scripts);
    defer global_scripts.deinit(allocator);
    defer transport_scripts.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), global_scripts.items.len);
    try std.testing.expectEqualStrings("bootstrap.lua", global_scripts.items[0].value());
    try std.testing.expectEqual(@as(usize, 1), transport_scripts.items.len);
    try std.testing.expectEqualStrings("bootstrap.lua", transport_scripts.items[0].value());

    var source: text.FixedText(limits.source_capacity) = .{};
    try transport_store.read(transport_scripts.items[0].value(), &source);
    try std.testing.expectEqualStrings("print('transport')", source.value());
    try transport_store.delete(transport_scripts.items[0].value());
}
