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
    config_dir: []const u8,
    kind: Kind,

    pub fn load(self: Store, allocator: std.mem.Allocator, catalog: *std.ArrayList(text.FieldText)) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, .{ .iterate = true });
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
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, .{});
        defer dir.close(io);
        var contents: [limits.source_capacity + 1]u8 = undefined;
        try source.set(try dir.readFile(io, file_name, &contents));
    }

    pub fn save(self: Store, name: []const u8, source: []const u8, previous_file_name: ?[]const u8) !text.FieldText {
        const base_name = std.mem.cutSuffix(u8, name, ".lua") orelse name;
        if (base_name.len == 0) return error.NameRequired;
        if (std.mem.indexOfAny(u8, base_name, "/\\\x00") != null) return error.InvalidName;
        var saved_file_name: text.FieldText = .{};
        saved_file_name.len = (std.fmt.bufPrintZ(&saved_file_name.bytes, "{s}.lua", .{base_name}) catch return error.CapacityExceeded).len;

        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, .{});
        defer dir.close(io);
        try file_store.writeAtomic(dir, io, saved_file_name.value(), source);
        if (previous_file_name) |previous| if (!std.mem.eql(u8, previous, saved_file_name.value())) try dir.deleteFile(io, previous);
        return saved_file_name;
    }

    pub fn delete(self: Store, file_name: []const u8) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = try self.openDirectory(io, .{});
        defer dir.close(io);
        try dir.deleteFile(io, file_name);
    }

    fn openDirectory(self: Store, io: std.Io, options: std.Io.Dir.OpenOptions) !std.Io.Dir {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, "{s}" ++ std.fs.path.sep_str ++ "scripts" ++ std.fs.path.sep_str ++ "{s}", .{ self.config_dir, @tagName(self.kind) });
        return std.Io.Dir.createDirPathOpen(.cwd(), io, path, .{ .open_options = options });
    }
};

fn lessByName(_: void, lhs: text.FieldText, rhs: text.FieldText) bool {
    return std.mem.order(u8, lhs.value(), rhs.value()) == .lt;
}

test "script kinds are isolated below the scripts root" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    const global_store = Store{ .config_dir = config_dir, .kind = .global };
    const transport_store = Store{ .config_dir = config_dir, .kind = .transport };

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

    var source: text.FixedText(limits.source_capacity) = undefined;
    try transport_store.read(transport_scripts.items[0].value(), &source);
    try std.testing.expectEqualStrings("print('transport')", source.value());
    const full_source = [_]u8{'x'} ** limits.source_capacity;
    _ = try transport_store.save("bootstrap", &full_source, null);
    try transport_store.read("bootstrap.lua", &source);
    try std.testing.expectEqualStrings(&full_source, source.value());
    _ = try transport_store.save("bootstrap", &([_]u8{'x'} ** (limits.source_capacity + 1)), null);
    try std.testing.expectError(error.CapacityExceeded, transport_store.read("bootstrap.lua", &source));
    try transport_store.delete(transport_scripts.items[0].value());
}
