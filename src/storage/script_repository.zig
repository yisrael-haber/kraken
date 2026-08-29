const std = @import("std");
const file_store = @import("file_store.zig");
const limits = @import("../limits.zig");
const model = @import("model.zig");

pub const Kind = enum {
    global,
    transport,
    helpers,

    fn directoryName(self: Kind) []const u8 {
        return switch (self) {
            .global => "global",
            .transport => "transport",
            .helpers => "helpers",
        };
    }
};

pub const Script = model.Script;
pub const Catalog = model.ScriptCatalog;
pub const Store = struct {
    scratch: *[limits.storage_scratch_capacity]u8,
    config_dir: []const u8,
    kind: Kind,

    pub fn load(self: Store, catalog: *Catalog) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try self.directoryPath(&path_buffer);
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, dir_path, .{
            .open_options = .{ .iterate = true },
        });
        defer dir.close(io);

        catalog.len = 0;
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".lua")) continue;
            const name = entry.name[0 .. entry.name.len - ".lua".len];
            if (name.len == 0) continue;
            if (catalog.len == catalog.values.len) return error.CapacityExceeded;
            var script: Script = .{};
            script.file_name.set(entry.name) catch return error.CapacityExceeded;
            script.name.set(name) catch return error.CapacityExceeded;
            catalog.values[catalog.len] = script;
            catalog.len += 1;
        }
        sortByName(catalog.values[0..catalog.len]);
    }

    pub fn read(self: Store, file_name: []const u8, source: *model.FixedText(limits.source_capacity)) !void {
        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir_path = try std.fs.path.join(allocator, &.{ self.config_dir, "scripts", self.kind.directoryName() });
        const dir = try std.Io.Dir.openDir(.cwd(), io, dir_path, .{});
        defer dir.close(io);
        const contents = try dir.readFileAlloc(io, file_name, allocator, .limited(limits.source_capacity));
        try source.set(contents);
    }

    pub fn save(self: Store, name: []const u8, source: []const u8, previous_file_name: ?[]const u8, saved_file_name: *model.FieldText) !void {
        if (source.len > limits.source_capacity) return error.SourceTooLarge;
        var transient = std.heap.FixedBufferAllocator.init(self.scratch);
        const allocator = transient.allocator();
        const file_name = try fileNameForName(allocator, name);
        try saved_file_name.set(file_name);

        const io = std.Io.Threaded.global_single_threaded.io();
        const dir_path = try std.fs.path.join(allocator, &.{ self.config_dir, "scripts", self.kind.directoryName() });
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, dir_path, .{});
        defer dir.close(io);
        try file_store.writeAtomic(dir, io, allocator, file_name, source);

        if (previous_file_name) |previous| {
            if (!std.mem.eql(u8, previous, file_name)) {
                dir.deleteFile(io, previous) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return err,
                };
            }
        }
    }

    pub fn delete(self: Store, file_name: []const u8) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try self.directoryPath(&path_buffer);
        const dir = try std.Io.Dir.openDir(.cwd(), io, dir_path, .{});
        defer dir.close(io);
        try dir.deleteFile(io, file_name);
    }

    fn directoryPath(self: Store, buffer: *[std.fs.max_path_bytes]u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{s}{c}scripts{c}{s}", .{ self.config_dir, std.fs.path.sep, std.fs.path.sep, self.kind.directoryName() });
    }
};

fn fileNameForName(allocator: std.mem.Allocator, raw_name: []const u8) ![]u8 {
    const name = if (std.mem.endsWith(u8, raw_name, ".lua")) raw_name[0 .. raw_name.len - ".lua".len] else raw_name;
    if (name.len == 0) return error.NameRequired;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidName;
    for (name) |byte| {
        if (byte == '/' or byte == '\\' or byte == 0) return error.InvalidName;
    }
    return std.fmt.allocPrint(allocator, "{s}.lua", .{name});
}

fn sortByName(scripts: []Script) void {
    var i: usize = 1;
    while (i < scripts.len) : (i += 1) {
        const script = scripts[i];
        var j = i;
        while (j > 0 and std.mem.order(u8, scripts[j - 1].name.value(), script.name.value()) == .gt) : (j -= 1) {
            scripts[j] = scripts[j - 1];
        }
        scripts[j] = script;
    }
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
    const helpers_store = Store{ .scratch = &scratch, .config_dir = config_dir, .kind = .helpers };

    var global_file: model.FieldText = .{};
    try global_store.save("bootstrap", "print('global')", null, &global_file);
    var transport_file: model.FieldText = .{};
    try transport_store.save("bootstrap.lua", "print('transport')", null, &transport_file);
    var helper_file: model.FieldText = .{};
    try helpers_store.save("network", "return {}", null, &helper_file);

    var global_scripts: Catalog = .{};
    try global_store.load(&global_scripts);
    var transport_scripts: Catalog = .{};
    try transport_store.load(&transport_scripts);
    var helper_scripts: Catalog = .{};
    try helpers_store.load(&helper_scripts);
    try std.testing.expectEqual(@as(usize, 1), global_scripts.len);
    try std.testing.expectEqualStrings("bootstrap", global_scripts.values[0].name.value());
    try std.testing.expectEqual(@as(usize, 1), transport_scripts.len);
    try std.testing.expectEqualStrings("bootstrap", transport_scripts.values[0].name.value());
    try std.testing.expectEqual(@as(usize, 1), helper_scripts.len);
    try std.testing.expectEqualStrings("network", helper_scripts.values[0].name.value());

    var source: model.FixedText(limits.source_capacity) = .{};
    try transport_store.read(transport_scripts.values[0].file_name.value(), &source);
    try std.testing.expectEqualStrings("print('transport')", source.value());
    try transport_store.delete(transport_scripts.values[0].file_name.value());
}
