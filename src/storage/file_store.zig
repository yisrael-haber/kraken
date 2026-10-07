const std = @import("std");
const io = @import("../io.zig");

pub fn writeAtomic(dir: std.Io.Dir, file_name: []const u8, data: []const u8) !void {
    var file = try dir.createFileAtomic(io.get(), file_name, .{ .replace = true });
    defer file.deinit(io.get());
    try file.file.writeStreamingAll(io.get(), data);
    try file.replace(io.get());
}
