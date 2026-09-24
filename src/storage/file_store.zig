const std = @import("std");

pub fn writeAtomic(dir: std.Io.Dir, io: std.Io, file_name: []const u8, data: []const u8) !void {
    var file = try dir.createFileAtomic(io, file_name, .{ .replace = true });
    defer file.deinit(io);
    try file.file.writeStreamingAll(io, data);
    try file.replace(io);
}
