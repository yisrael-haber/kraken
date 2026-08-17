const std = @import("std");

/// Replaces a file atomically within an already-open directory. The temporary
/// file is recoverable until the final rename succeeds.
pub fn writeAtomic(dir: std.Io.Dir, io: std.Io, allocator: std.mem.Allocator, file_name: []const u8, data: []const u8) !void {
    const temp_name = try std.fmt.allocPrint(allocator, ".{s}.tmp", .{file_name});
    defer allocator.free(temp_name);
    dir.deleteFile(io, temp_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try dir.writeFile(io, .{ .sub_path = temp_name, .data = data });
    errdefer dir.deleteFile(io, temp_name) catch {};
    try dir.rename(temp_name, dir, file_name, io);
}
