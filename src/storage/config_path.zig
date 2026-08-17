const std = @import("std");
const builtin = @import("builtin");
const known_folders = @import("known-folders");

pub fn discover(allocator: std.mem.Allocator) ![]u8 {
    const environ: std.process.Environ = switch (builtin.os.tag) {
        .windows => .{ .block = .global },
        else => .{ .block = .{ .slice = std.mem.span(std.c.environ) } },
    };
    var environ_map = try std.process.Environ.createMap(environ, allocator);
    defer environ_map.deinit();
    const base = try known_folders.getPath(std.Io.Threaded.global_single_threaded.io(), allocator, &environ_map, .local_configuration) orelse return error.ConfigDirectoryUnavailable;
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "kraken" });
}
