const std = @import("std");
const builtin = @import("builtin");
const known_folders = @import("known-folders");
const io = @import("../io.zig");
const identity_repository = @import("identity_repository.zig");
const script_repository = @import("script_repository.zig");

pub const Storage = struct {
    config_dir: []const u8,

    pub fn identities(self: *Storage) identity_repository.Store {
        return .{ .config_dir = self.config_dir };
    }

    pub fn scripts(self: *Storage, kind: script_repository.Kind) script_repository.Store {
        return .{ .config_dir = self.config_dir, .kind = kind };
    }
};

pub fn discoverConfigDir(allocator: std.mem.Allocator) ![]u8 {
    const environ: std.process.Environ = switch (builtin.os.tag) {
        .windows => .{ .block = .global },
        else => .{ .block = .{ .slice = std.mem.span(std.c.environ) } },
    };
    var environ_map = try std.process.Environ.createMap(environ, allocator);
    defer environ_map.deinit();
    const base = try known_folders.getPath(io.get(), allocator, &environ_map, .local_configuration) orelse return error.ConfigDirectoryUnavailable;
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "kraken" });
}
