const std = @import("std");
const builtin = @import("builtin");
const known_folders = @import("known-folders");
const identity_repository = @import("identity_repository.zig");
const script_repository = @import("script_repository.zig");
const limits = @import("../limits.zig");

pub const Storage = struct {
    allocator: std.mem.Allocator,
    config_dir: []const u8,
    scratch: *[limits.storage_scratch_capacity]u8,

    pub fn identities(self: *Storage) identity_repository.Store {
        return .{ .scratch = self.scratch, .config_dir = self.config_dir };
    }

    pub fn scripts(self: *Storage, kind: script_repository.Kind) script_repository.Store {
        return .{ .scratch = self.scratch, .config_dir = self.config_dir, .kind = kind };
    }
};

pub fn discoverConfigDir(allocator: std.mem.Allocator) ![]u8 {
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
