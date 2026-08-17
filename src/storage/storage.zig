const std = @import("std");
const config_path = @import("config_path.zig");
const identity_repository = @import("identity_repository.zig");
const script_repository = @import("script_repository.zig");
const limits = @import("../limits.zig");
const model = @import("model.zig");

pub const Storage = struct {
    allocator: std.mem.Allocator,
    config_dir: []const u8,
    scratch: *[limits.storage_scratch_capacity]u8,

    pub fn identities(self: *Storage) identity_repository.Store {
        return .{ .allocator = self.allocator, .scratch = self.scratch, .config_dir = self.config_dir };
    }

    pub fn scripts(self: *Storage, kind: script_repository.Kind) script_repository.Store {
        return .{ .scratch = self.scratch, .config_dir = self.config_dir, .kind = kind };
    }
};

pub const Identity = model.Identity;
pub const IdentityCatalog = model.IdentityCatalog;
pub const IdentityDraft = identity_repository.Draft;
pub const Script = model.Script;
pub const ScriptCatalog = model.ScriptCatalog;
pub const ScriptSource = model.ScriptSource;
pub const ScriptKind = script_repository.Kind;

pub fn discoverConfigDir(allocator: std.mem.Allocator) ![]u8 {
    return config_path.discover(allocator);
}
