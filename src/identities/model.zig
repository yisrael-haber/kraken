const std = @import("std");
const repository = @import("../storage/identity_repository.zig");
const storage_model = @import("../storage/model.zig");

pub const Identity = storage_model.Identity;
pub const Draft = repository.Draft;

pub const IdentityId = struct {
    bytes: [64]u8 = [_]u8{0} ** 64,
    len: u8 = 0,

    pub fn init(raw: []const u8) error{IdentityIdTooLong}!IdentityId {
        if (raw.len > 64) return error.IdentityIdTooLong;
        var id: IdentityId = .{ .len = @intCast(raw.len) };
        @memcpy(id.bytes[0..raw.len], raw);
        return id;
    }

    pub fn value(self: *const IdentityId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: IdentityId, value_: []const u8) bool {
        return std.mem.eql(u8, self.value(), value_);
    }
};
