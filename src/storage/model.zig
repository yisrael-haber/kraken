const std = @import("std");
const limits = @import("../limits.zig");

pub fn FixedText(comptime max_len: usize) type {
    return struct {
        pub const capacity = max_len;

        bytes: [max_len + 1]u8 = [_]u8{0} ** (max_len + 1),
        len: usize = 0,

        pub fn set(self: *@This(), text: []const u8) error{CapacityExceeded}!void {
            if (text.len > max_len) return error.CapacityExceeded;
            @memcpy(self.bytes[0..text.len], text);
            self.bytes[text.len] = 0;
            self.len = text.len;
        }

        pub fn value(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn valueZ(self: *const @This()) [:0]const u8 {
            return self.bytes[0..self.len :0];
        }

        pub fn eql(self: *const @This(), other: []const u8) bool {
            return std.mem.eql(u8, self.value(), other);
        }
    };
}

pub const IdentityIdText = FixedText(64);
pub const FieldText = FixedText(limits.field_capacity);
pub const Identity = struct {
    file_name: IdentityIdText = .{},
    label: FieldText = .{},
    ip: FieldText = .{},
    prefix: FieldText = .{},
    interface: FieldText = .{},
    gateway: FieldText = .{},
    mac: FieldText = .{},
    mtu: FieldText = .{},
};

pub const IdentityDraft = struct {
    label: []const u8 = "",
    ip: []const u8 = "",
    prefix: []const u8 = "",
    interface: []const u8 = "",
    gateway: []const u8 = "",
    mac: []const u8 = "",
    mtu: []const u8 = "",
};

pub const IdentityCatalog = struct {
    values: []Identity = &.{},
    len: usize = 0,

    pub fn slice(self: *const IdentityCatalog) []const Identity {
        return self.values[0..self.len];
    }

    pub fn deinit(self: *IdentityCatalog, allocator: std.mem.Allocator) void {
        if (self.values.len > 0) allocator.free(self.values);
        self.* = .{};
    }
};

pub const Script = struct {
    file_name: FieldText = .{},
    name: FieldText = .{},
};

pub const ScriptCatalog = struct {
    values: [limits.max_scripts_per_kind]Script = undefined,
    len: usize = 0,

    pub fn slice(self: *const ScriptCatalog) []const Script {
        return self.values[0..self.len];
    }
};

test "fixed text rejects overflow without changing its value" {
    var text: FieldText = .{};
    try text.set("kept");
    const oversized = [_]u8{'x'} ** (limits.field_capacity + 1);
    try std.testing.expectError(error.CapacityExceeded, text.set(&oversized));
    try std.testing.expectEqualStrings("kept", text.value());
}
