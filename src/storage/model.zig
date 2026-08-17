const limits = @import("../limits.zig");

pub fn FixedText(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = [_]u8{0} ** capacity,
        len: usize = 0,

        pub fn set(self: *@This(), text: []const u8) error{CapacityExceeded}!void {
            if (text.len > self.bytes.len) return error.CapacityExceeded;
            @memcpy(self.bytes[0..text.len], text);
            self.len = text.len;
        }

        pub fn value(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const IdentityIdText = FixedText(64);
pub const FieldText = FixedText(limits.field_capacity);
pub const ScriptSource = FixedText(limits.source_capacity);

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

pub const IdentityCatalog = struct {
    values: []Identity = &.{},
    len: usize = 0,

    pub fn slice(self: *const IdentityCatalog) []const Identity {
        return self.values[0..self.len];
    }

    pub fn deinit(self: *IdentityCatalog, allocator: @import("std").mem.Allocator) void {
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
