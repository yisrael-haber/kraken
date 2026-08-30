const std = @import("std");
const limits = @import("limits.zig");

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

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
            var result: @This() = .{};
            result.set(try std.json.innerParse([]const u8, allocator, source, options)) catch return error.LengthMismatch;
            return result;
        }

        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            try writer.write(self.value());
        }
    };
}

pub const FieldText = FixedText(limits.field_capacity);

test "fixed text rejects overflow without changing its value" {
    var value: FieldText = .{};
    try value.set("kept");
    const oversized = [_]u8{'x'} ** (limits.field_capacity + 1);
    try std.testing.expectError(error.CapacityExceeded, value.set(&oversized));
    try std.testing.expectEqualStrings("kept", value.value());
}
