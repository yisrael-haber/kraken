const std = @import("std");

pub fn TextBuffer(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = [_]u8{0} ** capacity,
        len: usize = 0,

        pub fn init(comptime initial: []const u8) @This() {
            comptime std.debug.assert(initial.len <= capacity);
            var input = @This(){};
            @memcpy(input.bytes[0..initial.len], initial);
            input.len = initial.len;
            return input;
        }

        pub fn value(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn set(self: *@This(), new_value: []const u8) void {
            self.len = @min(self.bytes.len, new_value.len);
            while (self.len > 0 and self.len < new_value.len and new_value[self.len] & 0xc0 == 0x80) self.len -= 1;
            @memcpy(self.bytes[0..self.len], new_value[0..self.len]);
        }
    };
}
