const std = @import("std");

/// A bounded single-producer, single-consumer queue. Its elements are stored
/// inline; a full queue is a normal, visible backpressure condition.
pub fn SpscRing(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    return struct {
        const Self = @This();

        values: [capacity]T = undefined,
        write_index: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        read_index: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        pub fn push(self: *Self, value: T) bool {
            const write = self.write_index.load(.monotonic);
            const read = self.read_index.load(.acquire);
            if (write -% read >= capacity) return false;
            self.values[write % capacity] = value;
            self.write_index.store(write +% 1, .release);
            return true;
        }

        pub fn pop(self: *Self) ?T {
            const read = self.read_index.load(.monotonic);
            const write = self.write_index.load(.acquire);
            if (read == write) return null;
            const value = self.values[read % capacity];
            self.read_index.store(read +% 1, .release);
            return value;
        }

        pub fn len(self: *const Self) usize {
            return self.write_index.load(.acquire) -% self.read_index.load(.acquire);
        }
    };
}

test "spsc ring preserves order and reports full" {
    var ring: SpscRing(u8, 2) = .{};
    try std.testing.expect(ring.push(3));
    try std.testing.expect(ring.push(7));
    try std.testing.expect(!ring.push(9));
    try std.testing.expectEqual(@as(?u8, 3), ring.pop());
    try std.testing.expect(ring.push(9));
    try std.testing.expectEqual(@as(?u8, 7), ring.pop());
    try std.testing.expectEqual(@as(?u8, 9), ring.pop());
    try std.testing.expectEqual(@as(?u8, null), ring.pop());
}
