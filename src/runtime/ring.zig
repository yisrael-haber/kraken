const std = @import("std");

pub fn MpscRing(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    return struct {
        values: [capacity]T = undefined,
        mutex: std.Io.Mutex = .init,
        write_index: usize = 0,
        read_index: usize = 0,
        closed: bool = false,

        pub fn push(self: *@This(), value: T) bool {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.closed or self.write_index -% self.read_index >= capacity) return false;
            self.values[self.write_index % capacity] = value;
            self.write_index +%= 1;
            return true;
        }

        /// Rejects every later push; values already queued can still be popped.
        pub fn close(self: *@This()) void {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            self.closed = true;
        }

        pub fn pop(self: *@This()) ?T {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.read_index == self.write_index) return null;
            const value = self.values[self.read_index % capacity];
            self.read_index +%= 1;
            return value;
        }
    };
}

test "closed ring rejects pushes but drains queued values" {
    var queue: MpscRing(u8, 2) = .{};
    try std.testing.expect(queue.push(1));
    queue.close();
    try std.testing.expect(!queue.push(2));
    try std.testing.expectEqual(@as(?u8, 1), queue.pop());
    try std.testing.expectEqual(@as(?u8, null), queue.pop());
}
