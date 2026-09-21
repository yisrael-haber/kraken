const std = @import("std");

pub fn MpscRing(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    return struct {
        values: [capacity]T = undefined,
        mutex: std.Io.Mutex = .init,
        write_index: usize = 0,
        read_index: usize = 0,

        pub fn push(self: *@This(), value: T) bool {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.write_index -% self.read_index >= capacity) return false;
            self.values[self.write_index % capacity] = value;
            self.write_index +%= 1;
            return true;
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
