const std = @import("std");

pub const Level = enum { info, warning, err };
pub const Subsystem = enum { app, ui, runtime, lua, global, sokol };

const write_buffer_capacity = 8 * 1024;
const read_chunk_capacity = 8 * 1024;
const flush_interval_ns: i96 = std.time.ns_per_ms * 250;

/// Process-wide only by ownership: every runtime component receives this
/// service explicitly. It retains only bytes waiting for the next file write.
pub const Logger = struct {
    allocator: std.mem.Allocator,
    logs_dir_path: []u8,
    dir: std.Io.Dir,
    file: std.Io.File = undefined,
    file_open: bool = false,
    session_name: [64]u8 = undefined,
    session_name_len: usize = 0,
    mutex: std.Io.Mutex = .init,
    write_buffer: [write_buffer_capacity]u8 = undefined,
    write_len: usize = 0,
    last_flush_ns: i96 = 0,
    failed: bool = false,

    pub fn init(self: *Logger, allocator: std.mem.Allocator, config_dir: []const u8) !void {
        const logs_dir_path = try std.fs.path.join(allocator, &.{ config_dir, "logs" });
        errdefer allocator.free(logs_dir_path);
        const io = ioInstance();
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io, logs_dir_path, .{});
        errdefer dir.close(io);

        self.* = .{
            .allocator = allocator,
            .logs_dir_path = logs_dir_path,
            .dir = dir,
        };
        errdefer self.deinit();
        try self.createSessionFile();
        try self.recordLocked(.info, .app, "Kraken logging started.");
        try self.flushLocked();
        self.last_flush_ns = nowAwakeNs();
    }

    pub fn deinit(self: *Logger) void {
        if (self.file_open) {
            self.recordLocked(.info, .app, "Kraken logging stopped.") catch {};
            self.flushLocked() catch {};
            self.file.close(ioInstance());
        }
        self.dir.close(ioInstance());
        self.allocator.free(self.logs_dir_path);
        self.* = undefined;
    }

    pub fn info(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.record(.info, subsystem, message);
    }

    pub fn warning(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.record(.warning, subsystem, message);
    }

    pub fn err(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.record(.err, subsystem, message);
    }

    pub fn flushDue(self: *Logger) void {
        const now = nowAwakeNs();
        self.mutex.lockUncancelable(ioInstance());
        defer self.mutex.unlock(ioInstance());
        if (self.write_len == 0 or now - self.last_flush_ns < flush_interval_ns) return;
        self.flushLocked() catch {
            self.failed = true;
        };
        self.last_flush_ns = now;
    }

    pub fn flush(self: *Logger) !void {
        self.mutex.lockUncancelable(ioInstance());
        defer self.mutex.unlock(ioInstance());
        try self.flushLocked();
        self.last_flush_ns = nowAwakeNs();
    }

    pub fn sessionFileName(self: *const Logger) []const u8 {
        return self.session_name[0..self.session_name_len];
    }

    /// Loads only the requested newest displayed lines. `destination` is
    /// caller-owned and is expected to be released when the Logs page closes.
    pub fn readTail(self: *Logger, allocator: std.mem.Allocator, destination: *std.ArrayList(u8), line_limit: usize) !void {
        self.mutex.lockUncancelable(ioInstance());
        defer self.mutex.unlock(ioInstance());
        try self.flushLocked();
        destination.clearRetainingCapacity();
        if (line_limit == 0) return;

        const io = ioInstance();
        var file = try self.dir.openFile(io, self.sessionFileName(), .{});
        defer file.close(io);
        var reader_buffer: [read_chunk_capacity]u8 = undefined;
        var reader = std.Io.File.Reader.init(file, io, &reader_buffer);
        var position = try reader.getSize();
        var chunk: [read_chunk_capacity]u8 = undefined;
        var reversed_line: std.ArrayList(u8) = .empty;
        defer reversed_line.deinit(allocator);
        var line_count: usize = 0;
        var skip_terminal_empty = true;

        while (position > 0 and line_count < line_limit) {
            const count: usize = @intCast(@min(position, chunk.len));
            position -= count;
            try reader.seekTo(position);
            try reader.interface.readSliceAll(chunk[0..count]);
            var index = count;
            while (index > 0 and line_count < line_limit) {
                index -= 1;
                const byte = chunk[index];
                if (byte == '\n') {
                    if (skip_terminal_empty and reversed_line.items.len == 0) {
                        skip_terminal_empty = false;
                        continue;
                    }
                    try appendReversedLine(destination, allocator, reversed_line.items);
                    reversed_line.clearRetainingCapacity();
                    line_count += 1;
                    skip_terminal_empty = false;
                } else if (byte != '\r') {
                    try reversed_line.append(allocator, byte);
                    skip_terminal_empty = false;
                }
            }
        }
        if (line_count < line_limit and reversed_line.items.len > 0) {
            try appendReversedLine(destination, allocator, reversed_line.items);
        }
        reverseLines(destination.items);
    }

    pub fn sokol(self: *Logger, level: u32, tag: []const u8, message: []const u8) void {
        var buffer: [512]u8 = undefined;
        const composed = std.fmt.bufPrint(&buffer, "{s}: {s}", .{ tag, message }) catch message;
        self.record(switch (level) {
            0, 1 => .err,
            2 => .warning,
            else => .info,
        }, .sokol, composed);
    }

    fn record(self: *Logger, level: Level, subsystem: Subsystem, message: []const u8) void {
        self.mutex.lockUncancelable(ioInstance());
        defer self.mutex.unlock(ioInstance());
        self.recordLocked(level, subsystem, message) catch {
            self.failed = true;
        };
    }

    fn recordLocked(self: *Logger, level: Level, subsystem: Subsystem, message: []const u8) !void {
        var timestamp_buffer: [32]u8 = undefined;
        const timestamp = formatTimestamp(&timestamp_buffer, std.Io.Clock.real.now(ioInstance()).toMilliseconds());
        var prefix_buffer: [96]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buffer, "[{s}] [{s}] [{s}] ", .{ timestamp, @tagName(level), @tagName(subsystem) });
        try self.appendLocked(prefix);
        // A logging call is one record. Preserve embedded newlines as written
        // so continuation text does not acquire a second record prefix.
        try self.appendLocked(message);
        try self.appendLocked("\n");
    }

    fn appendLocked(self: *Logger, bytes: []const u8) !void {
        if (bytes.len > self.write_buffer.len - self.write_len) try self.flushLocked();
        if (bytes.len >= self.write_buffer.len) {
            try self.file.writeStreamingAll(ioInstance(), bytes);
            return;
        }
        @memcpy(self.write_buffer[self.write_len .. self.write_len + bytes.len], bytes);
        self.write_len += bytes.len;
    }

    fn flushLocked(self: *Logger) !void {
        if (self.write_len == 0) return;
        try self.file.writeStreamingAll(ioInstance(), self.write_buffer[0..self.write_len]);
        self.write_len = 0;
    }

    fn createSessionFile(self: *Logger) !void {
        var timestamp_buffer: [32]u8 = undefined;
        const timestamp = formatFileTimestamp(&timestamp_buffer, std.Io.Clock.real.now(ioInstance()).toMilliseconds());
        var candidate: [64]u8 = undefined;
        var suffix: usize = 0;
        while (true) : (suffix += 1) {
            const file_name = if (suffix == 0)
                try std.fmt.bufPrint(&candidate, "{s}.log", .{timestamp})
            else
                try std.fmt.bufPrint(&candidate, "{s}-{d:0>3}.log", .{ timestamp, suffix });
            const file = self.dir.createFile(ioInstance(), file_name, .{ .exclusive = true, .truncate = false }) catch |caught| switch (caught) {
                error.PathAlreadyExists => continue,
                else => return caught,
            };
            @memcpy(self.session_name[0..file_name.len], file_name);
            self.session_name_len = file_name.len;
            self.file = file;
            self.file_open = true;
            return;
        }
    }
};

pub export fn kraken_sokol_log(tag: ?[*:0]const u8, level: u32, _: u32, message: ?[*:0]const u8, _: u32, _: ?[*:0]const u8, user_data: ?*anyopaque) callconv(.c) void {
    const logger: *Logger = @ptrCast(@alignCast(user_data orelse return));
    logger.sokol(level, if (tag) |value| std.mem.span(value) else "sokol", if (message) |value| std.mem.span(value) else "Sokol emitted an empty diagnostic.");
}

fn appendReversedLine(destination: *std.ArrayList(u8), allocator: std.mem.Allocator, reversed: []const u8) !void {
    var index = reversed.len;
    while (index > 0) {
        index -= 1;
        try destination.append(allocator, reversed[index]);
    }
    try destination.append(allocator, '\n');
}

fn reverseLines(bytes: []u8) void {
    if (bytes.len == 0) return;
    std.mem.reverse(u8, bytes);
    std.mem.copyForwards(u8, bytes[0 .. bytes.len - 1], bytes[1..]);
    bytes[bytes.len - 1] = '\n';
    var start: usize = 0;
    while (start < bytes.len) {
        const line_end = std.mem.indexOfScalarPos(u8, bytes, start, '\n') orelse bytes.len;
        std.mem.reverse(u8, bytes[start..line_end]);
        start = line_end + 1;
    }
}

fn formatTimestamp(buffer: []u8, milliseconds: i64) []const u8 {
    const values = calendarValues(milliseconds);
    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ values.year, values.month, values.day, values.hour, values.minute, values.second, values.millisecond }) catch unreachable;
}

fn formatFileTimestamp(buffer: []u8, milliseconds: i64) []const u8 {
    const values = calendarValues(milliseconds);
    return std.fmt.bufPrint(buffer, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}.{d:0>3}Z", .{ values.year, values.month, values.day, values.hour, values.minute, values.second, values.millisecond }) catch unreachable;
}

const CalendarValues = struct { year: u16, month: u4, day: u5, hour: u5, minute: u6, second: u6, millisecond: u16 };

fn calendarValues(milliseconds: i64) CalendarValues {
    const positive: u64 = @intCast(@max(milliseconds, 0));
    const epoch = std.time.epoch.EpochSeconds{ .secs = positive / std.time.ms_per_s };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return .{
        .year = year_day.year,
        .month = month_day.month.numeric(),
        .day = month_day.day_index + 1,
        .hour = day_seconds.getHoursIntoDay(),
        .minute = day_seconds.getMinutesIntoHour(),
        .second = day_seconds.getSecondsIntoMinute(),
        .millisecond = @intCast(positive % std.time.ms_per_s),
    };
}

fn nowAwakeNs() i96 {
    return std.Io.Clock.awake.now(ioInstance()).nanoseconds;
}

fn ioInstance() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

test "logger writes a session record and tail reads selected lines in file order" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var logger: Logger = undefined;
    try logger.init(allocator, config_dir);
    defer logger.deinit();
    logger.info(.app, "first");
    logger.err(.runtime, "second");
    try logger.flush();

    var tail: std.ArrayList(u8) = .empty;
    defer tail.deinit(allocator);
    try logger.readTail(allocator, &tail, 2);
    try std.testing.expect(std.mem.indexOf(u8, tail.items, "second") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail.items, "first") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail.items, "first") orelse 0 < std.mem.indexOf(u8, tail.items, "second") orelse tail.items.len);

    try logger.file.writeStreamingAll(ioInstance(), "unterminated record");
    try logger.readTail(allocator, &tail, 1);
    try std.testing.expectEqualStrings("unterminated record\n", tail.items);
}

test "logger serializes concurrent records" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var logger: Logger = undefined;
    try logger.init(allocator, config_dir);
    defer logger.deinit();

    const Context = struct { logger: *Logger, text: []const u8 };
    const write = struct {
        fn run(context: Context) void {
            for (0..32) |_| context.logger.info(.runtime, context.text);
        }
    }.run;
    const first = try std.Thread.spawn(.{}, write, .{Context{ .logger = &logger, .text = "worker-one" }});
    const second = try std.Thread.spawn(.{}, write, .{Context{ .logger = &logger, .text = "worker-two" }});
    first.join();
    second.join();
    try logger.flush();

    var tail: std.ArrayList(u8) = .empty;
    defer tail.deinit(allocator);
    try logger.readTail(allocator, &tail, 128);
    try std.testing.expectEqual(@as(usize, 65), std.mem.count(u8, tail.items, "\n"));
    try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, tail.items, "worker-one"));
    try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, tail.items, "worker-two"));
}
