const std = @import("std");
const io = @import("io.zig");

pub const Level = enum { info, warning, err };
pub const Subsystem = enum { app, ui, runtime, lua, sokol };

const write_buffer_capacity = 8 * 1024;
const read_chunk_capacity = 8 * 1024;
const flush_interval_ns: i96 = std.time.ns_per_ms * 250;

/// The file writer borrows the embedded buffer; keep the logger at a stable address after init.
pub const Logger = struct {
    writer: std.Io.File.Writer = undefined,
    session_name: [64]u8 = undefined,
    session_name_len: usize = 0,
    mutex: std.Io.Mutex = .init,
    write_buffer: [write_buffer_capacity]u8 = undefined,
    last_flush_ns: i96 = 0,

    pub fn init(self: *Logger, allocator: std.mem.Allocator, config_dir: []const u8) !void {
        const logs_dir_path = try std.fs.path.join(allocator, &.{ config_dir, "logs" });
        defer allocator.free(logs_dir_path);
        const dir = try std.Io.Dir.createDirPathOpen(.cwd(), io.get(), logs_dir_path, .{});
        defer dir.close(io.get());

        self.* = .{};
        try self.createSessionFile(dir);
        errdefer self.writer.file.close(io.get());
        try self.recordLocked(.info, .app, "Kraken logging started.", .{});
        try self.writer.interface.flush();
        self.last_flush_ns = io.now().nanoseconds;
    }

    pub fn deinit(self: *Logger) void {
        self.recordLocked(.info, .app, "Kraken logging stopped.", .{}) catch {};
        self.writer.interface.flush() catch {};
        self.writer.file.close(io.get());
        self.* = undefined;
    }

    pub fn info(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.formatted(.info, subsystem, "{s}", .{message});
    }

    pub fn warning(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.formatted(.warning, subsystem, "{s}", .{message});
    }

    pub fn err(self: *Logger, subsystem: Subsystem, message: []const u8) void {
        self.formatted(.err, subsystem, "{s}", .{message});
    }

    pub fn formatted(self: *Logger, level: Level, subsystem: Subsystem, comptime format: []const u8, args: anytype) void {
        self.mutex.lockUncancelable(io.get());
        defer self.mutex.unlock(io.get());
        self.recordLocked(level, subsystem, format, args) catch {};
    }

    pub fn flushDue(self: *Logger) void {
        const now = io.now().nanoseconds;
        self.mutex.lockUncancelable(io.get());
        defer self.mutex.unlock(io.get());
        if (self.writer.interface.end == 0 or now - self.last_flush_ns < flush_interval_ns) return;
        self.writer.interface.flush() catch {};
        self.last_flush_ns = now;
    }

    pub fn sessionFileName(self: *const Logger) []const u8 {
        return self.session_name[0..self.session_name_len];
    }

    /// Reads the newest whole lines in file order that fit the caller's buffer.
    pub fn readTail(self: *Logger, destination: []u8) ![]const u8 {
        self.mutex.lockUncancelable(io.get());
        defer self.mutex.unlock(io.get());
        try self.writer.interface.flush();
        if (destination.len == 0) return destination;

        const file = self.writer.file;
        var position = try file.length(io.get());
        var chunk: [read_chunk_capacity]u8 = undefined;
        const offset = scan: {
            var start = destination.len;
            var complete = destination.len;
            while (position > 0) {
                const count: usize = @intCast(@min(position, chunk.len));
                position -= count;
                if (try file.readPositionalAll(io.get(), chunk[0..count], position) != count) return error.EndOfStream;
                var index = count;
                while (index > 0) {
                    index -= 1;
                    const byte = chunk[index];
                    if (byte == '\r') continue;
                    if (start == destination.len) {
                        start -= 1;
                        destination[start] = '\n';
                        if (byte == '\n') continue;
                    }
                    if (byte == '\n') {
                        complete = start;
                    }
                    if (start == 0) break :scan complete;
                    start -= 1;
                    destination[start] = byte;
                }
            }
            // The delimiter at the beginning of the file has no preceding line.
            break :scan if (start < destination.len and destination[start] == '\n') start + 1 else start;
        };
        const bytes = destination[offset..];
        std.mem.copyForwards(u8, destination[0..bytes.len], bytes);
        return destination[0..bytes.len];
    }

    pub fn sokol(self: *Logger, level: u32, tag: []const u8, message: []const u8) void {
        self.formatted(switch (level) {
            0, 1 => .err,
            2 => .warning,
            else => .info,
        }, .sokol, "{s}: {s}", .{ tag, message });
    }

    fn recordLocked(self: *Logger, level: Level, subsystem: Subsystem, comptime format: []const u8, args: anytype) !void {
        var timestamp_buffer: [32]u8 = undefined;
        const timestamp = formatTimestamp(&timestamp_buffer, std.Io.Clock.real.now(io.get()).toMilliseconds());
        const severity = if (level == .info) "" else if (level == .warning) "warning/" else "err/";
        try self.writer.interface.print("{s} {s}{s} ", .{ timestamp, severity, @tagName(subsystem) });
        // A logging call is one record. Preserve embedded newlines as written
        // so continuation text does not acquire a second record prefix.
        try self.writer.interface.print(format, args);
        try self.writer.interface.writeByte('\n');
    }

    fn createSessionFile(self: *Logger, dir: std.Io.Dir) !void {
        var timestamp_buffer: [32]u8 = undefined;
        const timestamp = formatFileTimestamp(&timestamp_buffer, std.Io.Clock.real.now(io.get()).toMilliseconds());
        var suffix: usize = 0;
        while (true) : (suffix += 1) {
            const file_name = if (suffix == 0)
                try std.fmt.bufPrint(&self.session_name, "{s}.log", .{timestamp})
            else
                try std.fmt.bufPrint(&self.session_name, "{s}-{d:0>3}.log", .{ timestamp, suffix });
            const file = dir.createFile(io.get(), file_name, .{ .read = true, .exclusive = true, .truncate = false }) catch |caught| switch (caught) {
                error.PathAlreadyExists => continue,
                else => return caught,
            };
            self.session_name_len = file_name.len;
            self.writer = file.writer(io.get(), &self.write_buffer);
            return;
        }
    }
};

pub var logger: Logger = undefined;

pub fn sokolLog(tag: ?[*:0]const u8, level: u32, _: u32, message: ?[*:0]const u8, _: u32, _: ?[*:0]const u8, _: ?*anyopaque) callconv(.c) void {
    logger.sokol(level, if (tag) |value| std.mem.span(value) else "sokol", if (message) |value| std.mem.span(value) else "Sokol emitted an empty diagnostic.");
}

fn formatTimestamp(buffer: []u8, milliseconds: i64) []const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(@divTrunc(@max(milliseconds, 0), std.time.ms_per_s)) };
    const time = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>2}:{d:0>2}:{d:0>2}", .{ time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute() }) catch unreachable;
}

fn formatFileTimestamp(buffer: []u8, milliseconds: i64) []const u8 {
    const positive: u64 = @intCast(@max(milliseconds, 0));
    const epoch = std.time.epoch.EpochSeconds{ .secs = positive / std.time.ms_per_s };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(buffer, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        positive % std.time.ms_per_s,
    }) catch unreachable;
}

test "logger writes a session record and tail reads the newest lines in file order" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var test_logger: Logger = undefined;
    try test_logger.init(allocator, config_dir);
    defer test_logger.deinit();
    test_logger.info(.app, "first");
    test_logger.err(.runtime, "second");
    test_logger.formatted(.warning, .ui, "Identity \"{s}\" was rejected.", .{"base"});

    var buffer: [read_chunk_capacity + 64]u8 = undefined;
    var tail = try test_logger.readTail(&buffer);
    try std.testing.expect(std.mem.indexOf(u8, tail, "second") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail, "first") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail, "warning/ui Identity \"base\" was rejected.\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, tail, "first") orelse 0 < std.mem.indexOf(u8, tail, "second") orelse tail.len);

    const long = [_]u8{'x'} ** (read_chunk_capacity + 1);
    try test_logger.writer.interface.writeAll(&long);
    try test_logger.writer.interface.writeAll("unterminated record");
    tail = try test_logger.readTail(buffer[0 .. long.len + "unterminated record\n".len]);
    try std.testing.expectEqual(long.len + "unterminated record\n".len, tail.len);
    try std.testing.expectEqualStrings(&long, tail[0..long.len]);
    try std.testing.expectEqualStrings("unterminated record\n", tail[long.len..]);

    for ([_]struct { input: []const u8, capacity: usize, expected: []const u8 }{
        .{ .input = "old\n\r\nlast", .capacity = 6, .expected = "\nlast\n" },
        .{ .input = "old\nlast\n", .capacity = 5, .expected = "last\n" },
        .{ .input = "old\nlast\n", .capacity = 4, .expected = "" },
        .{ .input = "\r\n", .capacity = 16, .expected = "" },
    }) |case| {
        try test_logger.writer.seekTo(0);
        try test_logger.writer.file.setLength(io.get(), 0);
        try test_logger.writer.interface.writeAll(case.input);
        try std.testing.expectEqualStrings(case.expected, try test_logger.readTail(buffer[0..case.capacity]));
    }
}

test "logger serializes concurrent records" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const config_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/config", .{temp_dir.sub_path});
    defer allocator.free(config_dir);
    var test_logger: Logger = undefined;
    try test_logger.init(allocator, config_dir);
    defer test_logger.deinit();

    const Context = struct { logger: *Logger, text: []const u8 };
    const write = struct {
        fn run(context: Context) void {
            for (0..32) |_| context.logger.info(.runtime, context.text);
        }
    }.run;
    const first = try std.Thread.spawn(.{}, write, .{Context{ .logger = &test_logger, .text = "worker-one" }});
    const second = try std.Thread.spawn(.{}, write, .{Context{ .logger = &test_logger, .text = "worker-two" }});
    first.join();
    second.join();

    var buffer: [8192]u8 = undefined;
    const tail = try test_logger.readTail(&buffer);
    try std.testing.expectEqual(@as(usize, 65), std.mem.count(u8, tail, "\n"));
    try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, tail, "worker-one"));
    try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, tail, "worker-two"));
}
