const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const io = @import("io.zig");
const limits = @import("limits.zig");
const log = @import("log.zig");
const runtime = @import("runtime/runtime.zig");
const storage_module = @import("storage/storage.zig");
const text = @import("text.zig");
const pcap = @import("platform/pcap.zig");
const ui = @import("ui/ui.zig");

/// sokol_app calls the frame callback in a loop that never waits, so an idle window blocks here
/// until the X server sends input (or the timeout lapses, to pick up changes from other threads).
fn waitForInput(milliseconds: c_int) void {
    if (builtin.os.tag != .linux) return;
    const display = c.sapp_x11_get_display().?;
    if (XPending(display) > 0) return; // events Xlib already read
    var handle: std.c.pollfd = .{ .fd = XConnectionNumber(display), .events = std.c.POLL.IN, .revents = 0 };
    _ = std.c.poll(@ptrCast(&handle), 1, milliseconds);
}

extern fn XPending(display: *const anyopaque) c_int;
extern fn XConnectionNumber(display: *const anyopaque) c_int;

/// Allocated once; pointers borrowed by the runtime and UI stay stable until shutdown.
pub const App = struct {
    allocator: std.mem.Allocator = std.heap.c_allocator,
    storage: storage_module.Storage = undefined,
    manager: runtime.Manager = undefined,
    devices: [32]text.FieldText = undefined,
    subsystem: ui.Subsystem = undefined,
    clay_memory: []u8 = undefined,
    /// When clear, the next frame waits for input first.
    busy: bool = true,

    pub fn init(self: *App) !void {
        const config_dir = storage_module.discoverConfigDir(self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.ConfigurationDirectoryUnavailable,
        };
        errdefer self.allocator.free(config_dir);
        self.storage = .{ .config_dir = config_dir };
        log.logger.init(self.allocator, config_dir) catch return error.LoggingUnavailable;
        errdefer log.logger.deinit();
        self.manager.init(self.allocator, &self.storage) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.IdentityStorageUnavailable,
        };
        errdefer self.manager.deinit();
        const device_count = pcap.list(&self.devices);
        log.logger.formatted(.info, .app, "Kraken ready: {d} capture interfaces.", .{device_count});
        if (device_count == 0) log.logger.warning(.app, "No capture interfaces were found.");

        c.Clay_SetMaxElementCount(limits.ui_element_capacity);
        c.Clay_SetMaxMeasureTextCacheWordCount(limits.ui_text_word_capacity);
        self.clay_memory = try self.allocator.alloc(u8, c.Clay_MinMemorySize());
        errdefer self.allocator.free(self.clay_memory);
        c.sg_setup(&.{
            .environment = c.sglue_environment(),
            .logger = .{ .func = log.sokolLog },
        });
        errdefer c.sg_shutdown();
        c.sgl_setup(&.{ .logger = .{ .func = log.sokolLog } });
        errdefer c.sgl_shutdown();
        errdefer self.subsystem.deinit();
        try self.subsystem.init(.{
            .storage = &self.storage,
            .manager = &self.manager,
            .interfaces = self.devices[0..device_count],
        }, self.clay_memory);
    }

    pub fn frame(self: *App) void {
        if (!self.busy) waitForInput(500);
        std.Io.sleep(io.get(), .fromNanoseconds(std.time.ns_per_s / 30), .awake) catch unreachable;
        log.logger.flushDue();
        self.busy = self.subsystem.frame();
    }

    pub fn event(self: *App, event_data: [*c]const c.sapp_event) void {
        self.busy = true;
        self.subsystem.event(event_data);
    }

    pub fn deinit(self: *App) void {
        self.subsystem.deinit();
        c.sgl_shutdown();
        c.sg_shutdown();
        self.allocator.free(self.clay_memory);
        self.manager.deinit();
        log.logger.deinit();
        self.allocator.free(self.storage.config_dir);
    }
};

const use_debug_allocator = builtin.mode == .Debug;
var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

pub fn run() void {
    const allocator = if (use_debug_allocator) debug_allocator.allocator() else std.heap.c_allocator;
    const root = allocator.create(App) catch std.process.fatal("Kraken could not allocate its application state.", .{});
    root.* = .{ .allocator = allocator };
    c.sapp_run(&.{
        .user_data = root,
        .init_userdata_cb = initCallback,
        .frame_userdata_cb = frameCallback,
        .event_userdata_cb = eventCallback,
        .cleanup_userdata_cb = cleanupCallback,
        .window_title = "Kraken",
        .width = 1280,
        .height = 720,
        .swap_interval = 1,
        .high_dpi = true,
        .enable_clipboard = true,
        .clipboard_size = limits.source_capacity + 1,
    });
    allocator.destroy(root);
    if (use_debug_allocator and debug_allocator.deinit() == .leak) {
        std.process.fatal("memory leaks were detected during application shutdown", .{});
    }
}

fn initCallback(context: ?*anyopaque) callconv(.c) void {
    const root: *App = @ptrCast(@alignCast(context.?));
    root.init() catch |err| std.process.fatal("{s}", .{startupFailureMessage(err)});
}

fn startupFailureMessage(err: anyerror) [:0]const u8 {
    return switch (err) {
        error.ConfigurationDirectoryUnavailable => "Kraken could not determine its configuration directory. Check HOME and XDG_CONFIG_HOME on Linux, or LOCALAPPDATA on Windows.",
        error.IdentityStorageUnavailable => "Kraken could not create or read its configuration storage. Check that the configuration directory exists and is writable.",
        error.LoggingUnavailable => "Kraken could not create or write its session log. Check that the configuration directory is writable.",
        error.SystemFontUnavailable => "Kraken could not find a usable system UI font. Install DejaVu Sans, Liberation Sans, Noto Sans, or FreeSans on Linux, or restore Segoe UI on Windows.",
        error.OutOfMemory => "Kraken could not start because the system could not provide the required memory.",
        else => "Kraken could not start because of an unexpected initialization failure.",
    };
}

fn frameCallback(context: ?*anyopaque) callconv(.c) void {
    const root: *App = @ptrCast(@alignCast(context.?));
    root.frame();
}

fn eventCallback(event_data: [*c]const c.sapp_event, context: ?*anyopaque) callconv(.c) void {
    const root: *App = @ptrCast(@alignCast(context.?));
    root.event(event_data);
}

fn cleanupCallback(context: ?*anyopaque) callconv(.c) void {
    const root: *App = @ptrCast(@alignCast(context.?));
    root.deinit();
}
