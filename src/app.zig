const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const limits = @import("limits.zig");
const log = @import("log.zig");
const runtime = @import("runtime/runtime.zig");
const global = @import("runtime/global.zig");
const storage_module = @import("storage/storage.zig");
const text = @import("text.zig");
const identity_module = @import("identities/manager.zig");
const pcap = @import("platform/pcap.zig");
const ui = @import("ui/ui.zig");

/// Heap-owned so the pointers from the manager and UI into this object
/// remain stable for the complete application lifetime.
const AppServices = struct {
    helpers_root: []u8,
    logger: log.Logger = undefined,
    worker_pool: runtime.WorkerPool = undefined,
    storage: storage_module.Storage = undefined,
    identity_manager: identity_module.Manager = undefined,
    global_runner: global.Runner = undefined,
    devices: [32]pcap.Device = undefined,
    device_count: usize = 0,

    fn create(allocator: std.mem.Allocator) !*AppServices {
        const config_dir = storage_module.discoverConfigDir(allocator) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.ConfigurationDirectoryUnavailable,
        };
        errdefer allocator.free(config_dir);

        const helpers_root = try std.fs.path.join(allocator, &.{ config_dir, "scripts", "helpers" });
        errdefer allocator.free(helpers_root);

        const storage_scratch = try allocator.create([limits.storage_scratch_capacity]u8);
        errdefer allocator.destroy(storage_scratch);

        const self = try allocator.create(AppServices);
        errdefer allocator.destroy(self);
        self.* = .{
            .helpers_root = helpers_root,
            .storage = .{ .allocator = allocator, .config_dir = config_dir, .scratch = storage_scratch },
        };
        self.logger.init(allocator, config_dir) catch return error.LoggingUnavailable;
        errdefer self.logger.deinit();
        self.global_runner = .{ .helpers_root = helpers_root, .logger = &self.logger };
        self.worker_pool.init(allocator, self.helpers_root, &self.logger);
        errdefer self.worker_pool.deinit();
        self.identity_manager.init(&self.storage, &self.worker_pool) catch |err| {
            self.identity_manager.deinit();
            switch (err) {
                error.MalformedIdentity => return error.MalformedIdentity,
                error.OutOfMemory => return err,
                else => return error.IdentityStorageUnavailable,
            }
        };
        errdefer self.identity_manager.deinit();
        self.device_count = pcap.list(&self.devices);
        return self;
    }

    fn destroy(self: *AppServices, allocator: std.mem.Allocator) void {
        self.global_runner.stop();
        self.identity_manager.deinit();
        self.worker_pool.deinit();
        self.logger.deinit();
        allocator.destroy(self.storage.scratch);
        allocator.free(self.helpers_root);
        allocator.free(self.storage.config_dir);
        allocator.destroy(self);
    }
};

const Presentation = struct {
    clay_memory: []u8,
    subsystem: ui.Subsystem = .{},
    frame_limiter: FrameLimiter = .{},

    fn deinit(self: *Presentation, allocator: std.mem.Allocator) void {
        self.subsystem.deinit();
        c.sgl_shutdown();
        c.sg_shutdown();
        allocator.free(self.clay_memory);
    }
};

const FrameLimiter = struct {
    const period_ns: i96 = std.time.ns_per_s / 30;

    next_frame_ns: ?i96 = null,

    fn wait(self: *@This()) void {
        const now = std.Io.Clock.awake.now(io()).nanoseconds;
        if (self.next_frame_ns) |deadline| {
            if (deadline > now) {
                std.Io.sleep(io(), .fromNanoseconds(deadline - now), .awake) catch unreachable;
            }
        }
        const after_wait = std.Io.Clock.awake.now(io()).nanoseconds;
        const following = (self.next_frame_ns orelse after_wait) + period_ns;
        self.next_frame_ns = if (following > after_wait) following else after_wait + period_ns;
    }
};

pub const App = struct {
    allocator: std.mem.Allocator = std.heap.c_allocator,
    services: ?*AppServices = null,
    presentation: ?Presentation = null,

    pub fn init(self: *App) !void {
        std.debug.assert(self.services == null and self.presentation == null);
        errdefer self.deinit();

        self.services = try AppServices.create(self.allocator);
        const services = self.services.?;
        const clay_memory = try self.allocator.alloc(u8, c.Clay_MinMemorySize());
        c.sg_setup(&.{
            .environment = c.sglue_environment(),
            .logger = .{ .func = c.kraken_sokol_log, .user_data = &services.logger },
        });
        c.sgl_setup(&.{ .logger = .{ .func = c.kraken_sokol_log, .user_data = &services.logger } });

        self.presentation = .{ .clay_memory = clay_memory };
        try self.presentation.?.subsystem.init(.{
            .storage = &services.storage,
            .identity_manager = &services.identity_manager,
            .interfaces = services.devices[0..services.device_count],
            .global_runner = &services.global_runner,
            .logger = &services.logger,
        }, clay_memory);
    }

    pub fn frame(self: *App) void {
        const services = self.services orelse return;
        if (self.presentation) |*presentation| {
            presentation.frame_limiter.wait();
            services.logger.flushDue();
            presentation.subsystem.frame();
            while (services.global_runner.commands.pop()) |command| services.identity_manager.execute(command) catch {};
        }
    }

    pub fn event(self: *App, event_data: [*c]const c.sapp_event) void {
        if (self.presentation) |*presentation| {
            presentation.subsystem.event(event_data);
        }
    }

    pub fn deinit(self: *App) void {
        if (self.presentation) |*presentation| {
            presentation.deinit(self.allocator);
            self.presentation = null;
        }
        if (self.services) |services| {
            services.destroy(self.allocator);
            self.services = null;
        }
    }
};

var application: ?*App = null;
const use_debug_allocator = builtin.mode == .Debug;
var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

pub fn run() void {
    const allocator = if (use_debug_allocator) debug_allocator.allocator() else std.heap.c_allocator;
    const root = allocator.create(App) catch std.process.fatal("Kraken could not allocate its application state.", .{});
    root.* = .{ .allocator = allocator };
    application = root;
    c.sapp_run(&.{
        .init_cb = initCallback,
        .frame_cb = frameCallback,
        .event_cb = eventCallback,
        .cleanup_cb = cleanupCallback,
        .window_title = "Kraken",
        .width = 1280,
        .height = 720,
        .swap_interval = 1,
        .high_dpi = true,
        .enable_clipboard = true,
        .clipboard_size = limits.source_capacity + 1,
        .logger = .{ .func = c.kraken_sokol_log },
    });
    root.deinit();
    application = null;
    allocator.destroy(root);
    if (use_debug_allocator and debug_allocator.deinit() == .leak) {
        std.process.fatal("memory leaks were detected during application shutdown", .{});
    }
}

fn initCallback() callconv(.c) void {
    const root = application orelse std.process.fatal("Kraken application state is unavailable.", .{});
    root.init() catch |err| std.process.fatal("{s}", .{startupFailureMessage(err)});
}

fn startupFailureMessage(err: anyerror) [:0]const u8 {
    return switch (err) {
        error.ConfigurationDirectoryUnavailable => "Kraken could not determine its configuration directory. Check HOME and XDG_CONFIG_HOME on Linux, or LOCALAPPDATA on Windows.",
        error.IdentityStorageUnavailable => "Kraken could not create or read its configuration storage. Check that the configuration directory exists and is writable.",
        error.MalformedIdentity => "Kraken could not start because an identity configuration file contains malformed JSON.",
        error.LoggingUnavailable => "Kraken could not create or write its session log. Check that the configuration directory is writable.",
        error.SystemFontUnavailable => "Kraken could not find a usable system UI font. Install DejaVu Sans, Liberation Sans, Noto Sans, or FreeSans on Linux, or restore Segoe UI on Windows.",
        error.OutOfMemory => "Kraken could not start because the system could not provide the required memory.",
        else => "Kraken could not start because of an unexpected initialization failure.",
    };
}

fn frameCallback() callconv(.c) void {
    if (application) |root| root.frame();
}

fn eventCallback(event_data: [*c]const c.sapp_event) callconv(.c) void {
    if (application) |root| root.event(event_data);
}

fn cleanupCallback() callconv(.c) void {
    if (application) |root| root.deinit();
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

test "root initialization failure leaves an empty root" {
    var root: App = .{ .allocator = std.testing.failing_allocator };
    try std.testing.expectError(error.OutOfMemory, root.init());
    try std.testing.expect(root.services == null);
    try std.testing.expect(root.presentation == null);
    root.deinit();
}
