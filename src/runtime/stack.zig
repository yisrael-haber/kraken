const std = @import("std");
const c = @import("c");
const network_config = @import("network_config.zig");

pub const storage_size = 512 * 1024;
pub const max_frame_size = 1536;

pub const InputResult = enum {
    accepted,
    inactive,
    empty,
    oversized,
};

pub const Egress = *const fn (context: ?*anyopaque, frame: []const u8) c_int;

/// One worker-owned wolfIP instance. wolfIP remains a C library, but all
/// application state, configuration, timekeeping, and callback routing stay
/// in Zig.
pub const Stack = struct {
    storage: [storage_size]u8 align(16) = [_]u8{0} ** storage_size,
    context: ?*anyopaque = null,
    egress: ?Egress = null,
    active: bool = false,
    frame_mtu: u16 = max_frame_size,

    pub fn init(self: *Stack, slot: usize, config: network_config.Config, context: ?*anyopaque, egress: Egress) bool {
        if (slot >= 10 or c.wolfIP_instance_size() > self.storage.len) return false;
        @memset(&self.storage, 0);
        self.context = context;
        self.egress = egress;
        const instance: *c.struct_wolfIP = @ptrCast(&self.storage);
        c.wolfIP_init(instance);
        const device = c.wolfIP_getdev(instance) orelse return false;

        @memcpy(device[0].mac[0..6], &config.mac);
        device[0].ifname[0] = 'c';
        device[0].ifname[1] = 'g';
        device[0].ifname[2] = @intCast('0' + slot);
        device[0].ifname[3] = 0;
        device[0].non_ethernet = 0;
        self.frame_mtu = @intCast(@min(@as(u32, config.mtu) + ethernet_header_size, max_frame_size));
        device[0].mtu = self.frame_mtu;
        device[0].poll = poll;
        device[0].send = send;
        device[0].priv = @ptrCast(self);
        c.wolfIP_ipconfig_set(instance, ip4(config.address), prefixMask(config.prefix_length), if (config.gateway) |gateway| ip4(gateway) else 0);
        self.active = true;
        return true;
    }

    pub fn input(self: *Stack, frame: []const u8) InputResult {
        if (!self.active) return .inactive;
        if (frame.len == 0) return .empty;
        if (frame.len > self.frame_mtu) return .oversized;
        c.wolfIP_recv(self.raw(), @constCast(frame.ptr), @intCast(frame.len));
        return .accepted;
    }

    pub fn tick(self: *Stack) void {
        if (!self.active) return;
        const now_ms = std.Io.Clock.awake.now(io()).toMilliseconds();
        _ = c.wolfIP_poll(self.raw(), @intCast(now_ms));
    }

    pub fn deinit(self: *Stack) void {
        self.active = false;
        self.context = null;
        self.egress = null;
        self.frame_mtu = max_frame_size;
        @memset(&self.storage, 0);
    }

    fn raw(self: *Stack) *c.struct_wolfIP {
        return @ptrCast(&self.storage);
    }
};

pub export fn wolfIP_getrandom() callconv(.c) u32 {
    const random = struct {
        var state = std.atomic.Value(u32).init(0x9e3779b9);
    };
    return random.state.fetchAdd(0x9e3779b9, .monotonic);
}

fn poll(_: ?*c.struct_wolfIP_ll_dev, _: ?*anyopaque, _: u32) callconv(.c) c_int {
    return 0;
}

fn send(device: ?*c.struct_wolfIP_ll_dev, frame: ?*anyopaque, length: u32) callconv(.c) c_int {
    const value = device orelse return -1;
    const owner: *Stack = @ptrCast(@alignCast(value.priv orelse return -1));
    const callback = owner.egress orelse return -1;
    const bytes: [*]const u8 = @ptrCast(frame orelse return -1);
    return if (callback(owner.context, bytes[0..length]) == 0) @intCast(length) else -1;
}

const ethernet_header_size = 14;

fn ip4(value: [4]u8) c.ip4 {
    return (@as(c.ip4, value[0]) << 24) | (@as(c.ip4, value[1]) << 16) | (@as(c.ip4, value[2]) << 8) | value[3];
}

fn prefixMask(prefix_length: u8) c.ip4 {
    if (prefix_length == 0) return 0;
    return ~@as(c.ip4, 0) << @intCast(32 - prefix_length);
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
