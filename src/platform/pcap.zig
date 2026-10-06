const std = @import("std");
const c = @import("pcap_c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const wait = @import("wait.zig");
const linux = @import("builtin").os.tag == .linux;

pub fn list(devices: []text.FieldText) usize {
    var error_buffer: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var all: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&all, &error_buffer) != 0) return 0;
    defer c.pcap_freealldevs(all);

    var current = all;
    for (devices, 0..) |*destination, count| {
        const device = current orelse return count;
        destination.set(std.mem.span(device.name.?)) catch unreachable;
        current = device.next;
    }
    return devices.len;
}

pub const Handle = struct {
    raw: *c.pcap_t,
    ready: wait.Handle,

    pub fn open(device: [:0]const u8) error{OpenFailed}!Handle {
        var pcap_error: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        const raw = c.pcap_create(device.ptr, &pcap_error) orelse return error.OpenFailed;
        errdefer c.pcap_close(raw);
        if (c.pcap_set_snaplen(raw, limits.frame_capacity) != 0 or
            c.pcap_set_promisc(raw, 1) != 0 or
            c.pcap_set_immediate_mode(raw, 1) != 0 or
            c.pcap_activate(raw) < 0) return error.OpenFailed;
        if (c.pcap_datalink(raw) != c.DLT_EN10MB) return error.OpenFailed;
        if (c.pcap_setnonblock(raw, 1, &pcap_error) != 0) return error.OpenFailed;
        const ready: wait.Handle = if (linux) blk: {
            const fd = c.pcap_get_selectable_fd(raw);
            if (fd < 0) return error.OpenFailed;
            break :blk .{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 };
        } else c.pcap_getevent(raw) orelse return error.OpenFailed;
        return .{ .raw = raw, .ready = ready };
    }

    pub fn setFilter(self: *Handle, expression: [:0]const u8) ?[]const u8 {
        var program: c.struct_bpf_program = undefined;
        if (c.pcap_compile(self.raw, &program, expression.ptr, 1, c.PCAP_NETMASK_UNKNOWN) != 0) return std.mem.span(c.pcap_geterr(self.raw));
        defer c.pcap_freecode(&program);
        return if (c.pcap_setfilter(self.raw, &program) == 0) null else std.mem.span(c.pcap_geterr(self.raw));
    }

    pub fn close(self: *Handle) void {
        c.pcap_close(self.raw);
    }

    /// Borrows packet bytes until the next capture read or close on this handle.
    pub fn next(self: *Handle) error{ ReceiveFailed, TruncatedFrame }!?[]const u8 {
        var header: [*c]c.struct_pcap_pkthdr = undefined;
        var bytes: [*c]const u8 = undefined;
        const result = c.pcap_next_ex(self.raw, &header, &bytes);
        if (result == 0) return null;
        if (result < 0) return error.ReceiveFailed;
        if (header.*.caplen != header.*.len) return error.TruncatedFrame;
        return bytes[0..header.*.caplen];
    }

    pub fn inject(self: *Handle, bytes: []const u8) bool {
        return c.pcap_inject(self.raw, bytes.ptr, bytes.len) == @as(c_int, @intCast(bytes.len));
    }
};
