const std = @import("std");
const builtin = @import("builtin");
const c = @import("pcap_c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const identity = @import("../identities/identity.zig");

pub fn list(devices: []text.FieldText) usize {
    var error_buffer: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var all: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&all, &error_buffer) != 0) return 0;
    defer c.pcap_freealldevs(all);

    var count: usize = 0;
    var current = all;
    while (current) |device| : (current = device.next) {
        if (count == devices.len) break;
        devices[count].set(std.mem.span(device.name.?)) catch unreachable;
        count += 1;
    }
    return count;
}

pub const Handle = struct {
    raw: *c.pcap_t,
    ready: if (builtin.os.tag == .linux) c_int else *anyopaque,
    default_filter: [128]u8 = undefined,

    pub fn open(value: *const identity.Identity) ?Handle {
        var pcap_error: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        const raw = c.pcap_create(value.interface.bytes[0..value.interface.len :0].ptr, &pcap_error) orelse return null;
        errdefer c.pcap_close(raw);
        if (c.pcap_set_snaplen(raw, limits.frame_capacity) != 0 or
            c.pcap_set_promisc(raw, 1) != 0 or
            c.pcap_set_immediate_mode(raw, 1) != 0 or
            c.pcap_activate(raw) < 0) return null;
        if (c.pcap_datalink(raw) != c.DLT_EN10MB) return null;
        var handle: Handle = .{ .raw = raw, .ready = undefined };
        _ = identityFilter(&handle.default_filter, value.mac.value(), value.ip.value());
        if (handle.setFilter("") != null) return null;
        if (c.pcap_setnonblock(raw, 1, &pcap_error) != 0) return null;
        handle.ready = switch (builtin.os.tag) {
            .linux => blk: {
                const fd = c.pcap_get_selectable_fd(raw);
                if (fd < 0) return null;
                break :blk fd;
            },
            .windows => c.pcap_getevent(raw) orelse return null,
            else => unreachable,
        };
        return handle;
    }

    pub fn setFilter(self: *Handle, expression: [:0]const u8) ?[]const u8 {
        const filter = if (expression.len == 0) @as([*:0]const u8, @ptrCast(&self.default_filter)) else expression.ptr;
        var program: c.struct_bpf_program = undefined;
        if (c.pcap_compile(self.raw, &program, filter, 1, c.PCAP_NETMASK_UNKNOWN) != 0) return std.mem.span(c.pcap_geterr(self.raw));
        defer c.pcap_freecode(&program);
        return if (c.pcap_setfilter(self.raw, &program) == 0) null else std.mem.span(c.pcap_geterr(self.raw));
    }

    pub fn close(self: *Handle) void {
        c.pcap_close(self.raw);
    }

    pub fn next(self: *Handle, destination: *[limits.frame_capacity]u8) error{ReceiveFailed}!?usize {
        var header: [*c]c.struct_pcap_pkthdr = undefined;
        var bytes: [*c]const u8 = undefined;
        const result = c.pcap_next_ex(self.raw, &header, &bytes);
        if (result == 0) return null;
        if (result < 0) return error.ReceiveFailed;
        @memcpy(destination[0..header.*.caplen], bytes[0..header.*.caplen]);
        return header.*.caplen;
    }

    pub fn inject(self: *Handle, bytes: []const u8) bool {
        return c.pcap_inject(self.raw, bytes.ptr, bytes.len) == @as(c_int, @intCast(bytes.len));
    }
};

fn identityFilter(buffer: *[128]u8, mac: []const u8, address: []const u8) [:0]u8 {
    return std.fmt.bufPrintZ(
        buffer,
        "ether dst {s} or ip dst host {s} or arp dst host {s}",
        .{ mac, address, address },
    ) catch unreachable;
}

test "identity filter selects its MAC, IPv4, and ARP destinations" {
    var buffer: [128]u8 = undefined;
    const filter = identityFilter(&buffer, "02:11:22:33:44:55", "192.0.2.9");
    try std.testing.expectEqualStrings(
        "ether dst 02:11:22:33:44:55 or ip dst host 192.0.2.9 or arp dst host 192.0.2.9",
        filter,
    );

    const dead = c.pcap_open_dead(c.DLT_EN10MB, limits.frame_capacity) orelse return error.PcapUnavailable;
    defer c.pcap_close(dead);
    var program: c.struct_bpf_program = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.pcap_compile(dead, &program, filter.ptr, 1, c.PCAP_NETMASK_UNKNOWN));
    c.pcap_freecode(&program);
}

test "BPF replacement, rejection, and reset on captured packets" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const path = try std.fmt.allocPrintSentinel(std.testing.allocator, ".zig-cache/tmp/{s}/bpf.pcap", .{directory.sub_path}, 0);
    defer std.testing.allocator.free(path);
    const dead = c.pcap_open_dead(c.DLT_EN10MB, limits.frame_capacity) orelse return error.PcapUnavailable;
    defer c.pcap_close(dead);
    const dump = c.pcap_dump_open(dead, path.ptr) orelse return error.PcapUnavailable;
    var packet = [_]u8{0} ** 54;
    packet[12] = 8; // Ethernet IPv4.
    packet[14] = 0x45;
    packet[17] = 40;
    const header: c.struct_pcap_pkthdr = .{ .caplen = packet.len, .len = packet.len };
    for ([_]u8{ 6, 17, 6, 17 }) |protocol| {
        packet[23] = protocol;
        c.pcap_dump(@ptrCast(dump), &header, &packet);
    }
    c.pcap_dump_close(dump);
    var message: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var handle: Handle = .{ .raw = c.pcap_open_offline(path.ptr, &message) orelse return error.PcapUnavailable, .ready = undefined };
    defer handle.close();
    @memcpy(handle.default_filter[0..4], "udp\x00");
    var received: [limits.frame_capacity]u8 = undefined;
    try std.testing.expect(handle.setFilter("tcp") == null);
    try std.testing.expectEqual(@as(?usize, 54), try handle.next(&received));
    try std.testing.expectEqual(6, received[23]);
    try std.testing.expect(handle.setFilter("tcp and (") != null);
    try std.testing.expectEqual(@as(?usize, 54), try handle.next(&received));
    try std.testing.expectEqual(6, received[23]);
    try std.testing.expect(handle.setFilter("") == null);
    try std.testing.expectEqual(@as(?usize, 54), try handle.next(&received));
    try std.testing.expectEqual(17, received[23]);
}
