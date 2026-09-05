const std = @import("std");
const builtin = @import("builtin");
const c = @import("pcap_c");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const identity = @import("../identities/identity.zig");

/// A capture interface's stable libpcap identifier and its human-readable
/// adapter description. Only the identifier is used to open the interface.
pub const Device = struct {
    capture_name: text.FieldText = .{},
    label: text.FieldText = .{},

    pub fn displayName(self: *const Device) []const u8 {
        const description = self.label.value();
        return if (description.len > 0) description else self.capture_name.value();
    }
};

pub fn list(devices: []Device) usize {
    var error_buffer: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var all: ?*c.pcap_if_t = null;
    if (c.pcap_findalldevs(&all, &error_buffer) != 0) return 0;
    defer c.pcap_freealldevs(all);

    var count: usize = 0;
    var current = all;
    while (current) |device| : (current = device.next) {
        if (count == devices.len) break;
        devices[count].capture_name.set(std.mem.span(device.name.?)) catch unreachable;
        if (device.description) |description| devices[count].label.set(std.mem.span(description)) catch {};
        count += 1;
    }
    return count;
}

pub const Handle = struct {
    raw: *c.pcap_t,
    ready: if (builtin.os.tag == .linux) c_int else *anyopaque,

    pub fn open(value: *const identity.Identity) error{OpenFailed}!Handle {
        const mac = parseMac(value.mac.value()) orelse return error.OpenFailed;
        const address = parseIpv4(value.ip.value()) catch return error.OpenFailed;
        var pcap_error: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        const raw = c.pcap_create(value.interface.bytes[0..value.interface.len :0].ptr, &pcap_error) orelse return error.OpenFailed;
        errdefer c.pcap_close(raw);
        if (c.pcap_set_snaplen(raw, limits.frame_capacity) != 0 or
            c.pcap_set_promisc(raw, 1) != 0 or
            c.pcap_set_immediate_mode(raw, 1) != 0 or
            c.pcap_activate(raw) < 0) return error.OpenFailed;
        if (c.pcap_datalink(raw) != c.DLT_EN10MB) return error.OpenFailed;
        var filter_buffer: [128]u8 = undefined;
        const filter = identityFilter(&filter_buffer, mac, address);
        var program: c.struct_bpf_program = undefined;
        if (c.pcap_compile(raw, &program, filter.ptr, 1, c.PCAP_NETMASK_UNKNOWN) != 0) return error.OpenFailed;
        defer c.pcap_freecode(&program);
        if (c.pcap_setfilter(raw, &program) != 0) return error.OpenFailed;
        if (c.pcap_setnonblock(raw, 1, &pcap_error) != 0) return error.OpenFailed;
        return .{ .raw = raw, .ready = switch (builtin.os.tag) {
            .linux => blk: {
                const fd = c.pcap_get_selectable_fd(raw);
                if (fd < 0) return error.OpenFailed;
                break :blk fd;
            },
            .windows => c.pcap_getevent(raw) orelse return error.OpenFailed,
            else => unreachable,
        } };
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

fn identityFilter(buffer: *[128]u8, mac: [6]u8, address: [4]u8) [:0]u8 {
    return std.fmt.bufPrintZ(
        buffer,
        "ether dst {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} or ip dst host {d}.{d}.{d}.{d} or arp dst host {d}.{d}.{d}.{d}",
        .{
            mac[0],     mac[1],     mac[2],     mac[3],     mac[4],     mac[5],
            address[0], address[1], address[2], address[3], address[0], address[1],
            address[2], address[3],
        },
    ) catch unreachable;
}

fn parseIpv4(value: []const u8) ![4]u8 {
    return (try std.Io.net.Ip4Address.parse(value, 0)).bytes;
}

fn parseMac(value: []const u8) ?[6]u8 {
    if (value.len != 17) return null;
    var result: [6]u8 = undefined;
    for (&result, 0..) |*octet, index| {
        if (index < 5 and value[index * 3 + 2] != ':') return null;
        octet.* = std.fmt.parseInt(u8, value[index * 3 .. index * 3 + 2], 16) catch return null;
    }
    return result;
}

test "identity filter selects its MAC and IPv4 destinations" {
    var buffer: [128]u8 = undefined;
    const filter = identityFilter(&buffer, .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, .{ 192, 0, 2, 9 });
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
