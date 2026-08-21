const std = @import("std");
const c = @import("pcap_c");

pub const name_capacity = 128;
pub const description_capacity = 256;

pub const Device = struct {
    name: [name_capacity]u8 = [_]u8{0} ** name_capacity,
    description: [description_capacity]u8 = [_]u8{0} ** description_capacity,

    pub fn nameSlice(self: *const Device) []const u8 {
        return std.mem.sliceTo(&self.name, 0);
    }
};

pub const OpenError = error{ OpenFailed, FilterCompileFailed, FilterInstallFailed, NonBlockingFailed, UnsupportedLinkType };
pub const Next = union(enum) { none, frame: usize, failed };

pub const Handle = struct {
    raw: *c.pcap_t,

    pub fn list(devices: []Device) usize {
        var error_buffer: [c.PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** c.PCAP_ERRBUF_SIZE;
        var all: ?*c.pcap_if_t = null;
        if (c.pcap_findalldevs(&all, &error_buffer) != 0) return 0;
        defer c.pcap_freealldevs(all);

        var count: usize = 0;
        var current = all;
        while (current) |device| : (current = device.next) {
            if (count == devices.len) break;
            copyCString(&devices[count].name, device.name);
            copyCString(&devices[count].description, device.description);
            count += 1;
        }
        return count;
    }

    pub fn open(name: [:0]const u8, mac: [6]u8, address: [4]u8, error_output: []u8) OpenError!Handle {
        var pcap_error: [c.PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** c.PCAP_ERRBUF_SIZE;
        const raw = c.pcap_open_live(name.ptr, 2048, 1, 1, &pcap_error) orelse {
            copyCStringSlice(error_output, &pcap_error);
            return error.OpenFailed;
        };
        errdefer c.pcap_close(raw);
        if (c.pcap_datalink(raw) != c.DLT_EN10MB) {
            copyCStringSlice(error_output, "selected interface does not provide Ethernet frames");
            return error.UnsupportedLinkType;
        }
        var filter_buffer: [160]u8 = undefined;
        const filter = identityFilter(&filter_buffer, mac, address) catch {
            copyCStringSlice(error_output, "identity capture filter is too large");
            return error.FilterCompileFailed;
        };
        var program: c.struct_bpf_program = undefined;
        if (c.pcap_compile(raw, &program, filter.ptr, 1, c.PCAP_NETMASK_UNKNOWN) != 0) {
            copyCString(error_output, c.pcap_geterr(raw));
            return error.FilterCompileFailed;
        }
        defer c.pcap_freecode(&program);
        if (c.pcap_setfilter(raw, &program) != 0) {
            copyCString(error_output, c.pcap_geterr(raw));
            return error.FilterInstallFailed;
        }
        if (c.pcap_setnonblock(raw, 1, &pcap_error) != 0) {
            copyCStringSlice(error_output, &pcap_error);
            return error.NonBlockingFailed;
        }
        return .{ .raw = raw };
    }

    pub fn close(self: *Handle) void {
        c.pcap_close(self.raw);
    }

    pub fn next(self: *Handle, destination: []u8) Next {
        var header: [*c]c.struct_pcap_pkthdr = undefined;
        var bytes: [*c]const u8 = undefined;
        const result = c.pcap_next_ex(self.raw, &header, &bytes);
        if (result == 0) return .none;
        if (result < 0) return .failed;
        if (header.*.caplen > destination.len) return .failed;
        @memcpy(destination[0..header.*.caplen], bytes[0..header.*.caplen]);
        return .{ .frame = header.*.caplen };
    }

    pub fn inject(self: *Handle, bytes: []const u8) bool {
        return c.pcap_inject(self.raw, bytes.ptr, bytes.len) >= 0;
    }
};

fn identityFilter(buffer: []u8, mac: [6]u8, address: [4]u8) ![:0]u8 {
    return std.fmt.bufPrintZ(
        buffer,
        "ether dst {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} or ip dst host {d}.{d}.{d}.{d} or arp dst host {d}.{d}.{d}.{d}",
        .{
            mac[0],     mac[1],     mac[2],     mac[3],     mac[4],     mac[5],
            address[0], address[1], address[2], address[3], address[0], address[1],
            address[2], address[3],
        },
    );
}

fn copyCString(destination: []u8, source: ?[*:0]const u8) void {
    copyCStringSlice(destination, if (source) |value| std.mem.span(value) else "");
}

fn copyCStringSlice(destination: []u8, source: []const u8) void {
    if (destination.len == 0) return;
    const length = @min(destination.len - 1, source.len);
    @memcpy(destination[0..length], source[0..length]);
    destination[length] = 0;
}

test "identity filter selects its MAC and IPv4 destinations" {
    var buffer: [160]u8 = undefined;
    const filter = try identityFilter(&buffer, .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, .{ 192, 0, 2, 9 });
    try std.testing.expectEqualStrings(
        "ether dst 02:11:22:33:44:55 or ip dst host 192.0.2.9 or arp dst host 192.0.2.9",
        filter,
    );

    const dead = c.pcap_open_dead(c.DLT_EN10MB, 2048) orelse return error.PcapUnavailable;
    defer c.pcap_close(dead);
    var program: c.struct_bpf_program = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.pcap_compile(dead, &program, filter.ptr, 1, c.PCAP_NETMASK_UNKNOWN));
    c.pcap_freecode(&program);
}
