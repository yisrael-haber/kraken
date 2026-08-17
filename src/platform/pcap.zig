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

pub const OpenError = error{ OpenFailed, NonBlockingFailed, UnsupportedLinkType };
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

    pub fn open(name: [:0]const u8, error_output: []u8) OpenError!Handle {
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

fn copyCString(destination: []u8, source: ?[*:0]const u8) void {
    copyCStringSlice(destination, if (source) |value| std.mem.span(value) else "");
}

fn copyCStringSlice(destination: []u8, source: []const u8) void {
    if (destination.len == 0) return;
    const length = @min(destination.len - 1, source.len);
    @memcpy(destination[0..length], source[0..length]);
    destination[length] = 0;
}
