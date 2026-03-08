const std = @import("std");
const ph = @import("../protocol_headers.zig");
const pcap = @import("../pcap.zig").pcap;

/// A thin wrapper around libpcap that handles raw packet I/O only.
/// Protocol parsing is the responsibility of the manager layer.
pub const PcapHandler = struct {
    allocator: std.mem.Allocator,
    handle: ?*pcap.pcap_t,

    pub const Error = error{
        PcapOpenFailed,
        PcapSendFailed,
        PcapReceiveFailed,
        NoPacket,
    };

    pub fn init(allocator: std.mem.Allocator, device: []const u8) !PcapHandler {
        var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
        const dev = try allocator.dupeZ(u8, device);
        defer allocator.free(dev);

        const h_opt = pcap.pcap_open_live(dev, 65535, 1, 1000, &errbuf);
        if (h_opt == null) {
            std.debug.print("Error opening device: {s}\n", .{errbuf});
            return Error.PcapOpenFailed;
        }

        return PcapHandler{ .allocator = allocator, .handle = h_opt.? };
    }

    pub fn close(self: *PcapHandler) void {
        if (self.handle != null) {
            pcap.pcap_close(self.handle.?);
        }
        self.handle = null;
    }

    /// Return a slice of the next packet from the wire. The slice points into
    /// a pcap-managed buffer and is valid until the next call to receivePacket.
    pub fn receivePacket(self: *PcapHandler) ![]const u8 {
        var hdr: [*c]pcap.pcap_pkthdr = undefined;
        var pkt: [*c]const u8 = undefined;
        switch (pcap.pcap_next_ex(self.handle.?, &hdr, &pkt)) {
            1 => return pkt[0..hdr.*.caplen],
            0 => return Error.NoPacket,
            -1 => {
                std.debug.print("pcap error: {s}\n", .{pcap.pcap_geterr(self.handle)});
                return Error.PcapReceiveFailed;
            },
            else => return Error.PcapReceiveFailed,
        }
    }

    /// Serialize the provided header chain and send it out over the wire.
    pub fn sendPacket(self: *PcapHandler, hn: *ph.HeaderNode) !void {
        const bytes = hn.Serialize(self.allocator);
        if (pcap.pcap_sendpacket(self.handle.?, bytes.ptr, @intCast(bytes.len)) == -1) {
            std.debug.print("Error sending packet: {s}\n", .{pcap.pcap_geterr(self.handle)});
            return Error.PcapSendFailed;
        }
    }
};
