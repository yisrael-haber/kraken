const std = @import("std");
const ph = @import("../protocol_headers.zig");
const pcap = @import("../pcap.zig").pcap;

/// A thin wrapper around libpcap that centralises all packet I/O and
/// the (de)serialization of bytes <-> `ph.HeaderNode`.
///
/// Consumers never talk to the raw `pcap_t` pointer and they never
/// manually convert headers to/from slices; everything goes through
/// the handler.
pub const PcapHandler = struct {
    allocator: std.mem.Allocator,
    handle: ?*pcap.pcap_t,

    pub const Error = error{
        PcapOpenFailed,
        PcapSendFailed,
        PcapReceiveFailed,
        NoPacket,
    };

    /// Open a live capture on `device` using the supplied allocator for
    /// temporary buffers required during parsing/serialization.
    pub fn init(allocator: std.mem.Allocator, device: []const u8) !PcapHandler {
        var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
        const dev = try allocator.dupeZ(u8, device);
        defer allocator.free(dev);

        const snaplen = 65535;
        const promisc = 1;
        const timeout_ms = 1000;

        const h_opt = pcap.pcap_open_live(dev, snaplen, promisc, timeout_ms, &errbuf);
        if (h_opt == null) {
            std.debug.print("Error opening device: {s}\n", .{errbuf});
            return Error.PcapOpenFailed;
        }
        const h = h_opt.?;

        return PcapHandler{ .allocator = allocator, .handle = h };
    }

    pub fn close(self: *PcapHandler) void {
        if (self.handle != null) {
            pcap.pcap_close(self.handle.?);
        }
        self.handle = null;
    }

    /// Receive the next packet from the wire and return a freshly
    /// allocated `HeaderNode` chain representing the headers that we
    /// currently understand.  The caller is responsible for destroying
    /// the nodes when they are no longer needed.
    pub fn receivePacket(self: *PcapHandler) !*ph.HeaderNode {
        var hdr: [*c]pcap.pcap_pkthdr = undefined;
        var pkt: [*c]const u8 = undefined;
        const res = pcap.pcap_next_ex(self.handle.?, &hdr, &pkt);
        switch (res) {
            1 => return self.parsePacket(pkt[0..hdr.*.caplen]),
            0 => return Error.NoPacket, // timeout
            -1 => {
                std.debug.print("pcap error: {s}\n", .{pcap.pcap_geterr(self.handle)});
                return Error.PcapReceiveFailed;
            },
            else => return Error.PcapReceiveFailed,
        }
    }

    /// Parse a slice of raw bytes into a `HeaderNode` chain.  Only the
    /// headers we care about are converted; the remainder of the packet
    /// is left as `.Unparsed`.
    fn parsePacket(self: *PcapHandler, data: []const u8) !*ph.HeaderNode {
        const alloc = self.allocator;

        if (data.len < 14) {
            return Error.PcapReceiveFailed;
        }

        const eh_ptr = try alloc.create(ph.EthernetHeader);
        eh_ptr.* = @bitCast(std.mem.readInt(u112, data[0..14], .big));

        const eth_node = try alloc.create(ph.HeaderNode);
        eth_node.* = ph.HeaderNode{
            .header = ph.Header{ .Ethernet = eh_ptr },
            .next = null,
            .prev = null,
        };

        const inner = data[14..];
        const inner_node = try alloc.create(ph.HeaderNode);
        inner_node.* = ph.HeaderNode{
            .header = undefined,
            .next = null,
            .prev = eth_node,
        };
        eth_node.next = inner_node;

        if (eh_ptr.ether_type == 0x0806 and inner.len >= 28) {
            const ah_ptr = try alloc.create(ph.ArpHeader);
            ah_ptr.* = @bitCast(std.mem.readInt(u224, inner[0..28], .big));
            inner_node.*.header = ph.Header{ .Arp = ah_ptr };
        } else {
            const unparsed_ptr = try alloc.create(ph.UnparsedHeader);
            unparsed_ptr.* = ph.UnparsedHeader{ .data = inner };
            inner_node.*.header = ph.Header{ .Unparsed = unparsed_ptr };
        }

        return eth_node;
    }

    /// Serialize the provided header chain and send it out over the wire.
    ///
    /// The chain may consist of a single node, or several linked together
    /// via the `next` field; the serialization logic already handles
    /// flattening them.
    pub fn sendPacket(self: *PcapHandler, hn: *ph.HeaderNode) !void {
        const bytes = hn.Serialize(self.allocator);
        const len_u32: u32 = @intCast(bytes.len);
        const len_c: c_int = @intCast(len_u32);
        if (pcap.pcap_sendpacket(self.handle.?, bytes.ptr, len_c) == -1) {
            std.debug.print("Error sending packet: {s}\n", .{pcap.pcap_geterr(self.handle)});
            return Error.PcapSendFailed;
        }
    }

    /// Destroy a header node chain allocated via this handler, including
    /// any header objects that were put into the union.  This properly
    /// frees all of the memory used during parsing or when the caller
    /// manually constructed a chain for transmission.
    pub fn freeChain(self: *PcapHandler, hn: *ph.HeaderNode) void {
        var curr: ?*ph.HeaderNode = hn;
        while (curr) |node| {
            // free any pointer payloads we allocated
            switch (node.header) {
                .Ethernet => |hdr| self.allocator.destroy(hdr),
                .Arp => |hdr| self.allocator.destroy(hdr),
                .Unparsed => |hdr| self.allocator.destroy(hdr),
            }
            const next = node.next;
            self.allocator.destroy(node);
            curr = next;
        }
    }
};
