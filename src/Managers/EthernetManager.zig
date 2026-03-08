const std = @import("std");
const ph = @import("../protocol_headers.zig");
const libpcap = @import("../Handlers/libpcap_handler.zig");

/// Type-erased interface that any L3+ protocol manager implements to receive
/// packets dispatched by the EthernetManager. The payload slice passed to
/// `handle` points into a pcap-managed buffer; it is valid only for the
/// duration of the call and must not be retained.
pub const ProtocolHandler = struct {
    ptr: *anyopaque,
    handleFn: *const fn (ptr: *anyopaque, payload: []const u8) anyerror!void,

    pub fn handle(self: ProtocolHandler, payload: []const u8) !void {
        return self.handleFn(self.ptr, payload);
    }
};

pub const EthernetManager = struct {
    allocator: std.mem.Allocator,
    pcap: *libpcap.PcapHandler,
    our_mac: u48,
    handlers: std.AutoHashMap(u16, ProtocolHandler),

    pub fn init(allocator: std.mem.Allocator, pcap: *libpcap.PcapHandler, our_mac: u48) EthernetManager {
        return .{
            .allocator = allocator,
            .pcap = pcap,
            .our_mac = our_mac,
            .handlers = std.AutoHashMap(u16, ProtocolHandler).init(allocator),
        };
    }

    pub fn deinit(self: *EthernetManager) void {
        self.handlers.deinit();
    }

    /// Register a handler for a given EtherType (e.g. 0x0806 for ARP).
    pub fn registerHandler(self: *EthernetManager, ether_type: u16, h: ProtocolHandler) !void {
        try self.handlers.put(ether_type, h);
    }

    /// Wrap `payload` in an Ethernet frame addressed to `dest_mac` with the
    /// given `ether_type` and send it. The payload node is not modified.
    pub fn sendFrame(self: *EthernetManager, dest_mac: u48, ether_type: u16, payload: *ph.HeaderNode) !void {
        const eth_hdr = try self.allocator.create(ph.EthernetHeader);
        eth_hdr.* = .{
            .ether_type = ether_type,
            .src_mac = self.our_mac,
            .dest_mac = dest_mac,
        };
        const eth_node = try self.allocator.create(ph.HeaderNode);
        eth_node.* = .{
            .header = .{ .Ethernet = eth_hdr },
            .next = payload,
            .prev = null,
        };
        defer {
            self.allocator.destroy(eth_hdr);
            self.allocator.destroy(eth_node);
        }
        try self.pcap.sendPacket(eth_node);
    }

    /// Receive and dispatch one packet. Parses the Ethernet header and passes
    /// the remaining bytes to the registered handler for the ether_type.
    /// Returns immediately without error on timeout.
    pub fn poll(self: *EthernetManager) !void {
        const data = self.pcap.receivePacket() catch |err| {
            if (err == libpcap.PcapHandler.Error.NoPacket) return;
            return err;
        };

        if (data.len < 14) return;

        const eth: ph.EthernetHeader = @bitCast(std.mem.readInt(u112, data[0..14], .big));

        if (self.handlers.get(eth.ether_type)) |h| {
            try h.handle(data[14..]);
        }
    }

    /// Block indefinitely, polling for packets and dispatching them.
    pub fn run(self: *EthernetManager) !void {
        while (true) {
            try self.poll();
        }
    }
};
