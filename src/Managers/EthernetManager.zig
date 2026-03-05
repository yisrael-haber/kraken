const std = @import("std");
const ph = @import("../protocol_headers.zig");
const libpcap = @import("../Handlers/libpcap_handler.zig");

/// Type-erased interface that any L3+ protocol manager implements to receive
/// packets dispatched by the EthernetManager.  The inner HeaderNode passed to
/// `handle` is owned by the EthernetManager; handlers must not free it.
pub const ProtocolHandler = struct {
    ptr: *anyopaque,
    handleFn: *const fn (ptr: *anyopaque, node: *ph.HeaderNode) anyerror!void,

    pub fn handle(self: ProtocolHandler, node: *ph.HeaderNode) !void {
        return self.handleFn(self.ptr, node);
    }
};

pub const EthernetManager = struct {
    allocator: std.mem.Allocator,
    pcap: *libpcap.PcapHandler,
    handlers: std.AutoHashMap(u16, ProtocolHandler),

    pub fn init(allocator: std.mem.Allocator, pcap: *libpcap.PcapHandler) EthernetManager {
        return .{
            .allocator = allocator,
            .pcap = pcap,
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

    /// Send a header-node chain out over the wire.
    pub fn sendPacket(self: *EthernetManager, node: *ph.HeaderNode) !void {
        try self.pcap.sendPacket(node);
    }

    /// Receive and dispatch one packet.  Returns immediately without error on
    /// timeout so callers can intersperse other work between polls.
    pub fn poll(self: *EthernetManager) !void {
        const pkt = self.pcap.receivePacket() catch |err| {
            if (err == libpcap.PcapHandler.Error.NoPacket) return;
            return err;
        };
        defer self.pcap.freeChain(pkt);

        const eh = switch (pkt.header) {
            .Ethernet => |hdr| hdr,
            else => return,
        };

        const inner = pkt.next orelse return;

        if (self.handlers.get(eh.ether_type)) |h| {
            try h.handle(inner);
        }
    }

    /// Block indefinitely, polling for packets and dispatching them.
    pub fn run(self: *EthernetManager) !void {
        while (true) {
            try self.poll();
        }
    }
};
