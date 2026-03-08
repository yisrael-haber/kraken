const std = @import("std");
const ph = @import("../protocol_headers.zig");
const cmd = @import("Command.zig");
const PingManager = @import("../Managers/PingManager.zig").PingManager;

pub const cmd_name = "ping";
pub const cmd_description = "Send ICMP echo requests and respond to incoming echo requests";
pub const cmd_usage_args = "--target <ip> [--via <gateway_ip>]";

pub const Args = struct {
    target: u32,
    /// Next-hop IP for ARP resolution. Use this when the target is off-subnet:
    ///   moto ping --target 1.1.1.1 --via 192.168.1.1
    /// If omitted the target IP is ARP'd directly (only works on-LAN).
    via: ?u32 = null,
};

pub fn parseArgs(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    _: cmd.GlobalArgs,
) !Args {
    _ = allocator;
    var target: ?u32 = null;
    var via: ?u32 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        } else if (std.mem.eql(u8, arg, "--target")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --target requires an argument\n", .{});
                return error.MissingArgument;
            }
            target = cmd.parseIpv4(args[i]) catch {
                std.debug.print("error: invalid IP address: {s}\n", .{args[i]});
                return error.InvalidIpAddress;
            };
        } else if (std.mem.eql(u8, arg, "--via")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --via requires an argument\n", .{});
                return error.MissingArgument;
            }
            via = cmd.parseIpv4(args[i]) catch {
                std.debug.print("error: invalid IP address: {s}\n", .{args[i]});
                return error.InvalidIpAddress;
            };
        } else {
            std.debug.print("error: unknown argument for ping: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return .{
        .target = target orelse {
            std.debug.print("error: ping requires --target <ip>\n", .{});
            return error.MissingTarget;
        },
        .via = via,
    };
}

pub fn run(ctx: cmd.NetCtx, args: Args) !void {
    var ping_mgr = PingManager.init(ctx.allocator, ctx.ip, ctx.arp, ctx.src_ip);
    try ctx.ip.registerHandler(1, ping_mgr.ipProtocolHandler());

    // Resolve the next-hop MAC. For on-LAN targets, ARP the target directly.
    // For off-LAN targets the caller supplies --via <gateway_ip>.
    const arp_ip = args.via orelse args.target;
    const hop = ph.ip_to_be_bytes(arp_ip);
    std.debug.print("ARP resolving next hop {}.{}.{}.{}...\n", .{ hop[0], hop[1], hop[2], hop[3] });

    try ctx.arp.queryNetwork(arp_ip);
    const dst_mac: u48 = blk: {
        for (0..2000) |_| {
            if (ctx.arp.cache.get(arp_ip)) |mac| break :blk mac;
            try ctx.eth.poll();
        }
        std.debug.print("error: ARP timeout for {}.{}.{}.{}\n", .{ hop[0], hop[1], hop[2], hop[3] });
        return error.ArpTimeout;
    };

    const t = ph.ip_to_be_bytes(args.target);
    std.debug.print("Pinging {}.{}.{}.{}...\n", .{ t[0], t[1], t[2], t[3] });
    try ping_mgr.sendRequest(args.target, dst_mac, 0x1234, 1);

    try ctx.eth.run();
}
