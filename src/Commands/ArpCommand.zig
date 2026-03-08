const std = @import("std");
const ph = @import("../protocol_headers.zig");
const cmd = @import("Command.zig");

pub const cmd_name = "arp";
pub const cmd_description = "Send an ARP request and listen for replies";
pub const cmd_usage_args = "--target <ip>";

pub const Args = struct {
    target: u32,
};

pub fn parseArgs(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    _: cmd.GlobalArgs,
) !Args {
    _ = allocator;
    var target: ?u32 = null;
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
        } else {
            std.debug.print("error: unknown argument for arp: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return .{ .target = target orelse {
        std.debug.print("error: arp requires --target <ip>\n", .{});
        return error.MissingTarget;
    } };
}

pub fn run(ctx: cmd.NetCtx, args: Args) !void {
    const t = ph.ip_to_be_bytes(args.target);
    std.debug.print("ARP query for {}.{}.{}.{}...\n", .{ t[0], t[1], t[2], t[3] });
    try ctx.arp.queryNetwork(args.target);
    try ctx.eth.run();
}
