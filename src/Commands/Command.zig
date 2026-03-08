const std = @import("std");
const EthernetManager = @import("../Managers/EthernetManager.zig").EthernetManager;
const Ipv4Manager = @import("../Managers/Ipv4Manager.zig").Ipv4Manager;
const ArpManager = @import("../Managers/ArpManager.zig").ArpManager;

/// Arguments resolved from the global portion of the command line,
/// before the subcommand name.
pub const GlobalArgs = struct {
    src_ip: u32,
    src_mac: u48,
    iface: ?[]const u8 = null,
};

/// Fully-initialised network stack passed to every subcommand's run function.
/// The ARP (0x0806) and IPv4 (0x0800) handlers are already registered on
/// `eth` before run is called; subcommands register any additional handlers
/// they need before starting the event loop.
pub const NetCtx = struct {
    allocator: std.mem.Allocator,
    eth: *EthernetManager,
    ip: *Ipv4Manager,
    arp: *ArpManager,
    src_ip: u32,
    src_mac: u48,
};

pub fn parseIpv4(s: []const u8) !u32 {
    var iter = std.mem.splitScalar(u8, s, '.');
    var result: u32 = 0;
    var count: u8 = 0;
    while (iter.next()) |part| : (count += 1) {
        if (count >= 4) return error.InvalidIpAddress;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpAddress;
        result = (result << 8) | octet;
    }
    if (count != 4) return error.InvalidIpAddress;
    return result;
}

pub fn parseMac(s: []const u8) !u48 {
    var iter = std.mem.splitScalar(u8, s, ':');
    var result: u48 = 0;
    var count: u8 = 0;
    while (iter.next()) |part| : (count += 1) {
        if (count >= 6) return error.InvalidMacAddress;
        const byte = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMacAddress;
        result = (result << 8) | byte;
    }
    if (count != 6) return error.InvalidMacAddress;
    return result;
}

// ── Subcommand interface contract (enforced via comptime duck typing) ─────────
//
// Each subcommand module must export:
//
//   pub const cmd_name: []const u8
//       The word used on the command line, e.g. "arp".
//
//   pub const cmd_description: []const u8
//       One-line description shown in the global help listing.
//
//   pub const cmd_usage_args: []const u8
//       Argument synopsis shown after the subcommand name, e.g. "--target <ip>".
//
//   pub const Args: type
//       A struct that holds all parsed subcommand-specific arguments.
//
//   pub fn parseArgs(
//       allocator: std.mem.Allocator,
//       args:      []const []const u8,
//       global:    GlobalArgs,
//   ) !Args
//       Parse `args` (everything on the command line after the subcommand name).
//       Return `error.HelpRequested` if the user passed --help / -h.
//
//   pub fn run(ctx: NetCtx, args: Args) !void
//       Execute the subcommand. Responsible for registering any additional
//       protocol handlers, sending initial packets, and running the event loop.
