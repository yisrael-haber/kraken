const std = @import("std");
const posix = std.posix;
const ph = @import("protocol_headers.zig");
const cmd = @import("Commands/Command.zig");
const ArpManager = @import("Managers/ArpManager.zig").ArpManager;
const Ipv4Manager = @import("Managers/Ipv4Manager.zig").Ipv4Manager;
const EthernetManager = @import("Managers/EthernetManager.zig").EthernetManager;
const libpcap_handler = @import("Handlers/libpcap_handler.zig");

pub const pcap = @import("pcap.zig").pcap;

// ── Subcommand registry ───────────────────────────────────────────────────────
// To add a new subcommand: create src/Commands/XxxCommand.zig implementing the
// interface described in Command.zig, then add it to this tuple.
const commands = .{
    @import("Commands/ArpCommand.zig"),
    @import("Commands/PingCommand.zig"),
};

// Defaults for 192.168.30.0/24
const default_src_ip: u32 = 0xC0A81E64; // 192.168.30.100
const default_src_mac: u48 = 0xf068e373866e; // f0:68:e3:73:86:6e

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();

    var arg_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    const exe = arg_iter.next() orelse "moto";

    var all_args = std.array_list.Managed([]const u8).init(arena);
    while (arg_iter.next()) |arg| try all_args.append(arg);

    const parsed = parseGlobalArgs(all_args.items) catch |err| switch (err) {
        error.HelpRequested => return printUsage(exe),
        else => return err,
    };

    // ── Network stack setup ───────────────────────────────────────────────────

    const devices = try get_device_list(arena);
    const iface_name = parsed.global.iface orelse
        pickInterface(devices) orelse return error.NoSuitableInterface;
    std.debug.print("Using interface: {s}\n", .{iface_name});

    var handler = try libpcap_handler.PcapHandler.init(arena, iface_name);
    defer handler.close();

    var eth_mgr = EthernetManager.init(arena, &handler, parsed.global.src_mac);
    defer eth_mgr.deinit();

    var ip_mgr = Ipv4Manager.init(arena, &eth_mgr);
    defer ip_mgr.deinit();

    var arp_mgr = ArpManager.init(arena, &eth_mgr, parsed.global.src_ip, parsed.global.src_mac);
    defer arp_mgr.deinit();

    // Base handlers always registered regardless of subcommand.
    try eth_mgr.registerHandler(0x0806, arp_mgr.protocolHandler());
    try eth_mgr.registerHandler(0x0800, ip_mgr.protocolHandler());

    const ctx = cmd.NetCtx{
        .allocator = arena,
        .eth = &eth_mgr,
        .ip = &ip_mgr,
        .arp = &arp_mgr,
        .src_ip = parsed.global.src_ip,
        .src_mac = parsed.global.src_mac,
    };

    // ── Subcommand dispatch ───────────────────────────────────────────────────

    inline for (commands) |C| {
        if (std.mem.eql(u8, parsed.subcmd, C.cmd_name)) {
            const args = C.parseArgs(arena, parsed.remaining, parsed.global) catch |err| switch (err) {
                error.HelpRequested => return printSubcmdUsage(exe, C.cmd_name, C.cmd_description, C.cmd_usage_args),
                else => return err,
            };
            return C.run(ctx, args);
        }
    }

    std.debug.print("error: unknown subcommand '{s}'\n\n", .{parsed.subcmd});
    printUsage(exe);
    return error.UnknownSubcommand;
}

// ── Argument parsing ──────────────────────────────────────────────────────────

const ParseResult = struct {
    global: cmd.GlobalArgs,
    subcmd: []const u8,
    remaining: []const []const u8,
};

/// Parse global flags from `args`, stopping at the first non-flag word (the
/// subcommand name). Returns `error.HelpRequested` if --help/-h is seen, or
/// if no subcommand is provided.
fn parseGlobalArgs(args: []const []const u8) !ParseResult {
    var global = cmd.GlobalArgs{
        .src_ip = default_src_ip,
        .src_mac = default_src_mac,
    };

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        } else if (std.mem.eql(u8, arg, "--ip")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --ip requires an argument\n", .{});
                return error.MissingArgument;
            }
            global.src_ip = cmd.parseIpv4(args[i]) catch {
                std.debug.print("error: invalid IP address: {s}\n", .{args[i]});
                return error.InvalidIpAddress;
            };
        } else if (std.mem.eql(u8, arg, "--mac")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --mac requires an argument\n", .{});
                return error.MissingArgument;
            }
            global.src_mac = cmd.parseMac(args[i]) catch {
                std.debug.print("error: invalid MAC address: {s}\n", .{args[i]});
                return error.InvalidMacAddress;
            };
        } else if (std.mem.eql(u8, arg, "--iface")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --iface requires an argument\n", .{});
                return error.MissingArgument;
            }
            global.iface = args[i];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("error: unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        } else {
            // First non-flag word is the subcommand.
            return .{
                .global = global,
                .subcmd = arg,
                .remaining = args[i + 1 ..],
            };
        }
    }

    // No subcommand provided — show help.
    return error.HelpRequested;
}

// ── Help text ─────────────────────────────────────────────────────────────────

fn printUsage(exe: []const u8) void {
    std.debug.print(
        \\Usage: {s} [options] <subcommand> [subcommand-options]
        \\
        \\Global options:
        \\  --ip <addr>      Our source IP address   (default: 192.168.30.100)
        \\  --mac <addr>     Our source MAC address  (default: f0:68:e3:73:86:6e)
        \\  --iface <name>   Network interface to use (default: auto-detect)
        \\  --help, -h       Show this help message
        \\
        \\Subcommands:
        \\
    , .{exe});
    inline for (commands) |C| {
        std.debug.print("  {s:<16} {s}\n", .{ C.cmd_name, C.cmd_description });
    }
    std.debug.print("\nRun '{s} <subcommand> --help' for subcommand-specific options.\n", .{exe});
}

fn printSubcmdUsage(exe: []const u8, name: []const u8, description: []const u8, usage_args: []const u8) void {
    std.debug.print(
        \\Usage: {s} [options] {s} {s}
        \\
        \\{s}
        \\
    , .{ exe, name, usage_args, description });
}

// ── Interface selection ───────────────────────────────────────────────────────

fn hasIpv4Address(device: Device) bool {
    for (device.addresses) |address| {
        if (address.addr) |addr| {
            if (addr.family == posix.AF.INET) return true;
        }
    }
    return false;
}

fn pickInterface(devices: []Device) ?[]const u8 {
    // Prefer non-wireless interfaces: most WiFi drivers on Windows do not
    // support raw packet injection (pcap_sendpacket) in infrastructure mode.
    var wireless_fallback: ?[]const u8 = null;
    for (devices) |device| {
        const is_loopback = device.flags & pcap.PCAP_IF_LOOPBACK != 0;
        const is_up = device.flags & pcap.PCAP_IF_UP != 0;
        const is_running = device.flags & pcap.PCAP_IF_RUNNING != 0;
        const is_disconnected = (device.flags & pcap.PCAP_IF_CONNECTION_STATUS) ==
            pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
        const is_wireless = device.flags & pcap.PCAP_IF_WIRELESS != 0;
        if (!is_loopback and is_up and is_running and !is_disconnected and hasIpv4Address(device)) {
            if (!is_wireless) return device.name;
            if (wireless_fallback == null) wireless_fallback = device.name;
        }
    }
    return wireless_fallback;
}

fn get_device_list(allocator: std.mem.Allocator) ![]Device {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: ?*pcap.pcap_if_t = null;

    if (pcap.pcap_findalldevs(&alldevs, &errbuf) == -1) {
        std.debug.print("Error: {s}\n", .{errbuf});
        return error.PcapFindAllDevsFailed;
    }
    defer pcap.pcap_freealldevs(alldevs);

    var device_list = std.array_list.Managed(Device).init(allocator);
    defer device_list.deinit();

    var current_dev: ?*pcap.struct_pcap_if = alldevs;
    while (current_dev) |dev| {
        var addr_list = std.array_list.Managed(Address).init(allocator);
        var current_addr = dev.addresses;

        while (current_addr != null) {
            const ca = current_addr.*;
            try addr_list.append(.{
                .addr = if (ca.addr != null) @bitCast(ca.addr.*) else null,
                .netmask = if (ca.netmask != null) @bitCast(ca.netmask.*) else null,
                .broadaddr = if (ca.broadaddr != null) @bitCast(ca.broadaddr.*) else null,
                .dstaddr = if (ca.dstaddr != null) @bitCast(ca.dstaddr.*) else null,
            });
            current_addr = ca.next;
        }

        try device_list.append(.{
            .name = try allocator.dupe(u8, std.mem.span(dev.name)),
            .description = if (dev.description != null)
                try allocator.dupe(u8, std.mem.span(dev.description))
            else
                null,
            .flags = dev.flags,
            .addresses = try addr_list.toOwnedSlice(),
        });

        current_dev = dev.next;
    }

    return device_list.toOwnedSlice();
}

// ── Types ─────────────────────────────────────────────────────────────────────

pub const Device = struct {
    name: []const u8,
    description: ?[]const u8,
    flags: u32,
    addresses: []Address,

    pub fn print(self: Device) void {
        if (self.addresses.len == 0) return;

        std.debug.print("Device: \"{s}\":\n", .{self.name});
        if (self.description) |desc| std.debug.print("\tDescription: \"{s}\"\n", .{desc});
        std.debug.print("\tFlags: {d}\n", .{self.flags});
        std.debug.print("\tAddressing Information\n", .{});

        for (self.addresses) |address| {
            const addr = address.addr orelse continue;
            if (addr.family != posix.AF.INET) continue;

            const ipv4: posix.sockaddr.in = @bitCast(addr);
            const ip = ph.ip_to_bytes(ipv4.addr);
            std.debug.print("\t\tIPv4 address: {}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] });

            if (address.netmask) |nm| {
                const netmask: posix.sockaddr.in = @bitCast(nm);
                const nb = ph.ip_to_bytes(netmask.addr);
                std.debug.print("\tNetmask: {}.{}.{}.{}", .{ nb[0], nb[1], nb[2], nb[3] });
            }
            if (address.broadaddr) |ba| {
                const broadcast: posix.sockaddr.in = @bitCast(ba);
                const bb = ph.ip_to_bytes(broadcast.addr);
                std.debug.print("\tBroadcast: {}.{}.{}.{}", .{ bb[0], bb[1], bb[2], bb[3] });
            }
            std.debug.print("\n", .{});
        }
        std.debug.print("\n", .{});
    }
};

pub const Address = struct {
    addr: ?posix.sockaddr,
    netmask: ?posix.sockaddr,
    broadaddr: ?posix.sockaddr,
    dstaddr: ?posix.sockaddr,
};
