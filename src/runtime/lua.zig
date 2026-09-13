const std = @import("std");
const frame = @import("frame.zig");
const log = @import("../log.zig");
const text = @import("../text.zig");
const c = @import("c");

pub const global_heap_size = 1024 * 1024;
pub const max_instructions = 100_000;
const module_suffix = [_]u8{ std.fs.path.sep, '?', '.', 'l', 'u', 'a' };
const print_capacity = 8 * 1024;

pub fn FixedLuaHeap(comptime size: usize) type {
    return struct {
        bytes: [size]u8 align(16) = undefined,
        used: usize = 0,

        pub fn reset(self: *@This()) void {
            self.used = 0;
        }

        pub fn reallocate(self: *@This(), old: ?*anyopaque, old_size: usize, new_size: usize) ?*anyopaque {
            if (old) |pointer| {
                if (new_size == 0) return null;
                if (new_size <= old_size) return pointer;
                const replacement = self.allocate(new_size) orelse return null;
                const source: [*]const u8 = @ptrCast(pointer);
                const destination: [*]u8 = @ptrCast(replacement);
                @memcpy(destination[0..old_size], source[0..old_size]);
                return replacement;
            }
            if (new_size == 0) return null;
            return self.allocate(new_size);
        }

        fn allocate(self: *@This(), new_size: usize) ?*anyopaque {
            const start = std.mem.alignForward(usize, self.used, @alignOf(usize));
            if (start > self.bytes.len or new_size > self.bytes.len - start) return null;
            self.used = start + new_size;
            return @ptrCast(&self.bytes[start]);
        }
    };
}

pub const Error = error{ OutOfMemory, ScriptFailed };

pub const Invocation = struct {
    packet: *const frame.Frame,
    direction: frame.Direction,
    send: *const fn (*anyopaque, frame.Direction, []const u8) bool,
    context: ?*anyopaque,
};

pub const Transport = struct {
    state: ?*c.lua_State = null,
    helpers_root: []const u8 = "",
    logger: ?*log.Logger = null,
    scope: text.FixedText(text.FieldText.capacity + 32) = .{},
    instructions: usize = 0,
    sleep_cancelled: std.Io.Event = .unset,

    pub fn init(self: *Transport, source: []const u8, scope: []const u8) Error!void {
        self.deinit();
        self.scope.set(scope) catch unreachable;
        const state = c.lua_newstate(allocateTransport, @ptrCast(self)) orelse return error.OutOfMemory;
        errdefer c.lua_close(state);
        initialize(state, self.logger, self.scope.value(), self.helpers_root, &self.sleep_cancelled);
        c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
        if (c.luaL_loadbufferx(state, source.ptr, source.len, "transport", null) != c.LUA_OK or c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
            reportError(self.logger, state, self.scope.value(), "initialization failed");
            return error.ScriptFailed;
        }
        _ = c.lua_getglobal(state, "transport");
        if (c.lua_type(state, -1) != c.LUA_TFUNCTION) {
            c.lua_pop(state, 1);
            if (self.logger) |logger| logger.formatted(.err, .lua, "{s}: function transport is missing.", .{self.scope.value()});
            return error.ScriptFailed;
        }
        c.lua_pop(state, 1);
        self.state = state;
    }

    pub fn deinit(self: *Transport) void {
        if (self.state) |state| c.lua_close(state);
        self.state = null;
        self.instructions = 0;
    }

    pub fn run(self: *Transport, invocation: *const Invocation) Error!void {
        const state = self.state orelse return error.ScriptFailed;
        self.instructions = 0;
        const current: *Invocation = @ptrCast(@alignCast(c.lua_newuserdatauv(state, @sizeOf(Invocation), 0).?));
        current.* = invocation.*;
        defer {
            current.context = null;
            c.lua_pop(state, 1);
        }
        const context_index = c.lua_gettop(state);
        _ = c.lua_getglobal(state, "transport");
        _ = c.lua_pushlstring(state, &invocation.packet.bytes, invocation.packet.len);
        c.lua_createtable(state, 0, 2);
        _ = c.lua_pushstring(state, if (invocation.direction == .inbound) "inbound" else "outbound");
        c.lua_setfield(state, -2, "direction");
        c.lua_pushvalue(state, context_index);
        c.lua_pushcclosure(state, transmitLua, 1);
        c.lua_setfield(state, -2, "send");
        if (c.lua_pcallk(state, 2, 0, 0, 0, null) != c.LUA_OK) {
            reportError(self.logger, state, self.scope.value(), "runtime failed");
            return error.ScriptFailed;
        }
    }
};

fn transmitLua(state: ?*c.lua_State) callconv(.c) c_int {
    const invocation: *const Invocation = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    const context = invocation.context orelse return c.luaL_error(state, "transmitter is no longer active");
    return if (invocation.send(context, invocation.direction, checkBytes(state, 1))) 0 else c.luaL_error(state, "packet transmission failed");
}

pub fn initialize(state: ?*c.lua_State, logger: ?*log.Logger, scope: []const u8, helpers_root: []const u8, cancelled: *std.Io.Event) void {
    c.luaL_openlibs(state);
    installPrint(state, logger, scope);
    appendModulePath(state, helpers_root);
    preload(state, "kraken/packet", frame.packetModule);
    c.lua_createtable(state, 0, 1);
    c.lua_pushlightuserdata(state, cancelled);
    c.lua_pushcclosure(state, sleepLua, 1);
    c.lua_setfield(state, -2, "sleep");
    c.lua_setglobal(state, "kraken");
}

pub fn preload(state: ?*c.lua_State, name: [*:0]const u8, function: c.lua_CFunction) void {
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "preload");
    setFunction(state, -2, name, function);
    c.lua_pop(state, 2);
}

pub fn setFunction(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, function: c.lua_CFunction) void {
    c.lua_pushcclosure(state, function, 0);
    c.lua_setfield(state, table, name);
}

pub fn checkBytes(state: ?*c.lua_State, index: c_int) []const u8 {
    c.luaL_checktype(state, index, c.LUA_TSTRING);
    return toBytes(state, index).?;
}

pub fn toBytes(state: ?*c.lua_State, index: c_int) ?[]const u8 {
    var length: usize = 0;
    const bytes = c.lua_tolstring(state, index, &length) orelse return null;
    return bytes[0..length];
}

fn sleepLua(state: ?*c.lua_State) callconv(.c) c_int {
    const cancelled: *std.Io.Event = @ptrCast(@alignCast(c.lua_touserdata(state, c.lua_upvalueindex(1)).?));
    const milliseconds = c.luaL_checkinteger(state, 1);
    if (milliseconds < 0) return c.luaL_argerror(state, 1, "sleep duration must be non-negative");
    const io = std.Io.Threaded.global_single_threaded.io();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    while (!cancelled.isSet()) {
        if (std.Io.Clock.awake.now(io).nanoseconds >= deadline.raw.nanoseconds) return 0;
        cancelled.waitTimeout(io, .{ .deadline = deadline }) catch {};
    }
    return c.luaL_error(state, "script cancelled");
}

fn allocateTransport(_: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    if (old) |pointer| {
        const bytes: []u8 = @as([*]u8, @ptrCast(pointer))[0..old_size];
        if (new_size == 0) {
            std.heap.c_allocator.free(bytes);
            return null;
        }
        return (std.heap.c_allocator.realloc(bytes, new_size) catch return null).ptr;
    }
    if (new_size == 0) return null;
    return (std.heap.c_allocator.alloc(u8, new_size) catch return null).ptr;
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    var context: ?*anyopaque = null;
    _ = c.lua_getallocf(state, &context);
    const transport: *Transport = @ptrCast(@alignCast(context orelse return));
    transport.instructions += 1000;
    if (transport.instructions > max_instructions) _ = c.luaL_error(state, "transport instruction budget exceeded");
}

pub fn reportError(logger: ?*log.Logger, state: ?*c.lua_State, scope: []const u8, context: []const u8) void {
    defer c.lua_pop(state, 1);
    const target = logger orelse return;
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: {s}: {s}", .{ scope, context, toBytes(state, -1) orelse "Lua returned a non-string error value" }) catch {};
    target.err(.lua, output.buffered());
}

fn installPrint(state: ?*c.lua_State, logger: ?*log.Logger, scope: []const u8) void {
    c.lua_pushlightuserdata(state, if (logger) |value| @ptrCast(value) else null);
    _ = c.lua_pushlstring(state, scope.ptr, scope.len);
    c.lua_pushcclosure(state, luaPrint, 2);
    c.lua_setglobal(state, "print");
}

fn luaPrint(state: ?*c.lua_State) callconv(.c) c_int {
    const raw_logger = c.lua_touserdata(state, c.lua_upvalueindex(1)) orelse return 0;
    const logger: *log.Logger = @ptrCast(@alignCast(raw_logger));
    var buffer: [print_capacity]u8 = undefined;
    var output: std.Io.Writer = .fixed(&buffer);
    output.print("{s}: ", .{toBytes(state, c.lua_upvalueindex(2)).?}) catch {};
    const count = c.lua_gettop(state);
    var index: c_int = 1;
    while (index <= count) : (index += 1) {
        var value_len: usize = 0;
        const value = c.luaL_tolstring(state, index, &value_len) orelse continue;
        defer c.lua_pop(state, 1);
        if (index > 1) output.writeByte('\t') catch {};
        output.writeAll(value[0..value_len]) catch {};
    }
    logger.info(.lua, output.buffered());
    return 0;
}

fn appendModulePath(state: ?*c.lua_State, helpers_root: []const u8) void {
    if (helpers_root.len == 0) return;
    _ = c.lua_getglobal(state, "package");
    _ = c.lua_getfield(state, -1, "path");
    _ = c.lua_pushstring(state, ";");
    _ = c.lua_pushlstring(state, helpers_root.ptr, helpers_root.len);
    _ = c.lua_pushlstring(state, &module_suffix, module_suffix.len);
    c.lua_concat(state, 4);
    c.lua_setfield(state, -2, "path");
    c.lua_pop(state, 1);
}

const TestEmission = struct { count: usize = 0, value: frame.Frame = .{} };

fn testPacketSend(context: *anyopaque, _: frame.Direction, bytes: []const u8) bool {
    const capture: *TestEmission = @ptrCast(@alignCast(context));
    capture.value.set(bytes) catch return false;
    capture.count += 1;
    return true;
}

fn runTestTransport(source: []const u8, helpers_root: []const u8, value: *const frame.Frame, direction: frame.Direction, capture: *TestEmission) Error!void {
    var transport: Transport = .{ .helpers_root = helpers_root };
    defer transport.deinit();
    try transport.init(source, "Test transport");
    const invocation: Invocation = .{ .packet = value, .direction = direction, .send = testPacketSend, .context = @ptrCast(capture) };
    try transport.run(&invocation);
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

test "transport VMs persist, load helpers, and complete sends before errors" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = "network.lua", .data = "return { answer = 42 }" });
    const helpers_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{temp_dir.sub_path});
    defer allocator.free(helpers_root);
    const source = "counter = counter or 0; local codec = require('kraken/packet'); function transport(bytes, tx) local packet = codec.decode(bytes); local direction = tx.direction; counter = counter + 1; assert(require('network').answer == 42 and counter <= 2 and direction == 'outbound'); packet.eth.src[1] = 123; tx.send(codec.encode(packet, false)); packet.eth.src[1] = 123 + counter; tx.send(codec.encode(packet, false)); error('after send') end";
    var value: frame.Frame = .{};
    try value.set(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x12, 0x34 });
    var capture: TestEmission = .{};
    var transport: Transport = .{ .helpers_root = helpers_root };
    defer transport.deinit();
    try transport.init(source, "Test transport");
    const invocation: Invocation = .{ .packet = &value, .direction = .outbound, .send = testPacketSend, .context = @ptrCast(&capture) };
    try std.testing.expectError(error.ScriptFailed, transport.run(&invocation));
    try std.testing.expectError(error.ScriptFailed, transport.run(&invocation));
    try std.testing.expectEqual(@as(usize, 4), capture.count);
    try std.testing.expectEqual(@as(u8, 125), capture.value.bytes[6]);
}

test "IPv4 UDP and TCP fields round-trip through packet tables" {
    const source = "local codec = require('kraken/packet'); function transport(bytes, tx) local packet = codec.decode(bytes); if packet.udp then assert(packet.ip and packet.tcp == nil); packet.ip.src = codec.ipv4('192.0.2.9'); packet.udp.dstport = 5353; packet.udp.payload = string.char(9, 8, 7) else assert(packet.ip and packet.tcp and packet.udp == nil); packet.ip.options = string.char(1, 2, 3, 4); packet.tcp.options = string.char(2, 3, 4, 5) end; tx.send(codec.encode(packet, false)) end";
    var capture: TestEmission = .{};
    var udp: frame.Frame = .{};
    try udp.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 30, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 4, 0xd2, 0, 53, 0, 10, 0, 0, 1, 2 });
    try runTestTransport(source, "", &udp, .outbound, &capture);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[29]);
    try std.testing.expectEqual(@as(u16, 5353), readU16(capture.value.bytes[36..38]));
    try std.testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, capture.value.bytes[42..45]);
    var tcp: frame.Frame = .{};
    try tcp.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x46, 0, 0, 50, 0, 1, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0, 0xaa, 0xbb, 0xcc, 0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, 0x18, 0, 32, 0, 0, 0, 0, 1, 0, 0xfe, 0xfd, 1, 2 });
    try runTestTransport(source, "", &tcp, .outbound, &capture);
    try std.testing.expectEqual(@as(usize, 2), capture.count);
    try std.testing.expectEqual(@as(u16, 64), capture.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, capture.value.bytes[34..38]);
    try std.testing.expectEqualSlices(u8, &.{ 2, 3, 4, 5 }, capture.value.bytes[58..62]);
}

test "IPv4 fragments preserve DF, checksums and reassembled TCP bytes" {
    const hex = "000022334455525400e9748e08004500003c000040004006c564c0a87a01c0a87a054a922e6580c5ae3da70481f18012fe8875860000020405b40402080ade125303000b165a01030307";
    var value: frame.Frame = .{};
    value.len = @intCast((try std.fmt.hexToBytes(value.bytes[0 .. hex.len / 2], hex)).len);
    try value.recalculateChecksums();
    for ([_]usize{ 28, 44, 60 }) |mtu| {
        var offset: usize = 0;
        var index: usize = 1;
        while (offset < 40) : (index += 1) {
            var source_buffer: [1024]u8 = undefined;
            const source = try std.fmt.bufPrint(&source_buffer,
                \\local codec = require('kraken/packet'); function transport(bytes, tx) local packet = codec.decode(bytes);
                \\  assert(not pcall(codec.fragment, packet, 20))
                \\  local parts = codec.fragment(packet, {d})
                \\  assert(packet.ip.flags.df and not packet.ip.flags.mf)
                \\  tx.send(codec.encode(parts[{d}], false))
                \\end
            , .{ mtu, index });
            var capture: TestEmission = .{};
            try runTestTransport(source, "", &value, .outbound, &capture);
            try std.testing.expectEqual(@as(usize, 1), capture.count);
            const length = readU16(capture.value.bytes[16..18]);
            try std.testing.expect(length <= mtu);
            const count = length - 20;
            const more = offset + count < 40;
            try std.testing.expectEqual(@as(u16, @intCast(0x4000 | (if (more) @as(usize, 0x2000) else 0) | offset / 8)), readU16(capture.value.bytes[20..22]));
            try std.testing.expectEqualSlices(u8, value.bytes[0..14], capture.value.bytes[0..14]);
            try std.testing.expectEqualSlices(u8, value.bytes[34 + offset ..][0..count], capture.value.bytes[34..][0..count]);
            var checked = capture.value;
            try checked.recalculateChecksums();
            try std.testing.expectEqualSlices(u8, capture.value.bytes[0..capture.value.len], checked.bytes[0..checked.len]);
            offset += count;
        }
    }
}

test "fragmentation preserves VLANs and copies options when splitting again" {
    var value: frame.Frame = .{};
    try value.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 30, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 4, 0xd2, 0, 53, 0, 10, 0, 0, 1, 2 });
    const source =
        \\local codec = require('kraken/packet'); function transport(bytes, tx) local p = codec.decode(bytes);
        \\  p.eth.type = 0x8100
        \\  p.vlan = {{priority=0, dei=false, id=42, etype=0x0800}}
        \\  p.ip.options = string.char(0x82,4,12,34, 2,4,56,78)
        \\  p.ip.hdr_len, p.ip.len = 28, 58
        \\  p.udp.payload, p.udp.length = string.rep("x",22), 30
        \\  local f = codec.fragment(p,44)
        \\  assert(#f == 2 and f[1].ip.len == 44 and f[2].ip.len == 38)
        \\  assert(f[1].ip.options == p.ip.options)
        \\  assert(f[2].ip.options == p.ip.options:sub(1,4))
        \\  local split = codec.fragment(f[2],32)
        \\  assert(#split == 2 and split[1].ip.frag_offset == 2 and split[2].ip.frag_offset == 3)
        \\  assert(split[1].ip.flags.mf and not split[2].ip.flags.mf)
        \\  tx.send(codec.encode(split[2], false))
        \\  p.ip.options = string.char(0x82,0,0,0,0,0,0,0)
        \\  assert(not pcall(codec.fragment,p,44))
        \\end
    ;
    var capture: TestEmission = .{};
    try runTestTransport(source, "", &value, .outbound, &capture);
    try std.testing.expectEqual(@as(u16, 42), readU16(capture.value.bytes[14..16]));
    try std.testing.expectEqualStrings("xxxxxx", capture.value.bytes[42..capture.value.len]);
}

test "Ethernet VLAN ARP TCP and ICMP fields round-trip through packet tables" {
    const source = "local codec = require('kraken/packet'); function transport(bytes, tx) local packet = codec.decode(bytes); if packet.arp then packet.vlan[1].id = 43; packet.arp.dst.proto_ipv4[4] = 9 elseif packet.tcp then packet.tcp.payload = string.char(9) else packet.icmp.rest_of_header = string.char(0, 1, 0, 3); packet.icmp.data = string.char(9) end; tx.send(codec.encode(packet, false)) end";
    var capture: TestEmission = .{};
    var arp: frame.Frame = .{};
    try arp.set(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x81, 0x00, 0x70, 0x2a, 0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1, 0x02, 0, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2 });
    try runTestTransport(source, "", &arp, .outbound, &capture);
    try std.testing.expectEqual(@as(u16, 43), readU16(capture.value.bytes[14..16]) & 0x0fff);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[45]);
    var tcp: frame.Frame = .{};
    try tcp.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 42, 0, 1, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0, 32, 0, 0, 0, 0, 1, 2 });
    try runTestTransport(source, "", &tcp, .outbound, &capture);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[54]);
    var icmp: frame.Frame = .{};
    try icmp.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 30, 0, 1, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 8, 0, 0, 0, 0, 1, 0, 2, 1, 2 });
    try runTestTransport(source, "", &icmp, .outbound, &capture);
    try std.testing.expectEqual(@as(u8, 3), capture.value.bytes[41]);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[42]);
}

test "addresses have fixed-size mutable value semantics" {
    var value: frame.Frame = .{};
    var capture: TestEmission = .{};
    try runTestTransport("local codec = require('kraken/packet'); function transport() local ip = codec.ipv4('192.0.2.9'); ip[4] = 10; assert(tostring(ip) == '192.0.2.10' and ip == codec.ipv4('192.0.2.10')); local mac = codec.mac('02:11:22:33:44:55'); assert(#mac == 6 and mac == codec.mac('02-11-22-33-44-55')); assert(not pcall(codec.ipv4, '192.0.2.999')); assert(not pcall(function() ip[0] = 1 end)) end", "", &value, .outbound, &capture);
}

test "transport hook instruction budget aborts an infinite loop" {
    var value: frame.Frame = .{};
    try value.set(&[_]u8{1});
    var capture: TestEmission = .{};
    try std.testing.expectError(error.ScriptFailed, runTestTransport("function transport() while true do end end", "", &value, .inbound, &capture));
}

test "raw forwarding, explicit checksums and transmitter lifetime" {
    const source =
        \\local packet = require('kraken/packet')
        \\local previous
        \\function transport(bytes, tx)
        \\  if previous then assert(not pcall(previous.send, bytes)) end
        \\  previous = tx
        \\  assert(tx.direction == 'inbound' and not pcall(tx.send, {}))
        \\  local p = packet.decode(bytes)
        \\  assert(p.send == nil and packet.encode(p, false) == bytes)
        \\  assert(packet.encode(p) ~= bytes and p.ip.checksum == 0)
        \\  local fragments = packet.fragment(p, 28, false)
        \\  assert(#fragments == 2 and fragments[1].send == nil)
        \\  assert(fragments[1].ip.checksum == 0 and fragments[2].ip.checksum == 0)
        \\  assert(packet.encode(fragments[1], false) ~= packet.encode(fragments[1]))
        \\  assert(not pcall(packet.fragment, {data = bytes:sub(1, 18)}, 28, false))
        \\  tx.send(bytes)
        \\end
    ;
    var value: frame.Frame = .{};
    try value.set(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 30, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 4, 0xd2, 0, 53, 0, 10, 0, 0, 1, 2 });
    var capture: TestEmission = .{};
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.init(source, "Test transport");
    const invocation: Invocation = .{ .packet = &value, .direction = .inbound, .send = testPacketSend, .context = &capture };
    try transport.run(&invocation);
    try transport.run(&invocation);
    try std.testing.expectEqual(@as(usize, 2), capture.count);
    try std.testing.expectEqualSlices(u8, value.bytes[0..value.len], capture.value.bytes[0..capture.value.len]);
}

test "transport sleep is interrupted by worker cancellation" {
    const Probe = struct {
        started: std.Io.Event = .unset,
        failed: bool = false,

        fn send(context: *anyopaque, _: frame.Direction, _: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.started.set(std.Io.Threaded.global_single_threaded.io());
            return true;
        }

        fn run(self: *@This(), transport: *Transport) void {
            var value: frame.Frame = .{};
            transport.run(&.{ .packet = &value, .direction = .outbound, .send = send, .context = self }) catch {
                self.failed = true;
            };
        }
    };
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.init("function transport(bytes, tx) kraken.sleep(0); tx.send(bytes); kraken.sleep(10000) end", "Test transport");
    var probe: Probe = .{};
    {
        const thread = try std.Thread.spawn(.{}, Probe.run, .{ &probe, &transport });
        defer thread.join();
        const io = std.Io.Threaded.global_single_threaded.io();
        defer transport.sleep_cancelled.set(io);
        try probe.started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
    }
    try std.testing.expect(probe.failed);
}
