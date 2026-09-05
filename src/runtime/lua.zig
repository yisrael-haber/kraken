const std = @import("std");
const frame = @import("frame.zig");
const log = @import("../log.zig");
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
    send: c.lua_CFunction,
    context: *anyopaque,
};

pub const Transport = struct {
    state: ?*c.lua_State = null,
    helpers_root: []const u8 = "",
    logger: ?*log.Logger = null,
    instructions: usize = 0,

    pub fn init(self: *Transport, source: []const u8) Error!void {
        self.deinit();
        const state = c.lua_newstate(allocateTransport, @ptrCast(self)) orelse return error.OutOfMemory;
        errdefer c.lua_close(state);
        c.luaL_openlibs(state);
        installPrint(state, self.logger);
        appendModulePath(state, self.helpers_root);
        frame.installLuaTypes(state);
        c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
        if (c.luaL_loadbufferx(state, source.ptr, source.len, "transport", null) != c.LUA_OK or c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
            reportError(self.logger, state, "Lua transport failed:");
            return error.ScriptFailed;
        }
        _ = c.lua_getglobal(state, "transport");
        if (c.lua_type(state, -1) != c.LUA_TFUNCTION) {
            c.lua_pop(state, 1);
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
        _ = c.lua_getglobal(state, "transport");
        if (c.lua_type(state, -1) != c.LUA_TFUNCTION) {
            c.lua_pop(state, 1);
            return error.ScriptFailed;
        }
        invocation.packet.pushLua(state, invocation.send, @ptrCast(@constCast(invocation)));
        _ = c.lua_pushstring(state, if (invocation.direction == .inbound) "inbound" else "outbound");
        if (c.lua_pcallk(state, 2, 0, 0, 0, null) != c.LUA_OK) {
            reportError(self.logger, state, "Lua transport failed:");
            return error.ScriptFailed;
        }
    }
};

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

pub fn reportError(logger: ?*log.Logger, state: ?*c.lua_State, context: []const u8) void {
    const target = logger orelse {
        c.lua_pop(state, 1);
        return;
    };
    target.err(.lua, context);
    if (c.lua_tolstring(state, -1, null)) |message| {
        target.err(.lua, std.mem.span(message));
    } else {
        target.err(.lua, "Lua returned a non-string error value.");
    }
    c.lua_pop(state, 1);
}

pub fn installPrint(state: ?*c.lua_State, logger: ?*log.Logger) void {
    c.lua_pushlightuserdata(state, if (logger) |value| @ptrCast(value) else null);
    c.lua_pushcclosure(state, luaPrint, 1);
    c.lua_setglobal(state, "print");
}

fn luaPrint(state: ?*c.lua_State) callconv(.c) c_int {
    const raw_logger = c.lua_touserdata(state, c.lua_upvalueindex(1)) orelse return 0;
    const logger: *log.Logger = @ptrCast(@alignCast(raw_logger));
    var buffer: [print_capacity]u8 = undefined;
    var length: usize = 0;
    var truncated = false;
    const count = c.lua_gettop(state);
    var index: c_int = 1;
    while (index <= count) : (index += 1) {
        var value_len: usize = 0;
        const value = c.luaL_tolstring(state, index, &value_len) orelse continue;
        defer c.lua_pop(state, 1);
        if (index > 1) appendPrintBytes(&buffer, &length, &truncated, "\t");
        appendPrintBytes(&buffer, &length, &truncated, value[0..value_len]);
    }
    if (truncated) appendPrintBytes(&buffer, &length, &truncated, " [truncated]");
    logger.info(.lua, buffer[0..length]);
    return 0;
}

fn appendPrintBytes(buffer: []u8, length: *usize, truncated: *bool, value: []const u8) void {
    if (truncated.* or length.* == buffer.len) {
        truncated.* = true;
        return;
    }
    const count = @min(value.len, buffer.len - length.*);
    @memcpy(buffer[length.* .. length.* + count], value[0..count]);
    length.* += count;
    if (count < value.len) truncated.* = true;
}

pub fn appendModulePath(state: ?*c.lua_State, helpers_root: []const u8) void {
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

fn testPacketSend(state: ?*c.lua_State) callconv(.c) c_int {
    const raw = c.lua_touserdata(state, c.lua_upvalueindex(1)) orelse return c.luaL_error(state, "test invocation unavailable");
    const invocation: *const Invocation = @ptrCast(@alignCast(raw));
    const capture: *TestEmission = @ptrCast(@alignCast(invocation.context));
    capture.value = frame.Frame.fromLua(state) catch return c.luaL_error(state, "packet table contains an invalid or oversized value");
    capture.count += 1;
    return 0;
}

fn runTestTransport(source: []const u8, helpers_root: []const u8, value: *const frame.Frame, direction: frame.Direction, capture: *TestEmission) Error!void {
    var transport: Transport = .{ .helpers_root = helpers_root };
    defer transport.deinit();
    try transport.init(source);
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
    const source = "counter = counter or 0; function transport(packet, direction) counter = counter + 1; assert(require('network').answer == 42 and counter <= 2 and direction == 'outbound'); packet.eth.src[1] = 123; packet:send(); packet.eth.src[1] = 123 + counter; packet:send(); error('after send') end";
    var value: frame.Frame = .{};
    try value.set(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x12, 0x34 });
    var capture: TestEmission = .{};
    var transport: Transport = .{ .helpers_root = helpers_root };
    defer transport.deinit();
    try transport.init(source);
    const invocation: Invocation = .{ .packet = &value, .direction = .outbound, .send = testPacketSend, .context = @ptrCast(&capture) };
    try std.testing.expectError(error.ScriptFailed, transport.run(&invocation));
    try std.testing.expectError(error.ScriptFailed, transport.run(&invocation));
    try std.testing.expectEqual(@as(usize, 4), capture.count);
    try std.testing.expectEqual(@as(u8, 125), capture.value.bytes[6]);
}

test "IPv4 UDP and TCP fields round-trip through packet tables" {
    const source = "function transport(packet) if packet.udp then assert(packet.ip and packet.tcp == nil); packet.ip.src = kraken.ipv4('192.0.2.9'); packet.udp.dstport = 5353; packet.udp.payload = string.char(9, 8, 7) else assert(packet.ip and packet.tcp and packet.udp == nil); packet.ip.options = string.char(1, 2, 3, 4); packet.tcp.options = string.char(2, 3, 4, 5) end; packet:send() end";
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

test "Ethernet VLAN ARP TCP and ICMP fields round-trip through packet tables" {
    const source = "function transport(packet) if packet.arp then packet.vlan[1].id = 43; packet.arp.dst.proto_ipv4[4] = 9 elseif packet.tcp then packet.tcp.payload = string.char(9) else packet.icmp.rest_of_header = string.char(0, 1, 0, 3); packet.icmp.data = string.char(9) end; packet:send() end";
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
    try runTestTransport("function transport() local ip = kraken.ipv4('192.0.2.9'); ip[4] = 10; assert(tostring(ip) == '192.0.2.10' and ip == kraken.ipv4('192.0.2.10')); local mac = kraken.mac('02:11:22:33:44:55'); assert(#mac == 6 and mac == kraken.mac('02-11-22-33-44-55')); assert(not pcall(kraken.ipv4, '192.0.2.999')); assert(not pcall(function() ip[0] = 1 end)) end", "", &value, .outbound, &capture);
}

test "transport hook instruction budget aborts an infinite loop" {
    var value: frame.Frame = .{};
    try value.set(&[_]u8{1});
    var capture: TestEmission = .{};
    try std.testing.expectError(error.ScriptFailed, runTestTransport("function transport() while true do end end", "", &value, .inbound, &capture));
}
