const std = @import("std");
const packet = @import("packet.zig");

const c = @import("c");

pub const transport_heap_size = 256 * 1024;
pub const global_heap_size = 512 * 1024;
pub const max_transport_instructions = 100_000;

/// Lua allocations never leave this fixed backing store. Released regions are
/// reused so per-packet tables do not consume the VM's reservation forever.
pub fn FixedLuaHeap(comptime size: usize) type {
    return struct {
        const allocation_capacity = 4096;
        const Allocation = struct { offset: usize = 0, capacity: usize = 0, active: bool = false };

        bytes: [size]u8 align(16) = [_]u8{0} ** size,
        used: usize = 0,
        exhausted: bool = false,
        allocations: [allocation_capacity]Allocation = [_]Allocation{.{}} ** allocation_capacity,
        allocation_count: usize = 0,

        pub fn reset(self: *@This()) void {
            self.used = 0;
            self.exhausted = false;
            self.allocation_count = 0;
            self.allocations = [_]Allocation{.{}} ** allocation_capacity;
        }

        pub fn reallocate(self: *@This(), old: ?*anyopaque, old_size: usize, new_size: usize) ?*anyopaque {
            if (old) |old_pointer| {
                const base = @intFromPtr(&self.bytes);
                const address = @intFromPtr(old_pointer);
                if (address < base or address >= base + self.bytes.len) return null;
                const offset = address - base;
                for (self.allocations[0..self.allocation_count]) |*allocation| {
                    if (!allocation.active or allocation.offset != offset) continue;
                    if (new_size == 0) {
                        allocation.active = false;
                        return null;
                    }
                    if (new_size <= allocation.capacity) return old_pointer;
                    const replacement = self.reallocate(null, 0, new_size) orelse return null;
                    const source: [*]const u8 = @ptrCast(old_pointer);
                    const destination: [*]u8 = @ptrCast(replacement);
                    @memcpy(destination[0..@min(old_size, new_size)], source[0..@min(old_size, new_size)]);
                    allocation.active = false;
                    return replacement;
                }
                return null;
            }
            if (new_size == 0) return null;
            for (self.allocations[0..self.allocation_count]) |*allocation| {
                if (allocation.active or allocation.capacity < new_size) continue;
                allocation.active = true;
                return @ptrCast(&self.bytes[allocation.offset]);
            }
            const start = std.mem.alignForward(usize, self.used, @alignOf(usize));
            if (start > self.bytes.len or new_size > self.bytes.len - start or self.allocation_count == self.allocations.len) {
                self.exhausted = true;
                return null;
            }
            self.allocations[self.allocation_count] = .{ .offset = start, .capacity = new_size, .active = true };
            self.allocation_count += 1;
            self.used = start + new_size;
            return @ptrCast(&self.bytes[start]);
        }
    };
}

const TransportVm = struct {
    heap: FixedLuaHeap(transport_heap_size) = .{},
    state: ?*c.lua_State = null,
    instruction_count: usize = 0,
    run_depth: usize = 0,

    fn deinit(self: *TransportVm) void {
        if (self.state) |state| c.lua_close(state);
        self.* = .{};
    }

    fn load(self: *TransportVm, source: []const u8, name: [*:0]const u8, helpers_root: []const u8) Error!void {
        const state = c.lua_newstate(allocate, @ptrCast(self)) orelse return error.OutOfMemory;
        self.state = state;
        openLibraries(state);
        prependModulePath(state, helpers_root);
        installHelpers(state);
        if (c.luaL_loadbufferx(state, source.ptr, source.len, name, null) != c.LUA_OK) {
            reportError(state, "Lua compilation error:");
            return error.LoadFailed;
        }
        if (c.lua_pcallk(state, 0, 0, 0, 0, null) != c.LUA_OK) {
            reportError(state, "Lua runtime error:");
            return error.RuntimeFailed;
        }
    }
};

pub const Transport = struct {
    vms: [2]TransportVm = .{ .{}, .{} },
    active: ?u1 = null,

    pub fn deinit(self: *Transport) void {
        for (&self.vms) |*vm| vm.deinit();
        self.active = null;
    }

    /// Loads into the inactive VM and switches only after initialization
    /// succeeds, so a broken replacement cannot destroy the active hook.
    pub fn load(self: *Transport, source: []const u8, name: [*:0]const u8, helpers_root: []const u8) Error!void {
        const candidate: u1 = if (self.active == 0) 1 else 0;
        self.vms[candidate].deinit();
        self.vms[candidate].load(source, name, helpers_root) catch |err| {
            self.vms[candidate].deinit();
            return err;
        };
        const previous = self.active;
        self.active = candidate;
        if (previous) |index| self.vms[index].deinit();
    }

    pub fn loaded(self: *const Transport) bool {
        return self.active != null;
    }

    /// Every call to packet:send() serializes and emits synchronously before
    /// returning control to the next Lua statement.
    pub fn run(self: *Transport, value: *const packet.Packet, direction: packet.Direction, emit_context: ?*anyopaque, emit: Emit) Error!void {
        const vm = if (self.active) |index| &self.vms[index] else return;
        const state = vm.state orelse return;
        _ = c.lua_getglobal(state, "transport");
        if (c.lua_type(state, -1) != c.LUA_TFUNCTION) {
            c.lua_pop(state, 1);
            return;
        }
        const outermost = vm.run_depth == 0;
        if (outermost) vm.instruction_count = 0;
        vm.run_depth += 1;
        defer vm.run_depth -= 1;
        const previous_transport = active_transport;
        var invocation: Invocation = .{
            .source = value,
            .direction = direction,
            .emit_context = emit_context,
            .emit = emit,
        };
        const previous_invocation = active_invocation;
        active_transport = vm;
        active_invocation = &invocation;
        defer {
            active_transport = previous_transport;
            active_invocation = previous_invocation;
        }
        if (outermost) c.lua_sethook(state, budgetHook, c.LUA_MASKCOUNT, 1000);
        defer if (outermost) c.lua_sethook(state, null, 0, 0);
        pushPacketTable(state, value);
        invocation.table_identity = c.lua_topointer(state, -1);
        _ = c.lua_pushstring(state, if (direction == .inbound) "inbound" else "outbound");
        if (c.lua_pcallk(state, 2, 0, 0, 0, null) != c.LUA_OK) {
            reportError(state, "Lua runtime error:");
            return error.RuntimeFailed;
        }
    }
};

pub const Error = error{ OutOfMemory, LoadFailed, RuntimeFailed, InstructionBudgetExceeded };

pub const Emit = *const fn (context: ?*anyopaque, direction: packet.Direction, value: *packet.Packet) bool;

const Invocation = struct {
    source: *const packet.Packet,
    direction: packet.Direction,
    emit_context: ?*anyopaque,
    emit: Emit,
    table_identity: ?*const anyopaque = null,
};

threadlocal var active_transport: ?*TransportVm = null;
threadlocal var active_invocation: ?*Invocation = null;

fn allocate(user_data: ?*anyopaque, old: ?*anyopaque, old_size: usize, new_size: usize) callconv(.c) ?*anyopaque {
    const vm: *TransportVm = @ptrCast(@alignCast(user_data orelse return null));
    return vm.heap.reallocate(old, old_size, new_size);
}

fn budgetHook(state: ?*c.lua_State, _: ?*c.lua_Debug) callconv(.c) void {
    const vm = active_transport orelse return;
    vm.instruction_count += 1000;
    if (vm.instruction_count > max_transport_instructions) _ = c.luaL_error(state, "transport instruction budget exceeded");
}

const PacketTableError = error{ InvalidPacketTable, FrameTooLarge };

fn pushPacketTable(state: ?*c.lua_State, value: *const packet.Packet) void {
    c.lua_createtable(state, 0, 9);
    const table = c.lua_gettop(state);
    c.lua_pushcclosure(state, packetSend, 0);
    c.lua_setfield(state, table, "send");
    if (value.ethernet) |ethernet| {
        c.lua_createtable(state, 0, 3);
        MacAddress.pushField(state, "dst", &ethernet.destination);
        MacAddress.pushField(state, "src", &ethernet.source);
        pushInteger(state, "type", ethernet.ether_type);
        c.lua_setfield(state, table, "eth");
    }
    c.lua_createtable(state, value.vlan_count, 0);
    for (value.vlans[0..value.vlan_count], 1..) |vlan, index| {
        const tci = readU16(value.bytes[vlan.tci_offset .. vlan.tci_offset + 2]);
        c.lua_createtable(state, 0, 5);
        pushInteger(state, "tpid", readU16(value.bytes[vlan.type_offset .. vlan.type_offset + 2]));
        pushInteger(state, "priority", tci >> 13);
        pushBoolean(state, "dei", (tci & 0x1000) != 0);
        pushInteger(state, "id", tci & 0x0fff);
        pushInteger(state, "etype", readU16(value.bytes[vlan.inner_type_offset .. vlan.inner_type_offset + 2]));
        c.lua_rawseti(state, -2, @intCast(index));
    }
    c.lua_setfield(state, table, "vlan");
    if (value.arp) |arp| pushArp(state, table, value, arp);
    if (value.ipv4) |ipv4| pushIpv4(state, table, value, ipv4);
    if (value.transport) |transport| switch (transport) {
        .tcp => |tcp| pushTcp(state, table, value, tcp),
        .udp => |udp| pushUdp(state, table, value, udp),
        .icmp => |icmp| pushIcmp(state, table, value, icmp),
    };
}

fn pushArp(state: ?*c.lua_State, table: c_int, value: *const packet.Packet, arp: packet.Arp) void {
    const offset: usize = arp.offset;
    c.lua_createtable(state, 0, 5);
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "type", readU16(value.bytes[offset .. offset + 2]));
    pushInteger(state, "size", value.bytes[offset + 4]);
    c.lua_setfield(state, -2, "hw");
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "type", readU16(value.bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "size", value.bytes[offset + 5]);
    c.lua_setfield(state, -2, "proto");
    pushInteger(state, "opcode", readU16(value.bytes[offset + 6 .. offset + 8]));
    c.lua_createtable(state, 0, 2);
    MacAddress.pushField(state, "hw_mac", value.bytes[offset + 8 .. offset + 14]);
    Ipv4Address.pushField(state, "proto_ipv4", value.bytes[offset + 14 .. offset + 18]);
    c.lua_setfield(state, -2, "src");
    c.lua_createtable(state, 0, 2);
    MacAddress.pushField(state, "hw_mac", value.bytes[offset + 18 .. offset + 24]);
    Ipv4Address.pushField(state, "proto_ipv4", value.bytes[offset + 24 .. offset + 28]);
    c.lua_setfield(state, -2, "dst");
    c.lua_setfield(state, table, "arp");
}

fn pushIpv4(state: ?*c.lua_State, table: c_int, value: *const packet.Packet, ipv4: packet.Ipv4) void {
    const offset: usize = ipv4.offset;
    const flags_fragment = readU16(value.bytes[offset + 6 .. offset + 8]);
    c.lua_createtable(state, 0, 13);
    pushInteger(state, "version", value.bytes[offset] >> 4);
    pushInteger(state, "hdr_len", ipv4.header_length);
    c.lua_createtable(state, 0, 2);
    pushInteger(state, "dscp", value.bytes[offset + 1] >> 2);
    pushInteger(state, "ecn", value.bytes[offset + 1] & 3);
    c.lua_setfield(state, -2, "dsfield");
    pushInteger(state, "len", readU16(value.bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "id", readU16(value.bytes[offset + 4 .. offset + 6]));
    c.lua_createtable(state, 0, 3);
    pushBoolean(state, "rb", (flags_fragment & 0x8000) != 0);
    pushBoolean(state, "df", (flags_fragment & 0x4000) != 0);
    pushBoolean(state, "mf", (flags_fragment & 0x2000) != 0);
    c.lua_setfield(state, -2, "flags");
    pushInteger(state, "frag_offset", flags_fragment & 0x1fff);
    pushInteger(state, "ttl", value.bytes[offset + 8]);
    pushInteger(state, "proto", value.bytes[offset + 9]);
    pushInteger(state, "checksum", readU16(value.bytes[offset + 10 .. offset + 12]));
    Ipv4Address.pushField(state, "src", &ipv4.source);
    Ipv4Address.pushField(state, "dst", &ipv4.destination);
    pushOptionStrings(state, "options", value.bytes[offset + 20 .. offset + ipv4.header_length]);
    c.lua_setfield(state, table, "ip");
}

fn pushTcp(state: ?*c.lua_State, table: c_int, value: *const packet.Packet, tcp: anytype) void {
    const offset: usize = tcp.offset;
    const flags = value.bytes[offset + 13];
    c.lua_createtable(state, 0, 12);
    pushInteger(state, "srcport", readU16(value.bytes[offset .. offset + 2]));
    pushInteger(state, "dstport", readU16(value.bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "seq", readU32(value.bytes[offset + 4 .. offset + 8]));
    pushInteger(state, "ack", readU32(value.bytes[offset + 8 .. offset + 12]));
    pushInteger(state, "hdr_len", tcp.header_length);
    c.lua_createtable(state, 0, 10);
    pushBoolean(state, "ae", (value.bytes[offset + 12] & 1) != 0);
    pushInteger(state, "res", (value.bytes[offset + 12] >> 1) & 7);
    inline for (.{ .{ "fin", 0x01 }, .{ "syn", 0x02 }, .{ "reset", 0x04 }, .{ "push", 0x08 }, .{ "ack", 0x10 }, .{ "urg", 0x20 }, .{ "ece", 0x40 }, .{ "cwr", 0x80 } }) |field| {
        pushBoolean(state, field[0], (flags & field[1]) != 0);
    }
    c.lua_setfield(state, -2, "flags");
    pushInteger(state, "window_size_value", readU16(value.bytes[offset + 14 .. offset + 16]));
    pushInteger(state, "checksum", readU16(value.bytes[offset + 16 .. offset + 18]));
    pushInteger(state, "urgent_pointer", readU16(value.bytes[offset + 18 .. offset + 20]));
    pushOptionStrings(state, "options", value.bytes[offset + 20 .. offset + tcp.header_length]);
    pushPayload(state, value);
    c.lua_setfield(state, table, "tcp");
}

fn pushUdp(state: ?*c.lua_State, table: c_int, value: *const packet.Packet, udp: anytype) void {
    const offset: usize = udp.offset;
    c.lua_createtable(state, 0, 5);
    pushInteger(state, "srcport", readU16(value.bytes[offset .. offset + 2]));
    pushInteger(state, "dstport", readU16(value.bytes[offset + 2 .. offset + 4]));
    pushInteger(state, "length", readU16(value.bytes[offset + 4 .. offset + 6]));
    pushInteger(state, "checksum", readU16(value.bytes[offset + 6 .. offset + 8]));
    pushPayload(state, value);
    c.lua_setfield(state, table, "udp");
}

fn pushIcmp(state: ?*c.lua_State, table: c_int, value: *const packet.Packet, icmp: anytype) void {
    const offset: usize = icmp.offset;
    c.lua_createtable(state, 0, 5);
    pushInteger(state, "type", value.bytes[offset]);
    pushInteger(state, "code", value.bytes[offset + 1]);
    pushInteger(state, "checksum", readU16(value.bytes[offset + 2 .. offset + 4]));
    pushArray(state, "rest_of_header", value.bytes[offset + 4 .. offset + 8]);
    pushData(state, value);
    c.lua_setfield(state, table, "icmp");
}

fn pushPayload(state: ?*c.lua_State, value: *const packet.Packet) void {
    const payload = value.payloadBounds();
    _ = c.lua_pushlstring(state, value.bytes[payload.offset .. payload.offset + payload.length].ptr, payload.length);
    c.lua_setfield(state, -2, "payload");
}

fn pushData(state: ?*c.lua_State, value: *const packet.Packet) void {
    const payload = value.payloadBounds();
    _ = c.lua_pushlstring(state, value.bytes[payload.offset .. payload.offset + payload.length].ptr, payload.length);
    c.lua_setfield(state, -2, "data");
}

fn packetSend(state: ?*c.lua_State) callconv(.c) c_int {
    const invocation = active_invocation orelse return c.luaL_error(state, "packet is no longer active");
    if (c.lua_type(state, 1) != c.LUA_TTABLE or c.lua_topointer(state, 1) != invocation.table_identity) return c.luaL_error(state, "send must be called on the active packet");
    var output = invocation.source.*;
    applyPacketTable(state, &output) catch return c.luaL_error(state, "packet table contains an invalid or oversized value");
    const option_type = c.lua_type(state, 2);
    if (option_type != c.LUA_TNONE and option_type != c.LUA_TNIL and option_type != c.LUA_TBOOLEAN) return c.luaL_error(state, "send checksum argument must be a boolean");
    const fix_checksums = option_type == c.LUA_TNONE or option_type == c.LUA_TNIL or c.lua_toboolean(state, 2) != 0;
    output.repair(.{ .repair = if (fix_checksums) .automatic else .manual });
    if (!invocation.emit(invocation.emit_context, invocation.direction, &output)) return c.luaL_error(state, "packet transmission failed");
    return 0;
}

fn applyPacketTable(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    try applyEthernet(state, output);
    try applyVlans(state, output);
    try applyArp(state, output);
    try applyTransport(state, output);
    try applyIpv4(state, output);
}

fn applyEthernet(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    if (output.ethernet == null) return;
    const index = try layerTable(state, "eth");
    defer c.lua_pop(state, 1);
    try MacAddress.readField(state, index, "dst", output.bytes[0..6]);
    try MacAddress.readField(state, index, "src", output.bytes[6..12]);
    writeU16(output.bytes[12..14], @intCast(try readIntegerField(state, index, "type", 0xffff)));
}

fn applyVlans(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    _ = c.lua_getfield(state, 1, "vlan");
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
    const list = c.lua_gettop(state);
    for (output.vlans[0..output.vlan_count], 1..) |vlan, lua_index| {
        _ = c.lua_rawgeti(state, list, @intCast(lua_index));
        defer c.lua_pop(state, 1);
        if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
        const item = c.lua_gettop(state);
        writeU16(output.bytes[vlan.type_offset .. vlan.type_offset + 2], @intCast(try readIntegerField(state, item, "tpid", 0xffff)));
        const priority = try readIntegerField(state, item, "priority", 7);
        const dei = try readBooleanField(state, item, "dei");
        const id = try readIntegerField(state, item, "id", 0x0fff);
        writeU16(output.bytes[vlan.tci_offset .. vlan.tci_offset + 2], @intCast((priority << 13) | (@as(u64, @intFromBool(dei)) << 12) | id));
        writeU16(output.bytes[vlan.inner_type_offset .. vlan.inner_type_offset + 2], @intCast(try readIntegerField(state, item, "etype", 0xffff)));
    }
}

fn applyArp(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    const arp = output.arp orelse return;
    const index = try layerTable(state, "arp");
    defer c.lua_pop(state, 1);
    const offset: usize = arp.offset;
    const hw = try childTable(state, index, "hw");
    defer c.lua_pop(state, 1);
    const proto = try childTable(state, index, "proto");
    defer c.lua_pop(state, 1);
    const src = try childTable(state, index, "src");
    defer c.lua_pop(state, 1);
    const dst = try childTable(state, index, "dst");
    defer c.lua_pop(state, 1);
    writeU16(output.bytes[offset .. offset + 2], @intCast(try readIntegerField(state, hw, "type", 0xffff)));
    writeU16(output.bytes[offset + 2 .. offset + 4], @intCast(try readIntegerField(state, proto, "type", 0xffff)));
    output.bytes[offset + 4] = @intCast(try readIntegerField(state, hw, "size", 0xff));
    output.bytes[offset + 5] = @intCast(try readIntegerField(state, proto, "size", 0xff));
    writeU16(output.bytes[offset + 6 .. offset + 8], @intCast(try readIntegerField(state, index, "opcode", 0xffff)));
    try MacAddress.readField(state, src, "hw_mac", output.bytes[offset + 8 .. offset + 14]);
    try Ipv4Address.readField(state, src, "proto_ipv4", output.bytes[offset + 14 .. offset + 18]);
    try MacAddress.readField(state, dst, "hw_mac", output.bytes[offset + 18 .. offset + 24]);
    try Ipv4Address.readField(state, dst, "proto_ipv4", output.bytes[offset + 24 .. offset + 28]);
}

fn applyIpv4(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    const ipv4 = output.ipv4 orelse return;
    const index = try layerTable(state, "ip");
    defer c.lua_pop(state, 1);
    const offset: usize = ipv4.offset;
    const dsfield = try childTable(state, index, "dsfield");
    defer c.lua_pop(state, 1);
    const flags = try childTable(state, index, "flags");
    defer c.lua_pop(state, 1);
    const dscp = try readIntegerField(state, dsfield, "dscp", 63);
    const ecn = try readIntegerField(state, dsfield, "ecn", 3);
    const version = try readIntegerField(state, index, "version", 0x0f);
    const header_length = try readIntegerField(state, index, "hdr_len", 60);
    if (header_length < 20 or header_length & 3 != 0) return error.InvalidPacketTable;
    output.bytes[offset + 1] = @intCast((dscp << 2) | ecn);
    writeU16(output.bytes[offset + 2 .. offset + 4], @intCast(try readIntegerField(state, index, "len", 0xffff)));
    writeU16(output.bytes[offset + 4 .. offset + 6], @intCast(try readIntegerField(state, index, "id", 0xffff)));
    const rb = try readBooleanField(state, flags, "rb");
    const df = try readBooleanField(state, flags, "df");
    const mf = try readBooleanField(state, flags, "mf");
    const frag_offset = try readIntegerField(state, index, "frag_offset", 0x1fff);
    writeU16(output.bytes[offset + 6 .. offset + 8], @intCast((@as(u64, @intFromBool(rb)) << 15) | (@as(u64, @intFromBool(df)) << 14) | (@as(u64, @intFromBool(mf)) << 13) | frag_offset));
    output.bytes[offset + 8] = @intCast(try readIntegerField(state, index, "ttl", 0xff));
    output.bytes[offset + 9] = @intCast(try readIntegerField(state, index, "proto", 0xff));
    writeU16(output.bytes[offset + 10 .. offset + 12], @intCast(try readIntegerField(state, index, "checksum", 0xffff)));
    try Ipv4Address.readField(state, index, "src", output.bytes[offset + 12 .. offset + 16]);
    try Ipv4Address.readField(state, index, "dst", output.bytes[offset + 16 .. offset + 20]);
    const options = try readOptionStrings(state, index, "options");
    if (options.len != header_length - 20) return error.InvalidPacketTable;
    output.replaceRange(offset + 20, ipv4.header_length - 20, options.bytes[0..options.len]) catch return error.FrameTooLarge;
    output.bytes[offset] = @as(u8, @intCast(version << 4 | header_length / 4));
    output.parse();
}

fn applyTransport(state: ?*c.lua_State, output: *packet.Packet) PacketTableError!void {
    const transport = output.transport orelse return;
    switch (transport) {
        .tcp => |tcp| {
            const index = try layerTable(state, "tcp");
            defer c.lua_pop(state, 1);
            const flags_table = try childTable(state, index, "flags");
            defer c.lua_pop(state, 1);
            const offset: usize = tcp.offset;
            writeU16(output.bytes[offset .. offset + 2], @intCast(try readIntegerField(state, index, "srcport", 0xffff)));
            writeU16(output.bytes[offset + 2 .. offset + 4], @intCast(try readIntegerField(state, index, "dstport", 0xffff)));
            writeU32(output.bytes[offset + 4 .. offset + 8], @intCast(try readIntegerField(state, index, "seq", 0xffffffff)));
            writeU32(output.bytes[offset + 8 .. offset + 12], @intCast(try readIntegerField(state, index, "ack", 0xffffffff)));
            const header_length = try readIntegerField(state, index, "hdr_len", 60);
            if (header_length < 20 or header_length & 3 != 0) return error.InvalidPacketTable;
            const ae = try readBooleanField(state, flags_table, "ae");
            const reserved = try readIntegerField(state, flags_table, "res", 7);
            var flags: u8 = 0;
            inline for (.{ .{ "fin", 0x01 }, .{ "syn", 0x02 }, .{ "reset", 0x04 }, .{ "push", 0x08 }, .{ "ack", 0x10 }, .{ "urg", 0x20 }, .{ "ece", 0x40 }, .{ "cwr", 0x80 } }) |field| {
                if (try readBooleanField(state, flags_table, field[0])) flags |= field[1];
            }
            output.bytes[offset + 13] = flags;
            writeU16(output.bytes[offset + 14 .. offset + 16], @intCast(try readIntegerField(state, index, "window_size_value", 0xffff)));
            writeU16(output.bytes[offset + 16 .. offset + 18], @intCast(try readIntegerField(state, index, "checksum", 0xffff)));
            writeU16(output.bytes[offset + 18 .. offset + 20], @intCast(try readIntegerField(state, index, "urgent_pointer", 0xffff)));
            const options = try readOptionStrings(state, index, "options");
            if (options.len != header_length - 20) return error.InvalidPacketTable;
            output.replaceRange(offset + 20, tcp.header_length - 20, options.bytes[0..options.len]) catch return error.FrameTooLarge;
            output.bytes[offset + 12] = @as(u8, @intCast(header_length / 4)) << 4 | @as(u8, @intCast(reserved << 1)) | @as(u8, @intFromBool(ae));
            output.parse();
            try applyPayload(state, index, output);
        },
        .udp => |udp| {
            const index = try layerTable(state, "udp");
            defer c.lua_pop(state, 1);
            const offset: usize = udp.offset;
            writeU16(output.bytes[offset .. offset + 2], @intCast(try readIntegerField(state, index, "srcport", 0xffff)));
            writeU16(output.bytes[offset + 2 .. offset + 4], @intCast(try readIntegerField(state, index, "dstport", 0xffff)));
            writeU16(output.bytes[offset + 4 .. offset + 6], @intCast(try readIntegerField(state, index, "length", 0xffff)));
            writeU16(output.bytes[offset + 6 .. offset + 8], @intCast(try readIntegerField(state, index, "checksum", 0xffff)));
            try applyPayload(state, index, output);
        },
        .icmp => |icmp| {
            const index = try layerTable(state, "icmp");
            defer c.lua_pop(state, 1);
            const offset: usize = icmp.offset;
            output.bytes[offset] = @intCast(try readIntegerField(state, index, "type", 0xff));
            output.bytes[offset + 1] = @intCast(try readIntegerField(state, index, "code", 0xff));
            writeU16(output.bytes[offset + 2 .. offset + 4], @intCast(try readIntegerField(state, index, "checksum", 0xffff)));
            try readArrayField(state, index, "rest_of_header", output.bytes[offset + 4 .. offset + 8]);
            try applyData(state, index, output);
        },
    }
}

fn applyPayload(state: ?*c.lua_State, layer: c_int, output: *packet.Packet) PacketTableError!void {
    _ = c.lua_getfield(state, layer, "payload");
    defer c.lua_pop(state, 1);
    var length: usize = 0;
    const raw = c.lua_tolstring(state, -1, &length) orelse return error.InvalidPacketTable;
    output.replacePayload(raw[0..length]) catch return error.FrameTooLarge;
}

fn applyData(state: ?*c.lua_State, layer: c_int, output: *packet.Packet) PacketTableError!void {
    _ = c.lua_getfield(state, layer, "data");
    defer c.lua_pop(state, 1);
    var length: usize = 0;
    const raw = c.lua_tolstring(state, -1, &length) orelse return error.InvalidPacketTable;
    output.replacePayload(raw[0..length]) catch return error.FrameTooLarge;
}

fn layerTable(state: ?*c.lua_State, name: [*:0]const u8) PacketTableError!c_int {
    _ = c.lua_getfield(state, 1, name);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
    return c.lua_gettop(state);
}

fn childTable(state: ?*c.lua_State, parent: c_int, name: [*:0]const u8) PacketTableError!c_int {
    _ = c.lua_getfield(state, parent, name);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
    return c.lua_gettop(state);
}

fn readIntegerField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, maximum: u64) PacketTableError!u64 {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    var is_number: c_int = 0;
    const value = c.lua_tointegerx(state, -1, &is_number);
    if (is_number == 0 or value < 0 or @as(u64, @intCast(value)) > maximum) return error.InvalidPacketTable;
    return @intCast(value);
}

fn readBooleanField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) PacketTableError!bool {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TBOOLEAN) return error.InvalidPacketTable;
    return c.lua_toboolean(state, -1) != 0;
}

fn readArrayField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, destination: []u8) PacketTableError!void {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TTABLE or c.lua_rawlen(state, -1) != destination.len) return error.InvalidPacketTable;
    const array = c.lua_gettop(state);
    for (destination, 1..) |*byte, index| {
        _ = c.lua_rawgeti(state, array, @intCast(index));
        defer c.lua_pop(state, 1);
        var is_number: c_int = 0;
        const value = c.lua_tointegerx(state, -1, &is_number);
        if (is_number == 0 or value < 0 or value > 255) return error.InvalidPacketTable;
        byte.* = @intCast(value);
    }
}

const HeaderBytes = struct { bytes: [40]u8 = [_]u8{0} ** 40, len: usize = 0 };

fn readOptionStrings(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) PacketTableError!HeaderBytes {
    _ = c.lua_getfield(state, table, name);
    defer c.lua_pop(state, 1);
    if (c.lua_type(state, -1) != c.LUA_TTABLE) return error.InvalidPacketTable;
    const options = c.lua_gettop(state);
    var result: HeaderBytes = .{};
    const count = c.lua_rawlen(state, options);
    for (1..count + 1) |index| {
        _ = c.lua_rawgeti(state, options, @intCast(index));
        defer c.lua_pop(state, 1);
        if (c.lua_type(state, -1) != c.LUA_TSTRING) return error.InvalidPacketTable;
        var length: usize = 0;
        const raw = c.lua_tolstring(state, -1, &length) orelse return error.InvalidPacketTable;
        if (length == 0 or length > result.bytes.len - result.len) return error.InvalidPacketTable;
        @memcpy(result.bytes[result.len .. result.len + length], raw[0..length]);
        result.len += length;
    }
    return result;
}

fn pushInteger(state: ?*c.lua_State, name: [*:0]const u8, value: anytype) void {
    c.lua_pushinteger(state, @intCast(value));
    c.lua_setfield(state, -2, name);
}

fn pushBoolean(state: ?*c.lua_State, name: [*:0]const u8, value: bool) void {
    c.lua_pushboolean(state, @intFromBool(value));
    c.lua_setfield(state, -2, name);
}

fn pushArray(state: ?*c.lua_State, name: [*:0]const u8, value: []const u8) void {
    c.lua_createtable(state, @intCast(value.len), 0);
    for (value, 1..) |byte, index| {
        c.lua_pushinteger(state, byte);
        c.lua_rawseti(state, -2, @intCast(index));
    }
    c.lua_setfield(state, -2, name);
}

fn pushOptionStrings(state: ?*c.lua_State, name: [*:0]const u8, bytes: []const u8) void {
    c.lua_createtable(state, 0, 0);
    var offset: usize = 0;
    var index: usize = 1;
    while (offset < bytes.len) : (index += 1) {
        const kind = bytes[offset];
        const remaining = bytes.len - offset;
        const length: usize = if (kind == 0 or kind == 1)
            1
        else if (remaining >= 2 and bytes[offset + 1] >= 2 and bytes[offset + 1] <= remaining)
            bytes[offset + 1]
        else
            remaining;
        _ = c.lua_pushlstring(state, bytes[offset .. offset + length].ptr, length);
        c.lua_rawseti(state, -2, @intCast(index));
        offset += length;
    }
    c.lua_setfield(state, -2, name);
}

fn readU16(value: []const u8) u16 {
    return std.mem.readInt(u16, value[0..2], .big);
}

fn readU32(value: []const u8) u32 {
    return std.mem.readInt(u32, value[0..4], .big);
}

fn writeU16(value: []u8, integer: u16) void {
    std.mem.writeInt(u16, value[0..2], integer, .big);
}

fn writeU32(value: []u8, integer: u32) void {
    std.mem.writeInt(u32, value[0..4], integer, .big);
}

fn installHelpers(state: ?*c.lua_State) void {
    Ipv4Address.register(state);
    MacAddress.register(state);
    c.lua_createtable(state, 0, 2);
    c.lua_pushcclosure(state, Ipv4Address.construct, 0);
    c.lua_setfield(state, -2, "ipv4");
    c.lua_pushcclosure(state, MacAddress.construct, 0);
    c.lua_setfield(state, -2, "mac");
    c.lua_setglobal(state, "kraken");
}

const AddressKind = enum { ipv4, mac };

fn FixedAddress(comptime length: usize, comptime metatable_name: [:0]const u8, comptime kind: AddressKind) type {
    return struct {
        const Self = @This();
        const address_name = if (kind == .ipv4) "IPv4 address" else "MAC address";

        bytes: [length]u8,

        fn register(state: ?*c.lua_State) void {
            _ = c.luaL_newmetatable(state, metatable_name);
            c.lua_pushcclosure(state, index, 0);
            c.lua_setfield(state, -2, "__index");
            c.lua_pushcclosure(state, newIndex, 0);
            c.lua_setfield(state, -2, "__newindex");
            c.lua_pushcclosure(state, len, 0);
            c.lua_setfield(state, -2, "__len");
            c.lua_pushcclosure(state, equal, 0);
            c.lua_setfield(state, -2, "__eq");
            c.lua_pushcclosure(state, toString, 0);
            c.lua_setfield(state, -2, "__tostring");
            _ = c.lua_pushstring(state, metatable_name);
            c.lua_setfield(state, -2, "__metatable");
            c.lua_pop(state, 1);
        }

        fn push(state: ?*c.lua_State, value: []const u8) void {
            std.debug.assert(value.len == length);
            const raw = c.lua_newuserdatauv(state, @sizeOf(Self), 0) orelse unreachable;
            const address: *Self = @ptrCast(@alignCast(raw));
            @memcpy(&address.bytes, value);
            _ = c.lua_getfield(state, c.LUA_REGISTRYINDEX, metatable_name);
            _ = c.lua_setmetatable(state, -2);
        }

        fn pushField(state: ?*c.lua_State, name: [*:0]const u8, value: []const u8) void {
            push(state, value);
            c.lua_setfield(state, -2, name);
        }

        fn read(state: ?*c.lua_State, index_value: c_int) ?*Self {
            const raw = c.luaL_testudata(state, index_value, metatable_name) orelse return null;
            return @ptrCast(@alignCast(raw));
        }

        fn readField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8, destination: []u8) PacketTableError!void {
            _ = c.lua_getfield(state, table, name);
            defer c.lua_pop(state, 1);
            const address = read(state, -1) orelse return error.InvalidPacketTable;
            std.debug.assert(destination.len == length);
            @memcpy(destination, &address.bytes);
        }

        fn construct(state: ?*c.lua_State) callconv(.c) c_int {
            if (c.lua_type(state, 1) != c.LUA_TSTRING) return c.luaL_error(state, address_name ++ " must be a string");
            var text_length: usize = 0;
            const raw = c.lua_tolstring(state, 1, &text_length) orelse return c.luaL_error(state, address_name ++ " must be a string");
            const parsed = parse(raw[0..text_length]) orelse return c.luaL_error(state, "invalid " ++ address_name);
            push(state, &parsed);
            return 1;
        }

        fn index(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            const array_index = checkedIndex(state, 2) orelse return c.luaL_error(state, address_name ++ " index must be between 1 and " ++ std.fmt.comptimePrint("{d}", .{length}));
            c.lua_pushinteger(state, address.bytes[array_index]);
            return 1;
        }

        fn newIndex(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            const array_index = checkedIndex(state, 2) orelse return c.luaL_error(state, address_name ++ " index must be between 1 and " ++ std.fmt.comptimePrint("{d}", .{length}));
            if (c.lua_isinteger(state, 3) == 0) return c.luaL_error(state, "address byte must be an integer");
            var is_number: c_int = 0;
            const value = c.lua_tointegerx(state, 3, &is_number);
            if (is_number == 0 or value < 0 or value > 255) return c.luaL_error(state, "address byte must be between 0 and 255");
            address.bytes[array_index] = @intCast(value);
            return 0;
        }

        fn len(state: ?*c.lua_State) callconv(.c) c_int {
            _ = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            c.lua_pushinteger(state, length);
            return 1;
        }

        fn equal(state: ?*c.lua_State) callconv(.c) c_int {
            const left = read(state, 1);
            const right = read(state, 2);
            c.lua_pushboolean(state, @intFromBool(left != null and right != null and std.mem.eql(u8, &left.?.bytes, &right.?.bytes)));
            return 1;
        }

        fn toString(state: ?*c.lua_State) callconv(.c) c_int {
            const address = read(state, 1) orelse return c.luaL_error(state, "invalid " ++ address_name);
            var buffer: [17]u8 = undefined;
            const text = switch (kind) {
                .ipv4 => std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3] }),
                .mac => std.fmt.bufPrint(&buffer, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3], address.bytes[4], address.bytes[5] }),
            } catch return c.luaL_error(state, "invalid " ++ address_name);
            _ = c.lua_pushlstring(state, text.ptr, text.len);
            return 1;
        }

        fn checkedIndex(state: ?*c.lua_State, stack_index: c_int) ?usize {
            if (c.lua_isinteger(state, stack_index) == 0) return null;
            var is_number: c_int = 0;
            const value = c.lua_tointegerx(state, stack_index, &is_number);
            if (is_number == 0 or value < 1 or value > length) return null;
            return @intCast(value - 1);
        }

        fn parse(text: []const u8) ?[length]u8 {
            var address: [length]u8 = undefined;
            const separator: u8 = if (kind == .ipv4) '.' else if (std.mem.indexOfScalar(u8, text, ':') != null) ':' else '-';
            var parts = std.mem.splitScalar(u8, text, separator);
            for (&address) |*octet| {
                const part = parts.next() orelse return null;
                if (kind == .mac and part.len != 2) return null;
                octet.* = std.fmt.parseInt(u8, part, if (kind == .ipv4) 10 else 16) catch return null;
            }
            if (parts.next() != null) return null;
            return address;
        }
    };
}

const Ipv4Address = FixedAddress(4, "kraken.ipv4.address", .ipv4);
const MacAddress = FixedAddress(6, "kraken.mac.address", .mac);

fn luaIndex(state: ?*c.lua_State, index: c_int) ?usize {
    var is_number: c_int = 0;
    const value = c.lua_tointegerx(state, index, &is_number);
    if (is_number == 0 or value < 0) return null;
    return @intCast(value);
}

pub fn openLibraries(state: ?*c.lua_State) void {
    c.luaL_openlibs(state);
}

pub fn reportError(state: ?*c.lua_State, context: [*:0]const u8) void {
    c.kraken_log(context);
    const message = c.lua_tolstring(state, -1, null) orelse {
        c.kraken_log("Lua returned a non-string error value.");
        c.lua_pop(state, 1);
        return;
    };
    c.kraken_log(message);
    c.lua_pop(state, 1);
}

/// Adds Kraken's helpers directory ahead of Lua's standard module locations.
pub fn prependModulePath(state: ?*c.lua_State, helpers_root: []const u8) void {
    if (helpers_root.len == 0) return;
    _ = c.lua_getglobal(state, "package");
    const package_index = c.lua_gettop(state);
    _ = c.lua_pushlstring(state, helpers_root.ptr, helpers_root.len);
    const separator = [_]u8{std.fs.path.sep};
    _ = c.lua_pushlstring(state, &separator, separator.len);
    _ = c.lua_pushstring(state, "?.lua;");
    _ = c.lua_pushlstring(state, helpers_root.ptr, helpers_root.len);
    _ = c.lua_pushlstring(state, &separator, separator.len);
    _ = c.lua_pushstring(state, "?/init.lua;");
    _ = c.lua_getfield(state, package_index, "path");
    c.lua_concat(state, 7);
    c.lua_setfield(state, package_index, "path");
    c.lua_pop(state, 1);
}

test "fixed Lua heap is bounded" {
    var heap: FixedLuaHeap(16) = .{};
    const first = heap.reallocate(null, 0, 8);
    try std.testing.expect(first != null);
    try std.testing.expect(heap.reallocate(null, 0, 32) == null);
    try std.testing.expect(heap.exhausted);
    _ = heap.reallocate(first, 8, 0);
    try std.testing.expect(heap.reallocate(null, 0, 8) != null);
}

test "Lua runtime exposes the complete standard environment" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "local loaded_math = require('math'); assert(loaded_math == math); assert(io and os and package and debug)",
        "standard-environment-test",
        "",
    );
}

test "transport scripts require modules from the helpers root" {
    const allocator = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = "network.lua", .data = "return { answer = 42 }" });
    const helpers_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{temp_dir.sub_path});
    defer allocator.free(helpers_root);

    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("local network = require('network'); assert(network.answer == 42)", "helpers-test", helpers_root);
}

const TestEmission = struct {
    count: usize = 0,
    value: packet.Packet = .{},
};

fn captureTestEmission(context: ?*anyopaque, _: packet.Direction, value: *packet.Packet) bool {
    const capture: *TestEmission = @ptrCast(@alignCast(context orelse return false));
    capture.count += 1;
    capture.value = value.*;
    return true;
}

test "transport hook synchronously emits every requested snapshot" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet, direction) assert(direction == 'outbound'); packet.eth.src[1] = 123; packet:send(false); packet.eth.src[1] = 124; packet:send(false) end", "test", "");
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x12, 0x34 });
    var capture: TestEmission = .{};
    try transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 2), capture.count);
    try std.testing.expectEqual(@as(u8, 124), capture.value.bytes[6]);
}

test "a later script error does not roll back a completed send" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet) packet:send(false); error('after send') end", "test", "");
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x12, 0x34 });
    var capture: TestEmission = .{};
    try std.testing.expectError(error.RuntimeFailed, transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission));
    try std.testing.expectEqual(@as(usize, 1), capture.count);
}

test "a broken replacement leaves the active transport hook intact" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet) packet.eth.src[1] = 77; packet:send(false) end", "working", "");
    try std.testing.expectError(error.LoadFailed, transport.load("function transport(", "broken", ""));

    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x12, 0x34 });
    var capture: TestEmission = .{};
    try transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u8, 77), capture.value.bytes[6]);
}

test "parsed IPv4 and UDP tables serialize edited headers and payload" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "function transport(packet) assert(packet.ipv4 == nil and packet.ip and packet.udp and packet.tcp == nil and packet.payload == nil); assert(packet.ip.version == 4 and packet.ip.hdr_len == 20 and #packet.ip.options == 0 and packet.ip.dsfield.dscp == 0 and packet.ip.dsfield.ecn == 0 and packet.ip.len == 30 and packet.ip.id == 1 and not packet.ip.flags.rb and not packet.ip.flags.df and not packet.ip.flags.mf and packet.ip.frag_offset == 0 and packet.ip.proto == 17); packet.ip.src = kraken.ipv4('192.0.2.9'); packet.udp.dstport = 5353; packet.udp.payload = string.char(9, 8, 7); packet:send() end",
        "test",
        "",
    );
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{
        0,    1, 2,   3,  4, 5, 6, 7,    8,  9,  10, 11, 0x08, 0x00,
        0x45, 0, 0,   30, 0, 1, 0, 0,    64, 17, 0,  0,  192,  0,
        2,    1, 192, 0,  2, 2, 4, 0xd2, 0,  53, 0,  10, 0,    0,
        1,    2,
    });
    var capture: TestEmission = .{};
    try transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[29]);
    try std.testing.expectEqual(@as(u16, 5353), readU16(capture.value.bytes[36..38]));
    try std.testing.expectEqualSlices(u8, &.{ 9, 8, 7 }, capture.value.bytes[42..45]);
    try std.testing.expectEqual(@as(u16, 31), readU16(capture.value.bytes[16..18]));
    try std.testing.expectEqual(@as(u16, 11), readU16(capture.value.bytes[38..40]));
    try std.testing.expect(readU16(capture.value.bytes[24..26]) != 0);
    try std.testing.expect(readU16(capture.value.bytes[40..42]) != 0);
}

test "IPv4 and TCP options are arrays of opaque binary strings" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "function transport(packet) assert(packet.ip.hdr_len == 24 and #packet.ip.options == 2 and packet.ip.options[1] == string.char(0) and packet.ip.options[2] == string.char(0xaa, 0xbb, 0xcc)); assert(packet.tcp.hdr_len == 24 and #packet.tcp.options == 3 and packet.tcp.options[1] == string.char(1) and packet.tcp.options[2] == string.char(0) and packet.tcp.options[3] == string.char(0xfe, 0xfd)); packet.ip.options = { string.char(1), string.char(1), string.char(0, 0, 0, 0xaa, 0xbb, 0xcc) }; packet.ip.hdr_len = 28; packet.tcp.options = { string.char(1), string.char(1), string.char(0, 0, 0, 0xfe, 0xfd, 0xfc) }; packet.tcp.hdr_len = 28; packet:send() end",
        "test",
        "",
    );
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{
        0,    1, 2,   3,  4,    5,    6, 7,    8,    9,    10, 11, 0x08, 0x00,
        0x46, 0, 0,   50, 0,    1,    0, 0,    64,   6,    0,  0,  192,  0,
        2,    1, 192, 0,  2,    2,    0, 0xaa, 0xbb, 0xcc, 0,  80, 0,    81,
        0,    0, 0,   1,  0,    0,    0, 0,    0x60, 0x18, 0,  32, 0,    0,
        0,    0, 1,   0,  0xfe, 0xfd, 1, 2,
    });
    var capture: TestEmission = .{};
    try transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u16, 72), capture.value.len);
    try std.testing.expectEqual(@as(u16, 58), readU16(capture.value.bytes[16..18]));
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 0, 0, 0, 0xaa, 0xbb, 0xcc }, capture.value.bytes[34..42]);
    try std.testing.expectEqual(@as(u8, 0x70), capture.value.bytes[54] & 0xf0);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 0, 0, 0, 0xfe, 0xfd, 0xfc }, capture.value.bytes[62..70]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, capture.value.bytes[70..72]);
}

test "Ethernet VLAN and ARP tables use Wireshark field groupings" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "function transport(packet) assert(packet.ethernet == nil and packet.vlans == nil); assert(packet.eth.type == 0x8100); assert(#packet.vlan == 1 and packet.vlan[1].priority == 3 and packet.vlan[1].dei and packet.vlan[1].id == 42 and packet.vlan[1].etype == 0x0806); assert(packet.arp.hw.type == 1 and packet.arp.hw.size == 6); assert(packet.arp.proto.type == 0x0800 and packet.arp.proto.size == 4 and packet.arp.opcode == 1); packet.vlan[1].id = 43; packet.arp.dst.proto_ipv4[4] = 9; packet:send(false) end",
        "test",
        "",
    );
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x81, 0x00,
        0x70, 0x2a, 0x08, 0x06, 0,    1,    0x08, 0, 6, 4, 0, 1, 0x02, 0,
        0,    0,    0,    1,    192,  0,    2,    1, 0, 0, 0, 0, 0,    0,
        192,  0,    2,    2,
    });
    var capture: TestEmission = .{};
    try transport.run(&value, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u16, 43), readU16(capture.value.bytes[14..16]) & 0x0fff);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[45]);
}

test "TCP payload and ICMP data use Wireshark field names" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "function transport(packet) assert(packet.payload == nil and packet.icmpv4 == nil); if packet.tcp then assert(packet.tcp.srcport == 80 and packet.tcp.dstport == 81 and packet.tcp.seq == 1 and packet.tcp.ack == 0 and packet.tcp.hdr_len == 20 and #packet.tcp.options == 0 and packet.tcp.flags.res == 0 and packet.tcp.flags.ack and packet.tcp.flags.push and not packet.tcp.flags.reset and packet.tcp.window_size_value == 32); packet.tcp.payload = string.char(9) else assert(packet.icmp and packet.icmp.type == 8 and packet.icmp.code == 0 and #packet.icmp.rest_of_header == 4 and packet.icmp.rest_of_header[2] == 1 and packet.icmp.rest_of_header[4] == 2); packet.icmp.rest_of_header[4] = 3; packet.icmp.data = string.char(9) end; packet:send(false) end",
        "test",
        "",
    );
    var capture: TestEmission = .{};

    var tcp: packet.Packet = .{};
    try tcp.setBytes(&[_]u8{
        0,    1, 2,   3,  4,    5,    6, 7,  8,  9,  10, 11, 0x08, 0x00,
        0x45, 0, 0,   42, 0,    1,    0, 0,  64, 6,  0,  0,  192,  0,
        2,    1, 192, 0,  2,    2,    0, 80, 0,  81, 0,  0,  0,    1,
        0,    0, 0,   0,  0x50, 0x18, 0, 32, 0,  0,  0,  0,  1,    2,
    });
    try transport.run(&tcp, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u16, 55), capture.value.len);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[54]);

    var icmp: packet.Packet = .{};
    try icmp.setBytes(&[_]u8{
        0,    1, 2,   3,  4, 5, 6, 7, 8,  9, 10, 11, 0x08, 0x00,
        0x45, 0, 0,   30, 0, 1, 0, 0, 64, 1, 0,  0,  192,  0,
        2,    1, 192, 0,  2, 2, 8, 0, 0,  0, 0,  1,  0,    2,
        1,    2,
    });
    try transport.run(&icmp, .outbound, @ptrCast(&capture), captureTestEmission);
    try std.testing.expectEqual(@as(usize, 2), capture.count);
    try std.testing.expectEqual(@as(u16, 43), capture.value.len);
    try std.testing.expectEqual(@as(u8, 3), capture.value.bytes[41]);
    try std.testing.expectEqual(@as(u8, 9), capture.value.bytes[42]);
}

test "addresses have fixed-size mutable value semantics" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load(
        "local ip = kraken.ipv4('192.0.2.9'); assert(tostring(ip) == '192.0.2.9' and #ip == 4 and ip[4] == 9); ip[4] = 10; assert(tostring(ip) == '192.0.2.10' and ip == kraken.ipv4('192.0.2.10')); local mac = kraken.mac('02:11:22:33:44:55'); assert(tostring(mac) == '02:11:22:33:44:55' and #mac == 6 and mac == kraken.mac('02-11-22-33-44-55')); assert(not pcall(kraken.ipv4, '192.0.2.999')); assert(not pcall(function() ip[0] = 1 end)); assert(not pcall(function() ip[1] = 256 end))",
        "test",
        "",
    );
}

test "transport hook instruction budget aborts an infinite loop" {
    var transport: Transport = .{};
    defer transport.deinit();
    try transport.load("function transport(packet) while true do end end", "test", "");
    var value: packet.Packet = .{};
    try value.setBytes(&[_]u8{1});
    var capture: TestEmission = .{};
    try std.testing.expectError(error.RuntimeFailed, transport.run(&value, .inbound, @ptrCast(&capture), captureTestEmission));
}
