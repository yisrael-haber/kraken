const std = @import("std");
const command = @import("../command.zig");
const limits = @import("../limits.zig");
const lua = @import("lua.zig");
const c = @import("c");

const metatable = "kraken.socket";

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    _ = c.luaL_newmetatable(state, metatable);
    c.lua_createtable(state, 0, 5);
    inline for (.{ .{ "send", send }, .{ "receive", receive }, .{ "close", close }, .{ "listen", listen }, .{ "accept", accept } }) |entry| {
        lua.setFunction(state, -2, entry[0], entry[1]);
    }
    c.lua_setfield(state, -2, "__index");
    lua.setFunction(state, -2, "__gc", close);
    _ = c.lua_pushstring(state, metatable);
    c.lua_setfield(state, -2, "__metatable");
    c.lua_pop(state, 1);
    c.lua_createtable(state, 0, 3);
    inline for (comptime std.meta.tags(@FieldType(command.Socket, "kind"))) |kind| {
        c.lua_createtable(state, 0, 2);
        inline for (.{ command.SocketAction.connect, command.SocketAction.bind }) |action| {
            if (comptime kind == .raw and action == .connect) continue;
            c.lua_pushinteger(state, @intFromEnum(kind));
            c.lua_pushinteger(state, @intFromEnum(action));
            c.lua_pushcclosure(state, open, 2);
            c.lua_setfield(state, -2, if (kind == .raw) "open" else @tagName(action));
        }
        c.lua_setfield(state, -2, @tagName(kind));
    }
    return 1;
}

fn open(state: ?*c.lua_State) callconv(.c) c_int {
    const kind: @FieldType(command.Socket, "kind") = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(1), null));
    const action: command.SocketAction = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(2), null));
    var config: command.Socket = .{ .identity = lua.checkText(state, 1), .kind = kind };
    var address: c.struct_wolfIP_sockaddr_in = .{ .sin_family = c.AF_INET };
    if (kind == .raw) {
        const protocol = c.luaL_checkinteger(state, 2);
        if (protocol < 0 or protocol > 255) return c.luaL_error(state, "protocol must be between 0 and 255");
        config.protocol = @intCast(protocol);
        if (!c.lua_isnoneornil(state, 3)) {
            c.luaL_checktype(state, 3, c.LUA_TTABLE);
            _ = c.lua_getfield(state, 3, "header");
            if (!c.lua_isnil(state, -1)) c.luaL_checktype(state, -1, c.LUA_TBOOLEAN);
            config.header = c.lua_toboolean(state, -1) != 0;
            c.lua_pop(state, 1);
        }
    } else address = luaAddress(state, 2, 3) orelse return c.luaL_error(state, "IPv4 address and port are required");
    const timeout = if (kind == .tcp and action == .connect) luaTimeout(state, 4) else null;
    const value = newSocket(state);
    value.* = config;
    _ = call(state, action, value, &address, &.{}, timeout);
    return 1;
}

fn listen(state: ?*c.lua_State) callconv(.c) c_int {
    _ = call(state, .listen, luaSocket(state), null, &.{}, null);
    return 0;
}

fn accept(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    const peer = newSocket(state);
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const descriptor = call(state, .accept, value, &address, &.{}, luaTimeout(state, 2));
    peer.* = value.*;
    peer.descriptor = descriptor;
    peer.handshaking = true;
    pushAddress(state, address);
    return 3;
}

fn send(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    var length: usize = 0;
    const bytes = c.luaL_checklstring(state, 2, &length);
    var destination: c.struct_wolfIP_sockaddr_in = .{};
    var timeout_index: c_int = 3;
    if (value.kind == .raw or (value.kind == .udp and c.lua_type(state, 3) == c.LUA_TSTRING)) {
        timeout_index = if (value.kind == .raw) 4 else 5;
        destination = luaAddress(state, 3, if (value.kind == .raw) null else 4) orelse return c.luaL_error(state, "invalid destination address or port");
    }
    _ = call(state, .send, value, &destination, @constCast(bytes[0..length]), luaTimeout(state, timeout_index));
    return 0;
}

fn receive(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    const count = if (value.kind == .tcp) c.luaL_checkinteger(state, 2) else limits.socket_receive_capacity;
    if (count < 1 or count > limits.socket_receive_capacity) return c.luaL_error(state, "receive length must be between 1 and 32768");
    var received: [limits.socket_receive_capacity]u8 = undefined;
    var address: c.struct_wolfIP_sockaddr_in = .{};
    const length = call(state, .receive, value, &address, received[0..@intCast(count)], luaTimeout(state, if (value.kind == .tcp) 3 else 2));
    if (value.kind == .tcp) {
        if (length == 0) c.lua_pushnil(state) else _ = c.lua_pushlstring(state, &received, @intCast(length));
        return 1;
    }
    _ = c.lua_pushlstring(state, &received, @intCast(length));
    pushAddress(state, address);
    if (value.kind == .raw) {
        c.lua_pop(state, 1);
        return 2;
    }
    return 3;
}

fn close(state: ?*c.lua_State) callconv(.c) c_int {
    const value = luaSocket(state);
    if (value.descriptor < 0) return 0;
    _ = call(state, .close, value, null, &.{}, null);
    return 0;
}

fn call(state: ?*c.lua_State, action: command.SocketAction, value: *command.Socket, address: ?*c.struct_wolfIP_sockaddr_in, bytes: []u8, timeout: ?u64) c_int {
    const vm = lua.vm(state);
    var unused_address: c.struct_wolfIP_sockaddr_in = .{};
    var pending: command.SocketCall = .{
        .action = action,
        .socket = value,
        .address = address orelse &unused_address,
        .bytes = bytes,
        .deadline = if (timeout) |milliseconds| @as(u64, @intCast(std.Io.Clock.awake.now(io()).toMilliseconds())) + milliseconds else null,
        .cancelled = &vm.cancelled,
    };
    vm.manager.execute(.{ .socket = &pending }) catch return c.luaL_error(state, "socket call failed");
    if (action == .close) value.descriptor = -1;
    if (pending.result < 0) return c.luaL_error(state, if (pending.result == -c.WOLFIP_EAGAIN) "socket call timed out" else "socket call failed");
    return pending.result;
}

fn newSocket(state: ?*c.lua_State) *command.Socket {
    const raw = c.lua_newuserdatauv(state, @sizeOf(command.Socket), 0) orelse unreachable;
    const value: *command.Socket = @ptrCast(@alignCast(raw));
    value.descriptor = -1;
    _ = c.lua_getfield(state, c.LUA_REGISTRYINDEX, metatable);
    _ = c.lua_setmetatable(state, -2);
    return value;
}

fn luaSocket(state: ?*c.lua_State) *command.Socket {
    return @ptrCast(@alignCast(c.luaL_checkudata(state, 1, metatable)));
}

fn pushAddress(state: ?*c.lua_State, address: c.struct_wolfIP_sockaddr_in) void {
    const bytes: [4]u8 = @bitCast(address.sin_addr.s_addr);
    var buffer: [15]u8 = undefined;
    const output = std.fmt.bufPrint(&buffer, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch unreachable;
    _ = c.lua_pushlstring(state, output.ptr, output.len);
    c.lua_pushinteger(state, std.mem.bigToNative(u16, address.sin_port));
}

fn luaAddress(state: ?*c.lua_State, address_index: c_int, port_index: ?c_int) ?c.struct_wolfIP_sockaddr_in {
    const value = lua.toBytes(state, address_index) orelse return null;
    const port = if (port_index) |index| c.luaL_checkinteger(state, index) else 0;
    if (port < 0 or port > 65535) return null;
    const address = std.Io.net.Ip4Address.parse(value, 0) catch return null;
    return .{ .sin_family = c.AF_INET, .sin_port = std.mem.nativeToBig(u16, @intCast(port)), .sin_addr = .{ .s_addr = @bitCast(address.bytes) } };
}

fn luaTimeout(state: ?*c.lua_State, index: c_int) ?u64 {
    if (c.lua_isnoneornil(state, index)) return null;
    const value = c.luaL_checkinteger(state, index);
    if (value < 0) {
        _ = c.luaL_argerror(state, index, "timeout must be non-negative");
        unreachable;
    }
    return @intCast(value);
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
