const std = @import("std");
const command = @import("../command.zig");
const frame = @import("frame.zig");
const io = @import("../io.zig");
const limits = @import("../limits.zig");
const lua = @import("lua.zig");
const net = @import("net");
const c = @import("c");

const metatable = "kraken.socket";
const datagram_capacity = 65535;

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{ .{ "send", send }, .{ "receive", receive }, .{ "close", close }, .{ "listen", listen }, .{ "accept", accept } }, close);
    c.lua_createtable(state, 0, 3);
    inline for (comptime std.meta.tags(net.SocketKind)) |kind| {
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
    const kind: net.SocketKind = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(1), null));
    const action: command.SocketAction = @enumFromInt(c.lua_tointegerx(state, c.lua_upvalueindex(2), null));
    var config: command.Socket = .{ .identity = lua.checkText(state, 1), .endpoint = .{ .kind = kind } };
    var address: net.Address = .{};
    if (kind == .raw) {
        const protocol = c.luaL_checkinteger(state, 2);
        if (protocol < 0 or protocol > 255) return c.luaL_error(state, "protocol must be between 0 and 255");
        config.endpoint.protocol = @intCast(protocol);
    } else address = luaAddress(state, 2, 3) orelse return c.luaL_error(state, "IPv4 address and port are required");
    const timeout = if (kind == .tcp and action == .connect) luaTimeout(state, 4) else null;
    const value = newSocket(state);
    value.* = config;
    _ = call(state, action, value, &address, &.{}, timeout);
    return 1;
}

fn listen(state: ?*c.lua_State) callconv(.c) c_int {
    const value = check(state, 1);
    const backlog = c.luaL_optinteger(state, 2, 1);
    if (backlog < 1 or backlog > 255) return c.luaL_error(state, "backlog must be between 1 and 255");
    value.endpoint.backlog = @intCast(backlog);
    _ = call(state, .listen, value, null, &.{}, null);
    return 0;
}

fn accept(state: ?*c.lua_State) callconv(.c) c_int {
    const value = check(state, 1);
    const peer = newSocket(state);
    var address: net.Address = .{};
    const result = call(state, .accept, value, &address, &.{}, luaTimeout(state, 2));
    peer.* = value.*;
    peer.endpoint.handle = result.accepted;
    pushAddress(state, address);
    return 3;
}

fn send(state: ?*c.lua_State) callconv(.c) c_int {
    const value = check(state, 1);
    var length: usize = 0;
    const bytes = c.luaL_checklstring(state, 2, &length);
    var destination: net.Address = .{};
    var target: ?*net.Address = null;
    var timeout_index: c_int = 3;
    if (value.endpoint.kind == .raw or (value.endpoint.kind == .udp and c.lua_type(state, 3) == c.LUA_TSTRING)) {
        timeout_index = if (value.endpoint.kind == .raw) 4 else 5;
        destination = luaAddress(state, 3, if (value.endpoint.kind == .raw) null else 4) orelse return c.luaL_error(state, "invalid destination address or port");
        target = &destination;
    }
    _ = call(state, .send, value, target, @constCast(bytes[0..length]), luaTimeout(state, timeout_index));
    return 0;
}

fn receive(state: ?*c.lua_State) callconv(.c) c_int {
    const value = check(state, 1);
    const count = if (value.endpoint.kind == .tcp) receiveCount(state, 2) else datagram_capacity;
    var received: [datagram_capacity]u8 = undefined;
    var address: net.Address = .{};
    const result = call(state, .receive, value, &address, received[0..count], luaTimeout(state, if (value.endpoint.kind == .tcp) 3 else 2));
    if (value.endpoint.kind == .tcp) {
        if (result == .closed) c.lua_pushnil(state) else _ = c.lua_pushlstring(state, &received, result.success);
        return 1;
    }
    _ = c.lua_pushlstring(state, &received, result.success);
    pushAddress(state, address);
    if (value.endpoint.kind == .raw) {
        c.lua_pop(state, 1);
        return 2;
    }
    return 3;
}

fn close(state: ?*c.lua_State) callconv(.c) c_int {
    const value = check(state, 1);
    if (value.endpoint.handle == null) return 0;
    _ = call(state, .close, value, null, &.{}, null);
    return 0;
}

fn call(state: ?*c.lua_State, action: command.SocketAction, value: *command.Socket, address: ?*net.Address, bytes: []u8, timeout: ?u64) net.SocketResult {
    const result = perform(lua.vm(state), action, value, address, bytes, deadline(timeout));
    if (result == .would_block) raiseTimeout(state);
    if (result == .failed) lua.raise(state, "socket call failed", .{});
    return result;
}

/// Runs one socket operation on the identity's interface without raising, for callers
/// outside Lua such as protocol I/O callbacks.
pub fn perform(vm: *lua.VM, action: command.SocketAction, value: *command.Socket, address: ?*net.Address, bytes: []u8, until: ?i64) net.SocketResult {
    var pending: command.SocketCall = .{
        .action = action,
        .socket = value,
        .address = address,
        .bytes = bytes,
        .deadline = until,
        .cancelled = &vm.cancelled,
    };
    vm.manager.execute(.{ .socket = &pending }) catch return .failed;
    if (action == .close) value.endpoint.handle = null;
    return pending.result;
}

fn newSocket(state: ?*c.lua_State) *command.Socket {
    const value = lua.pushUserdata(state, command.Socket, metatable);
    value.endpoint.handle = null;
    return value;
}

pub fn check(state: ?*c.lua_State, index: c_int) *command.Socket {
    return lua.checkUserdata(state, index, command.Socket, metatable);
}

/// The absolute deadline, in milliseconds, of a call with `timeout`.
pub fn deadline(timeout: ?u64) ?i64 {
    return if (timeout) |milliseconds| io.now().toMilliseconds() + @as(i64, @intCast(milliseconds)) else null;
}

pub fn raiseTimeout(state: ?*c.lua_State) noreturn {
    lua.raise(state, "socket call timed out", .{});
}

/// The byte count argument of a stream receive.
pub fn receiveCount(state: ?*c.lua_State, index: c_int) usize {
    const count = c.luaL_checkinteger(state, index);
    if (count < 1 or count > limits.socket_receive_capacity) lua.raise(state, "receive length must be between 1 and 32768", .{});
    return @intCast(count);
}

fn pushAddress(state: ?*c.lua_State, address: net.Address) void {
    var buffer: [17]u8 = undefined;
    lua.pushBytes(state, frame.Ipv4Address.text(&address.ip, &buffer));
    c.lua_pushinteger(state, address.port);
}

fn luaAddress(state: ?*c.lua_State, address_index: c_int, port_index: ?c_int) ?net.Address {
    const value = lua.toBytes(state, address_index) orelse return null;
    const port = if (port_index) |index| c.luaL_checkinteger(state, index) else 0;
    if (port < 0 or port > 65535) return null;
    const address = std.Io.net.Ip4Address.parse(value, 0) catch return null;
    return .{ .ip = address.bytes, .port = @intCast(port) };
}

pub fn luaTimeout(state: ?*c.lua_State, index: c_int) ?u64 {
    if (c.lua_isnoneornil(state, index)) return null;
    const value = c.luaL_checkinteger(state, index);
    if (value < 0) {
        _ = c.luaL_argerror(state, index, "timeout must be non-negative");
        unreachable;
    }
    return @intCast(value);
}
