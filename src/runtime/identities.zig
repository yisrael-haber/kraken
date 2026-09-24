const std = @import("std");
const command = @import("../command.zig");
const identity = @import("../identities/identity.zig");
const text = @import("../text.zig");
const lua = @import("lua.zig");
const c = @import("c");

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_createtable(state, 0, 6);
    lua.setFunction(state, -2, "create", create);
    inline for (.{ "start", "stop", "delete" }) |action| lua.setFunction(state, -2, action, identityCommand(action));
    lua.setFunction(state, -2, "set_transport", setTransport);
    lua.setFunction(state, -2, "set_bpf", setBpf);
    return 1;
}

fn create(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    var value: identity.Identity = .{};
    inline for (.{ "label", "ip", "prefix", "interface", "gateway", "mac", "mtu" }) |field| {
        const required = comptime std.mem.eql(u8, field, "label");
        _ = c.lua_getfield(state, 1, if (required) "name" else field);
        if (required or !c.lua_isnil(state, -1)) @field(value, field) = lua.checkText(state, -1);
        c.lua_pop(state, 1);
    }
    return lua.executeCommand(state, .{ .save = value });
}

fn setTransport(state: ?*c.lua_State) callconv(.c) c_int {
    const name = lua.checkText(state, 1);
    const script = if (c.lua_isnil(state, 2)) null else lua.checkText(state, 2);
    return lua.executeCommand(state, .{ .set_transport = .{ .name = name, .script = script } });
}

fn setBpf(state: ?*c.lua_State) callconv(.c) c_int {
    const name = lua.checkText(state, 1);
    const expression: text.FieldText = if (c.lua_isnoneornil(state, 2)) .{} else lua.checkText(state, 2);
    if (std.mem.indexOfScalar(u8, expression.value(), 0) != null) return c.luaL_error(state, "BPF cannot contain NUL bytes");
    return lua.executeCommand(state, .{ .set_bpf = .{ .name = name, .expression = expression } });
}

fn identityCommand(comptime action: []const u8) c.lua_CFunction {
    return struct {
        fn call(state: ?*c.lua_State) callconv(.c) c_int {
            return lua.executeCommand(state, @unionInit(command.Command, action, lua.checkText(state, 1)));
        }
    }.call;
}
