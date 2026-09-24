const std = @import("std");
const c = @import("c");
const lua = @import("lua.zig");

pub const capacity = 3 * 1024 * 1024;

pub const Store = struct {
    mutex: std.Io.Mutex = .init,
    bytes: [capacity]u8 = undefined,
    len: usize = 0,
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_createtable(state, 0, 2);
    inline for (.{ .{ "get", get }, .{ "set", set } }) |entry| {
        c.lua_pushcclosure(state, entry[1], 0);
        c.lua_pushcclosure(state, locked, 1);
        c.lua_setfield(state, -2, entry[0]);
    }
    return 1;
}

// Lua errors longjmp past Zig defer. Catch them before releasing the lock.
fn locked(state: ?*c.lua_State) callconv(.c) c_int {
    const store = &lua.vm(state).manager.globals;
    const arguments = c.lua_gettop(state);
    c.lua_pushvalue(state, c.lua_upvalueindex(1));
    c.lua_insert(state, 1);
    store.mutex.lockUncancelable(io());
    const result = c.lua_pcallk(state, arguments, c.LUA_MULTRET, 0, 0, null);
    store.mutex.unlock(io());
    if (result != c.LUA_OK) return c.lua_error(state);
    return c.lua_gettop(state);
}

fn get(state: ?*c.lua_State) callconv(.c) c_int {
    const store = &lua.vm(state).manager.globals;
    if (store.len == 0) {
        c.lua_createtable(state, 0, 0);
        return 1;
    }
    var reader: c.mpack_reader_t = undefined;
    c.mpack_reader_init_data(&reader, &store.bytes, store.len);
    const decoded = decode(&reader, state);
    if (c.mpack_reader_destroy(&reader) != c.mpack_ok or !decoded) return c.luaL_error(state, "globals are invalid");
    return 1;
}

fn set(state: ?*c.lua_State) callconv(.c) c_int {
    if (c.lua_type(state, 1) != c.LUA_TTABLE) return c.luaL_argerror(state, 1, "table expected");
    const store = &lua.vm(state).manager.globals;
    store.len = 0;
    var writer: c.mpack_writer_t = undefined;
    c.mpack_writer_init(&writer, &store.bytes, store.bytes.len);
    const encoded = encode(&writer, state, 1, 0);
    if (c.mpack_writer_destroy(&writer) != c.mpack_ok or !encoded) return c.luaL_error(state, "globals exceed capacity or contain an unsupported value");
    store.len = c.mpack_writer_buffer_used(&writer);
    return 0;
}

fn encode(writer: *c.mpack_writer_t, state: ?*c.lua_State, index: c_int, depth: usize) bool {
    switch (c.lua_type(state, index)) {
        c.LUA_TBOOLEAN => c.mpack_write_bool(writer, c.lua_toboolean(state, index) != 0),
        c.LUA_TNUMBER => if (c.lua_isinteger(state, index) != 0)
            c.mpack_write_i64(writer, c.lua_tointegerx(state, index, null))
        else
            c.mpack_write_double(writer, c.lua_tonumberx(state, index, null)),
        c.LUA_TSTRING => {
            var len: usize = 0;
            const bytes = c.lua_tolstring(state, index, &len)[0..len];
            c.mpack_write_str(writer, bytes.ptr, @intCast(bytes.len));
        },
        c.LUA_TTABLE => {
            if (depth == 32) return false;
            c.luaL_checkstack(state, 3, "globals nesting exceeds Lua stack capacity");
            const table = c.lua_absindex(state, index);
            var count: u32 = 0;
            c.lua_pushnil(state);
            while (c.lua_next(state, table) != 0) {
                if (!key(state, -2)) return false;
                count += 1;
                c.lua_pop(state, 1);
            }
            c.mpack_start_map(writer, count);
            c.lua_pushnil(state);
            while (c.lua_next(state, table) != 0) {
                if (!encode(writer, state, -2, depth + 1) or !encode(writer, state, -1, depth + 1)) return false;
                c.lua_pop(state, 1);
            }
            c.mpack_finish_map(writer);
        },
        else => return false,
    }
    return c.mpack_writer_error(writer) == c.mpack_ok;
}

fn key(state: ?*c.lua_State, index: c_int) bool {
    return switch (c.lua_type(state, index)) {
        c.LUA_TBOOLEAN, c.LUA_TNUMBER, c.LUA_TSTRING => true,
        else => false,
    };
}

fn decode(reader: *c.mpack_reader_t, state: ?*c.lua_State) bool {
    const tag = c.mpack_read_tag(reader);
    switch (tag.type) {
        c.mpack_type_bool => c.lua_pushboolean(state, @intFromBool(tag.v.b)),
        c.mpack_type_int => c.lua_pushinteger(state, tag.v.i),
        c.mpack_type_uint => c.lua_pushinteger(state, @intCast(tag.v.u)),
        c.mpack_type_double => c.lua_pushnumber(state, tag.v.d),
        c.mpack_type_str => {
            const bytes = c.mpack_read_bytes_inplace(reader, tag.v.l) orelse return false;
            _ = c.lua_pushlstring(state, bytes, tag.v.l);
            c.mpack_done_str(reader);
        },
        c.mpack_type_map => {
            c.luaL_checkstack(state, 3, "globals nesting exceeds Lua stack capacity");
            c.lua_createtable(state, 0, @intCast(tag.v.n));
            for (0..tag.v.n) |_| {
                if (!decode(reader, state) or !decode(reader, state)) return false;
                c.lua_rawset(state, -3);
            }
            c.mpack_done_map(reader);
        },
        else => return false,
    }
    return c.mpack_reader_error(reader) == c.mpack_ok;
}

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
