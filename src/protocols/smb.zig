const c = @import("c");
const std = @import("std");
const lib = @import("libsmb2");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const client = @import("smb_client.zig");
const limits = @import("../limits.zig");

const metatable = "kraken.smb";

const Session = struct {
    connection: client.Client,
    file: ?*lib.smb2fh = null,
    dir: ?*lib.smb2dir = null,

    fn release(self: *Session) void {
        if (self.dir) |dir| lib.smb2_closedir(self.connection.context, dir);
        if (self.file) |file| lib.smb2_release_fh(file);
        self.dir = null;
        self.file = null;
        self.connection.release();
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "list", listLua },     .{ "stat", statLua },
        .{ "read", readLua },     .{ "write", writeLua },
        .{ "remove", removeLua }, .{ "mkdir", mkdirLua },
        .{ "rmdir", rmdirLua },   .{ "rename", renameLua },
        .{ "close", closeLua },
    }, collectLua);
    lua.pushFunctions(state, .{.{ "connect", connectLua }});
    return 1;
}

fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const session = stream.new(state, metatable, Session{ .connection = .{ .transport = transport } });
    session.connection.transport.begin(timeout);
    const share = lua.requiredString(state, 2, "share");
    if (!session.connection.init(state, share.ptr)) fail(state, session);
    return 1;
}

fn check(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.connection.context == null) lua.raise(state, "SMB session is closed", .{});
    return session;
}

fn finish(state: ?*c.lua_State, session: *Session, submitted: c_int) void {
    if (submitted != 0 or !session.connection.success()) fail(state, session);
}

fn fail(state: ?*c.lua_State, session: *Session) noreturn {
    const timed_out = session.connection.transport.timed_out;
    const source = std.mem.span(session.connection.errorText());
    var message: [512:0]u8 = @splat(0);
    const count = @min(source.len, message.len - 1);
    @memcpy(message[0..count], source[0..count]);
    session.release();
    session.connection.transport.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "%s", .{&message});
}

fn listLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    session.connection.begin(state, 3);
    finish(state, session, lib.smb2_opendir_async(session.connection.context, path.ptr, client.complete, &session.connection.operation));
    session.dir = @ptrCast(@alignCast(session.connection.operation.data orelse fail(state, session)));
    c.lua_createtable(state, 0, 0);
    var index: c.lua_Integer = 1;
    while (lib.smb2_readdir(session.connection.context, session.dir)) |entry| {
        if (index > 4096) fail(state, session);
        if (!statFitsLua(&entry.*.st)) {
            lib.smb2_closedir(session.connection.context, session.dir);
            session.dir = null;
            lua.raise(state, "SMB metadata exceeds Lua integer range", .{});
        }
        c.lua_createtable(state, 0, 3);
        lua.setString(state, "name", std.mem.span(entry.*.name));
        pushStat(state, &entry.*.st);
        c.lua_setfield(state, -2, "stat");
        c.lua_rawseti(state, -2, index);
        index += 1;
    }
    lib.smb2_closedir(session.connection.context, session.dir);
    session.dir = null;
    return 1;
}

fn statLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    var info: lib.smb2_stat_64 = .{};
    session.connection.begin(state, 3);
    finish(state, session, lib.smb2_stat_async(session.connection.context, path.ptr, &info, client.complete, &session.connection.operation));
    pushStat(state, &info);
    return 1;
}

fn pushStat(state: ?*c.lua_State, info: *const lib.smb2_stat_64) void {
    if (!statFitsLua(info)) lua.raise(state, "SMB metadata exceeds Lua integer range", .{});
    c.lua_createtable(state, 0, 5);
    c.lua_pushinteger(state, @intCast(info.smb2_size));
    c.lua_setfield(state, -2, "size");
    c.lua_pushinteger(state, @intCast(info.smb2_type));
    c.lua_setfield(state, -2, "type");
    c.lua_pushinteger(state, @intCast(info.smb2_attributes));
    c.lua_setfield(state, -2, "attributes");
    c.lua_pushinteger(state, @intCast(info.smb2_mtime));
    c.lua_setfield(state, -2, "mtime");
}

fn statFitsLua(info: *const lib.smb2_stat_64) bool {
    return info.smb2_size <= std.math.maxInt(c.lua_Integer) and
        info.smb2_mtime <= std.math.maxInt(c.lua_Integer);
}

fn openFile(state: ?*c.lua_State, session: *Session, path: [*:0]const u8, flags: c_int) void {
    session.connection.operation = .{};
    finish(state, session, lib.smb2_open_async(session.connection.context, path, flags, client.complete, &session.connection.operation));
    session.file = @ptrCast(@alignCast(session.connection.operation.data orelse fail(state, session)));
}

fn closeFile(state: ?*c.lua_State, session: *Session) void {
    session.connection.operation = .{};
    const submitted = lib.smb2_close_async(session.connection.context, session.file, client.complete, &session.connection.operation);
    if (submitted != 0) fail(state, session);
    session.file = null; // libsmb2 frees it in the close callback, including failure.
    if (!session.connection.success()) fail(state, session);
}

fn offsetArg(state: ?*c.lua_State, index: c_int) u64 {
    const value = c.luaL_optinteger(state, index, 0);
    if (value < 0) lua.raise(state, "offset must be non-negative", .{});
    return @intCast(value);
}

fn readLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    const count = socket.receiveCount(state, 3);
    const offset = offsetArg(state, 4);
    session.connection.begin(state, 5);
    openFile(state, session, path.ptr, lib.O_RDONLY);
    var buffer: [limits.socket_receive_capacity]u8 = undefined;
    var got: usize = 0;
    while (got < count) {
        const requested = @min(count - got, client.read_chunk_capacity);
        session.connection.operation = .{};
        finish(state, session, lib.smb2_pread_async(session.connection.context, session.file, buffer[got..].ptr, @intCast(requested), offset + got, client.complete, &session.connection.operation));
        const received: usize = @intCast(session.connection.operation.status);
        if (received > requested) fail(state, session);
        got += received;
        if (received < requested) break;
    }
    closeFile(state, session);
    lua.pushBytes(state, buffer[0..got]);
    return 1;
}

fn writeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    const bytes = lua.checkBytes(state, 3);
    if (bytes.len > limits.socket_receive_capacity) lua.raise(state, "write length must be at most 32768", .{});
    const offset = offsetArg(state, 4);
    session.connection.begin(state, 5);
    openFile(state, session, path.ptr, lib.O_RDWR | lib.O_CREAT);
    var written: usize = 0;
    while (written < bytes.len) {
        session.connection.operation = .{};
        finish(state, session, lib.smb2_pwrite_async(session.connection.context, session.file, bytes[written..].ptr, @intCast(bytes.len - written), offset + written, client.complete, &session.connection.operation));
        const count: usize = @intCast(session.connection.operation.status);
        if (count == 0 or count > bytes.len - written) fail(state, session);
        written += count;
    }
    closeFile(state, session);
    c.lua_pushinteger(state, @intCast(written));
    return 1;
}

fn removeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    session.connection.begin(state, 3);
    finish(state, session, lib.smb2_unlink_async(session.connection.context, path.ptr, client.complete, &session.connection.operation));
    return 0;
}

fn mkdirLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    session.connection.begin(state, 3);
    finish(state, session, lib.smb2_mkdir_async(session.connection.context, path.ptr, client.complete, &session.connection.operation));
    return 0;
}

fn rmdirLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const path = lua.stringAt(state, 2, "path");
    session.connection.begin(state, 3);
    finish(state, session, lib.smb2_rmdir_async(session.connection.context, path.ptr, client.complete, &session.connection.operation));
    return 0;
}

fn renameLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = check(state);
    const from = lua.stringAt(state, 2, "from");
    const to = lua.stringAt(state, 3, "to");
    session.connection.begin(state, 4);
    finish(state, session, lib.smb2_rename_async(session.connection.context, from.ptr, to.ptr, client.complete, &session.connection.operation));
    return 0;
}

fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.connection.context != null) session.connection.closeShare();
    session.release();
    session.connection.transport.close();
    return 0;
}

fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

test "SMB metadata must fit Lua integers" {
    var info: lib.smb2_stat_64 = .{};
    try std.testing.expect(statFitsLua(&info));
    info.smb2_size = std.math.maxInt(u64);
    try std.testing.expect(!statFitsLua(&info));
    info.smb2_size = 0;
    info.smb2_mtime = std.math.maxInt(u64);
    try std.testing.expect(!statFitsLua(&info));
}
