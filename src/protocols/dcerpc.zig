const c = @import("c");
const std = @import("std");
const smb = @import("libsmb2");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const smb_client = @import("smb_client.zig");
const command = @import("../command.zig");

const metatable = "kraken.dcerpc";
const pipe_read_capacity = smb_client.pipe_read_capacity;

const Mode = enum { tcp, smb };

const Session = struct {
    client: smb_client.Client,
    mode: Mode,
    service: *const smb.dcerpc_service,
    dce: ?*smb.dcerpc_context = null,
    pipe: ?*smb.smb2fh = null,
    pipe_read_buffer: [pipe_read_capacity]u8 = undefined,
    pipe_read_position: usize = 0,
    pipe_read_length: usize = 0,

    fn release(self: *Session) void {
        if (self.dce) |dce| smb.dcerpc_release_context(dce);
        if (self.pipe) |pipe| smb.smb2_release_fh(pipe);
        self.client.release();
        self.dce = null;
        self.pipe = null;
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{ .{ "call", callLua }, .{ "close", closeLua } }, collectLua);
    lua.pushFunctions(state, .{ .{ "tcp", tcpLua }, .{ "smb", smbLua } });
    return 1;
}

fn tcpLua(state: ?*c.lua_State) callconv(.c) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const service = findService(state, 2);
    const session = stream.new(state, metatable, Session{ .client = .{ .transport = transport }, .mode = .tcp, .service = service });
    session.client.transport.begin(timeout);
    var channel: smb.dcerpc_transport = .{ .read = channelRead, .write = channelWrite, .@"opaque" = session };
    session.dce = smb.dcerpc_create_context_transport(&channel) orelse lua.raise(state, "DCERPC context allocation failed", .{});
    if (smb.dcerpc_bind_transport(session.dce, service.*.syntax) != 0) fail(state, session);
    return 1;
}

fn smbLua(state: ?*c.lua_State) callconv(.c) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const service = findService(state, 2);
    const session = stream.new(state, metatable, Session{ .client = .{ .transport = transport }, .mode = .smb, .service = service });
    session.client.transport.begin(timeout);
    if (!session.client.init(state, "IPC$")) fail(state, session);
    const context = session.client.context;

    const pipe: [*c]const u8 = if (lua.optionalString(state, 2, "pipe")) |value| value.ptr else service.*.name;
    session.client.operation = .{};
    if (smb.smb2_open_async(context, pipe, smb.O_RDWR, smb_client.complete, &session.client.operation) != 0) fail(state, session);
    if (!session.client.success()) fail(state, session);
    session.pipe = @ptrCast(@alignCast(session.client.operation.data orelse fail(state, session)));

    var dce_channel: smb.dcerpc_transport = .{ .read = channelRead, .write = channelWrite, .@"opaque" = session };
    session.dce = smb.dcerpc_create_context_transport(&dce_channel) orelse fail(state, session);
    if (smb.dcerpc_bind_transport(session.dce, service.*.syntax) != 0) fail(state, session);
    return 1;
}

fn findService(state: ?*c.lua_State, options: c_int) *const smb.dcerpc_service {
    const name = lua.requiredString(state, options, "service");
    return smb.dcerpc_find_service(name.ptr) orelse lua.raise(state, "unknown DCERPC service", .{});
}

fn callLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const procedure = lua.stringAt(state, 2, "procedure");
    const request = lua.stringAt(state, 3, "request");
    session.client.transport.begin(socket.luaTimeout(state, 4));
    const result = smb.dcerpc_call_json(session.dce, session.service, procedure.ptr, request.ptr) orelse fail(state, session);
    defer smb.dcerpc_free_json(result);
    _ = c.lua_pushstring(state, result);
    return 1;
}

fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.mode == .smb and session.dce != null and session.client.context != null) {
        session.client.transport.begin(stream.close_timeout);
        smb.dcerpc_release_context(session.dce);
        session.dce = null;
        const completion = &session.client.operation;
        var can_disconnect = true;
        completion.* = .{};
        if (session.pipe) |pipe| {
            if (smb.smb2_close_async(session.client.context, pipe, smb_client.complete, completion) == 0)
                can_disconnect = session.client.pump()
            else
                smb.smb2_release_fh(pipe);
            session.pipe = null;
        }
        if (can_disconnect) {
            completion.* = .{};
            session.client.closeShare();
        }
    }
    session.release();
    session.client.transport.close();
    return 0;
}

fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.dce == null) lua.raise(state, "DCERPC session is closed", .{});
    return session;
}

fn fail(state: ?*c.lua_State, session: *Session) noreturn {
    const timed_out = session.client.transport.timed_out;
    const source: [*c]const u8 = if (session.dce) |dce| smb.dcerpc_get_error(dce) else session.client.errorText();
    var message: [512:0]u8 = @splat(0);
    const text = std.mem.span(source);
    @memcpy(message[0..@min(text.len, message.len - 1)], text[0..@min(text.len, message.len - 1)]);
    session.release();
    session.client.transport.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "%s", .{&message});
}

fn channelRead(context: ?*anyopaque, buffer: ?*anyopaque, len: usize, transferred: [*c]usize) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(context.?));
    if (session.mode == .smb) return pipeRead(session, buffer.?, len, transferred);
    return tcpTransfer(.receive, session, buffer, len, transferred);
}

fn pipeRead(session: *Session, buffer: *anyopaque, len: usize, transferred: [*c]usize) c_int {
    if (len == 0) return -1;
    if (session.pipe_read_position == session.pipe_read_length) {
        var received: usize = 0;
        if (session.client.pipe(.receive, session.pipe, &session.pipe_read_buffer, pipe_read_capacity, &received) != 0) return -1;
        session.pipe_read_position = 0;
        session.pipe_read_length = received;
    }
    const count = @min(len, session.pipe_read_length - session.pipe_read_position);
    @memcpy(@as([*]u8, @ptrCast(buffer))[0..count], session.pipe_read_buffer[session.pipe_read_position..][0..count]);
    session.pipe_read_position += count;
    transferred[0] = count;
    return 0;
}

fn channelWrite(context: ?*anyopaque, buffer: ?*const anyopaque, len: usize, transferred: [*c]usize) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(context.?));
    if (session.mode == .smb) return pipeTransfer(.send, session, @constCast(buffer.?), len, transferred);
    return tcpTransfer(.send, session, @constCast(buffer), len, transferred);
}

fn tcpTransfer(action: command.SocketAction, session: *Session, buffer: ?*anyopaque, len: usize, transferred: [*c]usize) c_int {
    const bytes: [*]u8 = @ptrCast(buffer.?);
    const result = session.client.transport.transfer(action, bytes[0..len], .{ .closed = -1, .want_read = -1, .failed = -1 });
    if (result <= 0) return -1;
    transferred[0] = @intCast(result);
    return 0;
}

fn pipeTransfer(action: command.SocketAction, session: *Session, buffer: *anyopaque, len: usize, transferred: [*c]usize) c_int {
    return session.client.pipe(action, session.pipe, buffer, len, transferred);
}

const bind_ack = [_]u8{
    5,    0,    12,   3,    0x10, 0,    0,    0,    80,   0,    0,    0,    1,    0,    0,    0,
    0x00, 0x10, 0x00, 0x10, 0,    0,    0,    0,    0,    0,    0,    0,    2,    0,    0,    0,
    0,    0,    0,    0,    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
    0x2b, 0x10, 0x48, 0x60, 2,    0,    0,    0,    2,    0,    2,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

const call_reply = [_]u8{
    5, 0, 2,    1,    0x10, 0, 0, 0, 26,   0,    0, 0, 2, 0, 0,    0,
    4, 0, 0,    0,    0,    0, 0, 0, 0x78, 0x56, 5, 0, 2, 2, 0x10, 0,
    0, 0, 26,   0,    0,    0, 2, 0, 0,    0,    2, 0, 0, 0, 0,    0,
    0, 0, 0x34, 0x12,
};

const Fake = struct {
    reply: []const u8,
    offset: usize = 0,
    wrote: usize = 0,
    writes: usize = 0,

    fn read(context: ?*anyopaque, buffer: ?*anyopaque, len: usize, transferred: [*c]usize) callconv(.c) c_int {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        if (self.offset == self.reply.len) return -1;
        const count = @min(len, self.reply.len - self.offset);
        @memcpy(@as([*]u8, @ptrCast(buffer.?))[0..count], self.reply[self.offset..][0..count]);
        self.offset += count;
        transferred[0] = count;
        return 0;
    }

    fn write(context: ?*anyopaque, _: ?*const anyopaque, len: usize, transferred: [*c]usize) callconv(.c) c_int {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        self.wrote += len;
        self.writes += 1;
        transferred[0] = len;
        return 0;
    }
};

fn wordCoder(name: [*c]u8, context: ?*smb.dcerpc_context, pdu: ?*smb.dcerpc_pdu, iov: [*c]smb.dcerpc_iovec, offset: [*c]c_int, pointer: ?*anyopaque) callconv(.c) c_int {
    return smb.dcerpc_uint32_coder(name, context, pdu, iov, offset, pointer);
}

fn largeCoder(_: [*c]u8, _: ?*smb.dcerpc_context, _: ?*smb.dcerpc_pdu, iov: [*c]smb.dcerpc_iovec, offset: [*c]c_int, _: ?*anyopaque) callconv(.c) c_int {
    const count = 5000;
    const start: usize = @intCast(offset[0]);
    if (start + count > iov[0].len) return -1;
    @memset(iov[0].buf[start .. start + count], 0xa5);
    offset[0] += count;
    return 0;
}

test "transport bind accepts a matched fragmented-capable context" {
    var fake: Fake = .{ .reply = &bind_ack };
    var transport: smb.dcerpc_transport = .{ .read = Fake.read, .write = Fake.write, .@"opaque" = &fake };
    const context = smb.dcerpc_create_context_transport(&transport).?;
    defer smb.dcerpc_release_context(context);
    const service = smb.dcerpc_find_service("srvsvc").?;
    try std.testing.expectEqual(@as(c_int, 0), smb.dcerpc_bind_transport(context, service.*.syntax));
    try std.testing.expect(fake.wrote > 16);
}

test "transport call fragments requests and decodes the matched reply" {
    const replies = bind_ack ++ call_reply;
    var fake: Fake = .{ .reply = &replies };
    var transport: smb.dcerpc_transport = .{ .read = Fake.read, .write = Fake.write, .@"opaque" = &fake };
    const context = smb.dcerpc_create_context_transport(&transport).?;
    defer smb.dcerpc_release_context(context);
    const service = smb.dcerpc_find_service("srvsvc").?;
    try std.testing.expectEqual(@as(c_int, 0), smb.dcerpc_bind_transport(context, service.*.syntax));
    const reply: *u32 = @ptrCast(@alignCast(smb.dcerpc_call_transport(context, 0, largeCoder, null, wordCoder, @sizeOf(u32)).?));
    defer smb.dcerpc_free_data(context, reply);
    try std.testing.expectEqual(@as(u32, 0x12345678), reply.*);
    try std.testing.expectEqual(@as(usize, 3), fake.writes);
}

test "srvsvc JSON example encodes a request before transport I/O" {
    var fake: Fake = .{ .reply = &bind_ack };
    var transport: smb.dcerpc_transport = .{ .read = Fake.read, .write = Fake.write, .@"opaque" = &fake };
    const context = smb.dcerpc_create_context_transport(&transport).?;
    defer smb.dcerpc_release_context(context);
    const service = smb.dcerpc_find_service("srvsvc").?;
    try std.testing.expectEqual(@as(c_int, 0), smb.dcerpc_bind_transport(context, service.*.syntax));
    const request =
        \\{"NetrShareEnum":{"InfoStruct":{"Level":1,"ShareInfo":{}},"PreferedMaximumLength":4294967295}}
    ;
    try std.testing.expect(smb.dcerpc_call_json(context, service, "NetrShareEnum", request) == null);
    try std.testing.expectEqual(@as(usize, 2), fake.writes);
}

test "endpoint mapper JSON example encodes a request before transport I/O" {
    try std.testing.expectEqual(@as(c_int, 1), smb.EPM_RPC_C_VERS_ALL);
    var fake: Fake = .{ .reply = &bind_ack };
    var transport: smb.dcerpc_transport = .{ .read = Fake.read, .write = Fake.write, .@"opaque" = &fake };
    const context = smb.dcerpc_create_context_transport(&transport).?;
    defer smb.dcerpc_release_context(context);
    const service = smb.dcerpc_find_service("epmapper").?;
    try std.testing.expectEqual(@as(c_int, 0), smb.dcerpc_bind_transport(context, service.*.syntax));
    const request =
        \\{"Lookup":{"InquiryType":0,"VersOption":1,"EntryHandle":{"ContextHandleAttributes":0,"UUID":"00000000-0000-0000-0000-000000000000"},"MaxEnts":1}}
    ;
    try std.testing.expect(smb.dcerpc_call_json(context, service, "Lookup", request) == null);
    try std.testing.expectEqual(@as(usize, 2), fake.writes);
}

test "transport bind rejects a mismatched call id and poisons the context" {
    var bad = bind_ack;
    bad[12] = 2;
    var fake: Fake = .{ .reply = &bad };
    var transport: smb.dcerpc_transport = .{ .read = Fake.read, .write = Fake.write, .@"opaque" = &fake };
    const context = smb.dcerpc_create_context_transport(&transport).?;
    defer smb.dcerpc_release_context(context);
    const service = smb.dcerpc_find_service("srvsvc").?;
    try std.testing.expect(smb.dcerpc_bind_transport(context, service.*.syntax) != 0);
    try std.testing.expect(smb.dcerpc_bind_transport(context, service.*.syntax) != 0);
}
