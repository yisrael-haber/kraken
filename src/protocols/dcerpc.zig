const c = @import("c");
const std = @import("std");
const smb = @import("libsmb2");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const smb_client = @import("smb_client.zig");
const yaml = @import("yaml.zig");

const metatable = "kraken.dcerpc";
const allocator = std.heap.c_allocator;
const max_reply = 16 * 1024 * 1024;

// libdcerpc runs the whole protocol. Over SMB it uses its own named-pipe path on
// the SMB session; over TCP the same code reads and writes the socket through
// `stream`. Both complete through `complete`, driven by the SMB pump when needed.
// A call is either a raw NDR stub for an opnum on any interface, or a named
// procedure of a libdcerpc service whose coders translate to and from YAML.
const Session = struct {
    client: smb_client.Client,
    syntax: smb.p_syntax_id_t,
    service: ?*const smb.dcerpc_service,
    smb: bool = false,
    dce: ?*smb.dcerpc_context = null,
    stream: smb.dcerpc_stream = undefined,

    pub fn release(self: *Session) void {
        if (self.dce) |dce| smb.dcerpc_destroy_context(dce);
        self.dce = null;
        self.client.release();
    }
};

const CallError = error{ UnknownProcedure, InvalidRequest, ReplyTooLarge, OutOfMemory, Failed };

/// Raw stub bytes, as a request to send or the reply payload that libdcerpc frees.
const Raw = extern struct { data: ?[*]u8, len: usize };

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{ .{ "call", callLua }, .{ "template", templateLua }, .{ "close", closeLua } }, lua.collector(Session, metatable));
    lua.pushFunctions(state, .{ .{ "tcp", tcpLua }, .{ "smb", smbLua } });
    return 1;
}

fn tcpLua(state: ?*c.lua_State) callconv(.c) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const service, const syntax = target(state);
    const session = stream.new(state, metatable, Session{ .client = .{ .transport = transport }, .syntax = syntax, .service = service });
    session.client.transport.begin(timeout);
    // Only holds configuration and error text; there is no SMB connection.
    session.client.context = smb.smb2_init_context();
    session.stream = .{ .send = streamSend, .recv = streamRecv, .@"opaque" = session };
    createContext(state, session);
    smb.dcerpc_set_stream(session.dce, &session.stream);
    bind(state, session, "");
    return 1;
}

fn smbLua(state: ?*c.lua_State) callconv(.c) c_int {
    const transport, const timeout = stream.arguments(state, true);
    const service, const syntax = target(state);
    const session = stream.new(state, metatable, Session{ .client = .{ .transport = transport }, .syntax = syntax, .service = service, .smb = true });
    session.client.transport.begin(timeout);
    if (!session.client.init(state, "IPC$")) fail(state, session);
    createContext(state, session);
    const pipe = lua.optionalString(state, 2, "pipe") orelse if (service) |named| std.mem.span(named.name) else lua.raise(state, "pipe is required with interface", .{});
    bind(state, session, pipe.ptr);
    return 1;
}

fn createContext(state: ?*c.lua_State, session: *Session) void {
    const context = session.client.context orelse fail(state, session);
    if (lua.optionalString(state, 2, "ndr")) |mode| {
        // libsmb2 reads the transfer-syntax policy from its URL arguments.
        const url = ndrUrl(mode) orelse lua.raise(state, "ndr must be \"32\", \"64\" or \"both\"", .{});
        smb.smb2_destroy_url(smb.smb2_parse_url(context, url.ptr));
    }
    session.dce = smb.dcerpc_create_context(context) orelse fail(state, session);
}

fn ndrUrl(mode: []const u8) ?[:0]const u8 {
    if (std.mem.eql(u8, mode, "32")) return "smb://x/y?ndr32";
    if (std.mem.eql(u8, mode, "64")) return "smb://x/y?ndr64";
    if (std.mem.eql(u8, mode, "both")) return "smb://x/y?ndr3264";
    return null;
}

fn bind(state: ?*c.lua_State, session: *Session, path: [*c]const u8) void {
    session.client.operation = .{};
    if (smb.dcerpc_connect_context_async(session.dce, path, &session.syntax, complete, &session.client.operation) != 0) fail(state, session);
    if (!session.client.pump() or session.client.operation.status != 0) fail(state, session);
}

fn complete(_: ?*smb.dcerpc_context, status: c_int, data: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    const completion: *smb_client.Completion = @ptrCast(@alignCast(context.?));
    completion.* = .{ .done = true, .status = status, .data = data };
}

/// The options' interface: a libdcerpc service by `service`, or any interface by
/// `interface` (a UUID) and `version` ("major.minor", default "1.0").
fn target(state: ?*c.lua_State) struct { ?*const smb.dcerpc_service, smb.p_syntax_id_t } {
    if (lua.optionalString(state, 2, "interface")) |uuid| {
        const version = lua.optionalString(state, 2, "version") orelse "1.0";
        const syntax = parseSyntax(uuid, version) orelse lua.raise(state, "interface must be a UUID and version \"major.minor\"", .{});
        return .{ null, syntax };
    }
    const name = lua.requiredString(state, 2, "service");
    var service: [*c]const smb.dcerpc_service = smb.dcerpc_services;
    while (service.*.name != null) : (service += 1) {
        if (std.mem.eql(u8, std.mem.span(service.*.name), name)) return .{ service, service.*.interface.* };
    }
    lua.raise(state, "unknown DCERPC service", .{});
}

fn parseSyntax(uuid: []const u8, version: []const u8) ?smb.p_syntax_id_t {
    if (uuid.len != 36 or uuid[8] != '-' or uuid[13] != '-' or uuid[18] != '-' or uuid[23] != '-') return null;
    var syntax: smb.p_syntax_id_t = undefined;
    const parse = std.fmt.parseInt;
    syntax.uuid.v1 = parse(u32, uuid[0..8], 16) catch return null;
    syntax.uuid.v2 = parse(u16, uuid[9..13], 16) catch return null;
    syntax.uuid.v3 = parse(u16, uuid[14..18], 16) catch return null;
    for (0..2) |i| syntax.uuid.v4[i] = parse(u8, uuid[19 + 2 * i ..][0..2], 16) catch return null;
    for (0..6) |i| syntax.uuid.v4[2 + i] = parse(u8, uuid[24 + 2 * i ..][0..2], 16) catch return null;
    const dot = std.mem.indexOfScalar(u8, version, '.') orelse return null;
    syntax.vers = std.fmt.parseInt(u16, version[0..dot], 10) catch return null;
    syntax.vers_minor = std.fmt.parseInt(u16, version[dot + 1 ..], 10) catch return null;
    return syntax;
}

fn findProcedure(service: *const smb.dcerpc_service, name: []const u8) ?*const smb.dcerpc_procedure {
    var procedure: [*c]const smb.dcerpc_procedure = service.procs;
    while (procedure.*.name != null) : (procedure += 1) {
        if (std.mem.eql(u8, std.mem.span(procedure.*.name), name)) return procedure;
    }
    return null;
}

/// `rpc:call(opnum, stub [, timeout_ms])` sends a raw NDR stub and returns the reply
/// stub; `rpc:call(procedure, yaml [, timeout_ms])` calls a named procedure.
fn callLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const raw = c.lua_type(state, 2) == c.LUA_TNUMBER;
    const opnum = if (raw) c.luaL_checkinteger(state, 2) else 0;
    if (raw and (opnum < 0 or opnum > std.math.maxInt(u16))) lua.raise(state, "opnum must be 0 to 65535", .{});
    const procedure = if (raw) "" else lua.stringAt(state, 2, "procedure");
    const request = lua.checkBytes(state, 3);
    session.client.begin(state, 4);
    const result = (if (raw) callRaw(session, @intCast(opnum), request) else callNamed(session, procedure, request)) catch |err| switch (err) {
        error.UnknownProcedure => lua.raise(state, "unknown DCERPC procedure", .{}),
        error.InvalidRequest => lua.raise(state, "invalid YAML request for %s", .{procedure.ptr}),
        error.ReplyTooLarge => lua.raise(state, "DCERPC reply is too large", .{}),
        error.OutOfMemory => lua.raise(state, "out of memory", .{}),
        error.Failed => fail(state, session),
    };
    if (raw) {
        _ = c.lua_pushlstring(state, result.ptr, result.len);
        allocator.free(result);
        return 1;
    }
    // A reply libyaml cannot parse is still returned: nil, its text, and the reason.
    var failure: yaml.Failure = .{};
    const parsed = pushReply(state, result, &failure);
    if (!parsed) c.lua_pushnil(state);
    _ = c.lua_pushlstring(state, result.ptr, result.len);
    allocator.free(result);
    if (parsed) return 2;
    _ = c.lua_pushfstring(state, "invalid YAML reply: %s", &failure.message);
    return 3;
}

/// Pushes the reply as a Lua table. libdcerpc writes the root line as `Name: Request`
/// above indented fields, which is not YAML, so that label is blanked on a copy.
fn pushReply(state: ?*c.lua_State, reply: []const u8, failure: *yaml.Failure) bool {
    const copy = allocator.dupe(u8, reply) catch return false;
    defer allocator.free(copy);
    if (std.mem.indexOfScalar(u8, copy, ':')) |colon| {
        const end = std.mem.indexOfScalarPos(u8, copy, colon, '\n') orelse copy.len;
        @memset(copy[colon + 1 .. end], ' ');
    }
    return yaml.push(state, copy, failure);
}

fn rawRequest(_: [*c]u8, _: ?*smb.dcerpc_context, _: ?*smb.dcerpc_pdu, iov: [*c]smb.dcerpc_iovec, offset: [*c]c_int, pointer: ?*anyopaque) callconv(.c) c_int {
    const request: *Raw = @ptrCast(@alignCast(pointer.?));
    const start: usize = @intCast(offset[0]);
    if (start + request.len > iov[0].len) return -1;
    if (request.data) |data| @memcpy(iov[0].buf[start..][0..request.len], data[0..request.len]);
    offset[0] += @intCast(request.len);
    return 0;
}

/// The reply coder: everything after the response header is the stub.
fn rawReply(_: [*c]u8, _: ?*smb.dcerpc_context, pdu: ?*smb.dcerpc_pdu, iov: [*c]smb.dcerpc_iovec, offset: [*c]c_int, pointer: ?*anyopaque) callconv(.c) c_int {
    const reply: *Raw = @ptrCast(@alignCast(pointer.?));
    const start: usize = @intCast(offset[0]);
    if (start > iov[0].len) return -1;
    reply.len = iov[0].len - start;
    reply.data = null;
    if (reply.len > 0) {
        const data: [*]u8 = @ptrCast(smb.dcerpc_alloc_data(pdu, reply.len) orelse return -1);
        @memcpy(data[0..reply.len], iov[0].buf[start..][0..reply.len]);
        reply.data = data;
    }
    offset[0] = @intCast(iov[0].len);
    return 0;
}

fn callRaw(session: *Session, opnum: u16, stub: []const u8) CallError![]u8 {
    const dce = session.dce.?;
    var request: Raw = .{ .data = @constCast(stub.ptr), .len = stub.len };
    if (smb.dcerpc_call_async(dce, opnum, rawRequest, &request, rawReply, @sizeOf(Raw), complete, &session.client.operation) != 0) return error.Failed;
    const done = session.client.pump();
    const reply = session.client.operation.data;
    defer if (reply) |data| smb.dcerpc_free_data(dce, data);
    if (!done or session.client.operation.status != 0) return error.Failed;
    const raw: *Raw = @ptrCast(@alignCast(reply.?));
    return allocator.dupe(u8, if (raw.data) |data| data[0..raw.len] else &.{});
}

/// Decodes the YAML request with libdcerpc's coders, calls, and encodes the reply.
fn callNamed(session: *Session, name: []const u8, request: []const u8) CallError![]u8 {
    const dce = session.dce.?;
    const procedure = findProcedure(session.service orelse return error.UnknownProcedure, name) orelse return error.UnknownProcedure;
    // libdcerpc names the root key; reject a mismatch here instead of in its decoder.
    const trimmed = std.mem.trimStart(u8, request, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, name) or !std.mem.startsWith(u8, trimmed[name.len..], ":")) return error.InvalidRequest;

    const input = smb.dcerpc_allocate_pdu(dce, smb.ENCODING_YAML, smb.DCERPC_DECODE, procedure.*.req_size) orelse return error.OutOfMemory;
    defer smb.dcerpc_free_pdu(dce, input);
    const text: [*]u8 = @ptrCast(smb.dcerpc_alloc_data(input, request.len + 1) orelse return error.OutOfMemory);
    @memcpy(text[0..request.len], request);
    text[request.len] = 0;
    var iov: smb.dcerpc_iovec = .{ .buf = text, .len = request.len + 1, .free = null };
    var offset: c_int = 0;
    const payload = smb.dcerpc_get_pdu_payload(input);
    if (smb.dcerpc_do_coder(@constCast(procedure.*.name), dce, input, &iov, &offset, payload, procedure.*.req_coder) != 0) return error.InvalidRequest;

    if (smb.dcerpc_call_async(dce, procedure.*.opnum, procedure.*.req_coder, payload, procedure.*.rep_coder, procedure.*.rep_size, complete, &session.client.operation) != 0) return error.Failed;
    const done = session.client.pump();
    const reply = session.client.operation.data;
    defer if (reply) |data| smb.dcerpc_free_data(dce, data);
    if (!done or session.client.operation.status != 0) return error.Failed;
    return encodeYaml(dce, procedure, procedure.*.rep_coder, reply.?);
}

/// `rpc:template(procedure)`: the request as YAML with every field zero, in the order
/// libdcerpc's decoder needs, to fill in.
fn templateLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const procedure = lua.stringAt(state, 2, "procedure");
    const result = template(session.dce.?, session.service, procedure) catch |err| switch (err) {
        error.UnknownProcedure => lua.raise(state, "unknown DCERPC procedure", .{}),
        error.OutOfMemory => lua.raise(state, "out of memory", .{}),
        else => lua.raise(state, "no YAML template for %s", .{procedure.ptr}),
    };
    _ = c.lua_pushlstring(state, result.ptr, result.len);
    allocator.free(result);
    return 1;
}

fn template(dce: ?*smb.dcerpc_context, service: ?*const smb.dcerpc_service, name: []const u8) CallError![]u8 {
    const procedure = findProcedure(service orelse return error.UnknownProcedure, name) orelse return error.UnknownProcedure;
    const empty = try allocator.alignedAlloc(u8, .@"16", @intCast(procedure.*.req_size));
    defer allocator.free(empty);
    @memset(empty, 0);
    return encodeYaml(dce, procedure, procedure.*.req_coder, empty.ptr);
}

fn encodeYaml(dce: ?*smb.dcerpc_context, procedure: *const smb.dcerpc_procedure, coder: smb.dcerpc_coder, data: *anyopaque) CallError![]u8 {
    var capacity: usize = 64 * 1024;
    while (capacity <= max_reply) : (capacity *= 2) {
        const output = try allocator.alloc(u8, capacity);
        @memset(output, 0);
        const pdu = smb.dcerpc_allocate_pdu(dce, smb.ENCODING_YAML, smb.DCERPC_ENCODE, 1) orelse {
            allocator.free(output);
            return error.OutOfMemory;
        };
        defer smb.dcerpc_free_pdu(dce, pdu);
        var iov: smb.dcerpc_iovec = .{ .buf = output.ptr, .len = capacity, .free = null };
        var offset: c_int = 0;
        const encoded = smb.dcerpc_do_coder(@constCast(procedure.name), dce, pdu, &iov, &offset, data, coder) == 0;
        defer allocator.free(output);
        if (encoded) return allocator.dupe(u8, output[0 .. std.mem.indexOfScalar(u8, output, 0) orelse capacity]);
    }
    return error.ReplyTooLarge;
}

fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.smb and session.dce != null) {
        // Destroying the context queues the pipe CLOSE ahead of the tree disconnect.
        smb.dcerpc_destroy_context(session.dce);
        session.dce = null;
        session.client.closeShare();
    }
    session.release();
    session.client.transport.close();
    return 0;
}

const checkSession = lua.liveChecker(Session, metatable, "dce", "DCERPC session is closed");

fn fail(state: ?*c.lua_State, session: *Session) noreturn {
    const timed_out = session.client.transport.timed_out;
    const message = c.lua_pushstring(state, session.client.errorText());
    session.release();
    session.client.transport.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "%s", .{message});
}

fn streamSend(context: ?*anyopaque, buffer: ?*const anyopaque, len: usize) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(context.?));
    var bytes = @as([*]u8, @ptrCast(@constCast(buffer.?)))[0..len];
    while (bytes.len > 0) {
        const sent = session.client.transport.transfer(.send, bytes, .{ .closed = -1, .want_read = -1, .failed = -1 });
        if (sent <= 0) return -1;
        bytes = bytes[@intCast(sent)..];
    }
    return 0;
}

fn streamRecv(context: ?*anyopaque, buffer: ?*anyopaque, len: usize) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(context.?));
    const bytes = @as([*]u8, @ptrCast(buffer.?))[0..len];
    const received = session.client.transport.transfer(.receive, bytes, .{ .closed = -1, .want_read = -1, .failed = -1 });
    return if (received > 0) received else -1;
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

/// Answers each request with the next canned reply, as a peer would.
const Fake = struct {
    replies: []const []const u8,
    sent: usize = 0,
    read: usize = 0,
    offset: usize = 0,

    fn recv(context: ?*anyopaque, buffer: ?*anyopaque, len: usize) callconv(.c) c_int {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        if (self.read >= self.sent or self.read >= self.replies.len) return -1;
        const reply = self.replies[self.read];
        const count = @min(len, reply.len - self.offset);
        @memcpy(@as([*]u8, @ptrCast(buffer.?))[0..count], reply[self.offset..][0..count]);
        self.offset += count;
        if (self.offset == reply.len) {
            self.read += 1;
            self.offset = 0;
        }
        return @intCast(count);
    }

    fn send(context: ?*anyopaque, _: ?*const anyopaque, _: usize) callconv(.c) c_int {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        self.sent += 1;
        return 0;
    }
};

/// A TCP-style session over `fake`, bound to `service_name`; returns whether the bind succeeded.
fn testSession(session: *Session, fake: *Fake, service_name: [*:0]const u8) bool {
    var service: [*c]const smb.dcerpc_service = smb.dcerpc_services;
    while (!std.mem.eql(u8, std.mem.span(service.*.name), std.mem.span(service_name))) : (service += 1) {}
    session.* = .{ .client = .{ .transport = .{ .vm = undefined, .socket = undefined } }, .syntax = service.*.interface.*, .service = service };
    session.client.context = smb.smb2_init_context();
    session.stream = .{ .send = Fake.send, .recv = Fake.recv, .@"opaque" = fake };
    session.dce = smb.dcerpc_create_context(session.client.context);
    smb.dcerpc_set_stream(session.dce, &session.stream);
    session.client.operation = .{};
    return smb.dcerpc_connect_context_async(session.dce, "", &session.syntax, complete, &session.client.operation) == 0 and
        session.client.operation.status == 0;
}

test "stream call splits a request larger than the peer's fragment size" {
    var fake: Fake = .{ .replies = &.{ &bind_ack, &call_reply } };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(testSession(&session, &fake, "srvsvc"));
    allocator.free(try callRaw(&session, 0, &(.{0xa5} ** 5000)));
    // The canned bind ack allows 4096-byte fragments: bind, then two request fragments.
    try std.testing.expectEqual(@as(usize, 3), fake.sent);
}

test "interface option parses a UUID and version" {
    const syntax = parseSyntax("e1af8308-5d1f-11c9-91a4-08002b14a0fa", "3.0").?;
    try std.testing.expectEqual(@as(u32, 0xe1af8308), syntax.uuid.v1);
    try std.testing.expectEqualSlices(u8, &.{ 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa }, &syntax.uuid.v4);
    try std.testing.expectEqual(@as(u16, 3), syntax.vers);
    try std.testing.expect(parseSyntax("e1af8308-5d1f-11c9-91a4", "3.0") == null);
    try std.testing.expect(parseSyntax("e1af8308-5d1f-11c9-91a4-08002b14a0fa", "3") == null);
}

test "stream raw call returns the reassembled reply stub" {
    var fake: Fake = .{ .replies = &.{ &bind_ack, &call_reply } };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(testSession(&session, &fake, "srvsvc"));
    session.client.operation = .{};
    const reply = try callRaw(&session, 0, "request");
    defer allocator.free(reply);
    try std.testing.expectEqualSlices(u8, &.{ 0x78, 0x56, 0x34, 0x12 }, reply);
}

// A real Windows 10 endpoint mapper exchange: the bind ack and a one-entry Lookup reply.
const epm_bind_ack = hex("05000c03100000003c00000002000000d016d016744e000004003133350038000100000000000000045d888aeb1cc9119fe808002b10486002000000");
const epm_lookup_reply = hex("0500020310000000c400000004000000ac000000000000000000000076a825e6472bf64eb6b7e1caeda1c43c01000000010000000000000001000000000000000000000000000000000000000100000000000000140000004e676320506f70204b65792053657276696365004b0000004b000000050013000dae27a2515b82f241b4a91ac9557a101801000200000013000d045d888aeb1cc9119fe808002b10486002000200000001000b020000000100070200c2000100090400c0a87af80000000000");

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var bytes: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable;
    return bytes;
}

test "endpoint mapper YAML call returns the tower" {
    var fake: Fake = .{ .replies = &.{ &epm_bind_ack, &epm_lookup_reply } };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(testSession(&session, &fake, "epmapper"));
    const request =
        \\Lookup: Request
        \\  InquiryType: 0
        \\  VersOption: 1
        \\  EntryHandle:
        \\    ContextHandleAttributes: 0
        \\    UUID: 00000000-0000-0000-0000-000000000000
        \\  MaxEnts: 1
        \\
    ;
    session.client.operation = .{};
    const reply = try callNamed(&session, "Lookup", request);
    defer allocator.free(reply);
    try std.testing.expect(std.mem.indexOf(u8, reply, "TowerOctetString: 050013000dae27a2515b82f2") != null);
    try std.testing.expectEqual(@as(usize, 2), fake.sent);

    // The same reply as a Lua table.
    const state = c.luaL_newstate().?;
    defer c.lua_close(state);
    c.luaL_openlibs(state);
    var failure: yaml.Failure = .{};
    try std.testing.expect(pushReply(state, reply, &failure));
    c.lua_setglobal(state, "reply");
    try lua.expectScript(state,
        \\local lookup = reply.Lookup
        \\assert(lookup.Status == 0 and lookup.NumEnts == 1)
        \\local entry = lookup.Entries[1]
        \\assert(entry.Annotation == "Ngc Pop Key Service" and entry.Tower.TowerLength == 75)
        \\assert(entry.Tower.TowerOctetString:sub(1, 16) == "050013000dae27a2")
    );
}

test "procedures have request templates except union-only ones" {
    const context = smb.smb2_init_context();
    defer smb.smb2_destroy_context(context);
    const dce = smb.dcerpc_create_context(context);
    defer smb.dcerpc_destroy_context(dce);
    var service: [*c]const smb.dcerpc_service = smb.dcerpc_services;
    while (service.*.name != null) : (service += 1) {
        var procedure: [*c]const smb.dcerpc_procedure = service.*.procs;
        while (procedure.*.name != null) : (procedure += 1) {
            // A union with no valid zero arm has no template: NetrFileEnum, NetrServerSetInfo, NetrWkstaSetInfo.
            const text = template(dce, service, std.mem.span(procedure.*.name)) catch continue;
            defer allocator.free(text);
            try std.testing.expect(std.mem.startsWith(u8, text, std.mem.span(procedure.*.name)));
        }
    }
    const lookup = try template(dce, smb.dcerpc_services + 4, "Lookup");
    defer allocator.free(lookup);
    try std.testing.expect(std.mem.indexOf(u8, lookup, "MaxEnts: 0") != null);
}

test "raw call returns the endpoint mapper's reply stub unchanged" {
    var fake: Fake = .{ .replies = &.{ &epm_bind_ack, &epm_lookup_reply } };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(testSession(&session, &fake, "epmapper"));
    session.client.operation = .{};
    const reply = try callRaw(&session, 2, &(.{0} ** 40));
    defer allocator.free(reply);
    try std.testing.expectEqualSlices(u8, epm_lookup_reply[24..], reply);
}

test "named call rejects a mismatched request and an unknown procedure" {
    var fake: Fake = .{ .replies = &.{&epm_bind_ack} };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(testSession(&session, &fake, "epmapper"));
    try std.testing.expectError(error.InvalidRequest, callNamed(&session, "Lookup", "Map: Request\n"));
    try std.testing.expectError(error.UnknownProcedure, callNamed(&session, "Nope", "Nope: Request\n"));
    try std.testing.expectEqual(@as(usize, 1), fake.sent);
}

test "stream bind fails on a closed stream" {
    var fake: Fake = .{ .replies = &.{bind_ack[0..8]} };
    var session: Session = undefined;
    defer session.release();
    try std.testing.expect(!testSession(&session, &fake, "srvsvc"));
}
