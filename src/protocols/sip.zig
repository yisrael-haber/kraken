const std = @import("std");
const c = @import("c");
const osip = @import("osip");
const lua = @import("../runtime/lua.zig");

// oSIP does the SIP: it parses a message and writes it back, and this module turns that
// into Lua tables and back. Like protocols/dns it does no I/O; the sockets, transactions
// and dialogs are the script's. oSIP parses each header into its own structure and writes
// them in its own order and spelling, so what comes back is oSIP's normal form of the
// message, not the bytes that arrived, and it refuses what it cannot parse.

/// Called once before any script runs: oSIP's parser keeps a table of header names.
pub fn init() void {
    _ = osip.parser_init();
}

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.pushFunctions(state, .{ .{ "encode", encodeLua }, .{ "decode", decodeLua } });
    return 1;
}

/// `sip.decode(bytes)`: the message as a table, `{ method, uri, version, headers, body }` for
/// a request or `{ status, reason, version, headers, body }` for a response, where `headers`
/// is oSIP's list of `{ name, value }` pairs. A message oSIP cannot parse raises an error.
fn decodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    var sip: ?*osip.osip_message_t = null;
    if (osip.osip_message_init(&sip) != osip.OSIP_SUCCESS) lua.raise(state, "SIP allocation failed", .{});
    var text: [*c]u8 = null;
    var length: usize = 0;
    var status = osip.osip_message_parse(sip, bytes.ptr, bytes.len);
    if (status == osip.OSIP_SUCCESS) status = osip.osip_message_to_str(sip, &text, &length);
    if (status != osip.OSIP_SUCCESS) {
        osip.osip_message_free(sip);
        lua.raise(state, "malformed SIP message (oSIP error %d)", .{@as(c_int, status)});
    }
    const message = sip.?;
    c.lua_createtable(state, 0, 6);
    if (message.sip_method != null) {
        var uri: [*c]u8 = null;
        _ = osip.osip_uri_to_str(message.req_uri, &uri);
        lua.setString(state, "method", std.mem.span(message.sip_method));
        lua.setString(state, "uri", if (uri != null) std.mem.span(uri) else "");
        std.c.free(uri);
    } else {
        lua.setInteger(state, "status", message.status_code);
        lua.setString(state, "reason", if (message.reason_phrase != null) std.mem.span(message.reason_phrase) else "");
    }
    lua.setString(state, "version", if (message.sip_version != null) std.mem.span(message.sip_version) else "");
    pushHeadersAndBody(state, text[0..length]);
    std.c.free(text);
    osip.osip_message_free(sip);
    return 1;
}

/// Sets `headers` and `body` on the table at the stack top from oSIP's text of the message:
/// the start line, header lines, a blank line and the body.
fn pushHeadersAndBody(state: ?*c.lua_State, text: []const u8) void {
    const end = std.mem.indexOf(u8, text, "\r\n\r\n") orelse text.len;
    var lines = std.mem.splitSequence(u8, text[0..end], "\r\n");
    _ = lines.next();
    c.lua_createtable(state, 8, 0);
    var count: c.lua_Integer = 0;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        c.lua_createtable(state, 2, 0);
        lua.pushBytes(state, line[0..colon]);
        c.lua_rawseti(state, -2, 1);
        lua.pushBytes(state, std.mem.trimStart(u8, line[colon + 1 ..], " \t"));
        c.lua_rawseti(state, -2, 2);
        count += 1;
        c.lua_rawseti(state, -2, count);
    }
    c.lua_setfield(state, -2, "headers");
    lua.setString(state, "body", if (end + 4 <= text.len) text[end + 4 ..] else "");
}

/// `sip.encode(message)`: the bytes of a message table, as oSIP writes them. A table with
/// `status` is a response (with `reason`) and one with `method` and `uri` is a request;
/// `version` is the text after `SIP/`, `"2.0"` by default. `headers` is a list of
/// `{ name, value }` pairs and `body` a string. oSIP parses the message first and a message
/// it cannot parse raises an error; it adds Content-Length when there is none. oSIP drops a
/// body that has no Content-Type when it parses one, so a body needs that header.
fn encodeLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    const version = lua.optionalString(state, 1, "version") orelse "2.0";
    const headers = lua.tableField(state, 1, "headers");
    var buffer: lua.Buffer = undefined;
    buffer.init(state);
    if (lua.field(state, 1, "status", c.LUA_TNUMBER)) {
        if (c.lua_isinteger(state, -1) == 0) lua.raise(state, "status must be an integer", .{});
        var number: [24]u8 = undefined;
        const code = std.fmt.bufPrint(&number, "{d}", .{c.lua_tointegerx(state, -1, null)}) catch unreachable;
        c.lua_pop(state, 1);
        for ([_][]const u8{ "SIP/", version, " ", code, " ", lua.optionalString(state, 1, "reason") orelse "" }) |piece| buffer.add(piece);
    } else {
        for ([_][]const u8{ lua.requiredString(state, 1, "method"), " ", lua.requiredString(state, 1, "uri"), " SIP/", version }) |piece| buffer.add(piece);
    }
    buffer.add("\r\n");
    if (headers) |list| buffer.addHeaders(list);
    buffer.add("\r\n");
    buffer.push();
    const head = lua.toBytes(state, -1).?;
    const body = lua.optionalString(state, 1, "body");

    var sip: ?*osip.osip_message_t = null;
    if (osip.osip_message_init(&sip) != osip.OSIP_SUCCESS) lua.raise(state, "SIP allocation failed", .{});
    var text: [*c]u8 = null;
    var length: usize = 0;
    var status = osip.osip_message_parse(sip, head.ptr, head.len);
    if (status == osip.OSIP_SUCCESS) if (body) |bytes| {
        status = osip.osip_message_set_body(sip, bytes.ptr, bytes.len);
    };
    if (status == osip.OSIP_SUCCESS) status = osip.osip_message_to_str(sip, &text, &length);
    osip.osip_message_free(sip);
    if (status != osip.OSIP_SUCCESS) lua.raise(state, "oSIP rejected the message (error %d)", .{@as(c_int, status)});
    lua.pushBytes(state, text[0..length]);
    std.c.free(text);
    return 1;
}

test "sip decodes and encodes messages through oSIP" {
    init();
    const state = lua.testState("protocols/sip", module);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local sip = require("protocols/sip")
        \\local invite = "INVITE sip:bob@192.0.2.2 SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n"
        \\    .. "Via: SIP/2.0/UDP 192.0.2.9\r\nMax-Forwards: 70\r\nf: <sip:a@x>;tag=1\r\nt: <sip:b@y>\r\ni: abc@x\r\n"
        \\    .. "CSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nl: 4\r\n\r\nv=0\n"
        \\local message = sip.decode(invite)
        \\assert(message.method == "INVITE" and message.uri == "sip:bob@192.0.2.2" and message.version == "SIP/2.0")
        \\assert(message.body == "v=0\n" and message.status == nil)
        \\-- oSIP's normal form: compact names expanded, one Via per line.
        \\assert(#message.headers == 9 and message.headers[1][1] == "Via" and message.headers[2][1] == "Via" and message.headers[8][1] == "Max-forwards")
        \\assert(message.headers[1][2] == "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1")
        \\assert(message.headers[5][2] == "abc@x" and message.headers[9][2] == "4")
        \\local response = sip.decode("SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=1\r\n"
        \\    .. "To: <sip:b@y>;tag=2\r\nCall-ID: abc@x\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
        \\assert(response.status == 180 and response.reason == "Ringing" and response.method == nil and response.body == "")
        \\-- Encoding goes through oSIP too, and adds the Content-Length that is missing.
        \\local bytes = sip.encode({ status = 200, reason = "OK", headers = { { "Via", "SIP/2.0/UDP 192.0.2.1" },
        \\    { "From", "<sip:a@x>;tag=1" }, { "To", "<sip:b@y>" }, { "Call-ID", "1" }, { "CSeq", "1 OPTIONS" },
        \\    { "Content-Type", "text/plain" } }, body = "hello" })
        \\assert(bytes:find("^SIP/2.0 200 OK\r\n") and bytes:find("Content%-Length: +5\r\n") and bytes:sub(-9) == "\r\n\r\nhello")
        \\assert(sip.decode(bytes).body == "hello")
        \\local request = sip.encode({ method = "OPTIONS", uri = "sip:a@192.0.2.1", headers = { { "Via", "SIP/2.0/UDP 192.0.2.1" },
        \\    { "From", "<sip:a@x>;tag=1" }, { "To", "<sip:b@y>" }, { "Call-ID", "1" }, { "CSeq", "1 OPTIONS" } } })
        \\assert(sip.decode(request).method == "OPTIONS")
        \\assert(#sip.encode({ method = "OPTIONS", uri = "sip:a", headers = { { "Subject", string.rep("a", 2000) } } }) > 2000)
        \\-- What oSIP cannot parse raises.
        \\assert(not pcall(sip.decode, "this is not sip\r\n\r\n"))
        \\assert(not pcall(sip.decode, "OPTIONS sip:a SIP/2.0\r\nVia: ???\r\n\r\n"))
        \\assert(not pcall(sip.encode, { method = "A", uri = "b" }))
        \\assert(not pcall(sip.encode, { method = "A" }))
        \\assert(not pcall(sip.encode, { status = "200" }))
        \\assert(not pcall(sip.encode, { method = "A", uri = "b", headers = { "Via: x" } }))
    );
}
