const std = @import("std");
const c = @import("c");
const lua = @import("../runtime/lua.zig");
const limits = @import("../limits.zig");

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.pushFunctions(state, .{
        .{ "request", requestLua },
        .{ "response", responseLua },
        .{ "parse_request", parseRequestLua },
        .{ "parse_response", parseResponseLua },
        .{ "dechunk", dechunkLua },
    });
    return 1;
}

// Encoders emit every field exactly as given: nothing is validated, added, or repaired.

fn requestLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    return message(state, &.{ lua.requiredString(state, 1, "method"), " ", lua.requiredString(state, 1, "path"), " HTTP/", version(state) });
}

fn responseLua(state: ?*c.lua_State) callconv(.c) c_int {
    c.luaL_checktype(state, 1, c.LUA_TTABLE);
    _ = c.lua_getfield(state, 1, "status");
    const code = lua.toBytes(state, -1) orelse lua.raise(state, "status must be a number or a string", .{});
    return message(state, &.{ "HTTP/", version(state), " ", code, " ", lua.optionalString(state, 1, "reason") orelse "" });
}

fn version(state: ?*c.lua_State) []const u8 {
    return lua.optionalString(state, 1, "version") orelse "1.1";
}

/// Pushes the message: the `start` line, each `{ name, value }` header, a blank
/// line, and the body. Field strings stay valid while the message table holds them.
fn message(state: ?*c.lua_State, start: []const []const u8) c_int {
    const headers = lua.tableField(state, 1, "headers");
    const body = lua.optionalString(state, 1, "body") orelse "";
    var buffer: lua.Buffer = undefined;
    buffer.init(state);
    for (start) |part| buffer.add(part);
    buffer.add("\r\n");
    if (headers) |list| buffer.addHeaders(list);
    buffer.add("\r\n");
    buffer.add(body);
    buffer.push();
    return 1;
}

const Headers = [limits.http_header_capacity]c.struct_phr_header;

fn parseRequestLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    var method: [*c]const u8 = null;
    var method_len: usize = 0;
    var path: [*c]const u8 = null;
    var path_len: usize = 0;
    var minor: c_int = 0;
    var headers: Headers = undefined;
    var count: usize = headers.len;
    const length = c.phr_parse_request(bytes.ptr, bytes.len, &method, &method_len, &path, &path_len, &minor, &headers, &count, 0);
    if (!parsed(state, length, "request")) return 1;
    c.lua_createtable(state, 0, 4);
    lua.setString(state, "method", method[0..method_len]);
    lua.setString(state, "path", path[0..path_len]);
    return finishParse(state, minor, headers[0..count], length);
}

fn parseResponseLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    var minor: c_int = 0;
    var status: c_int = 0;
    var reason: [*c]const u8 = null;
    var reason_len: usize = 0;
    var headers: Headers = undefined;
    var count: usize = headers.len;
    const length = c.phr_parse_response(bytes.ptr, bytes.len, &minor, &status, &reason, &reason_len, &headers, &count, 0);
    if (!parsed(state, length, "response")) return 1;
    c.lua_createtable(state, 0, 4);
    lua.setInteger(state, "status", status);
    lua.setString(state, "reason", reason[0..reason_len]);
    return finishParse(state, minor, headers[0..count], length);
}

/// Pushes nil for an incomplete head; raises for a malformed one.
fn parsed(state: ?*c.lua_State, length: c_int, kind: [*:0]const u8) bool {
    if (length == -2) {
        c.lua_pushnil(state);
        return false;
    }
    if (length < 0) lua.raise(state, "malformed HTTP %s head or more than %d headers", .{ kind, @as(c_int, limits.http_header_capacity) });
    return true;
}

/// Completes the table on top with version and headers, and returns it with the head length.
fn finishParse(state: ?*c.lua_State, minor: c_int, headers: []const c.struct_phr_header, length: c_int) c_int {
    _ = c.lua_pushfstring(state, "1.%d", minor);
    c.lua_setfield(state, -2, "version");
    c.lua_createtable(state, @intCast(headers.len), 0);
    var count: c.lua_Integer = 0;
    for (headers) |header| {
        // A folded continuation line is its own entry, with an empty name.
        c.lua_createtable(state, 2, 0);
        const name = if (header.name == null) "" else header.name[0..header.name_len];
        lua.pushBytes(state, name);
        c.lua_rawseti(state, -2, 1);
        lua.pushBytes(state, header.value[0..header.value_len]);
        c.lua_rawseti(state, -2, 2);
        count += 1;
        c.lua_rawseti(state, -2, count);
    }
    c.lua_setfield(state, -2, "headers");
    c.lua_pushinteger(state, length);
    return 2;
}

fn dechunkLua(state: ?*c.lua_State) callconv(.c) c_int {
    const bytes = lua.checkBytes(state, 1);
    // The decoder works in place, so it runs over a copy.
    const scratch: [*]u8 = @ptrCast(c.lua_newuserdatauv(state, @max(bytes.len, 1), 0).?);
    @memcpy(scratch[0..bytes.len], bytes);
    var decoder = std.mem.zeroes(c.struct_phr_chunked_decoder);
    decoder.consume_trailer = 1;
    var size = bytes.len;
    const rest = c.phr_decode_chunked(&decoder, @ptrCast(scratch), &size);
    if (rest == -2) {
        c.lua_pushnil(state);
        return 1;
    }
    if (rest < 0) return c.luaL_error(state, "malformed chunked body");
    lua.pushBytes(state, scratch[0..size]);
    lua.pushBytes(state, scratch[size..][0..@intCast(rest)]);
    return 2;
}

test "http encodes and parses heads, headers, and chunked bodies" {
    const state = lua.testState("protocols/http", module);
    defer c.lua_close(state);
    try lua.expectScript(state,
        \\local http = require("protocols/http")
        \\local request = http.request({ method = "GET", path = "/a", headers = { { "Host", "x" }, { "X-A", "1" }, { "X-A", "2" } } })
        \\assert(request == "GET /a HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n")
        \\local posted = http.request({ method = "POST", path = "/p", headers = { { "Content-Length", "4" } }, body = "data" })
        \\assert(posted == "POST /p HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata")
        \\local head, length = http.parse_request(request .. "body")
        \\assert(length == #request and head.method == "GET" and head.path == "/a" and head.version == "1.1")
        \\assert(#head.headers == 3 and head.headers[3][1] == "X-A" and head.headers[3][2] == "2")
        \\assert(http.parse_request("GET / HTTP/1.1\r\nHost:") == nil)
        \\assert(not pcall(http.parse_request, "GET / HTTP/1.1\r\nNo colon\r\n\r\n"))
        \\assert(http.request({ method = "A\r\nB", path = "" }) == "A\r\nB  HTTP/1.1\r\n\r\n")
        \\assert(not pcall(http.request, { method = "GET", path = "/", headers = { "Host: x" } }))
        \\local response = http.response({ status = 404, reason = "Not Found", version = "1.0", headers = { { "Content-Length", "2" } }, body = "no" })
        \\assert(response == "HTTP/1.0 404 Not Found\r\nContent-Length: 2\r\n\r\nno")
        \\local parsed, size = http.parse_response(response)
        \\assert(parsed.status == 404 and parsed.reason == "Not Found" and parsed.version == "1.0")
        \\assert(response:sub(size + 1) == "no" and parsed.headers[1][1] == "Content-Length")
        \\local folded = http.parse_response("HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n")
        \\assert(#folded.headers == 2 and folded.headers[2][1] == "" and folded.headers[2][2] == " b")
        \\local body, rest = http.dechunk("3\r\nabc\r\n2\r\nde\r\n0\r\n\r\nNEXT")
        \\assert(body == "abcde" and rest == "NEXT")
        \\assert(http.dechunk("3\r\nab") == nil)
        \\assert(not pcall(http.dechunk, "z\r\n"))
    );
}
