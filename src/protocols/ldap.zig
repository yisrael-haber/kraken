const c = @import("c");
const std = @import("std");
const builtin = @import("builtin");
const ldap = @import("ldap");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const Connection = @import("connection.zig").Connection;

// libldap does the protocol. Kraken gives it a connected TCP socket through a
// Sockbuf_IO handler (ldap_init_fd with LDAP_PROTO_EXT, libldap's own seam for a
// caller-supplied transport) and pumps its asynchronous API: send an operation,
// then take one result message at a time with a zero-timeout ldap_result.
//
// libldap waits for replies with poll() on a descriptor, and Kraken's sockets
// have none. So before each ldap_result the session blocks on its socket until a
// byte has arrived, which makes libldap's "data ready" check true and skips its
// poll; and the handler's read returns exactly the bytes libldap asks for, so a
// message never arrives half-read. A session is poisoned by a timeout or a failed
// transfer, like the other protocol sessions.

const metatable = "kraken.ldap";
const rx_capacity = 16 * 1024;
const LDAPMod = ldap.LDAPMod;

const Session = struct {
    connection: Connection = undefined,
    ld: ?*ldap.LDAP = null,
    /// Bytes read ahead of libldap, which drains them before reading the socket.
    rx: [rx_capacity]u8 = undefined,
    rx_pos: usize = 0,
    rx_len: usize = 0,
    /// Set while releasing without protocol I/O (garbage collection).
    mute: bool = false,

    /// Blocks until at least one byte is buffered; false when the stream failed.
    fn fill(self: *Session) bool {
        if (self.rx_pos < self.rx_len) return true;
        const received = self.connection.transfer(.receive, &self.rx);
        if (received <= 0) return false;
        self.rx_pos = 0;
        self.rx_len = @intCast(received);
        return true;
    }

    fn release(self: *Session) void {
        const connection = self.ld orelse return;
        self.ld = null;
        self.mute = true;
        _ = ldap.ldap_unbind_ext(connection, null, null);
    }
};

const Message = struct { message: *ldap.LDAPMessage, kind: c_int };

/// struct timeval, which ldap.h only forward-declares: a zero timeout for ldap_result.
const Timeval = extern struct { sec: c_long = 0, usec: c_long = 0 };

// The Sockbuf_IO handler: libldap's reads and writes, and its readiness query.

fn sessionOf(sbiod: [*c]ldap.Sockbuf_IO_Desc) *Session {
    return @ptrCast(@alignCast(sbiod.*.sbiod_pvt.?));
}

fn connectionReset() void {
    if (builtin.os.tag == .windows) {
        const WSASetLastError = struct {
            extern "ws2_32" fn WSASetLastError(code: c_int) callconv(.winapi) void;
        }.WSASetLastError;
        WSASetLastError(10054);
    } else {
        const errnoLocation = struct {
            extern "c" fn __errno_location() *c_int;
        }.__errno_location;
        errnoLocation().* = 104;
    }
}

fn ioSetup(sbiod: [*c]ldap.Sockbuf_IO_Desc, argument: ?*anyopaque) callconv(.c) c_int {
    sbiod.*.sbiod_pvt = argument;
    return 0;
}

fn ioRead(sbiod: [*c]ldap.Sockbuf_IO_Desc, buffer: ?*anyopaque, length: ldap.ber_len_t) callconv(.c) ldap.ber_slen_t {
    const session = sessionOf(sbiod);
    const out = @as([*]u8, @ptrCast(buffer.?))[0..length];
    const buffered = @min(session.rx_len - session.rx_pos, out.len);
    @memcpy(out[0..buffered], session.rx[session.rx_pos..][0..buffered]);
    session.rx_pos += buffered;
    var done = buffered;
    while (done < out.len) {
        const received = session.connection.transfer(.receive, out[done..]);
        if (received <= 0) {
            connectionReset();
            return -1;
        }
        done += @intCast(received);
    }
    return @intCast(done);
}

fn ioWrite(sbiod: [*c]ldap.Sockbuf_IO_Desc, buffer: ?*anyopaque, length: ldap.ber_len_t) callconv(.c) ldap.ber_slen_t {
    const session = sessionOf(sbiod);
    if (session.mute) return @intCast(length);
    var rest = @as([*]u8, @ptrCast(buffer.?))[0..length];
    while (rest.len > 0) {
        const sent = session.connection.transfer(.send, rest);
        if (sent <= 0) {
            connectionReset();
            return -1;
        }
        rest = rest[@intCast(sent)..];
    }
    return @intCast(length);
}

fn ioControl(sbiod: [*c]ldap.Sockbuf_IO_Desc, option: c_int, _: ?*anyopaque) callconv(.c) c_int {
    if (option == ldap.LBER_SB_OPT_DATA_READY) {
        const session = sessionOf(sbiod);
        return @intFromBool(session.rx_pos < session.rx_len);
    }
    return 0;
}

fn ioClose(_: [*c]ldap.Sockbuf_IO_Desc) callconv(.c) c_int {
    return 0;
}

var io: ldap.Sockbuf_IO = .{ .sbi_setup = ioSetup, .sbi_ctrl = ioControl, .sbi_read = ioRead, .sbi_write = ioWrite, .sbi_close = ioClose };

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn _putenv_s(name: [*:0]const u8, value: [*:0]const u8) c_int;

/// Called once before any script runs. LDAPNOINIT keeps libldap from reading
/// ldap.conf, ~/.ldaprc and the LDAP* environment, so a session behaves the same
/// on every machine.
pub fn init() void {
    if (builtin.os.tag == .windows) _ = _putenv_s("LDAPNOINIT", "1") else _ = setenv("LDAPNOINIT", "1", 1);
}

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "bind", bindLua },       .{ "search", searchLua },     .{ "add", addLua },
        .{ "modify", modifyLua },   .{ "delete", deleteLua },     .{ "rename", renameLua },
        .{ "compare", compareLua }, .{ "extended", extendedLua }, .{ "close", closeLua },
    }, collectLua);
    lua.pushFunctions(state, .{.{ "connect", connectLua }});
    return 1;
}

/// `ldap.connect(tcp)` or `ldap.connect(tls_session)`: an LDAPv3 session over a connected
/// TCP socket, or over a `protocols/tls` session for LDAPS. Nothing is sent until the first
/// operation; the session is anonymous until `bind`.
fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = stream.new(state, metatable, Session{ .connection = Connection.fromLua(state) });
    open(state, session);
    return 1;
}

/// libldap takes the descriptor -1 to mean "not connected" and would open a
/// connection of its own. Kraken has no descriptor, so it gets one that is never used.
const placeholder_descriptor: ldap.ber_socket_t = std.math.maxInt(c_int) - 1;

fn open(state: ?*c.lua_State, session: *Session) void {
    var connection: ?*ldap.LDAP = null;
    if (ldap.ldap_init_fd(placeholder_descriptor, ldap.LDAP_PROTO_EXT, null, &connection) != ldap.LDAP_SUCCESS) lua.raise(state, "LDAP initialization failed", .{});
    session.ld = connection;
    var version: c_int = ldap.LDAP_VERSION3;
    _ = ldap.ldap_set_option(connection, ldap.LDAP_OPT_PROTOCOL_VERSION, &version);
    // Referrals would make libldap open its own connections from the host.
    _ = ldap.ldap_set_option(connection, ldap.LDAP_OPT_REFERRALS, null);
    var sockbuf: ?*ldap.Sockbuf = null;
    _ = ldap.ldap_get_option(connection, ldap.LDAP_OPT_SOCKBUF, @ptrCast(&sockbuf));
    _ = ldap.ber_sockbuf_add_io(sockbuf, &io, ldap.LBER_SBIOD_LEVEL_PROVIDER, session);
}

fn checkSession(state: ?*c.lua_State) *Session {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ld == null) lua.raise(state, "LDAP session is closed", .{});
    return session;
}

/// Starts the call's deadline at the timeout argument.
fn begin(state: ?*c.lua_State, session: *Session, index: c_int) void {
    session.connection.begin(socket.luaTimeout(state, index));
}

fn closeLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = lua.checkUserdata(state, 1, Session, metatable);
    if (session.ld != null) {
        session.connection.begin(stream.close_timeout);
        const connection = session.ld;
        session.ld = null;
        _ = ldap.ldap_unbind_ext(connection, null, null);
    }
    session.connection.close();
    return 0;
}

fn collectLua(state: ?*c.lua_State) callconv(.c) c_int {
    lua.checkUserdata(state, 1, Session, metatable).release();
    return 0;
}

/// A transfer failed or timed out: the session cannot continue.
fn fail(state: ?*c.lua_State, session: *Session) noreturn {
    const timed_out = session.connection.timedOut();
    var message: [128:0]u8 = @splat(0);
    if (session.ld) |connection| {
        var code: c_int = 0;
        _ = ldap.ldap_get_option(connection, ldap.LDAP_OPT_RESULT_CODE, &code);
        _ = std.fmt.bufPrintZ(&message, "{s}", .{std.mem.span(ldap.ldap_err2string(code))}) catch {};
    }
    session.release();
    session.connection.close();
    if (timed_out) socket.raiseTimeout(state);
    lua.raise(state, "LDAP connection failed: %s", .{&message});
}

/// The next message for `msgid`, blocking on the socket until one is complete.
fn nextMessage(session: *Session, msgid: c_int) ?Message {
    while (true) {
        if (!session.fill()) return null;
        const before = session.rx_pos;
        var message: ?*ldap.LDAPMessage = null;
        var none: Timeval = .{};
        const kind = ldap.ldap_result(session.ld, msgid, ldap.LDAP_MSG_ONE, @ptrCast(&none), &message);
        if (kind > 0) return .{ .message = message.?, .kind = kind };
        // Nothing usable arrived and libldap read nothing: it will not make progress.
        if (kind < 0 or session.rx_pos == before) return null;
    }
}

/// The result of an operation sent with `ldap_*_ext`: its message, or a raised failure.
fn awaitResult(state: ?*c.lua_State, session: *Session, sent: c_int, msgid: c_int) *ldap.LDAPMessage {
    if (sent != ldap.LDAP_SUCCESS) fail(state, session);
    const reply = nextMessage(session, msgid) orelse fail(state, session);
    return reply.message;
}

/// Parses and frees a result message. Returns its LDAP result code; the matched DN
/// and diagnostic message are copied into `text` as "diagnostic" (possibly empty).
fn parseResult(state: ?*c.lua_State, session: *Session, message: *ldap.LDAPMessage, text: *[256:0]u8) c_int {
    var code: c_int = 0;
    var matched: [*c]u8 = null;
    var diagnostic: [*c]u8 = null;
    const parsed = ldap.ldap_parse_result(session.ld, message, &code, &matched, &diagnostic, null, null, 1);
    if (parsed != ldap.LDAP_SUCCESS) fail(state, session);
    text[0] = 0;
    if (diagnostic != null) {
        _ = std.fmt.bufPrintZ(text, "{s}", .{std.mem.span(diagnostic)}) catch {};
        ldap.ldap_memfree(diagnostic);
    }
    if (matched != null) ldap.ldap_memfree(matched);
    return code;
}

/// Raises the failure of operation `what` with result `code`; the session stays open.
fn raiseResult(state: ?*c.lua_State, what: [*:0]const u8, code: c_int, text: *const [256:0]u8) noreturn {
    const reason = ldap.ldap_err2string(code);
    if (text[0] == 0) lua.raise(state, "LDAP %s failed: %s (%d)", .{ what, reason, code });
    lua.raise(state, "LDAP %s failed: %s (%d): %s", .{ what, reason, code, text });
}

/// Waits for an operation's single result and raises unless it succeeded.
fn expectSuccess(state: ?*c.lua_State, session: *Session, sent: c_int, msgid: c_int, what: [*:0]const u8) void {
    const message = awaitResult(state, session, sent, msgid);
    var text: [256:0]u8 = @splat(0);
    const code = parseResult(state, session, message, &text);
    if (code != ldap.LDAP_SUCCESS) raiseResult(state, what, code, &text);
}

fn bytesOf(value: []const u8) ldap.struct_berval {
    return .{ .bv_len = @intCast(value.len), .bv_val = @constCast(value.ptr) };
}

/// `conn:bind(dn, password [, timeout_ms])`: a simple bind; empty strings bind
/// anonymously.
fn bindLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    const password = lua.stringAt(state, 3, "password");
    begin(state, session, 4);
    var credentials = bytesOf(password);
    var msgid: c_int = 0;
    const sent = ldap.ldap_sasl_bind(session.ld, dn.ptr, ldap.LDAP_SASL_SIMPLE, &credentials, null, null, &msgid);
    expectSuccess(state, session, sent, msgid, "bind");
    return 0;
}

const scopes = [_]struct { name: []const u8, value: c_int }{
    .{ .name = "base", .value = ldap.LDAP_SCOPE_BASE },
    .{ .name = "one", .value = ldap.LDAP_SCOPE_ONELEVEL },
    .{ .name = "sub", .value = ldap.LDAP_SCOPE_SUBTREE },
    .{ .name = "children", .value = ldap.LDAP_SCOPE_CHILDREN },
};

/// `conn:search{ base, scope, filter, attributes, limit, types_only } [, timeout_ms]`:
/// an array of entries `{ dn = "...", attributes = { name = { value, ... } } }`, then
/// the referral URLs the server returned, if any. `scope` is "base", "one", "sub"
/// (the default) or "children"; `filter` defaults to "(objectClass=*)".
fn searchLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    c.luaL_checktype(state, 2, c.LUA_TTABLE);
    const base = lua.optionalString(state, 2, "base") orelse "";
    const filter = lua.optionalString(state, 2, "filter") orelse "(objectClass=*)";
    const scope = scopeOf(state, lua.optionalString(state, 2, "scope") orelse "sub");
    const limit = integerField(state, 2, "limit");
    const types_only = lua.optionalBoolean(state, 2, "types_only");
    // Scratch memory goes on the stack, so the timeout argument is read first.
    begin(state, session, 3);
    const attributes = attributeList(state, 2);

    var msgid: c_int = 0;
    const sent = ldap.ldap_search_ext(session.ld, base.ptr, scope, filter.ptr, attributes, @intFromBool(types_only), null, null, null, limit, &msgid);
    if (sent != ldap.LDAP_SUCCESS) fail(state, session);

    c.lua_createtable(state, 0, 0);
    const entries = c.lua_gettop(state);
    c.lua_createtable(state, 0, 0);
    const references = c.lua_gettop(state);
    var entry_count: c_int = 0;
    var reference_count: c_int = 0;
    while (true) {
        const reply = nextMessage(session, msgid) orelse fail(state, session);
        switch (reply.kind) {
            @as(c_int, @intCast(ldap.LDAP_RES_SEARCH_ENTRY)) => {
                entry_count += 1;
                pushEntry(state, session.ld, reply.message);
                c.lua_rawseti(state, entries, entry_count);
                _ = ldap.ldap_msgfree(reply.message);
            },
            @as(c_int, @intCast(ldap.LDAP_RES_SEARCH_REFERENCE)) => {
                var urls: [*c][*c]u8 = null;
                if (ldap.ldap_parse_reference(session.ld, reply.message, &urls, null, 0) == ldap.LDAP_SUCCESS and urls != null) {
                    var index: usize = 0;
                    while (urls[index] != null) : (index += 1) {
                        reference_count += 1;
                        _ = c.lua_pushstring(state, urls[index]);
                        c.lua_rawseti(state, references, reference_count);
                    }
                    ldap.ber_memvfree(@ptrCast(urls));
                }
                _ = ldap.ldap_msgfree(reply.message);
            },
            else => {
                var text: [256:0]u8 = @splat(0);
                const code = parseResult(state, session, reply.message, &text);
                // A size limit still returns the entries received so far.
                if (code != ldap.LDAP_SUCCESS and code != ldap.LDAP_SIZELIMIT_EXCEEDED) raiseResult(state, "search", code, &text);
                break;
            },
        }
    }
    c.lua_settop(state, references);
    if (reference_count == 0) c.lua_pop(state, 1);
    return if (reference_count == 0) 1 else 2;
}

fn scopeOf(state: ?*c.lua_State, name: []const u8) c_int {
    for (scopes) |scope| if (std.mem.eql(u8, scope.name, name)) return scope.value;
    lua.raise(state, "scope must be \"base\", \"one\", \"sub\" or \"children\"", .{});
}

fn integerField(state: ?*c.lua_State, table: c_int, name: [*:0]const u8) c_int {
    if (!lua.field(state, table, name, c.LUA_TNUMBER)) return 0;
    defer c.lua_pop(state, 1);
    const value = c.lua_tointegerx(state, -1, null);
    if (value < 0 or value > std.math.maxInt(c_int)) lua.raise(state, "%s must be a non-negative integer", .{name});
    return @intCast(value);
}

/// A NULL-terminated array of the strings in `table.attributes`, in Lua-owned memory,
/// or null when it is absent.
fn attributeList(state: ?*c.lua_State, table: c_int) [*c][*c]u8 {
    if (!lua.field(state, table, "attributes", c.LUA_TTABLE)) return null;
    const count: usize = @intCast(c.lua_rawlen(state, -1));
    const memory: [*][*c]u8 = @ptrCast(@alignCast(c.lua_newuserdatauv(state, (count + 1) * @sizeOf([*c]u8), 0)));
    for (0..count) |index| {
        _ = c.lua_rawgeti(state, -2, @intCast(index + 1));
        if (c.lua_type(state, -1) != c.LUA_TSTRING) lua.raise(state, "attributes must be strings", .{});
        memory[index] = @constCast(c.lua_tolstring(state, -1, null));
        c.lua_pop(state, 1);
    }
    memory[count] = null;
    // The array table stays referenced by the options table, and so do its strings.
    c.lua_remove(state, -2);
    return memory;
}

/// Pushes `{ dn = ..., attributes = { name = { value, ... } } }` for an entry.
fn pushEntry(state: ?*c.lua_State, connection: ?*ldap.LDAP, entry: ?*ldap.LDAPMessage) void {
    c.lua_createtable(state, 0, 2);
    const dn = ldap.ldap_get_dn(connection, entry);
    if (dn != null) {
        _ = c.lua_pushstring(state, dn);
        c.lua_setfield(state, -2, "dn");
        ldap.ldap_memfree(dn);
    }
    c.lua_createtable(state, 0, 8);
    var position: ?*ldap.BerElement = null;
    var name = ldap.ldap_first_attribute(connection, entry, &position);
    while (name != null) : (name = ldap.ldap_next_attribute(connection, entry, position)) {
        c.lua_createtable(state, 0, 0);
        const values = ldap.ldap_get_values_len(connection, entry, name);
        if (values != null) {
            var index: usize = 0;
            while (values[index] != null) : (index += 1) {
                _ = c.lua_pushlstring(state, values[index].*.bv_val, values[index].*.bv_len);
                c.lua_rawseti(state, -2, @intCast(index + 1));
            }
            ldap.ldap_value_free_len(values);
        }
        c.lua_setfield(state, -2, name);
        ldap.ldap_memfree(name);
    }
    if (position != null) ldap.ber_free(position, 0);
    c.lua_setfield(state, -2, "attributes");
}

/// The values at stack `index`, a string or an array of strings, counted for building.
fn valueCount(state: ?*c.lua_State, index: c_int) usize {
    if (c.lua_type(state, index) == c.LUA_TSTRING) return 1;
    if (c.lua_type(state, index) != c.LUA_TTABLE) lua.raise(state, "values must be a string or an array of strings", .{});
    const count: usize = @intCast(c.lua_rawlen(state, index));
    for (1..count + 1) |position| {
        _ = c.lua_rawgeti(state, index, @intCast(position));
        if (c.lua_type(state, -1) != c.LUA_TSTRING) lua.raise(state, "values must be strings", .{});
        c.lua_pop(state, 1);
    }
    return count;
}

/// A Lua-owned buffer carved up as the LDAPMod array being built.
const Mods = struct {
    items: [*c][*c]LDAPMod,
    arena: std.heap.FixedBufferAllocator,

    /// Memory for `mods` modifications holding `values` values in all. Raises on a
    /// malformed argument before allocating anything.
    fn create(state: ?*c.lua_State, mods: usize, values: usize) Mods {
        const size = (mods + 1) * @sizeOf([*c]LDAPMod) + mods * (@sizeOf(LDAPMod) + @sizeOf([*c]ldap.struct_berval) + 64) +
            values * (@sizeOf(ldap.struct_berval) + @sizeOf([*c]ldap.struct_berval)) + 64;
        const memory: [*]u8 = @ptrCast(c.lua_newuserdatauv(state, size, 0));
        var arena = std.heap.FixedBufferAllocator.init(memory[0..size]);
        const items = arena.allocator().alloc([*c]LDAPMod, mods + 1) catch unreachable;
        items[mods] = null;
        return .{ .items = items.ptr, .arena = arena };
    }

    /// Slot `index`: operation `operation`, attribute `name`, and the values at stack `source`.
    fn set(self: *Mods, state: ?*c.lua_State, index: usize, operation: c_int, name: [*c]const u8, source: c_int) void {
        const allocator = self.arena.allocator();
        const mod = allocator.create(LDAPMod) catch unreachable;
        const count = valueCount(state, source);
        const values = allocator.alloc([*c]ldap.struct_berval, count + 1) catch unreachable;
        for (0..count) |position| {
            const value = allocator.create(ldap.struct_berval) catch unreachable;
            if (c.lua_type(state, source) == c.LUA_TSTRING) {
                _ = c.lua_pushvalue(state, source);
            } else {
                _ = c.lua_rawgeti(state, source, @intCast(position + 1));
            }
            var length: usize = 0;
            const bytes = c.lua_tolstring(state, -1, &length);
            c.lua_pop(state, 1);
            value.* = .{ .bv_len = @intCast(length), .bv_val = @constCast(bytes) };
            values[position] = value;
        }
        values[count] = null;
        mod.* = .{ .mod_op = operation | ldap.LDAP_MOD_BVALUES, .mod_type = @constCast(name), .mod_vals = .{ .modv_bvals = values.ptr } };
        self.items[index] = mod;
    }
};

/// `conn:add(dn, entry [, timeout_ms])`: `entry` maps attribute names to a string or an
/// array of strings.
fn addLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    c.luaL_checktype(state, 3, c.LUA_TTABLE);
    begin(state, session, 4);
    var attributes: usize = 0;
    var values: usize = 0;
    c.lua_pushnil(state);
    while (c.lua_next(state, 3) != 0) {
        if (c.lua_type(state, -2) != c.LUA_TSTRING) lua.raise(state, "attribute names must be strings", .{});
        attributes += 1;
        values += valueCount(state, -1);
        c.lua_pop(state, 1);
    }
    var mods = Mods.create(state, attributes, values);
    var index: usize = 0;
    c.lua_pushnil(state);
    while (c.lua_next(state, 3) != 0) : (index += 1) {
        mods.set(state, index, ldap.LDAP_MOD_ADD, c.lua_tolstring(state, -2, null), c.lua_gettop(state));
        c.lua_pop(state, 1);
    }
    var msgid: c_int = 0;
    const sent = ldap.ldap_add_ext(session.ld, dn.ptr, mods.items, null, null, &msgid);
    expectSuccess(state, session, sent, msgid, "add");
    return 0;
}

const operations = [_]struct { name: []const u8, value: c_int }{
    .{ .name = "add", .value = ldap.LDAP_MOD_ADD },
    .{ .name = "delete", .value = ldap.LDAP_MOD_DELETE },
    .{ .name = "replace", .value = ldap.LDAP_MOD_REPLACE },
};

/// `conn:modify(dn, changes [, timeout_ms])`: `changes` is an array of
/// `{ op = "add" | "delete" | "replace", attribute = "...", values = { ... } }`, applied in
/// order. A "delete" with no values removes the attribute.
fn modifyLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    c.luaL_checktype(state, 3, c.LUA_TTABLE);
    begin(state, session, 4);
    const count: usize = @intCast(c.lua_rawlen(state, 3));
    var values: usize = 0;
    for (1..count + 1) |position| {
        _ = c.lua_rawgeti(state, 3, @intCast(position));
        if (c.lua_type(state, -1) != c.LUA_TTABLE) lua.raise(state, "each change must be a table", .{});
        _ = lua.requiredString(state, -1, "attribute");
        _ = operationOf(state, -1);
        if (c.lua_getfield(state, -1, "values") != c.LUA_TNIL) values += valueCount(state, -1);
        c.lua_pop(state, 2);
    }
    var mods = Mods.create(state, count, values);
    for (0..count) |index| {
        _ = c.lua_rawgeti(state, 3, @intCast(index + 1));
        const attribute = lua.requiredString(state, -1, "attribute");
        const operation = operationOf(state, -1);
        if (c.lua_getfield(state, -1, "values") == c.LUA_TNIL) {
            c.lua_pop(state, 1);
            c.lua_createtable(state, 0, 0);
        }
        mods.set(state, index, operation, attribute.ptr, c.lua_gettop(state));
        c.lua_pop(state, 2);
    }
    var msgid: c_int = 0;
    const sent = ldap.ldap_modify_ext(session.ld, dn.ptr, mods.items, null, null, &msgid);
    expectSuccess(state, session, sent, msgid, "modify");
    return 0;
}

fn operationOf(state: ?*c.lua_State, change: c_int) c_int {
    const name = lua.requiredString(state, change, "op");
    for (operations) |operation| if (std.mem.eql(u8, operation.name, name)) return operation.value;
    lua.raise(state, "op must be \"add\", \"delete\" or \"replace\"", .{});
}

/// `conn:delete(dn [, timeout_ms])`.
fn deleteLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    begin(state, session, 3);
    var msgid: c_int = 0;
    const sent = ldap.ldap_delete_ext(session.ld, dn.ptr, null, null, &msgid);
    expectSuccess(state, session, sent, msgid, "delete");
    return 0;
}

/// `conn:rename(dn, new_rdn [, { parent = "...", keep_old = false }] [, timeout_ms])`.
fn renameLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    const new_rdn = lua.stringAt(state, 3, "new_rdn");
    var parent: ?[:0]const u8 = null;
    var keep_old = false;
    if (!c.lua_isnoneornil(state, 4)) {
        c.luaL_checktype(state, 4, c.LUA_TTABLE);
        parent = lua.optionalString(state, 4, "parent");
        keep_old = lua.optionalBoolean(state, 4, "keep_old");
    }
    begin(state, session, 5);
    var msgid: c_int = 0;
    const sent = ldap.ldap_rename(session.ld, dn.ptr, new_rdn.ptr, if (parent) |value| value.ptr else null, @intFromBool(!keep_old), null, null, &msgid);
    expectSuccess(state, session, sent, msgid, "rename");
    return 0;
}

/// `conn:compare(dn, attribute, value [, timeout_ms])`: true or false.
fn compareLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const dn = lua.stringAt(state, 2, "dn");
    const attribute = lua.stringAt(state, 3, "attribute");
    var value = bytesOf(lua.checkBytes(state, 4));
    begin(state, session, 5);
    var msgid: c_int = 0;
    const sent = ldap.ldap_compare_ext(session.ld, dn.ptr, attribute.ptr, &value, null, null, &msgid);
    const message = awaitResult(state, session, sent, msgid);
    var text: [256:0]u8 = @splat(0);
    const code = parseResult(state, session, message, &text);
    if (code != ldap.LDAP_COMPARE_TRUE and code != ldap.LDAP_COMPARE_FALSE) raiseResult(state, "compare", code, &text);
    c.lua_pushboolean(state, @intFromBool(code == ldap.LDAP_COMPARE_TRUE));
    return 1;
}

/// `conn:extended(oid [, value [, timeout_ms]])`: the response value, or nil when the
/// server sent none.
fn extendedLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const oid = lua.stringAt(state, 2, "oid");
    var request: ldap.struct_berval = undefined;
    const has_value = !c.lua_isnoneornil(state, 3);
    if (has_value) request = bytesOf(lua.checkBytes(state, 3));
    begin(state, session, 4);
    var msgid: c_int = 0;
    const sent = ldap.ldap_extended_operation(session.ld, oid.ptr, if (has_value) &request else null, null, null, &msgid);
    const message = awaitResult(state, session, sent, msgid);
    var response_oid: [*c]u8 = null;
    var response: ?*ldap.struct_berval = null;
    if (ldap.ldap_parse_extended_result(session.ld, message, &response_oid, &response, 0) != ldap.LDAP_SUCCESS) {
        _ = ldap.ldap_msgfree(message);
        fail(state, session);
    }
    if (response_oid != null) ldap.ldap_memfree(response_oid);
    if (response) |value| {
        _ = c.lua_pushlstring(state, value.bv_val, value.bv_len);
        ldap.ber_bvfree(value);
    } else c.lua_pushnil(state);
    var text: [256:0]u8 = @splat(0);
    const code = parseResult(state, session, message, &text);
    if (code != ldap.LDAP_SUCCESS) {
        c.lua_pop(state, 1);
        raiseResult(state, "extended", code, &text);
    }
    return 1;
}

// The test runs a real Lua session over in-memory pipes against a scripted server:
// each operation reads its request, and the server answers with hand-built BER.

const Duplex = stream.Duplex;

const Ber = struct {
    bytes: [4096]u8 = undefined,
    len: usize = 0,

    fn raw(self: *Ber, data: []const u8) void {
        @memcpy(self.bytes[self.len..][0..data.len], data);
        self.len += data.len;
    }

    fn tlv(self: *Ber, tag: u8, content: []const u8) void {
        self.raw(&.{tag});
        if (content.len < 128) {
            self.raw(&.{@intCast(content.len)});
        } else {
            self.raw(&.{ 0x82, @intCast(content.len >> 8), @intCast(content.len & 0xff) });
        }
        self.raw(content);
    }

    fn slice(self: *const Ber) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn envelope(msgid: u8, operation: []const u8) Ber {
    var content: Ber = .{};
    content.tlv(0x02, &.{msgid});
    content.raw(operation);
    var out: Ber = .{};
    out.tlv(0x30, content.slice());
    return out;
}

/// An LDAPResult-shaped operation: result code, matched DN "", diagnostic `diagnostic`.
fn resultOp(tag: u8, code: u8, diagnostic: []const u8, tail: []const u8) Ber {
    var content: Ber = .{};
    content.tlv(0x0a, &.{code});
    content.tlv(0x04, "");
    content.tlv(0x04, diagnostic);
    content.raw(tail);
    var out: Ber = .{};
    out.tlv(tag, content.slice());
    return out;
}

fn entryOp(dn: []const u8, attributes: []const struct { []const u8, []const []const u8 }) Ber {
    var list: Ber = .{};
    for (attributes) |attribute| {
        var values: Ber = .{};
        for (attribute[1]) |value| values.tlv(0x04, value);
        var pair: Ber = .{};
        pair.tlv(0x04, attribute[0]);
        pair.tlv(0x31, values.slice());
        list.tlv(0x30, pair.slice());
    }
    var content: Ber = .{};
    content.tlv(0x04, dn);
    content.tlv(0x30, list.slice());
    var out: Ber = .{};
    out.tlv(0x64, content.slice());
    return out;
}

var test_link: ?*Duplex = null;
var test_step: usize = 0;
var test_requests: [16][512]u8 = undefined;
var test_request_lengths: [16]usize = @splat(0);

fn msgidOf(request: []const u8) u8 {
    const length_bytes: usize = if (request[1] & 0x80 != 0) 1 + (request[1] & 0x7f) else 1;
    return request[1 + length_bytes + 2];
}

/// Runs when the client waits for a reply: reads the request, answers it.
fn scriptedServer() void {
    const link = test_link.?;
    const request = link.to_server.bytes[0..link.to_server.len];
    const step = test_step;
    test_step += 1;
    const keep = @min(request.len, test_requests[step].len);
    @memcpy(test_requests[step][0..keep], request[0..keep]);
    test_request_lengths[step] = keep;
    const id = msgidOf(request);
    link.to_server.len = 0;
    var reply: Ber = .{};
    const out = &link.to_client;
    switch (step) {
        0 => reply = envelope(id, resultOp(0x61, 0, "", "").slice()),
        1 => {
            const alice = entryOp("cn=alice,dc=example,dc=com", &.{ .{ "cn", &.{"alice"} }, .{ "mail", &.{ "a@example.com", "alice@example.com" } } });
            const bob = entryOp("cn=bob,dc=example,dc=com", &.{.{ "cn", &.{"bob"} }});
            var reference: Ber = .{};
            reference.tlv(0x73, blk: {
                var url: Ber = .{};
                url.tlv(0x04, "ldap://other.example.com/dc=x");
                break :blk url.slice();
            });
            for ([_]Ber{ envelope(id, alice.slice()), envelope(id, bob.slice()), envelope(id, reference.slice()), envelope(id, resultOp(0x65, 0, "", "").slice()) }) |part| reply.raw(part.slice());
        },
        2, 3, 4 => reply = envelope(id, resultOp(@as(u8, switch (step) {
            2 => 0x69,
            3 => 0x67,
            else => 0x6b,
        }), 0, "", "").slice()),
        5 => reply = envelope(id, resultOp(0x6d, 0, "", "").slice()),
        6 => reply = envelope(id, resultOp(0x6f, 6, "", "").slice()),
        7 => reply = envelope(id, resultOp(0x6f, 5, "", "").slice()),
        8 => {
            var value: Ber = .{};
            value.tlv(0x8b, "dn:cn=admin,dc=example,dc=com");
            reply = envelope(id, resultOp(0x78, 0, "", value.slice()).slice());
        },
        9 => reply = envelope(id, resultOp(0x61, 49, "bad password", "").slice()),
        else => {},
    }
    _ = out.transfer(.send, @constCast(reply.slice()), .{ .closed = -1, .want_read = -1, .failed = -1 });
}

test "ldap session round trip against a scripted server" {
    init();
    const state = lua.testState("protocols/ldap", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    link.to_client.on_empty = scriptedServer;
    test_link = &link;
    test_step = 0;
    const session = stream.new(state, metatable, Session{ .connection = .{ .pipes = &link } });
    open(state, session);
    c.lua_setglobal(state, "conn");
    try lua.expectScript(state,
        \\conn:bind("cn=admin,dc=example,dc=com", "secret")
        \\local entries, references = conn:search{ base = "dc=example,dc=com", scope = "sub", filter = "(cn=*)", attributes = { "cn", "mail" } }
        \\assert(#entries == 2 and entries[1].dn == "cn=alice,dc=example,dc=com" and entries[2].dn == "cn=bob,dc=example,dc=com")
        \\assert(entries[1].attributes.cn[1] == "alice" and #entries[1].attributes.mail == 2 and entries[1].attributes.mail[2] == "alice@example.com")
        \\assert(references[1] == "ldap://other.example.com/dc=x")
        \\conn:add("cn=carol,dc=example,dc=com", { objectClass = { "top", "person" }, cn = "carol", sn = "c" })
        \\conn:modify("cn=carol,dc=example,dc=com", { { op = "replace", attribute = "sn", values = { "d" } }, { op = "delete", attribute = "mail" } })
        \\conn:delete("cn=carol,dc=example,dc=com")
        \\conn:rename("cn=bob,dc=example,dc=com", "cn=robert", { parent = "ou=people,dc=example,dc=com" })
        \\assert(conn:compare("cn=bob,dc=example,dc=com", "cn", "bob") == true)
        \\assert(conn:compare("cn=bob,dc=example,dc=com", "cn", "alice") == false)
        \\assert(conn:extended("1.3.6.1.4.1.4203.1.11.3") == "dn:cn=admin,dc=example,dc=com")
        \\local ok, err = pcall(function() conn:bind("cn=admin,dc=example,dc=com", "wrong") end)
        \\assert(not ok and err:find("Invalid credentials", 1, true) and err:find("bad password", 1, true), err)
        \\assert(not pcall(function() conn:search{ scope = "everywhere" } end))
        \\assert(not pcall(function() conn:modify("cn=x", { { op = "bogus", attribute = "a" } }) end))
        \\conn:close()
        \\assert(not pcall(function() conn:delete("cn=x") end))
    );
    try std.testing.expectEqual(@as(usize, 10), test_step);
    // The requests carry what the script asked for.
    for ([_]struct { usize, []const u8 }{
        .{ 0, "secret" },    .{ 1, "mail" }, .{ 2, "carol" },                   .{ 3, "mail" }, .{ 4, "cn=carol" },
        .{ 5, "ou=people" }, .{ 6, "bob" },  .{ 8, "1.3.6.1.4.1.4203.1.11.3" },
    }) |expected| {
        const request = test_requests[expected[0]][0..test_request_lengths[expected[0]]];
        if (std.mem.indexOf(u8, request, expected[1]) == null) {
            std.debug.print("request {d} lacks {s}\n", .{ expected[0], expected[1] });
            return error.TestUnexpectedResult;
        }
    }
}

test "ldap session is closed when the peer goes silent" {
    init();
    const state = lua.testState("protocols/ldap", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    const session = stream.new(state, metatable, Session{ .connection = .{ .pipes = &link } });
    open(state, session);
    c.lua_setglobal(state, "conn");
    // Nothing ever answers: the read fails, the session reports it and is closed.
    try lua.expectScript(state,
        \\local ok, err = pcall(function() conn:bind("cn=a", "b") end)
        \\assert(not ok and err:find("LDAP connection failed", 1, true), err)
        \\local ok2, err2 = pcall(function() conn:search{ base = "" } end)
        \\assert(not ok2 and err2:find("closed", 1, true), err2)
        \\conn:close()
    );
    try std.testing.expect(session.ld == null);
}
