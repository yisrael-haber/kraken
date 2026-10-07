const std = @import("std");
const c = @import("c");
const etpan = @import("etpan");
const lua = @import("../runtime/lua.zig");
const socket = @import("../runtime/socket.zig");
const stream = @import("stream.zig");
const etpan_stream = @import("etpan_stream.zig");

// libetpan does the protocol: its IMAP client builds each command from typed structures,
// sends it over the connection that etpan_stream.zig gives it, and parses the untagged
// responses into typed structures again. This module reads a call's arguments into plain
// values first, so a bad argument raises before libetpan allocates anything; builds the
// libetpan structures; and turns what comes back into Lua tables.

const metatable = "kraken.imap";
const allocator = std.heap.c_allocator;
const max_ranges = 32;
const max_criteria = 16;
const max_flags = 32;

const Session = struct {
    wire: etpan_stream.Wire = .{},
    imap: ?*etpan.mailimap = null,

    /// Ends the session without protocol I/O.
    pub fn release(self: *Session) void {
        const imap = self.imap orelse return;
        self.imap = null;
        self.wire.broken = true;
        etpan.mailimap_free(imap);
    }
};

pub fn module(state: ?*c.lua_State) callconv(.c) c_int {
    lua.defineClass(state, metatable, .{
        .{ "login", loginLua },        .{ "list", listLua },            .{ "select", selectLua },
        .{ "search", variant(search, false) }, .{ "uid_search", variant(search, true) }, .{ "fetch", variant(fetch, false) },
        .{ "uid_fetch", variant(fetch, true) }, .{ "store", variant(store, false) }, .{ "uid_store", variant(store, true) },
        .{ "copy", variant(copy, false) }, .{ "uid_copy", variant(copy, true) }, .{ "expunge", expungeLua },
        .{ "create", createLua },      .{ "delete", deleteLua },        .{ "rename", renameLua },
        .{ "append", appendLua },      .{ "noop", noopLua },            .{ "info", infoLua },
        .{ "close", closeLua },
    }, lua.collector(Session, metatable));
    lua.pushFunctions(state, .{.{ "connect", connectLua }});
    return 1;
}

/// `imap.connect(tcp [, timeout_ms])` or `imap.connect(tls_session [, timeout_ms])`: an IMAP
/// client over a connected TCP socket, or over a `protocols/tls` session for IMAPS. It reads the
/// greeting.
fn connectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const timeout = socket.luaTimeout(state, 2);
    c.lua_settop(state, 1);
    const session = etpan_stream.create(state, Session, metatable);
    open(state, session, timeout);
    return 1;
}

fn open(state: ?*c.lua_State, session: *Session, timeout: ?u64) void {
    const imap = etpan.mailimap_new(0, null) orelse lua.raise(state, "IMAP allocation failed", .{});
    session.imap = imap;
    session.wire.connection.begin(timeout);
    check(state, session, etpan.mailimap_connect(imap, session.wire.open(state)), "greeting");
}

const checkSession = lua.liveChecker(Session, metatable, "imap", "IMAP session is closed");

/// Raises for a library error `code`. A broken connection ends the session; a refusal by
/// the server is an error that leaves it usable.
fn check(state: ?*c.lua_State, session: *Session, code: c_int, what: [*:0]const u8) void {
    if (code == etpan.MAILIMAP_NO_ERROR or code == etpan.MAILIMAP_NO_ERROR_AUTHENTICATED or code == etpan.MAILIMAP_NO_ERROR_NON_AUTHENTICATED) return;
    const imap = session.imap.?;
    if (session.wire.broken or code == etpan.MAILIMAP_ERROR_STREAM) {
        session.release();
        session.wire.raiseBroken(state, "IMAP");
    }
    if (imap.*.imap_response != null) lua.raise(state, "IMAP %s failed: %s", .{ what, imap.*.imap_response });
    lua.raise(state, "IMAP %s failed (error %d)", .{ what, code });
}

fn dup(bytes: []const u8) ?[:0]u8 {
    return allocator.dupeZ(u8, bytes) catch null;
}

/// The Lua function `session:name(strings... [, timeout_ms])` of a command whose library call
/// takes the session and then only strings.
fn simple(comptime function: anytype, comptime name: [*:0]const u8) c.lua_CFunction {
    return struct {
        fn call(state: ?*c.lua_State) callconv(.c) c_int {
            const session = checkSession(state);
            var arguments: std.meta.ArgsTuple(@TypeOf(function)) = undefined;
            arguments[0] = session.imap;
            inline for (1..arguments.len) |position| arguments[position] = lua.checkBytes(state, position + 1).ptr;
            session.wire.begin(state, arguments.len + 1);
            check(state, session, @call(.auto, function, arguments), name);
            return 0;
        }
    }.call;
}

/// `session:login(user, password [, timeout_ms])`.
const loginLua = simple(etpan.mailimap_login, "LOGIN");

/// The Lua function of a command that has a message-number form and a UID form.
fn variant(comptime function: anytype, comptime uid: bool) c.lua_CFunction {
    return struct {
        fn call(state: ?*c.lua_State) callconv(.c) c_int {
            return function(state, uid);
        }
    }.call;
}

// Lists of results.

const Cells = struct {
    cell: [*c]etpan.clistcell,

    fn init(list: [*c]etpan.clist) Cells {
        return .{ .cell = if (list == null) null else list.*.first };
    }

    fn next(self: *Cells) ?*anyopaque {
        if (self.cell == null) return null;
        const data = self.cell.*.data;
        self.cell = self.cell.*.next;
        return data;
    }
};

/// `session:list([reference [, pattern [, timeout_ms]]])`: the mailboxes as
/// `{ name, delimiter, flags }`; the reference is `""` and the pattern `"*"` by default.
fn listLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const reference = if (c.lua_isnoneornil(state, 2)) "" else lua.checkBytes(state, 2);
    const pattern = if (c.lua_isnoneornil(state, 3)) "*" else lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    var result: [*c]etpan.clist = null;
    check(state, session, etpan.mailimap_list(session.imap, reference.ptr, pattern.ptr, &result), "LIST");
    c.lua_createtable(state, 0, 0);
    var cells = Cells.init(result);
    while (cells.next()) |data| {
        const mailbox: *etpan.struct_mailimap_mailbox_list = @ptrCast(@alignCast(data));
        c.lua_createtable(state, 0, 3);
        lua.setString(state, "name", std.mem.span(mailbox.mb_name));
        if (mailbox.mb_delimiter != 0) lua.setString(state, "delimiter", &.{@bitCast(mailbox.mb_delimiter)});
        c.lua_createtable(state, 0, 0);
        if (mailbox.mb_flag != null) {
            const list = mailbox.mb_flag.*;
            if (list.mbf_type == etpan.MAILIMAP_MBX_LIST_FLAGS_SFLAG) {
                const name: ?[:0]const u8 = switch (list.mbf_sflag) {
                    etpan.MAILIMAP_MBX_LIST_SFLAG_MARKED => "\\Marked",
                    etpan.MAILIMAP_MBX_LIST_SFLAG_NOSELECT => "\\Noselect",
                    etpan.MAILIMAP_MBX_LIST_SFLAG_UNMARKED => "\\Unmarked",
                    else => null,
                };
                if (name) |text| pushAt(state, text);
            }
            var others = Cells.init(list.mbf_oflags);
            while (others.next()) |entry| {
                const flag: *etpan.struct_mailimap_mbx_list_oflag = @ptrCast(@alignCast(entry));
                if (flag.of_type == etpan.MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS) {
                    pushAt(state, "\\Noinferiors");
                } else if (flag.of_flag_ext != null) pushExtension(state, std.mem.span(flag.of_flag_ext));
            }
        }
        c.lua_setfield(state, -2, "flags");
        lua.append(state);
    }
    etpan.mailimap_list_result_free(result);
    return 1;
}

/// Appends `text` to the array on the stack top.
fn pushAt(state: ?*c.lua_State, text: []const u8) void {
    lua.pushBytes(state, text);
    lua.append(state);
}

// Selecting.

/// `session:select(mailbox [, readonly [, timeout_ms]])`: SELECT, or EXAMINE when `readonly` is
/// true. Returns what the server reported: `{ exists, recent, uidnext, uidvalidity, unseen, flags }`,
/// `unseen` being the number of the first unseen message.
fn selectLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const mailbox = lua.checkBytes(state, 2);
    const readonly = c.lua_toboolean(state, 3) != 0;
    session.wire.begin(state, 4);
    const code = if (readonly) etpan.mailimap_examine(session.imap, mailbox.ptr) else etpan.mailimap_select(session.imap, mailbox.ptr);
    check(state, session, code, if (readonly) "EXAMINE" else "SELECT");
    c.lua_createtable(state, 0, 6);
    var exists: u32 = 0;
    var recent: u32 = 0;
    var uidnext: u32 = 0;
    var uidvalidity: u32 = 0;
    var first_unseen: u32 = 0;
    var flag_list: [*c]etpan.clist = null;
    if (etpan.kraken_imap_selection(session.imap, &exists, &recent, &uidnext, &uidvalidity, &first_unseen, &flag_list) != 0) {
        lua.setInteger(state, "exists", exists);
        lua.setInteger(state, "recent", recent);
        lua.setInteger(state, "uidnext", uidnext);
        lua.setInteger(state, "uidvalidity", uidvalidity);
        lua.setInteger(state, "unseen", first_unseen);
        c.lua_createtable(state, 0, 0);
        var cells = Cells.init(flag_list);
        while (cells.next()) |data| pushFlag(state, @ptrCast(@alignCast(data)));
        c.lua_setfield(state, -2, "flags");
    }
    return 1;
}

/// Appends a flag's name to the array on the stack top.
fn pushFlag(state: ?*c.lua_State, flag: *etpan.struct_mailimap_flag) void {
    switch (flag.fl_type) {
        etpan.MAILIMAP_FLAG_ANSWERED => pushAt(state, "\\Answered"),
        etpan.MAILIMAP_FLAG_FLAGGED => pushAt(state, "\\Flagged"),
        etpan.MAILIMAP_FLAG_DELETED => pushAt(state, "\\Deleted"),
        etpan.MAILIMAP_FLAG_SEEN => pushAt(state, "\\Seen"),
        etpan.MAILIMAP_FLAG_DRAFT => pushAt(state, "\\Draft"),
        etpan.MAILIMAP_FLAG_KEYWORD => if (flag.fl_data.fl_keyword != null) pushAt(state, std.mem.span(flag.fl_data.fl_keyword)),
        etpan.MAILIMAP_FLAG_EXTENSION => if (flag.fl_data.fl_extension != null) pushExtension(state, std.mem.span(flag.fl_data.fl_extension)),
        else => {},
    }
}

/// Appends an extension flag to the array on the stack top: libetpan drops its backslash.
fn pushExtension(state: ?*c.lua_State, name: []const u8) void {
    lua.pushBytes(state, "\\");
    lua.pushBytes(state, name);
    c.lua_concat(state, 2);
    lua.append(state);
}

// Message sets.

const Ranges = struct {
    first: [max_ranges]u32 = undefined,
    last: [max_ranges]u32 = undefined,
    count: usize = 0,
};

/// A message set from an integer or a string such as `"3"`, `"1:5"` or `"2,4:*"`; `*` is
/// the last message.
fn parseSet(state: ?*c.lua_State, index: c_int) Ranges {
    var ranges: Ranges = .{};
    if (c.lua_type(state, index) == c.LUA_TNUMBER) {
        const number = c.luaL_checkinteger(state, index);
        if (number < 1 or number > std.math.maxInt(u32)) lua.raise(state, "message number out of range", .{});
        ranges.first[0] = @intCast(number);
        ranges.last[0] = @intCast(number);
        ranges.count = 1;
        return ranges;
    }
    const text = lua.checkBytes(state, index);
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part| {
        if (ranges.count == max_ranges) lua.raise(state, "a message set has at most %d parts", .{@as(c_int, max_ranges)});
        const colon = std.mem.indexOfScalar(u8, part, ':');
        ranges.first[ranges.count] = parseNumber(state, if (colon) |at| part[0..at] else part);
        ranges.last[ranges.count] = if (colon) |at| parseNumber(state, part[at + 1 ..]) else ranges.first[ranges.count];
        ranges.count += 1;
    }
    return ranges;
}

fn parseNumber(state: ?*c.lua_State, text: []const u8) u32 {
    if (std.mem.eql(u8, text, "*")) return 0;
    const number = std.fmt.parseInt(u32, text, 10) catch 0;
    if (number == 0) lua.raise(state, "bad message set: use numbers, ranges like 1:5, and * for the last message", .{});
    return number;
}

fn buildSet(ranges: Ranges) ?*etpan.struct_mailimap_set {
    const set = etpan.mailimap_set_new_empty() orelse return null;
    for (0..ranges.count) |index| {
        if (etpan.mailimap_set_add_interval(set, ranges.first[index], ranges.last[index]) != etpan.MAILIMAP_NO_ERROR) {
            etpan.mailimap_set_free(set);
            return null;
        }
    }
    return set;
}

// Searching.

const Kind = enum { text, number, flag, header };

const Criterion = struct {
    kind: c_int,
    text: []const u8 = "",
    other: []const u8 = "",
    number: u32 = 0,
};

const criteria_table = [_]struct { [:0]const u8, Kind, c_int }{
    .{ "from", .text, etpan.MAILIMAP_SEARCH_KEY_FROM },             .{ "to", .text, etpan.MAILIMAP_SEARCH_KEY_TO },
    .{ "cc", .text, etpan.MAILIMAP_SEARCH_KEY_CC },                 .{ "bcc", .text, etpan.MAILIMAP_SEARCH_KEY_BCC },
    .{ "subject", .text, etpan.MAILIMAP_SEARCH_KEY_SUBJECT },       .{ "body", .text, etpan.MAILIMAP_SEARCH_KEY_BODY },
    .{ "text", .text, etpan.MAILIMAP_SEARCH_KEY_TEXT },             .{ "keyword", .text, etpan.MAILIMAP_SEARCH_KEY_KEYWORD },
    .{ "unkeyword", .text, etpan.MAILIMAP_SEARCH_KEY_UNKEYWORD },   .{ "header", .header, etpan.MAILIMAP_SEARCH_KEY_HEADER },
    .{ "larger", .number, etpan.MAILIMAP_SEARCH_KEY_LARGER },       .{ "smaller", .number, etpan.MAILIMAP_SEARCH_KEY_SMALLER },
    .{ "all", .flag, etpan.MAILIMAP_SEARCH_KEY_ALL },               .{ "seen", .flag, etpan.MAILIMAP_SEARCH_KEY_SEEN },
    .{ "unseen", .flag, etpan.MAILIMAP_SEARCH_KEY_UNSEEN },         .{ "answered", .flag, etpan.MAILIMAP_SEARCH_KEY_ANSWERED },
    .{ "unanswered", .flag, etpan.MAILIMAP_SEARCH_KEY_UNANSWERED }, .{ "deleted", .flag, etpan.MAILIMAP_SEARCH_KEY_DELETED },
    .{ "undeleted", .flag, etpan.MAILIMAP_SEARCH_KEY_UNDELETED },   .{ "flagged", .flag, etpan.MAILIMAP_SEARCH_KEY_FLAGGED },
    .{ "unflagged", .flag, etpan.MAILIMAP_SEARCH_KEY_UNFLAGGED },   .{ "draft", .flag, etpan.MAILIMAP_SEARCH_KEY_DRAFT },
    .{ "undraft", .flag, etpan.MAILIMAP_SEARCH_KEY_UNDRAFT },       .{ "recent", .flag, etpan.MAILIMAP_SEARCH_KEY_RECENT },
    .{ "new", .flag, etpan.MAILIMAP_SEARCH_KEY_NEW },               .{ "old", .flag, etpan.MAILIMAP_SEARCH_KEY_OLD },
};

const Criteria = struct { items: [max_criteria]Criterion = undefined, count: usize = 0 };

/// The search criteria in the table at `index`: strings for `from`, `to`, `cc`, `bcc`,
/// `subject`, `body`, `text`, `keyword` and `unkeyword`; `{ name, value }` for `header`;
/// numbers for `larger` and `smaller`; and `true` for `all`, `seen`, `unseen`, `answered`,
/// `unanswered`, `deleted`, `undeleted`, `flagged`, `unflagged`, `draft`, `undraft`, `recent`,
/// `new` and `old`. A search with none is `all`.
fn parseCriteria(state: ?*c.lua_State, index: c_int) Criteria {
    var found: Criteria = .{};
    c.luaL_checktype(state, index, c.LUA_TTABLE);
    c.lua_pushnil(state);
    while (c.lua_next(state, index) != 0) {
        defer c.lua_pop(state, 1);
        if (c.lua_type(state, -2) != c.LUA_TSTRING) lua.raise(state, "search criteria are named fields", .{});
        const name = lua.toBytes(state, -2).?;
        const entry = for (criteria_table) |candidate| {
            if (std.mem.eql(u8, candidate[0], name)) break candidate;
        } else lua.raise(state, "unknown search criterion \"%s\"", .{name.ptr});
        if (entry[1] == .flag) {
            if (c.lua_type(state, -1) != c.LUA_TBOOLEAN) lua.raise(state, "%s must be true or false", .{name.ptr});
            if (c.lua_toboolean(state, -1) == 0) continue;
        }
        if (found.count == max_criteria) lua.raise(state, "a search has at most %d criteria", .{@as(c_int, max_criteria)});
        var item: Criterion = .{ .kind = entry[2] };
        switch (entry[1]) {
            .text => item.text = lua.stringAt(state, -1, entry[0]),
            .number => {
                const number = c.luaL_checkinteger(state, -1);
                if (number < 0 or number > std.math.maxInt(u32)) lua.raise(state, "%s out of range", .{name.ptr});
                item.number = @intCast(number);
            },
            .header => {
                if (c.lua_type(state, -1) != c.LUA_TTABLE) lua.raise(state, "header must be { name, value }", .{});
                _ = c.lua_rawgeti(state, -1, 1);
                _ = c.lua_rawgeti(state, -2, 2);
                item.text = lua.stringAt(state, -2, "header name");
                item.other = lua.stringAt(state, -1, "header value");
                c.lua_pop(state, 2);
            },
            .flag => {},
        }
        found.items[found.count] = item;
        found.count += 1;
    }
    return found;
}

/// The libetpan key for one criterion, owning copies of its strings; null when out of memory.
fn buildKey(item: Criterion) ?*etpan.struct_mailimap_search_key {
    switch (item.kind) {
        etpan.MAILIMAP_SEARCH_KEY_FROM => return keyWith(item, etpan.mailimap_search_key_new_from),
        etpan.MAILIMAP_SEARCH_KEY_TO => return keyWith(item, etpan.mailimap_search_key_new_to),
        etpan.MAILIMAP_SEARCH_KEY_CC => return keyWith(item, etpan.mailimap_search_key_new_cc),
        etpan.MAILIMAP_SEARCH_KEY_BCC => return keyWith(item, etpan.mailimap_search_key_new_bcc),
        etpan.MAILIMAP_SEARCH_KEY_SUBJECT => return keyWith(item, etpan.mailimap_search_key_new_subject),
        etpan.MAILIMAP_SEARCH_KEY_BODY => return keyWith(item, etpan.mailimap_search_key_new_body),
        etpan.MAILIMAP_SEARCH_KEY_TEXT => return keyWith(item, etpan.mailimap_search_key_new_text),
        etpan.MAILIMAP_SEARCH_KEY_KEYWORD => return keyWith(item, etpan.mailimap_search_key_new_keyword),
        etpan.MAILIMAP_SEARCH_KEY_UNKEYWORD => return keyWith(item, etpan.mailimap_search_key_new_unkeyword),
        etpan.MAILIMAP_SEARCH_KEY_HEADER => {
            const name = dup(item.text) orelse return null;
            const value = dup(item.other) orelse {
                allocator.free(name);
                return null;
            };
            return etpan.mailimap_search_key_new_header(name.ptr, value.ptr);
        },
        etpan.MAILIMAP_SEARCH_KEY_LARGER => return etpan.mailimap_search_key_new_larger(item.number),
        etpan.MAILIMAP_SEARCH_KEY_SMALLER => return etpan.mailimap_search_key_new_smaller(item.number),
        else => return etpan.mailimap_search_key_new(item.kind, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null, null, null, null, 0, null, null, null),
    }
}

fn keyWith(item: Criterion, make: *const fn ([*c]u8) callconv(.c) ?*etpan.struct_mailimap_search_key) ?*etpan.struct_mailimap_search_key {
    const text = dup(item.text) orelse return null;
    return make(text.ptr);
}

/// All criteria as one key, which ANDs them; null when out of memory.
fn buildCriteria(found: Criteria) ?*etpan.struct_mailimap_search_key {
    if (found.count == 0) return etpan.mailimap_search_key_new_all();
    if (found.count == 1) return buildKey(found.items[0]);
    const keys = etpan.mailimap_search_key_new_multiple_empty() orelse return null;
    for (found.items[0..found.count]) |item| {
        const key = buildKey(item) orelse {
            etpan.mailimap_search_key_free(keys);
            return null;
        };
        if (etpan.mailimap_search_key_multiple_add(keys, key) != etpan.MAILIMAP_NO_ERROR) {
            etpan.mailimap_search_key_free(key);
            etpan.mailimap_search_key_free(keys);
            return null;
        }
    }
    return keys;
}

/// `session:search(criteria [, timeout_ms])` and `session:uid_search(...)`: the numbers of the
/// matching messages, as message numbers or as UIDs.
fn search(state: ?*c.lua_State, comptime uid: bool) c_int {
    const session = checkSession(state);
    const found = parseCriteria(state, 2);
    session.wire.begin(state, 3);
    const key = buildCriteria(found) orelse lua.raise(state, "out of memory", .{});
    var result: [*c]etpan.clist = null;
    const code = if (uid) etpan.mailimap_uid_search(session.imap, null, key, &result) else etpan.mailimap_search(session.imap, null, key, &result);
    etpan.mailimap_search_key_free(key);
    check(state, session, code, "SEARCH");
    c.lua_createtable(state, 0, 0);
    var cells = Cells.init(result);
    while (cells.next()) |data| {
        const number: *u32 = @ptrCast(@alignCast(data));
        c.lua_pushinteger(state, number.*);
        lua.append(state);
    }
    etpan.mailimap_search_result_free(result);
    return 1;
}

// Fetching.

const Item = enum { flags, uid, size, header, text, body };

fn parseItems(state: ?*c.lua_State, index: c_int) std.EnumSet(Item) {
    var items: std.EnumSet(Item) = .initEmpty();
    c.luaL_checktype(state, index, c.LUA_TTABLE);
    for (1..@as(usize, @intCast(c.lua_rawlen(state, index))) + 1) |position| {
        _ = c.lua_rawgeti(state, index, @intCast(position));
        const name = lua.stringAt(state, -1, "item");
        c.lua_pop(state, 1);
        items.insert(std.meta.stringToEnum(Item, name) orelse lua.raise(state, "unknown fetch item \"%s\"", .{name.ptr}));
    }
    return items;
}

fn buildFetch(items: std.EnumSet(Item)) ?*etpan.struct_mailimap_fetch_type {
    const types = etpan.mailimap_fetch_type_new_fetch_att_list_empty() orelse return null;
    var iterator = items.iterator();
    while (iterator.next()) |item| {
        const attribute = switch (item) {
            .flags => etpan.mailimap_fetch_att_new_flags(),
            .uid => etpan.mailimap_fetch_att_new_uid(),
            .size => etpan.mailimap_fetch_att_new_rfc822_size(),
            .header => etpan.mailimap_fetch_att_new_body_peek_section(etpan.mailimap_section_new_header()),
            .text => etpan.mailimap_fetch_att_new_body_peek_section(etpan.mailimap_section_new_text()),
            .body => etpan.mailimap_fetch_att_new_body_peek_section(etpan.mailimap_section_new(null)),
        } orelse {
            etpan.mailimap_fetch_type_free(types);
            return null;
        };
        if (etpan.mailimap_fetch_type_new_fetch_att_list_add(types, attribute) != etpan.MAILIMAP_NO_ERROR) {
            etpan.mailimap_fetch_att_free(attribute);
            etpan.mailimap_fetch_type_free(types);
            return null;
        }
    }
    return types;
}

/// `session:fetch(set, items [, timeout_ms])` and `session:uid_fetch(...)`: for each message in
/// `set`, a table of what `items` asked for, among `"flags"`, `"uid"`, `"size"`, `"header"`,
/// `"text"` and `"body"` (the whole message), with the message's `number`. Reading does not
/// set \Seen.
fn fetch(state: ?*c.lua_State, comptime uid: bool) c_int {
    const session = checkSession(state);
    const ranges = parseSet(state, 2);
    const items = parseItems(state, 3);
    session.wire.begin(state, 4);
    const set = buildSet(ranges) orelse lua.raise(state, "out of memory", .{});
    const attributes = buildFetch(items) orelse {
        etpan.mailimap_set_free(set);
        lua.raise(state, "out of memory", .{});
    };
    var result: [*c]etpan.clist = null;
    const code = if (uid) etpan.mailimap_uid_fetch(session.imap, set, attributes, &result) else etpan.mailimap_fetch(session.imap, set, attributes, &result);
    etpan.mailimap_set_free(set);
    etpan.mailimap_fetch_type_free(attributes);
    check(state, session, code, "FETCH");
    c.lua_createtable(state, 0, 0);
    var messages = Cells.init(result);
    while (messages.next()) |data| {
        const message: *etpan.struct_mailimap_msg_att = @ptrCast(@alignCast(data));
        c.lua_createtable(state, 0, 6);
        lua.setInteger(state, "number", message.att_number);
        var attributes_list = Cells.init(message.att_list);
        while (attributes_list.next()) |entry| pushAttribute(state, @ptrCast(@alignCast(entry)));
        lua.append(state);
    }
    etpan.mailimap_fetch_list_free(result);
    return 1;
}

/// Sets one fetched attribute on the message table at the stack top.
fn pushAttribute(state: ?*c.lua_State, item: *etpan.struct_mailimap_msg_att_item) void {
    switch (item.att_type) {
        etpan.MAILIMAP_MSG_ATT_ITEM_DYNAMIC => {
            c.lua_createtable(state, 0, 0);
            if (item.att_data.att_dyn != null) {
                var cells = Cells.init(item.att_data.att_dyn.*.att_list);
                while (cells.next()) |data| {
                    const flag: *etpan.struct_mailimap_flag_fetch = @ptrCast(@alignCast(data));
                    if (flag.fl_type == etpan.MAILIMAP_FLAG_FETCH_RECENT) pushAt(state, "\\Recent") else if (flag.fl_flag != null) pushFlag(state, flag.fl_flag);
                }
            }
            c.lua_setfield(state, -2, "flags");
        },
        etpan.MAILIMAP_MSG_ATT_ITEM_STATIC => {
            const static = item.att_data.att_static orelse return;
            switch (static.*.att_type) {
                etpan.MAILIMAP_MSG_ATT_UID => lua.setInteger(state, "uid", static.*.att_data.att_uid),
                etpan.MAILIMAP_MSG_ATT_RFC822_SIZE => lua.setInteger(state, "size", static.*.att_data.att_rfc822_size),
                etpan.MAILIMAP_MSG_ATT_BODY_SECTION => {
                    const section = static.*.att_data.att_body_section orelse return;
                    const bytes: []const u8 = if (section.*.sec_body_part != null) section.*.sec_body_part[0..section.*.sec_length] else "";
                    lua.setString(state, sectionName(section.*.sec_section), bytes);
                },
                else => {},
            }
        },
        else => {},
    }
}

/// `header`, `text` or `body`, by the section the server answered.
fn sectionName(section: ?*etpan.struct_mailimap_section) [*:0]const u8 {
    const spec = (section orelse return "body").*.sec_spec orelse return "body";
    if (spec.*.sec_type == etpan.MAILIMAP_SECTION_SPEC_SECTION_MSGTEXT and spec.*.sec_data.sec_msgtext != null) {
        return switch (spec.*.sec_data.sec_msgtext.*.sec_type) {
            etpan.MAILIMAP_SECTION_MSGTEXT_HEADER => "header",
            etpan.MAILIMAP_SECTION_MSGTEXT_TEXT => "text",
            else => "body",
        };
    }
    return "body";
}

// Storing.

const Flags = struct {
    names: [max_flags][]const u8 = undefined,
    count: usize = 0,
};

fn parseFlags(state: ?*c.lua_State, index: c_int) Flags {
    var flags: Flags = .{};
    c.luaL_checktype(state, index, c.LUA_TTABLE);
    for (1..@as(usize, @intCast(c.lua_rawlen(state, index))) + 1) |position| {
        if (flags.count == max_flags) lua.raise(state, "at most %d flags", .{@as(c_int, max_flags)});
        _ = c.lua_rawgeti(state, index, @intCast(position));
        flags.names[flags.count] = lua.stringAt(state, -1, "flag");
        flags.count += 1;
        c.lua_pop(state, 1);
    }
    return flags;
}

fn buildFlag(name: []const u8) ?*etpan.struct_mailimap_flag {
    inline for (.{
        .{ "\\Answered", etpan.mailimap_flag_new_answered },
        .{ "\\Flagged", etpan.mailimap_flag_new_flagged },
        .{ "\\Deleted", etpan.mailimap_flag_new_deleted },
        .{ "\\Seen", etpan.mailimap_flag_new_seen },
        .{ "\\Draft", etpan.mailimap_flag_new_draft },
    }) |known| {
        if (std.ascii.eqlIgnoreCase(known[0], name)) return known[1]();
    }
    if (name.len > 0 and name[0] == '\\') {
        const extension = dup(name[1..]) orelse return null;
        return etpan.mailimap_flag_new_flag_extension(extension.ptr);
    }
    const keyword = dup(name) orelse return null;
    return etpan.mailimap_flag_new_flag_keyword(keyword.ptr);
}

fn buildFlagList(flags: Flags) ?*etpan.struct_mailimap_flag_list {
    const list = etpan.mailimap_flag_list_new_empty() orelse return null;
    for (flags.names[0..flags.count]) |name| {
        const flag = buildFlag(name) orelse {
            etpan.mailimap_flag_list_free(list);
            return null;
        };
        if (etpan.mailimap_flag_list_add(list, flag) != etpan.MAILIMAP_NO_ERROR) {
            etpan.mailimap_flag_free(flag);
            etpan.mailimap_flag_list_free(list);
            return null;
        }
    }
    return list;
}

/// `session:store(set, mode, flags [, timeout_ms])` and `session:uid_store(...)`: changes the
/// flags of the messages in `set`, with `mode` `"add"`, `"remove"` or `"set"`. A flag is a
/// name like `"\\Seen"`, `"\\Deleted"`, `"\\Flagged"`, `"\\Answered"` or `"\\Draft"`, or a keyword.
fn store(state: ?*c.lua_State, comptime uid: bool) c_int {
    const session = checkSession(state);
    const ranges = parseSet(state, 2);
    const mode = lua.checkBytes(state, 3);
    const flags = parseFlags(state, 4);
    if (!std.mem.eql(u8, mode, "add") and !std.mem.eql(u8, mode, "remove") and !std.mem.eql(u8, mode, "set")) lua.raise(state, "mode must be \"add\", \"remove\" or \"set\"", .{});
    session.wire.begin(state, 5);
    const set = buildSet(ranges) orelse lua.raise(state, "out of memory", .{});
    const list = buildFlagList(flags) orelse {
        etpan.mailimap_set_free(set);
        lua.raise(state, "out of memory", .{});
    };
    // The attribute takes over the flag list.
    const attribute = (if (mode[0] == 'a') etpan.mailimap_store_att_flags_new_add_flags_silent(list) else if (mode[0] == 'r') etpan.mailimap_store_att_flags_new_remove_flags_silent(list) else etpan.mailimap_store_att_flags_new_set_flags_silent(list)) orelse {
        etpan.mailimap_flag_list_free(list);
        etpan.mailimap_set_free(set);
        lua.raise(state, "out of memory", .{});
    };
    const code = if (uid) etpan.mailimap_uid_store(session.imap, set, attribute) else etpan.mailimap_store(session.imap, set, attribute);
    etpan.mailimap_set_free(set);
    etpan.mailimap_store_att_flags_free(attribute);
    check(state, session, code, "STORE");
    return 0;
}

/// `session:copy(set, mailbox [, timeout_ms])` and `session:uid_copy(...)`.
fn copy(state: ?*c.lua_State, comptime uid: bool) c_int {
    const session = checkSession(state);
    const ranges = parseSet(state, 2);
    const mailbox = lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    const set = buildSet(ranges) orelse lua.raise(state, "out of memory", .{});
    const code = if (uid) etpan.mailimap_uid_copy(session.imap, set, mailbox.ptr) else etpan.mailimap_copy(session.imap, set, mailbox.ptr);
    etpan.mailimap_set_free(set);
    check(state, session, code, "COPY");
    return 0;
}

// Commands with a mailbox name or nothing.

/// `session:expunge([timeout_ms])`: removes the messages flagged \Deleted.
const expungeLua = simple(etpan.mailimap_expunge, "EXPUNGE");

/// `session:create(mailbox [, timeout_ms])`.
const createLua = simple(etpan.mailimap_create, "CREATE");

/// `session:delete(mailbox [, timeout_ms])`.
const deleteLua = simple(etpan.mailimap_delete, "DELETE");

/// `session:rename(mailbox, new_name [, timeout_ms])`.
const renameLua = simple(etpan.mailimap_rename, "RENAME");

/// `session:append(mailbox, message [, timeout_ms])`: stores `message`, the whole message, in `mailbox`.
fn appendLua(state: ?*c.lua_State) callconv(.c) c_int {
    const session = checkSession(state);
    const mailbox = lua.checkBytes(state, 2);
    const message = lua.checkBytes(state, 3);
    session.wire.begin(state, 4);
    check(state, session, etpan.mailimap_append(session.imap, mailbox.ptr, null, null, message.ptr, message.len), "APPEND");
    return 0;
}

/// `session:noop([timeout_ms])`.
const noopLua = simple(etpan.mailimap_noop, "NOOP");

/// `session:info()`: `{ state, response }`, the session's state (`"non-authenticated"`,
/// `"authenticated"` or `"selected"`) and the server's last tagged response.
fn infoLua(state: ?*c.lua_State) callconv(.c) c_int {
    const imap = checkSession(state).imap.?;
    c.lua_createtable(state, 0, 2);
    lua.setString(state, "state", switch (imap.*.imap_state) {
        etpan.MAILIMAP_STATE_AUTHENTICATED => "authenticated",
        etpan.MAILIMAP_STATE_SELECTED => "selected",
        else => "non-authenticated",
    });
    if (imap.*.imap_response != null) lua.setString(state, "response", std.mem.span(imap.*.imap_response));
    return 1;
}

const closeLua = etpan_stream.closer(Session, metatable, "imap", etpan.mailimap_logout);

// The test runs a real Lua session over in-memory pipes against a scripted server.

const Duplex = stream.Duplex;

var test_link: ?*Duplex = null;
var append_tag: [16]u8 = undefined;
var append_tag_len: usize = 0;
var reply_buffer: [2048]u8 = undefined;

const message_header = "Subject: one\r\n\r\n";
const message_text = "hello\r\n";

/// Runs when the client waits for a reply: logs what it sent and answers the last command.
fn scriptedServer() void {
    const link = test_link.?;
    const request = link.take();
    var words = std.mem.tokenizeAny(u8, request, " \r\n");
    const tag = words.next() orelse "";
    var name = words.next() orelse "";
    if (std.mem.eql(u8, name, "UID")) name = words.next() orelse "";
    const body: []const u8 = blk: {
        if (append_tag_len > 0 and !std.mem.startsWith(u8, request, tag) or std.mem.eql(u8, request, "hello\r\n")) {
            const done = std.fmt.bufPrint(&reply_buffer, "{s} OK [APPENDUID 1 200] Append completed\r\n", .{append_tag[0..append_tag_len]}) catch unreachable;
            append_tag_len = 0;
            break :blk done;
        }
        if (std.mem.eql(u8, name, "LOGIN")) {
            break :blk if (std.mem.indexOf(u8, request, "secret") != null)
                std.fmt.bufPrint(&reply_buffer, "{s} OK Logged in\r\n", .{tag}) catch unreachable
            else
                std.fmt.bufPrint(&reply_buffer, "{s} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", .{tag}) catch unreachable;
        }
        if (std.mem.eql(u8, name, "LIST")) break :blk std.fmt.bufPrint(&reply_buffer, "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n* LIST (\\Noselect \\HasChildren) \"/\" \"Archive\"\r\n{s} OK List completed\r\n", .{tag}) catch unreachable;
        if (std.mem.eql(u8, name, "SELECT") or std.mem.eql(u8, name, "EXAMINE")) {
            if (std.mem.indexOf(u8, request, "Missing") != null) break :blk std.fmt.bufPrint(&reply_buffer, "{s} NO [NONEXISTENT] Mailbox doesn't exist\r\n", .{tag}) catch unreachable;
            break :blk std.fmt.bufPrint(&reply_buffer, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* 3 EXISTS\r\n* 1 RECENT\r\n* OK [UNSEEN 2] First unseen.\r\n* OK [UIDVALIDITY 1234] UIDs valid\r\n* OK [UIDNEXT 10] Predicted next UID\r\n{s} OK [READ-WRITE] Select completed\r\n", .{tag}) catch unreachable;
        }
        if (std.mem.eql(u8, name, "SEARCH")) {
            const numbers = if (std.mem.startsWith(u8, request[tag.len + 1 ..], "UID")) "101 103" else "1 3";
            break :blk std.fmt.bufPrint(&reply_buffer, "* SEARCH {s}\r\n{s} OK Search completed\r\n", .{ numbers, tag }) catch unreachable;
        }
        if (std.mem.eql(u8, name, "FETCH")) {
            if (std.mem.indexOf(u8, request, " 99 ") != null or std.mem.indexOf(u8, request, " 99(") != null) break :blk std.fmt.bufPrint(&reply_buffer, "{s} NO [NONEXISTENT] No such message\r\n", .{tag}) catch unreachable;
            break :blk std.fmt.bufPrint(&reply_buffer, "* 1 FETCH (FLAGS (\\Seen $Junk) UID 101 RFC822.SIZE 23 BODY[HEADER] {{{d}}}\r\n{s} BODY[TEXT] {{{d}}}\r\n{s} BODY[] {{{d}}}\r\n{s}{s})\r\n{s} OK Fetch completed\r\n", .{ message_header.len, message_header, message_text.len, message_text, message_header.len + message_text.len, message_header, message_text, tag }) catch unreachable;
        }
        if (std.mem.eql(u8, name, "APPEND")) {
            @memcpy(append_tag[0..tag.len], tag);
            append_tag_len = tag.len;
            break :blk "+ Ready for literal data\r\n";
        }
        if (std.mem.eql(u8, name, "EXPUNGE")) break :blk std.fmt.bufPrint(&reply_buffer, "* 2 EXPUNGE\r\n{s} OK Expunge completed\r\n", .{tag}) catch unreachable;
        if (std.mem.eql(u8, name, "LOGOUT")) break :blk std.fmt.bufPrint(&reply_buffer, "* BYE Logging out\r\n{s} OK Logout completed\r\n", .{tag}) catch unreachable;
        break :blk std.fmt.bufPrint(&reply_buffer, "{s} OK {s} completed\r\n", .{ tag, name }) catch unreachable;
    };
    _ = link.to_client.transfer(.send, @constCast(body), .{ .closed = -1, .want_read = -1, .failed = -1 });
}

/// Opens a session over `test_link`, like `connect`.
fn openOverPipes(state: ?*c.lua_State) callconv(.c) c_int {
    c.lua_createtable(state, 0, 0);
    const session = stream.new(state, metatable, Session{});
    session.wire.connection = .{ .pipes = test_link.?.client() };
    open(state, session, null);
    return 1;
}

test "imap session round trip against a scripted server" {
    const state = lua.testState("protocols/imap", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    link.to_client.on_empty = scriptedServer;
    test_link = &link;
    append_tag_len = 0;
    _ = link.to_client.transfer(.send, @constCast("* OK [CAPABILITY IMAP4rev1] ready\r\n"), .{ .closed = -1, .want_read = -1, .failed = -1 });
    c.lua_pushcclosure(state, openOverPipes, 0);
    try std.testing.expect(c.LUA_OK == c.lua_pcallk(state, 0, 1, 0, 0, null));
    c.lua_setglobal(state, "mail");
    try lua.expectScript(state,
        \\assert(mail:info().state == "non-authenticated")
        \\local ok, err = pcall(mail.login, mail, "test", "wrong")
        \\assert(not ok and err:find("Authentication failed", 1, true), err)
        \\mail:login("test", "secret")
        \\assert(mail:info().state == "authenticated")
        \\local boxes = mail:list()
        \\assert(#boxes == 2 and boxes[1].name == "INBOX" and boxes[1].delimiter == "/" and boxes[1].flags[1] == "\\HasNoChildren")
        \\assert(boxes[2].name == "Archive" and boxes[2].flags[1] == "\\Noselect")
        \\local selected = mail:select("INBOX")
        \\assert(selected.exists == 3 and selected.recent == 1 and selected.uidvalidity == 1234 and selected.uidnext == 10 and selected.unseen == 2)
        \\assert(#selected.flags == 5 and selected.flags[4] == "\\Seen")
        \\assert(mail:info().state == "selected")
        \\ok, err = pcall(mail.select, mail, "Missing")
        \\assert(not ok and err:find("Mailbox doesn't exist", 1, true), err)
        \\mail:select("INBOX") -- a failed SELECT leaves no mailbox selected
        \\local found = mail:search({ from = "alice", unseen = true, larger = 100, header = { "X-Tag", "lab" } })
        \\assert(#found == 2 and found[1] == 1 and found[2] == 3)
        \\assert(mail:uid_search({})[1] == 101)
        \\local messages = mail:fetch("1:2", { "flags", "uid", "size", "header", "text", "body" })
        \\local first = messages[1]
        \\assert(first.number == 1 and first.uid == 101 and first.size == 23)
        \\assert(first.flags[1] == "\\Seen" and first.flags[2] == "$Junk")
        \\assert(first.header == "Subject: one\r\n\r\n" and first.text == "hello\r\n" and first.body == "Subject: one\r\n\r\nhello\r\n")
        \\assert(mail:uid_fetch(101, { "uid" })[1].uid == 101)
        \\ok, err = pcall(mail.fetch, mail, 99, { "flags" })
        \\assert(not ok and err:find("No such message", 1, true), err)
        \\mail:store("1,3:*", "add", { "\\Seen", "\\Deleted", "$Junk" })
        \\mail:uid_store("101", "remove", { "\\Flagged" })
        \\mail:copy("1", "Archive")
        \\mail:append("INBOX", "hello")
        \\mail:expunge()
        \\mail:create("Archive/2026")
        \\mail:rename("Archive/2026", "Archive/2027")
        \\mail:delete("Archive/2027")
        \\mail:noop()
        \\-- Bad arguments raise before anything is sent.
        \\assert(not pcall(mail.fetch, mail, "1:x", { "flags" }))
        \\assert(not pcall(mail.fetch, mail, 1, { "flags", "everything" }))
        \\assert(not pcall(mail.search, mail, { colour = "red" }))
        \\assert(not pcall(mail.search, mail, { unseen = "yes" }))
        \\assert(not pcall(mail.store, mail, 1, "toggle", { "\\Seen" }))
        \\assert(not pcall(mail.store, mail, 1, "add", "\\Seen"))
        \\mail:close()
        \\assert(not pcall(mail.noop, mail))
    );
    try link.expectSent(&.{
        "LOGIN test secret", "LIST \"\" \"*\"", "SELECT INBOX",            "FROM alice",                               "UNSEEN",                                             "LARGER 100",                              "HEADER X-Tag lab",
        "BODY.PEEK[HEADER]", "BODY.PEEK[TEXT]", "BODY.PEEK[]",             "UID FETCH 101",                            "STORE 1,3:* +FLAGS.SILENT (\\Seen \\Deleted $Junk)", "UID STORE 101 -FLAGS.SILENT (\\Flagged)", "COPY 1 Archive",
        "APPEND INBOX {5}",  "EXPUNGE",         "CREATE \"Archive/2026\"", "RENAME \"Archive/2026\" \"Archive/2027\"", "DELETE \"Archive/2027\"",                            "NOOP",                                    "LOGOUT",
    });
}

test "imap session ends when the server goes silent" {
    const state = lua.testState("protocols/imap", module);
    defer c.lua_close(state);
    var link: Duplex = .{};
    test_link = &link;
    c.lua_pushcclosure(state, openOverPipes, 0);
    // The pipe is empty: no greeting ever comes.
    try std.testing.expect(c.LUA_OK != c.lua_pcallk(state, 0, 1, 0, 0, null));
    try std.testing.expect(std.mem.indexOf(u8, lua.toBytes(state, -1).?, "IMAP connection failed") != null);
}
