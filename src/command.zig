const std = @import("std");
const c = @import("c");
const frame = @import("runtime/frame.zig");
const limits = @import("limits.zig");
const text = @import("text.zig");
const identity = @import("identities/identity.zig");

pub const Transport = struct {
    name: text.FieldText,
    source: text.FixedText(limits.source_capacity),
};

pub const Socket = struct {
    identity: text.FieldText,
    run: u64 = 0,
    descriptor: c_int = -1,
    tcp: bool,
    handshaking: bool = false,
};

pub const SocketAction = enum { connect, bind, listen, accept, send, receive, close };

pub const SocketCall = struct {
    cancelled: *const std.atomic.Value(bool) = undefined,
    done: std.Io.Event = .unset,
    action: SocketAction = undefined,
    socket: *Socket = undefined,
    address: *c.struct_wolfIP_sockaddr_in = undefined,
    bytes: []u8 = undefined,
    deadline: ?u64 = null,
    result: c_int = -1,
};

pub const Command = union(enum) {
    save: identity.Identity,
    delete: text.FieldText,
    start: text.FieldText,
    stop: text.FieldText,
    set_transport: struct { name: text.FieldText, script: ?Transport },
    send_packet: struct { name: text.FieldText, value: frame.Frame },
    socket: *SocketCall,
};
