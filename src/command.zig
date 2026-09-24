const c = @import("c");
const std = @import("std");
const frame = @import("runtime/frame.zig");
const text = @import("text.zig");
const identity = @import("identities/identity.zig");

pub const Socket = struct {
    identity: text.FieldText,
    run: u64 = 0,
    descriptor: c_int = -1,
    kind: enum(u8) { tcp = c.IPSTACK_SOCK_STREAM, udp = c.IPSTACK_SOCK_DGRAM, raw = c.IPSTACK_SOCK_RAW },
    protocol: u8 = 0,
    header: bool = false,
    handshaking: bool = false,
};

pub const SocketAction = enum { connect, bind, listen, accept, send, receive, close };

pub const SocketCall = struct {
    action: SocketAction,
    socket: *Socket,
    address: *c.struct_wolfIP_sockaddr_in,
    bytes: []u8,
    deadline: ?u64,
    cancelled: *std.Io.Event,
    result: c_int = -1,
};

pub const Command = union(enum) {
    save: identity.Identity,
    delete: text.FieldText,
    start: text.FieldText,
    stop: text.FieldText,
    set_transport: struct { name: text.FieldText, script: ?text.FieldText },
    set_bpf: struct { name: text.FieldText, expression: text.FieldText },
    transmit: struct { name: text.FieldText, value: frame.Frame, direction: frame.Direction },
    socket: *SocketCall,
};
