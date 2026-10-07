const std = @import("std");
const net = @import("net");
const text = @import("text.zig");
const identity = @import("identities/identity.zig");

pub const Socket = struct {
    identity: text.FieldText,
    run: u64 = 0,
    endpoint: net.Socket,
};

pub const SocketAction = net.SocketAction;

pub const Direction = enum { inbound, outbound };

pub const SocketCall = struct {
    action: SocketAction,
    socket: *Socket,
    address: ?*net.Address,
    bytes: []u8,
    deadline: ?i64,
    cancelled: *std.Io.Event,
    result: net.SocketResult = .{ .success = 0 },
};

pub const Command = union(enum) {
    save: identity.Identity,
    delete: text.FieldText,
    start: text.FieldText,
    stop: text.FieldText,
    set_transport: struct { name: text.FieldText, script: ?text.FieldText },
    set_bpf: struct { name: text.FieldText, expression: text.FieldText },
    transmit: struct { name: text.FieldText, bytes: []const u8, direction: Direction },
    socket: *SocketCall,
};
