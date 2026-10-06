const std = @import("std");
const net = @import("net");
const frame = @import("runtime/frame.zig");
const text = @import("text.zig");
const identity = @import("identities/identity.zig");

pub const Socket = struct {
    identity: text.FieldText,
    run: u64 = 0,
    endpoint: net.Socket,
};

pub const SocketAction = net.SocketAction;

pub const SocketCall = struct {
    action: SocketAction,
    socket: *Socket,
    address: ?*net.Address,
    bytes: []u8,
    deadline: ?u64,
    cancelled: *std.Io.Event,
    result: net.SocketResult = .failed,
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
