pub const Address = struct {
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    port: u16 = 0,
};

pub const Config = struct {
    ip: [4]u8,
    prefix: u8,
    gateway: ?[4]u8,
    mac: [6]u8,
    mtu: u16,
};

pub const SocketKind = enum { tcp, udp, raw };
pub const SocketAction = enum { connect, bind, listen, accept, send, receive, close };

// Only a stack backend may create or interpret a handle.
pub const InterfaceHandle = enum(usize) { _ };
pub const SocketHandle = enum(usize) { _ };

pub const Socket = struct {
    handle: ?SocketHandle = null,
    kind: SocketKind,
    protocol: u8 = 0,
    header: bool = false,
    backlog: u8 = 1,
};

pub const SocketResult = union(enum) {
    // Byte count for transfers; zero for connect, bind, listen, and close.
    success: usize,
    accepted: SocketHandle,
    // End of a TCP stream; zero-byte UDP datagrams remain successful reads.
    closed,
    would_block,
    failed,
};

pub const Error = error{RuntimeUnavailable};
