const std = @import("std");
const c = @import("lwip_c");

pub const frame_capacity = 2048;

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

// Only this frontend creates or interprets handles.
pub const InterfaceHandle = enum(usize) { _ };
pub const SocketHandle = enum(usize) { _ };

pub const Socket = struct {
    handle: ?SocketHandle = null,
    kind: SocketKind,
    protocol: u8 = 0,
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

const Interface = struct {
    raw: c.struct_netif = std.mem.zeroes(c.struct_netif),
    stack: *Stack,
    context: *anyopaque,
    mtu: u16,
    sockets: std.ArrayList(c_int) = .empty,
};
const Frame = struct { iface: ?*Interface, length: u16, bytes: [frame_capacity]u8 };
pub const Output = struct { context: *anyopaque, length: usize };

// lwIP owns one process-wide TCP/IP thread, which outlives individual stacks.
var initialized = false;

pub const Stack = struct {
    allocator: std.mem.Allocator,
    context: *anyopaque,
    wake: *const fn (?*anyopaque) callconv(.c) void,
    // lwIP produces frames under its core lock; consumers use the same lock.
    frames: [64]Frame = undefined,
    read: usize = 0,
    write: usize = 0,

    pub fn init(self: *Stack, allocator: std.mem.Allocator, context: *anyopaque, wake: *const fn (?*anyopaque) callconv(.c) void) Error!void {
        self.* = .{ .allocator = allocator, .context = context, .wake = wake };
        if (!initialized) {
            var started: c.sys_sem_t = undefined;
            if (c.sys_sem_new(&started, 0) != c.ERR_OK) return error.RuntimeUnavailable;
            defer c.sys_sem_free(&started);
            c.tcpip_init(ready, @ptrCast(&started));
            _ = c.sys_arch_sem_wait(&started, 0);
            initialized = true;
        }
    }

    pub fn addInterface(self: *Stack, config: Config, context: *anyopaque) Error!InterfaceHandle {
        const iface = self.allocator.create(Interface) catch return error.RuntimeUnavailable;
        errdefer self.allocator.destroy(iface);
        iface.* = .{ .stack = self, .context = context, .mtu = config.mtu };
        @memcpy(iface.raw.hwaddr[0..6], &config.mac);
        const local: c.ip4_addr_t = .{ .addr = @bitCast(config.ip) };
        const mask: c.ip4_addr_t = .{ .addr = std.mem.nativeToBig(u32, if (config.prefix == 0) 0 else @as(u32, std.math.maxInt(u32)) << @intCast(32 - config.prefix)) };
        const gateway: c.ip4_addr_t = .{ .addr = @bitCast(config.gateway orelse .{ 0, 0, 0, 0 }) };
        if (c.netifapi_netif_add(&iface.raw, &local, &mask, &gateway, iface, initInterface, c.tcpip_input) != c.ERR_OK)
            return error.RuntimeUnavailable;
        _ = c.netifapi_netif_common(&iface.raw, c.netif_set_link_up, null);
        _ = c.netifapi_netif_common(&iface.raw, c.netif_set_up, null);
        return @enumFromInt(@intFromPtr(iface));
    }

    pub fn removeInterface(self: *Stack, handle: InterfaceHandle) void {
        const iface = interface(handle);
        for (iface.sockets.items) |fd| _ = c.lwip_close(fd);
        iface.sockets.deinit(self.allocator);
        _ = c.netifapi_netif_common(&iface.raw, c.netif_remove, null);
        c.sys_lock_tcpip_core();
        var index = self.read;
        while (index != self.write) : (index +%= 1) {
            const item = &self.frames[index % self.frames.len];
            if (item.iface == iface) item.iface = null;
        }
        c.sys_unlock_tcpip_core();
        self.allocator.destroy(iface);
    }

    pub fn input(_: *Stack, handle: InterfaceHandle, frame: []const u8) Error!void {
        const iface = interface(handle);
        const p = c.pbuf_alloc(c.PBUF_RAW, @intCast(frame.len), c.PBUF_RAM) orelse return error.RuntimeUnavailable;
        _ = c.pbuf_take(p, frame.ptr, @intCast(frame.len));
        if (iface.raw.input.?(p, &iface.raw) != c.ERR_OK) {
            _ = c.pbuf_free(p);
            return error.RuntimeUnavailable;
        }
    }

    pub fn output(self: *Stack, bytes: *[frame_capacity]u8) ?Output {
        c.sys_lock_tcpip_core();
        defer c.sys_unlock_tcpip_core();
        while (self.read != self.write) {
            const item = &self.frames[self.read % self.frames.len];
            self.read +%= 1;
            const iface = item.iface orelse continue;
            @memcpy(bytes[0..item.length], item.bytes[0..item.length]);
            return .{ .context = iface.context, .length = item.length };
        }
        return null;
    }

    pub fn socket(self: *Stack, handle: InterfaceHandle, action: SocketAction, value: *Socket, address: ?*Address, bytes: []u8) SocketResult {
        const iface = interface(handle);
        if ((action == .connect or action == .bind) and value.handle == null) {
            const fd = c.lwip_socket(c.AF_INET, switch (value.kind) {
                .tcp => c.SOCK_STREAM,
                .udp => c.SOCK_DGRAM,
                .raw => c.SOCK_RAW,
            }, value.protocol);
            if (fd < 0) return .failed;
            var device = std.mem.zeroes(c.struct_ifreq);
            _ = c.netif_index_to_name(c.netif_get_index(&iface.raw), &device.ifr_name);
            _ = c.lwip_setsockopt(fd, c.SOL_SOCKET, c.SO_BINDTODEVICE, &device, @sizeOf(@TypeOf(device)));
            value.handle = self.register(iface, fd) catch return .failed;
        }
        const fd: c_int = @intCast(@intFromEnum(value.handle orelse return .failed));
        var raw = std.mem.zeroes(c.struct_sockaddr_in);
        var raw_length: c.socklen_t = @sizeOf(@TypeOf(raw));
        if (address) |a| {
            raw.sin_len = @sizeOf(@TypeOf(raw));
            raw.sin_family = c.AF_INET;
            raw.sin_port = std.mem.nativeToBig(u16, a.port);
            raw.sin_addr.s_addr = @bitCast(a.ip);
            if (action == .bind and value.kind != .raw and raw.sin_addr.s_addr == 0)
                raw.sin_addr.s_addr = iface.raw.ip_addr.addr;
        }
        const result = switch (action) {
            .connect => c.lwip_connect(fd, @ptrCast(&raw), raw_length),
            .bind => c.lwip_bind(fd, @ptrCast(&raw), raw_length),
            .listen => c.lwip_listen(fd, value.backlog),
            .accept => c.lwip_accept(fd, @ptrCast(&raw), &raw_length),
            .send => if (address != null) c.lwip_sendto(fd, bytes.ptr, bytes.len, 0, @ptrCast(&raw), raw_length) else c.lwip_send(fd, bytes.ptr, bytes.len, 0),
            .receive => c.lwip_recvfrom(fd, bytes.ptr, bytes.len, 0, @ptrCast(&raw), &raw_length),
            .close => c.lwip_close(fd),
        };
        if (result < 0) {
            const err = c.kraken_lwip_errno();
            if (action == .connect and err == c.EISCONN) return .{ .success = 0 };
            return if (err == c.EAGAIN or err == c.EWOULDBLOCK or err == c.EINPROGRESS or err == c.EALREADY) .would_block else .failed;
        }
        if (address) |a| if (action == .accept or action == .receive) {
            a.* = .{ .ip = @bitCast(raw.sin_addr.s_addr), .port = std.mem.bigToNative(u16, raw.sin_port) };
        };
        if (action == .accept) return .{ .accepted = self.register(iface, @intCast(result)) catch return .failed };
        if (action == .close) {
            if (std.mem.indexOfScalar(c_int, iface.sockets.items, fd)) |index| _ = iface.sockets.swapRemove(index);
            value.handle = null;
        }
        if (action == .receive and result == 0 and value.kind == .tcp) return .closed;
        return .{ .success = @intCast(result) };
    }

    // Takes ownership of fd, closing it if registration fails.
    fn register(self: *Stack, iface: *Interface, fd: c_int) Error!SocketHandle {
        errdefer _ = c.lwip_close(fd);
        _ = c.lwip_fcntl(fd, c.F_SETFL, c.O_NONBLOCK);
        iface.sockets.append(self.allocator, fd) catch return error.RuntimeUnavailable;
        return @enumFromInt(@as(usize, @intCast(fd)));
    }
};

fn interface(handle: InterfaceHandle) *Interface {
    return @ptrFromInt(@intFromEnum(handle));
}

fn ready(context: ?*anyopaque) callconv(.c) void {
    c.sys_sem_signal(@ptrCast(@alignCast(context.?)));
}

fn initInterface(raw_pointer: [*c]c.struct_netif) callconv(.c) c.err_t {
    const raw: *c.struct_netif = @ptrCast(raw_pointer);
    const iface: *Interface = @ptrCast(@alignCast(raw.state.?));
    raw.name = .{ 'k', 'r' };
    raw.hwaddr_len = 6;
    raw.mtu = iface.mtu;
    raw.flags = c.NETIF_FLAG_BROADCAST | c.NETIF_FLAG_ETHARP | c.NETIF_FLAG_ETHERNET;
    raw.output = c.etharp_output;
    raw.linkoutput = emit;
    return c.ERR_OK;
}

fn emit(raw_pointer: [*c]c.struct_netif, p_pointer: [*c]c.struct_pbuf) callconv(.c) c.err_t {
    const raw: *c.struct_netif = @ptrCast(raw_pointer);
    const p: *c.struct_pbuf = @ptrCast(p_pointer);
    const iface: *Interface = @ptrCast(@alignCast(raw.state.?));
    const self = iface.stack;
    if (p.tot_len > self.frames[0].bytes.len or self.write -% self.read == self.frames.len) return c.ERR_MEM;
    const item = &self.frames[self.write % self.frames.len];
    _ = c.pbuf_copy_partial(p, &item.bytes, p.tot_len, 0);
    item.iface = iface;
    item.length = p.tot_len;
    self.write +%= 1;
    self.wake(self.context);
    return c.ERR_OK;
}
