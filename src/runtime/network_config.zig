pub const Config = struct {
    address: [4]u8,
    prefix_length: u8,
    gateway: ?[4]u8 = null,
    mac: [6]u8,
    mtu: u16 = 1500,

    pub fn defaultForSlot(slot: usize) Config {
        return .{
            .address = .{ 192, 0, 2, @intCast(slot + 1) },
            .prefix_length = 24,
            .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, @intCast(slot + 1) },
        };
    }
};
