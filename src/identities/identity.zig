const text = @import("../text.zig");

pub const Identity = struct {
    id: text.FieldText = .{},
    label: text.FieldText = .{},
    ip: text.FieldText = .{},
    prefix: text.FieldText = .{},
    interface: text.FieldText = .{},
    gateway: text.FieldText = .{},
    mac: text.FieldText = .{},
    mtu: text.FieldText = .{},
    transport: text.FieldText = .{},
};
