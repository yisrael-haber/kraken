const frame = @import("runtime/frame.zig");
const limits = @import("limits.zig");
const text = @import("text.zig");
const identity = @import("identities/identity.zig");

pub const Transport = struct {
    name: text.FieldText,
    source: text.FixedText(limits.source_capacity),
};

pub const Command = union(enum) {
    save: identity.Identity,
    delete: text.FieldText,
    start: text.FieldText,
    stop: text.FieldText,
    set_transport: struct { name: text.FieldText, script: ?Transport },
    send_packet: struct { name: text.FieldText, value: frame.Frame },
};
