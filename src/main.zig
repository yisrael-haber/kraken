const std = @import("std");
const application = @import("app.zig");

// The alternate signal stack only serves the segfault handler, which release builds disable.
// Without this, every thread reserves 256 KiB of thread-local storage for it.
pub const std_options: std.Options = .{
    .signal_stack_size = if (std.debug.default_enable_segfault_handler) 1 << 18 else null,
};

pub fn main() void {
    application.run();
}

test {
    _ = @import("identities/identity.zig");
    _ = @import("runtime/runtime.zig");
    _ = @import("text.zig");
    _ = @import("ui/script_editor.zig");
    _ = @import("ui/text_editor.zig");
    _ = @import("ui/ui.zig").kraken_handle_hover;
}
