const application = @import("app.zig");

pub fn main() void {
    application.run();
}

test {
    _ = @import("identities/identity.zig");
    _ = @import("identities/config.zig");
    _ = @import("identities/manager.zig");
    _ = @import("platform/pcap.zig");
    _ = @import("runtime/runtime.zig");
    _ = @import("text.zig");
    _ = @import("ui/script_editor.zig");
    _ = @import("ui/text_editor.zig");
    _ = @import("ui/ui.zig").kraken_handle_hover;
}
