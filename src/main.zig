const application = @import("app.zig");

pub fn main() void {
    application.run();
}

test {
    _ = @import("identities/service.zig");
    _ = @import("platform/pcap.zig");
    _ = @import("runtime/lua.zig");
    _ = @import("runtime/runtime.zig");
    _ = @import("storage/model.zig");
    _ = @import("ui/script_editor.zig");
    _ = @import("ui/text_editor.zig");
    _ = @import("ui/ui.zig").kraken_handle_hover;
}
