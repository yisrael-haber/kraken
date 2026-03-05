const std = @import("std");
const builtin = @import("builtin");

/// libpcap bindings used throughout the codebase.  This is pulled out of
/// `main.zig` to avoid a cycle when the handler also needs to reference
/// the same definitions.
pub const pcap = @cImport({
    // Npcap on Windows requires these defines before including pcap.h.
    if (builtin.os.tag == .windows) {
        @cDefine("WPCAP", "");
        @cDefine("HAVE_REMOTE", "");
    }
    @cInclude("pcap.h");
});
