const event = @import("event.zig");

/// Exhaustive, compile-time dispatch entrypoint. Adding a UiEvent tag requires
/// updating this switch and therefore cannot silently go unhandled.
pub fn dispatch(context: anytype, value: event.UiEvent) void {
    switch (value) {
        .signal => |payload| context.handleSignal(payload),
        .input => |payload| context.handleInput(payload),
        .editor => |payload| context.handleEditor(payload),
    }
}
