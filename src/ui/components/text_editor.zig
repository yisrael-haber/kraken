const limits = @import("../../limits.zig");
const input = @import("input.zig");

pub const TextArea = input.TextBuffer(limits.source_capacity);

pub const State = struct {
    buffer: TextArea = .{},
    focused: bool = false,
    cursor: usize = 0,
    cursor_visual_line: usize = 0,
    selection_anchor: ?usize = null,
    font_size: u16 = 20,
    font_size_menu_open: bool = false,
};
