const std = @import("std");
const c = @import("c");
const clay = @import("clay.zig");

const fixed = clay.fixed;
const grow = clay.grow;
const openElement = clay.open;
const openIndexedElement = clay.openIndexed;
const pointerOver = clay.pointerOver;
const text = clay.text;

const min_width: f32 = 150;
const initial_width: f32 = 240;
const main_min_width: f32 = 640;
const resize_handle_width: f32 = 4;

pub const State = struct {
    width: f32 = initial_width,
    drag_offset: f32 = 0,
    resizing: bool = false,

    pub fn updateWidth(self: *State) void {
        if (!self.resizing) return;
        const pointer_state = c.kraken_pointer_state();
        if (pointer_state == c.CLAY_POINTER_DATA_RELEASED_THIS_FRAME or pointer_state == c.CLAY_POINTER_DATA_RELEASED) {
            self.resizing = false;
            return;
        }
        const available_width = @as(f32, @floatFromInt(c.sapp_width())) / c.sapp_dpi_scale() - main_min_width - resize_handle_width;
        const max_width = @max(min_width, @min(min_width * 2, available_width));
        self.width = std.math.clamp(c.kraken_pointer_x() - self.drag_offset, min_width, max_width);
    }
};

pub fn render(state: *State, active_page: anytype, config_dir: []const u8, context: anytype) void {
    openElement("sidebar", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = fixed(state.width), .height = grow(0) },
            .padding = .{ .left = 4, .right = 8, .top = 16, .bottom = 0 },
        },
        .backgroundColor = .{ .r = 15, .g = 17, .b = 24, .a = 255 },
    });
    navigationItem(context, "identities", "Identities", .identities, 0, active_page == .identities);
    navigationItem(context, "script-editor", "Script Editor", .script_editor, 1, active_page == .script_editor);
    openElement("sidebar-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    openElement("config-directory-footer", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = fixed(108) },
            .padding = .{ .left = 16, .right = 12, .top = 14, .bottom = 12 },
            .childGap = 7,
        },
        .border = .{ .color = .{ .r = 31, .g = 34, .b = 45, .a = 255 }, .width = .{ .top = 1 } },
    });
    text("CONFIGURATION DIRECTORY", 14, .{ .r = 151, .g = 157, .b = 174, .a = 255 });
    pathText(context, config_dir);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    const resize_hovered = pointerOver("sidebar-resize-handle");
    openElement("sidebar-resize-handle", .{
        .layout = .{ .sizing = .{ .width = fixed(resize_handle_width), .height = grow(0) } },
        .backgroundColor = if (resize_hovered or state.resizing) .{ .r = 55, .g = 111, .b = 192, .a = 255 } else .{ .r = 28, .g = 38, .b = 57, .a = 255 },
    });
    context.bindSignal(.resize_sidebar);
    c.Clay__CloseElement();
}

fn navigationItem(context: anytype, id: []const u8, label: []const u8, page: anytype, index: usize, selected: bool) void {
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(34) },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    context.bindSignal(.{ .select_page = page });
    openIndexedElement("navigation-indicator", index, .{
        .layout = .{ .sizing = .{ .width = fixed(3), .height = grow(0) } },
        .backgroundColor = if (selected) .{ .r = 166, .g = 82, .b = 255, .a = 255 } else .{},
    });
    c.Clay__CloseElement();
    openIndexedElement("navigation-label", index, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .padding = .{ .left = 9, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 28, .g = 30, .b = 40, .a = 255 } else .{},
    });
    text(label, 17, if (selected) .{ .r = 238, .g = 240, .b = 247, .a = 255 } else .{ .r = 218, .g = 222, .b = 232, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn pathText(context: anytype, value: []const u8) void {
    c.Clay__OpenTextElement(clay.string(value, false), .{
        .userData = @ptrCast(&context.path_wrap_marker),
        .fontId = 0,
        .fontSize = 15,
        .textColor = .{ .r = 204, .g = 209, .b = 222, .a = 255 },
    });
}
