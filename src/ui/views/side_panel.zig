const std = @import("std");
const c = @import("c");
const event = @import("../event.zig");

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
        const pointer_state = c.Clay_GetPointerState().state;
        if (pointer_state == c.CLAY_POINTER_DATA_RELEASED_THIS_FRAME or pointer_state == c.CLAY_POINTER_DATA_RELEASED) {
            self.resizing = false;
            return;
        }
        const available_width = @as(f32, @floatFromInt(c.sapp_width())) / c.sapp_dpi_scale() - main_min_width - resize_handle_width;
        const max_width = @max(min_width, @min(min_width * 2, available_width));
        self.width = std.math.clamp(c.Clay_GetPointerState().position.x - self.drag_offset, min_width, max_width);
    }
};

pub fn render(state: *State, active_page: event.Page, config_dir: []const u8, context: anytype) void {
    openElement("sidebar", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = fixed(state.width), .height = grow(0) },
            .padding = .{ .left = 4, .right = 8, .top = 16, .bottom = 0 },
        },
        .backgroundColor = .{ .r = 15, .g = 17, .b = 24, .a = 255 },
    });
    if (active_page == .identities) {
        selectedLeaf(context, "identities-selected", "Identities", 12, .identities);
    } else {
        menuItem(context, "identities", "Identities", 12, .identities);
    }
    if (active_page == .script_editor) {
        selectedLeaf(context, "script-editor-selected", "Script Editor", 12, .script_editor);
    } else {
        menuItem(context, "script-editor", "Script Editor", 12, .script_editor);
    }
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

fn menuItem(context: anytype, id: []const u8, label: []const u8, indentation: u16, page: event.Page) void {
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(34) },
            .padding = .{ .left = indentation, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    context.bindSignal(.{ .select_page = page });
    text(label, 17, .{ .r = 218, .g = 222, .b = 232, .a = 255 });
    c.Clay__CloseElement();
}

fn selectedLeaf(context: anytype, id: []const u8, label: []const u8, indentation: u16, page: event.Page) void {
    openElement(id, .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(34) }, .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER } },
    });
    context.bindSignal(.{ .select_page = page });
    openElement("active-leaf-indicator", .{
        .layout = .{ .sizing = .{ .width = fixed(3), .height = grow(0) } },
        .backgroundColor = .{ .r = 166, .g = 82, .b = 255, .a = 255 },
    });
    c.Clay__CloseElement();
    openElement("active-leaf-label", .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .padding = .{ .left = indentation - 3, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = .{ .r = 28, .g = 30, .b = 40, .a = 255 },
    });
    text(label, 17, .{ .r = 238, .g = 240, .b = 247, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn pathText(context: anytype, value: []const u8) void {
    const config: c.Clay_TextElementConfig = .{
        .userData = @ptrCast(&context.path_wrap_marker),
        .fontId = 0,
        .fontSize = 15,
        .textColor = .{ .r = 204, .g = 209, .b = 222, .a = 255 },
    };
    c.Clay__OpenTextElement(clayString(value, false), config);
}

fn text(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    c.Clay__OpenTextElement(clayString(value, true), .{ .fontId = 0, .fontSize = font_size, .textColor = color });
}

fn openElement(id: []const u8, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementId(clayString(id, true)));
    c.Clay__ConfigureOpenElementPtr(&declaration);
}

fn pointerOver(id: []const u8) bool {
    return c.Clay_PointerOver(c.Clay_GetElementId(clayString(id, true)));
}

fn fixed(value: f32) c.Clay_SizingAxis {
    return .{ .size = .{ .minMax = .{ .min = value, .max = value } }, .type = c.CLAY__SIZING_TYPE_FIXED };
}

fn grow(minimum: f32) c.Clay_SizingAxis {
    return .{ .size = .{ .minMax = .{ .min = minimum, .max = 0 } }, .type = c.CLAY__SIZING_TYPE_GROW };
}

fn clayString(value: []const u8, is_static: bool) c.Clay_String {
    return .{ .chars = value.ptr, .length = @intCast(value.len), .isStaticallyAllocated = is_static };
}
