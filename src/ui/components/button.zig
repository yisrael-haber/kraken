const c = @import("c");
const event = @import("../event.zig");

pub const Style = enum { primary, secondary, danger };

pub fn render(context: anytype, id: []const u8, style: Style, action: event.Action, index: ?usize) void {
    const primary = style == .primary;
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = fixed(38), .height = fixed(38) },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_CENTER, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary)
            if (pointerOver(id)) .{ .r = 122, .g = 54, .b = 190, .a = 255 } else .{ .r = 101, .g = 36, .b = 165, .a = 255 }
        else if (pointerOver(id)) .{ .r = 30, .g = 33, .b = 44, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
    });
    context.bindSignal(.{ .form_action = .{ .action = action, .index = index } });
    icon(actionGlyph(action), 19, if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 171, .g = 180, .b = 202, .a = 255 });
    c.Clay__CloseElement();
}

fn actionGlyph(action: event.Action) []const u8 {
    return switch (action) {
        .save_identity, .save_script => "\u{e248}",
        .clear_identity => "\u{e21e}",
        .edit_identity, .edit_script => "\u{e3b4}",
        .delete_identity, .delete_script => "\u{e4a6}",
        .start_identity, .run_global_script => "\u{e3d0}",
        .stop_identity, .stop_global_script => "\u{e46c}",
        .new_script => "\u{e3d4}",
    };
}

fn icon(glyph: []const u8, font_size: u16, color: c.Clay_Color) void {
    c.Clay__OpenTextElement(clayString(glyph, true), .{ .fontId = 1, .fontSize = font_size, .textColor = color });
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

fn clayString(value: []const u8, is_static: bool) c.Clay_String {
    return .{ .chars = value.ptr, .length = @intCast(value.len), .isStaticallyAllocated = is_static };
}
