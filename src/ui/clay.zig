const c = @import("c");

pub const MenuAnchor = enum { left, right };

pub fn fixed(value: f32) c.Clay_SizingAxis {
    return .{
        .size = .{ .minMax = .{ .min = value, .max = value } },
        .type = c.CLAY__SIZING_TYPE_FIXED,
    };
}

pub fn grow(minimum: f32) c.Clay_SizingAxis {
    return .{
        .size = .{ .minMax = .{ .min = minimum, .max = 0 } },
        .type = c.CLAY__SIZING_TYPE_GROW,
    };
}

pub fn string(value: []const u8, is_static: bool) c.Clay_String {
    return .{ .chars = value.ptr, .length = @intCast(value.len), .isStaticallyAllocated = is_static };
}

pub fn open(id: []const u8, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementId(string(id, true)));
    c.Clay__ConfigureOpenElementPtr(&declaration);
}

pub fn openIndexed(id: []const u8, index: usize, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementIdWithIndex(string(id, true), @intCast(index)));
    c.Clay__ConfigureOpenElementPtr(&declaration);
}

pub fn openScrollable(id: []const u8, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementId(string(id, true)));
    var scroll_declaration = declaration;
    scroll_declaration.clip.childOffset = c.Clay_GetScrollOffset();
    c.Clay__ConfigureOpenElementPtr(&scroll_declaration);
}

pub fn menu(width: f32, height: f32, anchor: MenuAnchor, z_index: i16) c.Clay_ElementDeclaration {
    return .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = fixed(width), .height = fixed(height) },
            .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
        },
        .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
        .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .attachPoints = if (anchor == .left)
                .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_BOTTOM }
            else
                .{ .element = c.CLAY_ATTACH_POINT_RIGHT_TOP, .parent = c.CLAY_ATTACH_POINT_RIGHT_BOTTOM },
            .offset = .{ .y = 4 },
            .zIndex = z_index,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
        },
    };
}

pub fn menuOption(selected: bool, hovered: bool) c.Clay_ElementDeclaration {
    return .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(28) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    };
}

pub fn pointerOver(id: []const u8) bool {
    return c.Clay_PointerOver(c.Clay_GetElementId(string(id, true)));
}

pub fn pointerOverIndexed(id: []const u8, index: usize) bool {
    return c.Clay_PointerOver(c.Clay_GetElementIdWithIndex(string(id, true), @intCast(index)));
}

pub fn text(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    c.Clay__OpenTextElement(string(value, true), .{
        .fontId = 0,
        .fontSize = font_size,
        .textColor = color,
    });
}

pub fn dynamicText(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    c.Clay__OpenTextElement(string(value, false), .{
        .fontId = 0,
        .fontSize = font_size,
        .textColor = color,
    });
}

pub fn measureText(fonts: *[2]c.sclay_font_t, value: []const u8, font_size: u16) f32 {
    var config: c.Clay_TextElementConfig = .{ .fontId = 0, .fontSize = font_size };
    return c.sclay_measure_text(.{
        .chars = value.ptr,
        .baseChars = value.ptr,
        .length = @intCast(value.len),
    }, &config, @ptrCast(fonts[0..].ptr)).width;
}

pub fn textOffsetAtX(fonts: *[2]c.sclay_font_t, value: []const u8, x: f32, font_size: u16) usize {
    if (x <= 0) return 0;
    var offset: usize = 0;
    while (offset < value.len) {
        var next = offset + 1;
        while (next < value.len and value[next] & 0b1100_0000 == 0b1000_0000) : (next += 1) {}
        const midpoint = (measureText(fonts, value[0..offset], font_size) + measureText(fonts, value[0..next], font_size)) / 2;
        if (x < midpoint) return offset;
        offset = next;
    }
    return value.len;
}
