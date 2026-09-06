const c = @import("c");
const clay = @import("clay.zig");

pub fn render(active_page: anytype, config_dir: []const u8, context: anytype) void {
    clay.open("sidebar", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.fixed(240), .height = clay.grow(0) },
            .padding = .{ .left = 4, .right = 8, .top = 16, .bottom = 0 },
        },
        .backgroundColor = .{ .r = 15, .g = 17, .b = 24, .a = 255 },
    });
    navigationItem(context, "identities", "Identities", .identities, 0, active_page == .identities);
    navigationItem(context, "script-editor", "Script Editor", .script_editor, 1, active_page == .script_editor);
    navigationItem(context, "logs", "Logs", .logs, 2, active_page == .logs);
    clay.open("sidebar-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    clay.open("config-directory-footer", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(108) },
            .padding = .{ .left = 16, .right = 12, .top = 14, .bottom = 12 },
            .childGap = 7,
        },
        .border = .{ .color = .{ .r = 31, .g = 34, .b = 45, .a = 255 }, .width = .{ .top = 1 } },
    });
    clay.text("CONFIGURATION DIRECTORY", 14, .{ .r = 151, .g = 157, .b = 174, .a = 255 });
    pathText(context, config_dir);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn navigationItem(context: anytype, id: []const u8, label: []const u8, page: anytype, index: usize, selected: bool) void {
    clay.open(id, .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(34) },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    context.bindSignal(.{ .select_page = page });
    clay.openIndexed("navigation-indicator", index, .{
        .layout = .{ .sizing = .{ .width = clay.fixed(3), .height = clay.grow(0) } },
        .backgroundColor = if (selected) .{ .r = 166, .g = 82, .b = 255, .a = 255 } else .{},
    });
    c.Clay__CloseElement();
    clay.openIndexed("navigation-label", index, .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .padding = .{ .left = 9, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 28, .g = 30, .b = 40, .a = 255 } else .{},
    });
    clay.text(label, 17, if (selected) .{ .r = 238, .g = 240, .b = 247, .a = 255 } else .{ .r = 218, .g = 222, .b = 232, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn pathText(context: anytype, value: []const u8) void {
    c.Clay__OpenTextElement(clay.string(value, false), .{
        .userData = @ptrCast(context),
        .fontId = 0,
        .fontSize = 15,
        .textColor = .{ .r = 204, .g = 209, .b = 222, .a = 255 },
    });
}
