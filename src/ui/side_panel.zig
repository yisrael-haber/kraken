const c = @import("c");
const clay = @import("clay.zig");
const theme = @import("theme.zig");

pub fn render(active_page: anytype, config_dir: []const u8, context: anytype) void {
    clay.open("sidebar", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.fixed, 240), .height = clay.size(.grow, 0) },
            .padding = .{ .left = 4, .right = 8, .top = 16 },
        },
        .backgroundColor = theme.recessed,
    });
    navigationItem(context, active_page, "Identities", .identities);
    navigationItem(context, active_page, "Script Editor", .script_editor);
    navigationItem(context, active_page, "Logs", .logs);
    clay.spacer();
    clay.open("config-directory-footer", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 108) },
            .padding = .{ .left = 16, .right = 12, .top = 14, .bottom = 12 },
            .childGap = 7,
        },
        .border = .{ .color = theme.border, .width = .{ .top = 1 } },
    });
    clay.text("CONFIGURATION DIRECTORY", 14, theme.text_secondary);
    // Non-null user data makes Clay also wrap at path separators.
    clay.openText(config_dir, false, .{
        .userData = @ptrCast(@constCast(config_dir.ptr)),
        .fontId = 0,
        .fontSize = 15,
        .textColor = theme.text,
    });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn navigationItem(context: anytype, active_page: anytype, label: []const u8, page: @TypeOf(active_page)) void {
    const selected = active_page == page;
    clay.openIndexed("navigation-item", @intFromEnum(page), .{
        .layout = .{
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 34) },
            .padding = .{ .left = 12, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) theme.field else .{},
        .border = .{ .color = theme.highlight, .width = .{ .left = if (selected) 3 else 0 } },
    });
    context.bindAction(.{ .select_page = page });
    clay.text(label, 17, theme.text_bright);
    c.Clay__CloseElement();
}
