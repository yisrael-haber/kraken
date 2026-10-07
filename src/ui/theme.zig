const c = @import("c");

fn rgb(r: f32, g: f32, b: f32) c.Clay_Color {
    return .{ .r = r, .g = g, .b = b, .a = 255 };
}

pub const window = rgb(18, 24, 38);
pub const recessed = rgb(17, 20, 29);
pub const field = rgb(27, 29, 39);
pub const field_active = rgb(33, 36, 48);
pub const option_hover = rgb(43, 47, 62);
pub const border = rgb(47, 52, 68);

pub const primary = rgb(101, 36, 165);
pub const accent = rgb(139, 82, 207);
pub const highlight = rgb(183, 119, 255);
pub const selection: c.Clay_Color = .{ .r = 90, .g = 75, .b = 150, .a = 150 };

pub const text_bright = rgb(228, 232, 243);
pub const text = rgb(203, 208, 222);
pub const text_secondary = rgb(155, 164, 187);
pub const text_muted = rgb(123, 131, 152);

pub const syntax_literal = rgb(242, 183, 104);
pub const syntax_string = rgb(156, 215, 157);
pub const syntax_builtin = rgb(118, 187, 242);
