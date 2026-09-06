const std = @import("std");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const clay = @import("clay.zig");
const text_editor = @import("text_editor.zig");
const c = @import("c");

const Text = text_editor.Editor(text.FixedText(limits.source_capacity), .multiline);
pub const text_area_id = "script-text-area";
pub const Fonts = text_editor.Fonts;

pub const Action = union(enum) {
    focus,
    toggle_font_size_menu,
    select_font_size: u16,
};

pub const RenderContext = struct {
    fonts: *Fonts,
    focused: bool,
    binding_context: *anyopaque,
    bind_action: *const fn (*anyopaque, Action) void,
};

pub const State = struct {
    text: Text = .{},
    cursor_visual_line: usize = 0,
    preferred_x: ?f32 = null,
    visual_row_starts: [limits.source_capacity + 1]u16 = undefined,
    visual_row_count: usize = 0,
    font_size: u16 = 20,
    font_size_menu_open: bool = false,

    pub fn reset(self: *State) void {
        const font_size = self.font_size;
        self.* = .{ .font_size = font_size };
    }

    pub fn load(self: *State, contents: text.FixedText(limits.source_capacity)) void {
        const font_size = self.font_size;
        self.* = .{ .text = .{ .buffer = contents }, .font_size = font_size };
    }

    pub fn render(self: *State, context: RenderContext) void {
        renderToolbar(self, context);
        renderTextArea(self, context);
    }

    pub fn handleAction(self: *State, action: Action) void {
        switch (action) {
            .focus => unreachable,
            .toggle_font_size_menu => self.font_size_menu_open = !self.font_size_menu_open,
            .select_font_size => |font_size| {
                self.font_size = font_size;
                self.preferred_x = null;
                self.font_size_menu_open = false;
            },
        }
    }

    pub fn handlePointer(self: *State, fonts: *Fonts, pointer_state: c_int) void {
        if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
            self.font_size_menu_open = false;
            self.preferred_x = null;
            moveCursorFromPointer(self, fonts);
            self.text.selection_anchor = self.text.cursor;
            self.text.dragging = true;
        } else if (pointer_state == c.CLAY_POINTER_DATA_PRESSED and self.text.dragging) {
            moveCursorFromPointer(self, fonts);
        }
    }

    pub fn handleEvent(self: *State, fonts: *Fonts, event_data: c.sapp_event) error{CapacityExceeded}!text_editor.Result {
        if (verticalDirection(event_data)) |down| {
            moveCursorVertically(self, fonts, down, event_data.modifiers & c.SAPP_MODIFIER_SHIFT != 0);
            keepCursorVisible(self);
            return .handled;
        }
        const result = self.text.handleEvent(event_data) catch |err| switch (err) {
            error.CapacityExceeded => return error.CapacityExceeded,
            error.MultilineText => unreachable,
        };
        if (result == .handled) {
            self.preferred_x = null;
            keepCursorVisible(self);
        }
        return result;
    }

    pub fn keepCursorVisible(self: *const State) void {
        const scroll_data = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clay.string(text_area_id, true)));
        if (!scroll_data.found or scroll_data.scrollPosition == null) return;

        const line_height = lineHeight(self.font_size);
        const line_top = @as(f32, @floatFromInt(self.cursor_visual_line)) * line_height;
        const line_bottom = line_top + line_height;
        const viewport_height = scroll_data.scrollContainerDimensions.height;
        const scroll_position = scroll_data.scrollPosition;
        const visible_top = -scroll_position.*.y;
        const visible_bottom = visible_top + viewport_height;
        var target_scroll = scroll_position.*.y;
        if (line_top < visible_top) {
            target_scroll = -line_top;
        } else if (line_bottom > visible_bottom) {
            target_scroll = -(line_bottom - viewport_height);
        }
        const minimum_scroll = @min(0, viewport_height - scroll_data.contentDimensions.height);
        scroll_position.*.y = std.math.clamp(target_scroll, minimum_scroll, 0);
    }

    fn recordVisualRow(self: *State, start: usize) usize {
        self.visual_row_starts[self.visual_row_count] = @intCast(start);
        self.visual_row_count += 1;
        return self.visual_row_count - 1;
    }
};

const font_size_labels = [_][]const u8{
    "10 px", "12 px", "14 px", "16 px", "18 px", "20 px", "22 px", "24 px", "26 px", "28 px", "30 px",
};

fn renderToolbar(editor: *State, context: RenderContext) void {
    clay.open("script-editor-toolbar", .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(34) },
            .padding = .{ .right = 8 },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = .{ .r = 20, .g = 23, .b = 33, .a = 255 },
        .border = .{ .color = .{ .r = 47, .g = 52, .b = 68, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1 } },
    });
    renderFontSizeSelector(editor, context);
    c.Clay__CloseElement();
}

fn renderTextArea(editor: *State, context: RenderContext) void {
    const hovered = clay.pointerOver(text_area_id);
    clay.openScrollable(text_area_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
        },
        .backgroundColor = if (context.focused or hovered) .{ .r = 28, .g = 31, .b = 43, .a = 255 } else .{ .r = 24, .g = 27, .b = 38, .a = 255 },
        .border = .{
            .color = if (context.focused) .{ .r = 139, .g = 82, .b = 207, .a = 255 } else .{ .r = 47, .g = 52, .b = 68, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        },
        .clip = .{ .horizontal = true, .vertical = true },
    });
    context.bind_action(context.binding_context, .focus);
    renderDocument(editor, context.fonts, context.focused);
    c.Clay__CloseElement();
}

fn renderFontSizeSelector(editor: *State, context: RenderContext) void {
    const id = "script-font-size";
    const hovered = clay.pointerOver(id);
    clay.open(id, .{
        .layout = .{
            .sizing = .{ .width = clay.fixed(104), .height = clay.fixed(26) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or editor.font_size_menu_open) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 29, .g = 32, .b = 44, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
    });
    context.bind_action(context.binding_context, .toggle_font_size_menu);
    clay.text(font_size_labels[@as(usize, (editor.font_size - 10) / 2)], 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    clay.open("font-size-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    c.Clay__OpenTextElement(clay.string("\u{e136}", true), .{ .fontId = 1, .fontSize = 16, .textColor = .{ .r = 147, .g = 155, .b = 175, .a = 255 } });
    if (editor.font_size_menu_open) {
        clay.open("font-size-menu", clay.menu(104, 316, .right, 1));
        for (font_size_labels, 0..) |label, index| {
            const font_size: u16 = @intCast(10 + index * 2);
            renderFontSizeOption(font_size, label, editor.font_size == font_size, context);
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn renderFontSizeOption(font_size: u16, label: []const u8, selected: bool, context: RenderContext) void {
    const index: usize = @as(usize, (font_size - 10) / 2);
    const hovered = clay.pointerOverIndexed("font-size-option", index);
    clay.openIndexed("font-size-option", index, clay.menuOption(selected, hovered));
    context.bind_action(context.binding_context, .{ .select_font_size = font_size });
    clay.text(label, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

const LuaLexState = enum { normal, single_quote, double_quote, long_string, long_comment };

const lua_default_color = c.Clay_Color{ .r = 203, .g = 208, .b = 222, .a = 255 };
const lua_keyword_color = c.Clay_Color{ .r = 194, .g = 137, .b = 255, .a = 255 };
const lua_literal_color = c.Clay_Color{ .r = 242, .g = 183, .b = 104, .a = 255 };
const lua_string_color = c.Clay_Color{ .r = 156, .g = 215, .b = 157, .a = 255 };
const lua_comment_color = c.Clay_Color{ .r = 120, .g = 139, .b = 130, .a = 255 };
const lua_builtin_color = c.Clay_Color{ .r = 118, .g = 187, .b = 242, .a = 255 };
const lua_operator_color = c.Clay_Color{ .r = 211, .g = 218, .b = 233, .a = 255 };
const lua_keywords = [_][]const u8{ "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local", "not", "or", "repeat", "return", "then", "until", "while" };
const lua_builtins = [_][]const u8{ "assert", "error", "ipairs", "pairs", "pcall", "print", "require", "select", "tonumber", "tostring", "type", "xpcall" };

const LuaLineRenderer = struct {
    line: []const u8,
    state: *LuaLexState,
    editor: *State,
    focused: bool,
    cursor_start: usize,
    available_width: f32,
    fonts: *Fonts,
    visual_row: usize = 0,
    row_width: f32 = 0,
    caret_drawn: bool = false,

    fn span(self: *LuaLineRenderer, value: []const u8, color: c.Clay_Color) void {
        const source_start = self.cursor_start + @intFromPtr(value.ptr) - @intFromPtr(self.line.ptr);
        var start: usize = 0;
        while (start < value.len) {
            var end = start + 1;
            const whitespace = std.ascii.isWhitespace(value[start]);
            while (end < value.len and std.ascii.isWhitespace(value[end]) == whitespace) : (end += 1) {}
            const segment = value[start..end];
            const segment_start = source_start + start;
            const width = clay.measureText(self.fonts, segment, self.editor.font_size);
            if (self.row_width > 0 and self.row_width + width > self.available_width) {
                c.Clay__CloseElement();
                self.row_width = 0;
                self.openRow(segment_start);
            }
            self.drawCaretInSegment(segment, segment_start);
            self.drawSegment(segment, segment_start, color);
            self.row_width += width;
            start = end;
        }
    }

    fn openRow(self: *LuaLineRenderer, start: usize) void {
        self.visual_row = self.editor.recordVisualRow(start);
        clay.openIndexed("script-visual-line", self.visual_row, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = clay.grow(0), .height = clay.fixed(lineHeight(self.editor.font_size)) },
            },
        });
    }

    fn drawCaretInSegment(self: *LuaLineRenderer, segment: []const u8, segment_start: usize) void {
        if (self.caret_drawn or !self.focused) return;
        const segment_end = segment_start + segment.len;
        const cursor = self.editor.text.cursor;
        if (cursor < segment_start or cursor > segment_end) return;
        self.drawCaret(self.row_width + clay.measureText(self.fonts, segment[0 .. cursor - segment_start], self.editor.font_size));
    }

    fn drawSegment(self: *LuaLineRenderer, segment: []const u8, segment_start: usize, color: c.Clay_Color) void {
        const selected = if (self.focused) self.editor.text.selection() else null;
        const segment_end = segment_start + segment.len;
        const range = selected orelse {
            scriptSpan(segment, self.editor.font_size, color);
            return;
        };
        const selected_start = @max(range.start, segment_start);
        const selected_end = @min(range.end, segment_end);
        if (selected_start >= selected_end) {
            scriptSpan(segment, self.editor.font_size, color);
            return;
        }

        const local_start = selected_start - segment_start;
        const local_end = selected_end - segment_start;
        if (local_start > 0) scriptSpan(segment[0..local_start], self.editor.font_size, color);
        clay.openIndexed("script-selection", selected_start, .{
            .layout = .{ .sizing = .{ .height = clay.fixed(lineHeight(self.editor.font_size)) } },
            .backgroundColor = text_editor.selection_color,
        });
        scriptSpan(segment[local_start..local_end], self.editor.font_size, color);
        c.Clay__CloseElement();
        if (local_end < segment.len) scriptSpan(segment[local_end..], self.editor.font_size, color);
    }

    fn drawSelectedNewline(self: *LuaLineRenderer) void {
        if (!self.focused) return;
        const selected = self.editor.text.selection() orelse return;
        const newline = self.cursor_start + self.line.len;
        const document = self.editor.text.value();
        if (newline >= document.len or document[newline] != '\n') return;
        if (selected.start > newline or selected.end <= newline) return;
        clay.openIndexed("script-selected-newline", newline, .{
            .layout = .{ .sizing = .{
                .width = clay.fixed(@as(f32, @floatFromInt(self.editor.font_size)) / 2),
                .height = clay.fixed(lineHeight(self.editor.font_size)),
            } },
            .backgroundColor = text_editor.selection_color,
        });
        c.Clay__CloseElement();
    }

    fn drawCaret(self: *LuaLineRenderer, x: f32) void {
        clay.open("script-caret", .{
            .layout = .{ .sizing = .{ .width = clay.fixed(2), .height = clay.fixed(lineHeight(self.editor.font_size) - 8) } },
            .backgroundColor = text_editor.caret_color,
            .floating = .{
                .attachTo = c.CLAY_ATTACH_TO_PARENT,
                .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
                .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_TOP },
                .offset = .{ .x = x, .y = 4 },
                .zIndex = 1,
                .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_PASSTHROUGH,
            },
        });
        c.Clay__CloseElement();
        self.caret_drawn = true;
        self.editor.cursor_visual_line = self.visual_row;
    }
};

fn renderDocument(editor: *State, fonts: *Fonts, focused: bool) void {
    const document = editor.text.value();
    editor.visual_row_count = 0;
    var line_start: usize = 0;
    var line_index: usize = 0;
    var lua_state: LuaLexState = .normal;
    const available_width = textAreaWidth();
    while (line_start <= document.len) {
        const line_end = std.mem.indexOfScalarPos(u8, document, line_start, '\n') orelse document.len;
        clay.openIndexed("script-line", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = clay.grow(0) },
            },
        });
        renderLineNumber(line_index + 1, editor.font_size);
        clay.openIndexed("script-line-text", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = clay.grow(0) },
                .padding = .{ .left = 14, .right = 14 },
            },
        });
        var renderer = LuaLineRenderer{
            .line = document[line_start..line_end],
            .state = &lua_state,
            .editor = editor,
            .focused = focused,
            .cursor_start = line_start,
            .available_width = available_width,
            .fonts = fonts,
        };
        renderer.openRow(line_start);
        renderLuaLine(&renderer);
        renderer.drawSelectedNewline();
        if (!renderer.caret_drawn and focused and editor.text.cursor == line_end) renderer.drawCaret(renderer.row_width);
        c.Clay__CloseElement();
        c.Clay__CloseElement();
        if (line_end == document.len) break;
        line_start = line_end + 1;
        line_index += 1;
    }
}

fn renderLuaLine(renderer: *LuaLineRenderer) void {
    var index: usize = 0;
    while (index < renderer.line.len) {
        switch (renderer.state.*) {
            .single_quote => renderLuaQuoted(renderer, &index, '\''),
            .double_quote => renderLuaQuoted(renderer, &index, '"'),
            .long_string => renderLuaLong(renderer, &index, false),
            .long_comment => renderLuaLong(renderer, &index, true),
            .normal => renderLuaNormal(renderer, &index),
        }
    }
}

fn renderLuaQuoted(renderer: *LuaLineRenderer, index: *usize, quote: u8) void {
    const start = index.*;
    while (index.* < renderer.line.len) {
        if (renderer.line[index.*] == '\\' and index.* + 1 < renderer.line.len) {
            index.* += 2;
        } else if (renderer.line[index.*] == quote) {
            index.* += 1;
            renderer.state.* = .normal;
            break;
        } else {
            index.* += 1;
        }
    }
    renderer.span(renderer.line[start..index.*], lua_string_color);
}

fn renderLuaLong(renderer: *LuaLineRenderer, index: *usize, comment: bool) void {
    const start = index.*;
    if (std.mem.indexOfPos(u8, renderer.line, index.*, "]]")) |closing| {
        index.* = closing + 2;
        renderer.state.* = .normal;
    } else {
        index.* = renderer.line.len;
    }
    renderer.span(renderer.line[start..index.*], if (comment) lua_comment_color else lua_string_color);
}

fn renderLuaNormal(renderer: *LuaLineRenderer, index: *usize) void {
    const line = renderer.line;
    const start = index.*;
    const byte = line[index.*];
    if (byte == '-' and index.* + 1 < line.len and line[index.* + 1] == '-') {
        if (index.* + 3 < line.len and std.mem.eql(u8, line[index.* + 2 .. index.* + 4], "[[")) {
            renderer.span(line[index.* .. index.* + 4], lua_comment_color);
            index.* += 4;
            renderer.state.* = .long_comment;
            renderLuaLong(renderer, index, true);
        } else {
            renderer.span(line[index.*..], lua_comment_color);
            index.* = line.len;
        }
        return;
    }
    if (byte == '[' and index.* + 1 < line.len and line[index.* + 1] == '[') {
        renderer.span(line[index.* .. index.* + 2], lua_string_color);
        index.* += 2;
        renderer.state.* = .long_string;
        renderLuaLong(renderer, index, false);
        return;
    }
    if (byte == '\'' or byte == '"') {
        renderer.span(line[index.* .. index.* + 1], lua_string_color);
        index.* += 1;
        renderer.state.* = if (byte == '\'') .single_quote else .double_quote;
        renderLuaQuoted(renderer, index, byte);
        return;
    }
    if (isIdentifierStart(byte)) {
        index.* += 1;
        while (index.* < line.len and isIdentifierContinue(line[index.*])) : (index.* += 1) {}
        const identifier = line[start..index.*];
        const color = if (hasLuaWord(identifier, &lua_keywords))
            lua_keyword_color
        else if (std.mem.eql(u8, identifier, "nil") or std.mem.eql(u8, identifier, "true") or std.mem.eql(u8, identifier, "false"))
            lua_literal_color
        else if (hasLuaWord(identifier, &lua_builtins))
            lua_builtin_color
        else
            lua_default_color;
        renderer.span(identifier, color);
        return;
    }
    if (std.ascii.isDigit(byte)) {
        index.* += 1;
        while (index.* < line.len and (std.ascii.isAlphanumeric(line[index.*]) or line[index.*] == '.' or line[index.*] == '_')) : (index.* += 1) {}
        renderer.span(line[start..index.*], lua_literal_color);
        return;
    }
    index.* += 1;
    renderer.span(line[start..index.*], if (std.ascii.isWhitespace(byte)) lua_default_color else lua_operator_color);
}

fn isIdentifierStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn isIdentifierContinue(byte: u8) bool {
    return isIdentifierStart(byte) or std.ascii.isDigit(byte);
}

fn hasLuaWord(value: []const u8, comptime words: []const []const u8) bool {
    inline for (words) |word| {
        if (std.mem.eql(u8, value, word)) return true;
    }
    return false;
}

fn scriptSpan(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    c.Clay__OpenTextElement(clay.string(value, false), .{
        .fontId = 0,
        .fontSize = font_size,
        .lineHeight = font_size + 6,
        .textColor = color,
        .wrapMode = c.CLAY_TEXT_WRAP_NONE,
    });
}

fn textAreaWidth() f32 {
    const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(text_area_id, true)));
    if (!element.found) return 600;
    return @max(80, element.boundingBox.width - 52 - 28);
}

fn lineHeight(font_size: u16) f32 {
    return @floatFromInt(font_size + 6);
}

const digit_text = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };

fn renderLineNumber(line_number: usize, font_size: u16) void {
    clay.openIndexed("script-line-number", line_number, .{
        .layout = .{
            .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
            .sizing = .{ .width = clay.fixed(52), .height = clay.grow(0) },
            .padding = .{ .left = 10, .right = 6 },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_LEFT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = .{ .r = 21, .g = 24, .b = 34, .a = 255 },
        .border = .{ .color = .{ .r = 47, .g = 52, .b = 68, .a = 255 }, .width = .{ .right = 1 } },
    });
    var divisor: usize = 1000;
    var remaining = line_number;
    var emitted = false;
    while (divisor > 0) : (divisor /= 10) {
        const digit = remaining / divisor;
        if (digit != 0 or emitted or divisor == 1) {
            clay.text(digit_text[digit], @min(font_size, 16), .{ .r = 126, .g = 134, .b = 153, .a = 255 });
            emitted = true;
        }
        remaining %= divisor;
    }
    c.Clay__CloseElement();
}

fn moveCursorFromPointer(editor: *State, fonts: *Fonts) void {
    const pointer: c.Clay_Vector2 = .{ .x = c.kraken_pointer_x(), .y = c.kraken_pointer_y() };
    if (visualRowAtY(editor, pointer.y)) |row| {
        const row_data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clay.string("script-visual-line", true), @intCast(row)));
        editor.cursor_visual_line = row;
        editor.text.cursor = cursorAtVisualRow(editor, fonts, row, pointer.x - row_data.boundingBox.x);
    } else {
        editor.text.cursor = editor.text.buffer.len;
    }
    editor.keepCursorVisible();
}

fn verticalDirection(event: c.sapp_event) ?bool {
    if (event.type != c.SAPP_EVENTTYPE_KEY_DOWN or event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER | c.SAPP_MODIFIER_ALT) != 0) return null;
    return switch (event.key_code) {
        c.SAPP_KEYCODE_UP => false,
        c.SAPP_KEYCODE_DOWN => true,
        else => null,
    };
}

fn moveCursorVertically(editor: *State, fonts: *Fonts, down: bool, selecting: bool) void {
    const current_row = editor.cursor_visual_line;
    const target_row = if (down) current_row + 1 else if (current_row == 0) return else current_row - 1;
    if (target_row == editor.visual_row_count) return;
    const current_start: usize = editor.visual_row_starts[current_row];
    const cursor = std.math.clamp(editor.text.cursor, current_start, editor.text.buffer.len);
    const x = editor.preferred_x orelse clay.measureText(fonts, editor.text.value()[current_start..cursor], editor.font_size);
    editor.text.moveTo(cursorAtVisualRow(editor, fonts, target_row, x), selecting);
    editor.cursor_visual_line = target_row;
    editor.preferred_x = x;
}

fn cursorAtVisualRow(editor: *const State, fonts: *Fonts, row: usize, x: f32) usize {
    const document = editor.text.value();
    const start: usize = editor.visual_row_starts[row];
    var end = if (row + 1 < editor.visual_row_count) @as(usize, editor.visual_row_starts[row + 1]) else document.len;
    if (end > start and document[end - 1] == '\n') end -= 1;
    return start + clay.textOffsetAtX(fonts, document[start..end], x, editor.font_size);
}

fn visualRowAtY(editor: *const State, y: f32) ?usize {
    for (0..editor.visual_row_count) |row| {
        const row_data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clay.string("script-visual-line", true), @intCast(row)));
        if (y >= row_data.boundingBox.y and y < row_data.boundingBox.y + row_data.boundingBox.height) return row;
    }
    return null;
}

test "reset clears editing state and preserves the font preference" {
    var editor: State = .{ .font_size = 32 };
    try editor.text.buffer.set("print('hello')");
    editor.text.cursor = editor.text.buffer.len;

    editor.reset();

    try std.testing.expectEqualStrings("", editor.text.value());
    try std.testing.expectEqual(@as(u16, 32), editor.font_size);
    try std.testing.expectEqual(@as(usize, 0), editor.text.cursor);
}
