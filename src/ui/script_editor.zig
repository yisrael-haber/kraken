const std = @import("std");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const clay = @import("clay.zig");
const theme = @import("theme.zig");
const text_editor = @import("text_editor.zig");
const c = @import("c");

const Text = text_editor.Editor(text.FixedText(limits.source_capacity), .multiline);
pub const text_area_id = "script-text-area";

fn textAreaId(editor: *const State) []const u8 {
    return if (editor.log) "logs-output" else text_area_id;
}

pub const Action = union(enum) {
    focus,
    select_font_size: u16,
};

pub const State = struct {
    text: Text,
    log: bool,
    cursor_visual_line: usize,
    preferred_x: ?f32,
    visual_row_starts: [limits.source_capacity + 1]u16,
    visual_row_count: usize,
    line_numbers: [(limits.source_capacity + 1) * line_number_digits]u8,
    font_size: u16,

    /// The log view is read-only.
    pub fn init(self: *State, log: bool, font_size: u16) void {
        self.text.init(log);
        self.log = log;
        self.font_size = font_size;
        self.clearState();
    }

    pub fn reset(self: *State) void {
        self.text.reset();
        self.clearState();
    }

    pub fn load(self: *State, contents: text.FixedText(limits.source_capacity)) void {
        self.text.set(contents.value()) catch unreachable;
        self.text.cursor = 0;
        self.clearState();
    }

    fn clearState(self: *State) void {
        self.cursor_visual_line = 0;
        self.preferred_x = null;
        self.visual_row_count = 0;
    }

    pub fn setFontSize(self: *State, font_size: u16) void {
        self.font_size = font_size;
        self.preferred_x = null;
    }

    pub fn handlePointer(self: *State, fonts: *clay.Fonts, pointer_state: c_int) void {
        if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
            self.preferred_x = null;
            moveCursorFromPointer(self, fonts);
            self.text.selection_anchor = self.text.cursor;
            self.text.dragging = true;
        } else if (pointer_state == c.CLAY_POINTER_DATA_PRESSED and self.text.dragging) {
            moveCursorFromPointer(self, fonts);
        }
    }

    pub fn handleEvent(self: *State, fonts: *clay.Fonts, event_data: c.sapp_event) error{CapacityExceeded}!text_editor.Result {
        if (verticalDirection(event_data)) |down| {
            moveCursorVertically(self, fonts, down, event_data.modifiers & c.SAPP_MODIFIER_SHIFT != 0);
            keepCursorVisible(self);
            return .handled;
        }
        const result = self.text.handleEvent(event_data) catch |err| return @errorCast(err);
        if (result == .handled) {
            self.preferred_x = null;
            keepCursorVisible(self);
        }
        return result;
    }

    pub fn keepCursorVisible(self: *const State) void {
        const scroll_data = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clay.string(textAreaId(self), true)));
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
};

const font_sizes = [_]u16{ 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 };

pub fn render(editor: *State, context: anytype, focused: bool) void {
    const hovered = clay.pointerOver(textAreaId(editor));
    clay.openScrollable(textAreaId(editor), .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.grow, 0) },
        },
        .backgroundColor = if (focused or hovered) theme.field_active else theme.field,
        .border = .{
            .color = if (focused) theme.accent else theme.border,
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        },
        .clip = .{ .horizontal = true, .vertical = true },
    });
    context.bindAction(.{ .script_editor = .focus });
    renderDocument(editor, &context.fonts, focused);
    renderFontSizeSelector(editor, context);
    c.Clay__CloseElement();
}

fn renderFontSizeSelector(editor: *State, context: anytype) void {
    clay.selector("script-font-size", 0, 104, 26, fontSizeLabel(editor.font_size), context.menu == .font_size, .{
        .attachTo = c.CLAY_ATTACH_TO_PARENT,
        .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
        .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_RIGHT_TOP, .parent = c.CLAY_ATTACH_POINT_RIGHT_TOP },
        .offset = .{ .x = -8, .y = 8 },
        .zIndex = 1,
    });
    context.bindAction(.{ .toggle_menu = .font_size });
    if (context.menu == .font_size) {
        clay.open("font-size-menu", clay.menu(104, font_sizes.len * 28 + 8, .right, 1));
        inline for (font_sizes) |size| {
            const option_id = std.fmt.comptimePrint("font-size-{d}", .{size});
            clay.open(option_id, clay.menuOption(editor.font_size == size, clay.pointerOver(option_id)));
            context.bindAction(.{ .script_editor = .{ .select_font_size = size } });
            clay.text(fontSizeLabel(size), 14, theme.text_bright);
            c.Clay__CloseElement();
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn fontSizeLabel(value: u16) []const u8 {
    inline for (font_sizes) |size| if (size == value) return std.fmt.comptimePrint("{d} px", .{size});
    return std.fmt.comptimePrint("{d} px", .{font_sizes[0]});
}

const LuaLexState = enum { normal, single_quote, double_quote, long_string, long_comment };

const LuaLineRenderer = struct {
    line: []const u8,
    state: *LuaLexState,
    editor: *State,
    focused: bool,
    font_size: u16,
    available_width: f32,
    fonts: *clay.Fonts,
    visual_row: usize = 0,
    row_width: f32 = 0,
    caret_drawn: bool = false,
    /// Adjacent runs of one color are drawn as a single Clay text element.
    pending: []const u8 = &.{},
    pending_color: c.Clay_Color = undefined,

    fn finish(self: *LuaLineRenderer) void {
        self.flush();
        self.drawSelectedNewline();
        if (!self.caret_drawn and self.focused and self.editor.text.cursor == self.lineCursorEnd()) {
            self.drawCaret(self.row_width);
        }
        c.Clay__CloseElement();
    }

    fn span(self: *LuaLineRenderer, value: []const u8, color: c.Clay_Color) void {
        var start: usize = 0;
        while (start < value.len) {
            var end = start + 1;
            const whitespace = std.ascii.isWhitespace(value[start]);
            while (end < value.len and std.ascii.isWhitespace(value[end]) == whitespace) : (end += 1) {}
            const segment = value[start..end];
            const width = clay.measureText(self.fonts, segment, self.font_size);
            if (self.row_width > 0 and self.row_width + width > self.available_width) {
                self.flush();
                c.Clay__CloseElement();
                self.row_width = 0;
                self.openRow(self.documentOffset(segment));
            }
            self.drawCaretInSegment(segment);
            self.drawSegment(segment, color);
            self.row_width += width;
            start = end;
        }
    }

    fn openRow(self: *LuaLineRenderer, start: usize) void {
        self.visual_row = self.editor.visual_row_count;
        self.editor.visual_row_starts[self.visual_row] = @intCast(start);
        self.editor.visual_row_count += 1;
        clay.openIndexed("script-visual-line", self.visual_row, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, lineHeight(self.font_size)) },
            },
        });
    }

    fn drawCaretInSegment(self: *LuaLineRenderer, segment: []const u8) void {
        if (self.caret_drawn or !self.focused) return;
        const start = self.documentOffset(segment);
        const cursor = self.editor.text.cursor;
        if (cursor < start or cursor > start + segment.len) return;
        self.drawCaret(self.row_width + clay.measureText(self.fonts, segment[0 .. cursor - start], self.font_size));
    }

    fn drawSegment(self: *LuaLineRenderer, segment: []const u8, color: c.Clay_Color) void {
        const selected = if (self.focused) self.editor.text.selection() else null;
        const segment_start = self.documentOffset(segment);
        const segment_end = segment_start + segment.len;
        const range = selected orelse {
            self.emit(segment, color);
            return;
        };
        const selected_start = @max(range.start, segment_start);
        const selected_end = @min(range.end, segment_end);
        if (selected_start >= selected_end) {
            self.emit(segment, color);
            return;
        }

        self.flush();
        const local_start = selected_start - segment_start;
        const local_end = selected_end - segment_start;
        if (local_start > 0) scriptSpan(segment[0..local_start], self.font_size, color);
        selectedScriptSpan(segment[local_start..local_end], selected_start, self.font_size, color);
        if (local_end < segment.len) scriptSpan(segment[local_end..], self.font_size, color);
    }

    fn emit(self: *LuaLineRenderer, segment: []const u8, color: c.Clay_Color) void {
        if (self.pending.len > 0 and std.meta.eql(self.pending_color, color)) {
            self.pending = self.pending.ptr[0 .. self.pending.len + segment.len];
            return;
        }
        self.flush();
        self.pending = segment;
        self.pending_color = color;
    }

    fn flush(self: *LuaLineRenderer) void {
        if (self.pending.len == 0) return;
        scriptSpan(self.pending, self.font_size, self.pending_color);
        self.pending = &.{};
    }

    fn drawSelectedNewline(self: *LuaLineRenderer) void {
        if (!self.focused) return;
        const selected = self.editor.text.selection() orelse return;
        const newline = self.lineCursorEnd();
        const document = self.editor.text.value();
        if (newline >= document.len or document[newline] != '\n') return;
        if (selected.start > newline or selected.end <= newline) return;
        clay.openIndexed("script-selected-newline", newline, .{
            .layout = .{ .sizing = .{
                .width = clay.size(.fixed, @as(f32, @floatFromInt(self.font_size)) / 2),
                .height = clay.size(.fixed, lineHeight(self.font_size)),
            } },
            .backgroundColor = theme.selection,
        });
        c.Clay__CloseElement();
    }

    fn drawCaret(self: *LuaLineRenderer, x: f32) void {
        text_editor.floatingRect("script-caret", 0, x, 4, 2, lineHeight(self.font_size) - 8, theme.highlight, 1);
        self.caret_drawn = true;
        self.editor.cursor_visual_line = self.visual_row;
    }

    fn documentOffset(self: *const LuaLineRenderer, segment: []const u8) usize {
        return self.lineCursorStart() + @intFromPtr(segment.ptr) - @intFromPtr(self.line.ptr);
    }

    fn lineCursorStart(self: *const LuaLineRenderer) usize {
        return @intFromPtr(self.line.ptr) - @intFromPtr(self.editor.text.buffer.bytes[0..].ptr);
    }

    fn lineCursorEnd(self: *const LuaLineRenderer) usize {
        return self.lineCursorStart() + self.line.len;
    }
};

fn renderDocument(editor: *State, fonts: *clay.Fonts, focused: bool) void {
    const document = editor.text.value();
    editor.visual_row_count = 0;
    var line_start: usize = 0;
    var line_index: usize = 0;
    var lua_state: LuaLexState = .normal;
    const available_width = textAreaWidth(editor);
    while (line_start <= document.len) {
        const line_end = std.mem.indexOfScalarPos(u8, document, line_start, '\n') orelse document.len;
        clay.openIndexed("script-line", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = clay.size(.grow, 0) },
            },
        });
        if (!editor.log) renderLineNumber(editor, line_index);
        clay.openIndexed("script-line-text", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = clay.size(.grow, 0) },
                .padding = .{ .left = 14, .right = 14 },
            },
        });
        var renderer = LuaLineRenderer{
            .line = document[line_start..line_end],
            .state = &lua_state,
            .editor = editor,
            .focused = focused,
            .font_size = editor.font_size,
            .available_width = available_width,
            .fonts = fonts,
        };
        renderer.openRow(renderer.lineCursorStart());
        if (editor.log) {
            const line = renderer.line;
            const prefix = if (line.len >= 9 and line[2] == ':' and line[5] == ':' and line[8] == ' ')
                if (std.mem.indexOfScalarPos(u8, line, 9, ' ')) |end| end + 1 else 9
            else
                0;
            renderer.span(line[0..prefix], theme.text_muted);
            renderer.span(line[prefix..], theme.text);
        } else renderLuaLine(&renderer);
        renderer.finish();
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
    renderer.span(renderer.line[start..index.*], theme.syntax_string);
}

fn renderLuaLong(renderer: *LuaLineRenderer, index: *usize, comment: bool) void {
    const start = index.*;
    if (std.mem.indexOfPos(u8, renderer.line, index.*, "]]")) |closing| {
        index.* = closing + 2;
        renderer.state.* = .normal;
    } else {
        index.* = renderer.line.len;
    }
    renderer.span(renderer.line[start..index.*], if (comment) theme.text_muted else theme.syntax_string);
}

fn renderLuaNormal(renderer: *LuaLineRenderer, index: *usize) void {
    const line = renderer.line;
    const start = index.*;
    const byte = line[index.*];
    if (byte == '-' and index.* + 1 < line.len and line[index.* + 1] == '-') {
        if (index.* + 3 < line.len and std.mem.eql(u8, line[index.* + 2 .. index.* + 4], "[[")) {
            renderer.span(line[index.* .. index.* + 4], theme.text_muted);
            index.* += 4;
            renderer.state.* = .long_comment;
        } else {
            renderer.span(line[index.*..], theme.text_muted);
            index.* = line.len;
        }
        return;
    }
    if (byte == '[' and index.* + 1 < line.len and line[index.* + 1] == '[') {
        renderer.span(line[index.* .. index.* + 2], theme.syntax_string);
        index.* += 2;
        renderer.state.* = .long_string;
        return;
    }
    if (byte == '\'' or byte == '"') {
        renderer.span(line[index.* .. index.* + 1], theme.syntax_string);
        index.* += 1;
        renderer.state.* = if (byte == '\'') .single_quote else .double_quote;
        return;
    }
    if (isIdentifierStart(byte)) {
        index.* += 1;
        while (index.* < line.len and isIdentifierContinue(line[index.*])) : (index.* += 1) {}
        const identifier = line[start..index.*];
        const color = if (isOneOf(identifier, &.{ "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local", "not", "or", "repeat", "return", "then", "until", "while" }))
            theme.highlight
        else if (isOneOf(identifier, &.{ "nil", "true", "false" }))
            theme.syntax_literal
        else if (isOneOf(identifier, &.{ "assert", "error", "ipairs", "pairs", "pcall", "print", "require", "select", "tonumber", "tostring", "type", "xpcall" }))
            theme.syntax_builtin
        else
            theme.text;
        renderer.span(identifier, color);
        return;
    }
    if (std.ascii.isDigit(byte)) {
        index.* += 1;
        while (index.* < line.len and (std.ascii.isAlphanumeric(line[index.*]) or line[index.*] == '.' or line[index.*] == '_')) : (index.* += 1) {}
        renderer.span(line[start..index.*], theme.syntax_literal);
        return;
    }
    index.* += 1;
    renderer.span(line[start..index.*], theme.text);
}

fn isIdentifierStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn isIdentifierContinue(byte: u8) bool {
    return isIdentifierStart(byte) or std.ascii.isDigit(byte);
}

fn isOneOf(value: []const u8, comptime words: []const []const u8) bool {
    inline for (words) |word| if (std.mem.eql(u8, value, word)) return true;
    return false;
}

fn scriptSpan(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    clay.openText(value, false, .{
        .fontId = 0,
        .fontSize = font_size,
        .lineHeight = font_size + 6,
        .textColor = color,
        .wrapMode = c.CLAY_TEXT_WRAP_NONE,
    });
}

fn selectedScriptSpan(value: []const u8, index: usize, font_size: u16, color: c.Clay_Color) void {
    clay.openIndexed("script-selection", index, .{
        .layout = .{ .sizing = .{ .height = clay.size(.fixed, lineHeight(font_size)) } },
        .backgroundColor = theme.selection,
    });
    scriptSpan(value, font_size, color);
    c.Clay__CloseElement();
}

fn textAreaWidth(editor: *const State) f32 {
    const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(textAreaId(editor), true)));
    if (!element.found) return 600;
    return @max(80, element.boundingBox.width - (if (editor.log) @as(f32, 0) else 52) - 28);
}

fn lineHeight(font_size: u16) f32 {
    return @floatFromInt(font_size + 6);
}

/// Clay keeps text pointers until the frame is submitted, so each line's number lives in the editor.
const line_number_digits = std.fmt.count("{d}", .{limits.source_capacity + 1});

fn renderLineNumber(editor: *State, line_index: usize) void {
    clay.openIndexed("script-line-number", line_index, .{
        .layout = .{
            .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
            .sizing = .{ .width = clay.size(.fixed, 52), .height = clay.size(.grow, 0) },
            .padding = .{ .left = 10, .right = 6 },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_LEFT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = theme.recessed,
        .border = .{ .color = theme.border, .width = .{ .right = 1 } },
    });
    const number = std.fmt.bufPrint(editor.line_numbers[line_index * line_number_digits ..][0..line_number_digits], "{d}", .{line_index + 1}) catch unreachable;
    clay.dynamicText(number, @min(editor.font_size, 16), theme.text_muted);
    c.Clay__CloseElement();
}

fn moveCursorFromPointer(editor: *State, fonts: *clay.Fonts) void {
    const pointer = c.Clay_GetPointerState().position;
    for (0..editor.visual_row_count) |row| {
        const data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clay.string("script-visual-line", true), @intCast(row)));
        if (!data.found or pointer.y < data.boundingBox.y or pointer.y >= data.boundingBox.y + data.boundingBox.height) continue;
        editor.cursor_visual_line = row;
        editor.text.cursor = cursorAtVisualRow(editor, fonts, row, pointer.x - data.boundingBox.x);
        editor.keepCursorVisible();
        return;
    }
    editor.text.cursor = editor.text.buffer.len;
    editor.keepCursorVisible();
}

fn verticalDirection(event: c.sapp_event) ?bool {
    if (event.type != c.SAPP_EVENTTYPE_KEY_DOWN) return null;
    if (event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER | c.SAPP_MODIFIER_ALT) != 0) return null;
    return switch (event.key_code) {
        c.SAPP_KEYCODE_UP => false,
        c.SAPP_KEYCODE_DOWN => true,
        else => null,
    };
}

fn moveCursorVertically(editor: *State, fonts: *clay.Fonts, down: bool, selecting: bool) void {
    if (editor.visual_row_count == 0) return;
    const current_row = @min(editor.cursor_visual_line, editor.visual_row_count - 1);
    const target_row = if (down) current_row + 1 else if (current_row == 0) return else current_row - 1;
    if (target_row >= editor.visual_row_count) return;
    const current_start: usize = editor.visual_row_starts[current_row];
    const cursor = std.math.clamp(editor.text.cursor, current_start, editor.text.buffer.len);
    const x = editor.preferred_x orelse clay.measureText(fonts, editor.text.value()[current_start..cursor], editor.font_size);
    editor.text.moveTo(cursorAtVisualRow(editor, fonts, target_row, x), selecting);
    editor.cursor_visual_line = target_row;
    editor.preferred_x = x;
}

fn cursorAtVisualRow(editor: *const State, fonts: *clay.Fonts, row: usize, x: f32) usize {
    const document = editor.text.value();
    const start: usize = editor.visual_row_starts[row];
    var end = if (row + 1 < editor.visual_row_count) @as(usize, editor.visual_row_starts[row + 1]) else document.len;
    if (end > start and document[end - 1] == '\n') end -= 1;
    return start + clay.textOffsetAtX(fonts, document[start..end], x, editor.font_size);
}

test "reset clears editing state and preserves the font preference" {
    var editor: State = undefined;
    editor.init(false, 32);
    try editor.text.buffer.set("print('hello')");
    editor.text.cursor = editor.text.buffer.len;

    editor.reset();

    try std.testing.expectEqualStrings("", editor.text.value());
    try std.testing.expectEqual(@as(u16, 32), editor.font_size);
    try std.testing.expectEqual(@as(usize, 0), editor.text.cursor);
}
