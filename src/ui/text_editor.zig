const std = @import("std");
const clay = @import("clay.zig");
const c = @import("c");

pub const Fonts = [2]c.sclay_font_t;
pub const Mode = enum { single_line, multiline };
pub const Result = enum { ignored, handled, advance, blur };
pub const selection_color = c.Clay_Color{ .r = 90, .g = 75, .b = 150, .a = 150 };
pub const caret_color = c.Clay_Color{ .r = 183, .g = 119, .b = 255, .a = 255 };

const Selection = struct { start: usize, end: usize };
const no_anchor = std.math.maxInt(usize);

const Change = struct {
    text_offset: usize,
    start: usize,
    removed_len: usize,
    inserted_len: usize,
    cursor_before: usize,
    anchor_before: usize,
};

pub fn Editor(comptime Buffer: type, comptime mode: Mode) type {
    const buffer_capacity = @sizeOf(@TypeOf(@as(Buffer, undefined).bytes));
    const history_capacity = if (mode == .multiline) 256 else 32;
    return struct {
        buffer: Buffer = .{},
        cursor: usize = 0,
        selection_anchor: ?usize = null,
        scroll_x: f32 = 0,
        dragging: bool = false,
        changes: [history_capacity]Change = undefined,
        change_count: usize = 0,
        change_cursor: usize = 0,
        history_text: [buffer_capacity * 2]u8 = undefined,
        history_text_len: usize = 0,

        const Self = @This();

        pub fn reset(self: *Self) void {
            self.* = .{};
        }

        pub fn load(self: *Self, buffer: Buffer) void {
            self.* = .{
                .buffer = buffer,
                .cursor = if (mode == .single_line) buffer.len else 0,
            };
        }

        pub fn set(self: *Self, text: []const u8) error{CapacityExceeded}!void {
            try self.buffer.set(text);
            self.cursor = self.buffer.len;
            self.selection_anchor = null;
            self.scroll_x = 0;
            self.dragging = false;
            self.clearHistory();
        }

        pub fn value(self: *const Self) []const u8 {
            return self.buffer.value();
        }

        pub fn selection(self: *const Self) ?Selection {
            const anchor = self.selection_anchor orelse return null;
            if (anchor == self.cursor) return null;
            return if (anchor < self.cursor)
                .{ .start = anchor, .end = self.cursor }
            else
                .{ .start = self.cursor, .end = anchor };
        }

        pub fn handleEvent(self: *Self, event: c.sapp_event) error{ CapacityExceeded, MultilineText }!Result {
            switch (event.type) {
                c.SAPP_EVENTTYPE_CLIPBOARD_PASTED => {
                    const clipboard = c.sapp_get_clipboard_string() orelse return .handled;
                    const pasted = std.mem.span(clipboard);
                    if (mode == .single_line and std.mem.indexOfAny(u8, pasted, "\r\n") != null) return error.MultilineText;
                    try self.insertText(pasted);
                },
                c.SAPP_EVENTTYPE_CHAR => {
                    if (commandModifier(event.modifiers)) return .ignored;
                    try self.insertCodepoint(event.char_code);
                },
                c.SAPP_EVENTTYPE_KEY_DOWN => {
                    const selecting = event.modifiers & c.SAPP_MODIFIER_SHIFT != 0;
                    if (commandModifier(event.modifiers)) {
                        switch (event.key_code) {
                            c.SAPP_KEYCODE_A => {
                                self.selectAll();
                                return .handled;
                            },
                            c.SAPP_KEYCODE_C => {
                                self.copySelection();
                                return .handled;
                            },
                            c.SAPP_KEYCODE_X => {
                                self.copySelection();
                                _ = self.deleteSelection();
                                return .handled;
                            },
                            c.SAPP_KEYCODE_Z => {
                                if (selecting) self.redo() else self.undo();
                                return .handled;
                            },
                            c.SAPP_KEYCODE_Y => {
                                self.redo();
                                return .handled;
                            },
                            else => {},
                        }
                    }
                    const by_word = wordModifier(event.modifiers);
                    switch (event.key_code) {
                        c.SAPP_KEYCODE_BACKSPACE => if (by_word) self.deleteWordBackward() else self.backspace(),
                        c.SAPP_KEYCODE_DELETE => if (by_word) self.deleteWordForward() else self.deleteForward(),
                        c.SAPP_KEYCODE_LEFT => if (by_word) self.moveWordLeft(selecting) else self.moveLeft(selecting),
                        c.SAPP_KEYCODE_RIGHT => if (by_word) self.moveWordRight(selecting) else self.moveRight(selecting),
                        c.SAPP_KEYCODE_HOME => self.moveLineStart(selecting),
                        c.SAPP_KEYCODE_END => self.moveLineEnd(selecting),
                        c.SAPP_KEYCODE_UP, c.SAPP_KEYCODE_DOWN => return .ignored,
                        c.SAPP_KEYCODE_ENTER => if (mode == .multiline) try self.insertText("\n") else return .advance,
                        c.SAPP_KEYCODE_TAB => if (mode == .multiline) try self.insertText("\t") else return .advance,
                        c.SAPP_KEYCODE_ESCAPE => {
                            self.selection_anchor = null;
                            self.dragging = false;
                            return .blur;
                        },
                        else => return .ignored,
                    }
                },
                else => return .ignored,
            }
            return .handled;
        }

        pub fn handlePointer(self: *Self, fonts: *Fonts, element_id: []const u8, pointer_x: f32, pointer_state: c_int, font_size: u16, padding_left: f32) void {
            const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(element_id, true)));
            if (!element.found) return;
            const x = pointer_x - element.boundingBox.x - padding_left + self.scroll_x;
            const target = clay.textOffsetAtX(fonts, self.value(), x, font_size);
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                self.cursor = target;
                self.selection_anchor = target;
                self.dragging = true;
            } else if (pointer_state == c.CLAY_POINTER_DATA_PRESSED and self.dragging) {
                self.cursor = target;
            }
        }

        pub fn endPointerSelection(self: *Self) void {
            if (self.selection_anchor == self.cursor) self.selection_anchor = null;
            self.dragging = false;
        }

        pub fn moveTo(self: *Self, target: usize, selecting: bool) void {
            if (selecting) {
                if (self.selection_anchor == null) self.selection_anchor = self.cursor;
                self.cursor = @min(target, self.buffer.len);
                if (self.selection_anchor == self.cursor) self.selection_anchor = null;
            } else {
                self.cursor = @min(target, self.buffer.len);
                self.selection_anchor = null;
            }
        }

        pub fn render(self: *Self, fonts: *Fonts, element_id: []const u8, index: usize, focused: bool, placeholder: []const u8, font_size: u16, padding_left: f32, padding_right: f32, height: f32) void {
            const text = self.value();
            if (focused) self.updateScroll(fonts, element_id, font_size, padding_left, padding_right) else self.scroll_x = 0;

            if (focused) if (self.selection()) |selected| {
                const start_x = clay.measureText(fonts, text[0..selected.start], font_size);
                const width = clay.measureText(fonts, text[selected.start..selected.end], font_size);
                floatingRect("text-selection", index, padding_left + start_x - self.scroll_x, 4, width, height - 8, selection_color, 1);
            };

            floatingContent(index, padding_left - self.scroll_x, height);
            if (text.len == 0) clay.text(placeholder, font_size, .{ .r = 128, .g = 137, .b = 159, .a = 255 }) else clay.dynamicText(text, font_size, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
            c.Clay__CloseElement();

            if (focused) {
                const cursor_x = clay.measureText(fonts, text[0..self.cursor], font_size);
                floatingRect("text-caret", index, padding_left + cursor_x - self.scroll_x, 6, 2, height - 12, caret_color, 3);
            }
        }

        fn insertText(self: *Self, text: []const u8) error{CapacityExceeded}!void {
            const selected = self.selection();
            const start = if (selected) |range| range.start else self.cursor;
            const end = if (selected) |range| range.end else self.cursor;
            const available = self.buffer.bytes.len - (self.buffer.len - (end - start));
            if (text.len > available) return error.CapacityExceeded;
            if (start == end and text.len == 0) return;
            self.recordChange(start, end, text);
            self.replace(start, end, text);
            self.cursor = start + text.len;
            self.selection_anchor = null;
        }

        fn insertCodepoint(self: *Self, character: u32) error{CapacityExceeded}!void {
            if (character < 0x20 or character > 0x10ffff) return;
            var encoded: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(@intCast(character), &encoded) catch return;
            try self.insertText(encoded[0..len]);
        }

        fn deleteSelection(self: *Self) bool {
            const selected = self.selection() orelse return false;
            self.deleteRange(selected.start, selected.end);
            return true;
        }

        fn backspace(self: *Self) void {
            if (!self.deleteSelection()) self.deleteRange(previousCodepoint(&self.buffer, self.cursor), self.cursor);
        }

        fn deleteForward(self: *Self) void {
            if (!self.deleteSelection()) self.deleteRange(self.cursor, nextCodepoint(&self.buffer, self.cursor));
        }

        fn deleteWordBackward(self: *Self) void {
            if (!self.deleteSelection()) self.deleteRange(previousWord(&self.buffer, self.cursor), self.cursor);
        }

        fn deleteWordForward(self: *Self) void {
            if (!self.deleteSelection()) self.deleteRange(self.cursor, nextWord(&self.buffer, self.cursor));
        }

        fn moveLeft(self: *Self, selecting: bool) void {
            if (!selecting) if (self.selection()) |selected| return self.moveTo(selected.start, false);
            self.moveTo(previousCodepoint(&self.buffer, self.cursor), selecting);
        }

        fn moveRight(self: *Self, selecting: bool) void {
            if (!selecting) if (self.selection()) |selected| return self.moveTo(selected.end, false);
            self.moveTo(nextCodepoint(&self.buffer, self.cursor), selecting);
        }

        fn moveWordLeft(self: *Self, selecting: bool) void {
            if (!selecting) if (self.selection()) |selected| return self.moveTo(selected.start, false);
            self.moveTo(previousWord(&self.buffer, self.cursor), selecting);
        }

        fn moveWordRight(self: *Self, selecting: bool) void {
            if (!selecting) if (self.selection()) |selected| return self.moveTo(selected.end, false);
            self.moveTo(nextWord(&self.buffer, self.cursor), selecting);
        }

        fn moveLineStart(self: *Self, selecting: bool) void {
            self.moveTo(lineStart(&self.buffer, self.cursor), selecting);
        }

        fn moveLineEnd(self: *Self, selecting: bool) void {
            self.moveTo(lineEnd(&self.buffer, self.cursor), selecting);
        }

        fn selectAll(self: *Self) void {
            self.selection_anchor = 0;
            self.cursor = self.buffer.len;
        }

        fn copySelection(self: *Self) void {
            const selected = self.selection() orelse return;
            const text = self.buffer.bytes[selected.start..selected.end];
            var clipboard: [@sizeOf(@TypeOf(self.buffer.bytes)) + 1]u8 = undefined;
            @memcpy(clipboard[0..text.len], text);
            clipboard[text.len] = 0;
            c.sapp_set_clipboard_string(@ptrCast(&clipboard));
        }

        fn deleteRange(self: *Self, start: usize, end: usize) void {
            if (start >= end or end > self.buffer.len) return;
            self.recordChange(start, end, "");
            self.replace(start, end, "");
            self.cursor = start;
            self.selection_anchor = null;
        }

        fn undo(self: *Self) void {
            if (self.change_cursor == 0) return;
            self.change_cursor -= 1;
            const change = self.changes[self.change_cursor];
            const removed = self.history_text[change.text_offset .. change.text_offset + change.removed_len];
            self.replace(change.start, change.start + change.inserted_len, removed);
            self.cursor = change.cursor_before;
            self.selection_anchor = if (change.anchor_before == no_anchor) null else change.anchor_before;
        }

        fn redo(self: *Self) void {
            if (self.change_cursor == self.change_count) return;
            const change = self.changes[self.change_cursor];
            const inserted_start = change.text_offset + change.removed_len;
            const inserted = self.history_text[inserted_start .. inserted_start + change.inserted_len];
            self.replace(change.start, change.start + change.removed_len, inserted);
            self.cursor = change.start + change.inserted_len;
            self.selection_anchor = null;
            self.change_cursor += 1;
        }

        fn recordChange(self: *Self, start: usize, end: usize, inserted: []const u8) void {
            self.discardRedo();
            const removed = self.buffer.bytes[start..end];
            const required = removed.len + inserted.len;
            while (self.change_count == self.changes.len or self.history_text_len + required > self.history_text.len) self.dropOldestChange();

            const offset = self.history_text_len;
            @memcpy(self.history_text[offset .. offset + removed.len], removed);
            @memcpy(self.history_text[offset + removed.len .. offset + required], inserted);
            self.history_text_len += required;
            self.changes[self.change_count] = .{
                .text_offset = offset,
                .start = start,
                .removed_len = removed.len,
                .inserted_len = inserted.len,
                .cursor_before = self.cursor,
                .anchor_before = self.selection_anchor orelse no_anchor,
            };
            self.change_count += 1;
            self.change_cursor = self.change_count;
        }

        fn discardRedo(self: *Self) void {
            if (self.change_cursor == self.change_count) return;
            self.history_text_len = self.changes[self.change_cursor].text_offset;
            self.change_count = self.change_cursor;
        }

        fn dropOldestChange(self: *Self) void {
            const first = self.changes[0];
            const removed_bytes = first.removed_len + first.inserted_len;
            std.mem.copyForwards(u8, self.history_text[0..], self.history_text[removed_bytes..self.history_text_len]);
            self.history_text_len -= removed_bytes;
            for (self.changes[1..self.change_count], self.changes[0 .. self.change_count - 1]) |source, *destination| {
                destination.* = source;
                destination.text_offset -= removed_bytes;
            }
            self.change_count -= 1;
            self.change_cursor -= 1;
        }

        fn clearHistory(self: *Self) void {
            self.change_count = 0;
            self.change_cursor = 0;
            self.history_text_len = 0;
        }

        fn replace(self: *Self, start: usize, end: usize, text: []const u8) void {
            const tail = self.buffer.bytes[end..self.buffer.len];
            const new_end = start + text.len;
            if (new_end > end) {
                std.mem.copyBackwards(u8, self.buffer.bytes[new_end .. new_end + tail.len], tail);
            } else if (new_end < end) {
                std.mem.copyForwards(u8, self.buffer.bytes[new_end..], tail);
            }
            @memcpy(self.buffer.bytes[start..new_end], text);
            self.buffer.len = new_end + tail.len;
        }

        fn updateScroll(self: *Self, fonts: *Fonts, element_id: []const u8, font_size: u16, padding_left: f32, padding_right: f32) void {
            const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(element_id, true)));
            if (!element.found) return;
            const available = @max(0, element.boundingBox.width - padding_left - padding_right - 2);
            const cursor_x = clay.measureText(fonts, self.value()[0..self.cursor], font_size);
            if (cursor_x < self.scroll_x) self.scroll_x = cursor_x else if (cursor_x > self.scroll_x + available) self.scroll_x = cursor_x - available;
            self.scroll_x = std.math.clamp(self.scroll_x, 0, @max(0, clay.measureText(fonts, self.value(), font_size) - available));
        }
    };
}

fn commandModifier(modifiers: c_uint) bool {
    return modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER) != 0;
}

fn wordModifier(modifiers: c_uint) bool {
    return modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_ALT) != 0;
}

fn previousCodepoint(buffer: anytype, index: usize) usize {
    var result = index;
    while (result > 0) {
        result -= 1;
        if (buffer.bytes[result] & 0b1100_0000 != 0b1000_0000) break;
    }
    return result;
}

fn nextCodepoint(buffer: anytype, index: usize) usize {
    if (index >= buffer.len) return buffer.len;
    var result = index + 1;
    while (result < buffer.len and buffer.bytes[result] & 0b1100_0000 == 0b1000_0000) : (result += 1) {}
    return result;
}

const WordClass = enum { whitespace, word, punctuation };

fn wordClass(buffer: anytype, index: usize) WordClass {
    const byte = buffer.bytes[index];
    if (std.ascii.isWhitespace(byte)) return .whitespace;
    if (byte >= 0x80 or std.ascii.isAlphanumeric(byte) or byte == '_') return .word;
    return .punctuation;
}

fn previousWord(buffer: anytype, index: usize) usize {
    var result = @min(index, buffer.len);
    while (result > 0) {
        const previous = previousCodepoint(buffer, result);
        if (wordClass(buffer, previous) != .whitespace) break;
        result = previous;
    }
    if (result == 0) return 0;
    const class = wordClass(buffer, previousCodepoint(buffer, result));
    while (result > 0) {
        const previous = previousCodepoint(buffer, result);
        if (wordClass(buffer, previous) != class) break;
        result = previous;
    }
    return result;
}

fn nextWord(buffer: anytype, index: usize) usize {
    var result = @min(index, buffer.len);
    if (result == buffer.len) return result;
    const class = wordClass(buffer, result);
    if (class != .whitespace) {
        while (result < buffer.len and wordClass(buffer, result) == class) result = nextCodepoint(buffer, result);
    }
    while (result < buffer.len and wordClass(buffer, result) == .whitespace) result = nextCodepoint(buffer, result);
    return result;
}

fn lineStart(buffer: anytype, index: usize) usize {
    var result = @min(index, buffer.len);
    while (result > 0 and buffer.bytes[result - 1] != '\n') : (result -= 1) {}
    return result;
}

fn lineEnd(buffer: anytype, index: usize) usize {
    var result = @min(index, buffer.len);
    while (result < buffer.len and buffer.bytes[result] != '\n') : (result += 1) {}
    return result;
}

fn floatingContent(index: usize, x: f32, height: f32) void {
    clay.openIndexed("text-content", index, .{
        .layout = .{ .sizing = .{ .height = clay.fixed(height) }, .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER } },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_TOP },
            .offset = .{ .x = x },
            .zIndex = 2,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_PASSTHROUGH,
        },
    });
}

fn floatingRect(id: []const u8, index: usize, x: f32, y: f32, width: f32, height: f32, color: c.Clay_Color, z_index: i16) void {
    clay.openIndexed(id, index, .{
        .layout = .{ .sizing = .{ .width = clay.fixed(width), .height = clay.fixed(height) } },
        .backgroundColor = color,
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_TOP },
            .offset = .{ .x = x, .y = y },
            .zIndex = z_index,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_PASSTHROUGH,
        },
    });
    c.Clay__CloseElement();
}

const TestBuffer = struct {
    bytes: [8]u8 = [_]u8{0} ** 8,
    len: usize = 0,

    fn set(self: *@This(), text: []const u8) error{CapacityExceeded}!void {
        if (text.len > self.bytes.len) return error.CapacityExceeded;
        @memcpy(self.bytes[0..text.len], text);
        self.len = text.len;
    }

    fn value(self: *const @This()) []const u8 {
        return self.bytes[0..self.len];
    }
};

const TestEditor = Editor(TestBuffer, .single_line);

test "insertion is atomic and replaces selected text" {
    var editor: TestEditor = .{};
    try editor.set("12345678");
    try std.testing.expectError(error.CapacityExceeded, editor.insertText("x"));
    try std.testing.expectEqualStrings("12345678", editor.value());

    try editor.set("abc");
    editor.selection_anchor = 1;
    editor.cursor = 3;
    try editor.insertText("x");
    try std.testing.expectEqualStrings("ax", editor.value());
    try std.testing.expectEqual(@as(usize, 2), editor.cursor);
}

test "cursor movement respects UTF-8 codepoint boundaries" {
    var editor: TestEditor = .{};
    try editor.set("aé");
    editor.moveLeft(false);
    try std.testing.expectEqual(@as(usize, 1), editor.cursor);
    editor.moveRight(false);
    try std.testing.expectEqual(editor.buffer.len, editor.cursor);
}

test "word movement and deletion use lexical boundaries" {
    var editor: TestEditor = .{};
    try editor.set("one two");

    editor.moveWordLeft(false);
    try std.testing.expectEqual(@as(usize, 4), editor.cursor);
    editor.deleteWordBackward();
    try std.testing.expectEqualStrings("two", editor.value());
}

test "undo and redo preserve replacements and discard divergent redo" {
    var editor: TestEditor = .{};
    try editor.set("abc");
    editor.selection_anchor = 1;
    editor.cursor = 3;
    try editor.insertText("x");

    editor.undo();
    try std.testing.expectEqualStrings("abc", editor.value());
    try std.testing.expectEqual(@as(?usize, 1), editor.selection_anchor);
    try std.testing.expectEqual(@as(usize, 3), editor.cursor);

    editor.redo();
    try std.testing.expectEqualStrings("ax", editor.value());
    editor.undo();
    try editor.insertText("z");
    editor.redo();
    try std.testing.expectEqualStrings("az", editor.value());
}

test "bounded history evicts old changes without corrupting newer ones" {
    var editor: TestEditor = .{};
    try editor.set("0");
    for (0..20) |index| {
        const replacement = [_]u8{'a' + @as(u8, @intCast(index))};
        editor.selection_anchor = 0;
        editor.cursor = 1;
        try editor.insertText(&replacement);
    }
    for (0..9) |_| editor.undo();
    try std.testing.expectEqualStrings("l", editor.value());
}
