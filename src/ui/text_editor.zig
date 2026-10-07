const std = @import("std");
const clay = @import("clay.zig");
const theme = @import("theme.zig");
const c = @import("c");

pub const Mode = enum { single_line, multiline };
pub const Result = enum { ignored, handled, advance, blur };

const Selection = struct { start: usize, end: usize };

const Change = struct {
    text_offset: usize,
    start: usize,
    removed_len: usize,
    inserted_len: usize,
    cursor_before: usize,
    anchor_before: ?usize,
};

pub fn Editor(comptime Buffer: type, comptime mode: Mode) type {
    const buffer_capacity = Buffer.capacity;
    const history_capacity = if (mode == .multiline) 256 else 32;
    return struct {
        buffer: Buffer = .{},
        read_only: bool = false,
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

        pub fn init(self: *Self, read_only: bool) void {
            self.read_only = read_only;
            self.reset();
        }

        pub fn reset(self: *Self) void {
            self.buffer.set("") catch unreachable;
            self.clearEditingState();
        }

        pub fn set(self: *Self, text: []const u8) error{CapacityExceeded}!void {
            try self.buffer.set(text);
            self.clearEditingState();
            self.cursor = self.buffer.len;
        }

        fn clearEditingState(self: *Self) void {
            self.cursor = 0;
            self.selection_anchor = null;
            self.scroll_x = 0;
            self.dragging = false;
            self.change_count = 0;
            self.change_cursor = 0;
            self.history_text_len = 0;
        }

        pub fn value(self: *const Self) []const u8 {
            return self.buffer.value();
        }

        pub fn selection(self: *const Self) ?Selection {
            const anchor = self.selection_anchor orelse return null;
            if (anchor == self.cursor) return null;
            return .{ .start = @min(anchor, self.cursor), .end = @max(anchor, self.cursor) };
        }

        pub fn handleEvent(self: *Self, event: c.sapp_event) error{ CapacityExceeded, MultilineText }!Result {
            if (self.read_only) {
                if (event.type != c.SAPP_EVENTTYPE_KEY_DOWN) return .ignored;
                switch (event.key_code) {
                    c.SAPP_KEYCODE_LEFT, c.SAPP_KEYCODE_RIGHT, c.SAPP_KEYCODE_HOME, c.SAPP_KEYCODE_END, c.SAPP_KEYCODE_ESCAPE => {},
                    c.SAPP_KEYCODE_A, c.SAPP_KEYCODE_C => if (event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER) == 0) return .ignored,
                    else => return .ignored,
                }
            }
            switch (event.type) {
                c.SAPP_EVENTTYPE_CLIPBOARD_PASTED => {
                    const clipboard = c.sapp_get_clipboard_string() orelse return .handled;
                    const pasted = std.mem.span(clipboard);
                    if (mode == .single_line and std.mem.indexOfAny(u8, pasted, "\r\n") != null) return error.MultilineText;
                    try self.insertText(pasted);
                },
                c.SAPP_EVENTTYPE_CHAR => {
                    if (event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER) != 0) return .ignored;
                    try self.insertCodepoint(event.char_code);
                },
                c.SAPP_EVENTTYPE_KEY_DOWN => {
                    const selecting = event.modifiers & c.SAPP_MODIFIER_SHIFT != 0;
                    if (event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER) != 0 and self.command(event.key_code, selecting)) return .handled;
                    const by_word = event.modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_ALT) != 0;
                    switch (event.key_code) {
                        c.SAPP_KEYCODE_BACKSPACE => self.delete(true, by_word),
                        c.SAPP_KEYCODE_DELETE => self.delete(false, by_word),
                        c.SAPP_KEYCODE_LEFT => self.move(false, by_word, selecting),
                        c.SAPP_KEYCODE_RIGHT => self.move(true, by_word, selecting),
                        c.SAPP_KEYCODE_HOME => self.moveTo(lineStart(&self.buffer, self.cursor), selecting),
                        c.SAPP_KEYCODE_END => self.moveTo(lineEnd(&self.buffer, self.cursor), selecting),
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

        pub fn handlePointer(self: *Self, fonts: *clay.Fonts, element_id: []const u8, pointer_x: f32, pointer_state: c_int, font_size: u16, padding_left: f32) void {
            const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(element_id, true)));
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
            if (selecting and self.selection_anchor == null) self.selection_anchor = self.cursor;
            if (!selecting) self.selection_anchor = null;
            self.cursor = target;
            if (self.selection_anchor == self.cursor) self.selection_anchor = null;
        }

        pub fn render(self: *Self, fonts: *clay.Fonts, element_id: []const u8, index: usize, focused: bool, placeholder: []const u8, font_size: u16, padding_left: f32, padding_right: f32, height: f32) void {
            const text = self.value();
            const cursor_x = if (focused) clay.measureText(fonts, text[0..self.cursor], font_size) else 0;
            if (focused) {
                const element = c.Clay_GetElementData(c.Clay_GetElementId(clay.string(element_id, true)));
                const available = @max(0, element.boundingBox.width - padding_left - padding_right - 2);
                if (cursor_x < self.scroll_x) self.scroll_x = cursor_x else if (cursor_x > self.scroll_x + available) self.scroll_x = cursor_x - available;
                self.scroll_x = std.math.clamp(self.scroll_x, 0, @max(0, clay.measureText(fonts, text, font_size) - available));
            } else self.scroll_x = 0;

            if (focused) if (self.selection()) |selected| {
                const start_x = clay.measureText(fonts, text[0..selected.start], font_size);
                const width = clay.measureText(fonts, text[selected.start..selected.end], font_size);
                floatingRect("text-selection", index, padding_left + start_x - self.scroll_x, 4, width, height - 8, theme.selection, 1);
            };

            clay.openIndexed("text-content", index, .{
                .layout = .{ .sizing = .{ .height = clay.size(.fixed, height) }, .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER } },
                .floating = floating(padding_left - self.scroll_x, 0, 2),
            });
            if (text.len == 0) clay.text(placeholder, font_size, theme.text_muted) else clay.dynamicText(text, font_size, theme.text);
            c.Clay__CloseElement();

            if (focused) floatingRect("text-caret", index, padding_left + cursor_x - self.scroll_x, 6, 2, height - 12, theme.highlight, 3);
        }

        fn insertText(self: *Self, text: []const u8) error{CapacityExceeded}!void {
            const range = self.selection() orelse Selection{ .start = self.cursor, .end = self.cursor };
            const available = buffer_capacity - (self.buffer.len - (range.end - range.start));
            if (text.len > available) return error.CapacityExceeded;
            self.replaceRange(range.start, range.end, text);
        }

        fn insertCodepoint(self: *Self, character: u32) error{CapacityExceeded}!void {
            if (character < 0x20 or character > 0x10ffff) return;
            var encoded: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(@intCast(character), &encoded) catch return;
            try self.insertText(encoded[0..len]);
        }

        fn deleteSelection(self: *Self) bool {
            const selected = self.selection() orelse return false;
            self.replaceRange(selected.start, selected.end, "");
            return true;
        }

        fn delete(self: *Self, comptime backward: bool, by_word: bool) void {
            if (self.deleteSelection()) return;
            const target = self.step(!backward, by_word);
            if (backward) self.replaceRange(target, self.cursor, "") else self.replaceRange(self.cursor, target, "");
        }

        fn move(self: *Self, comptime forward: bool, by_word: bool, selecting: bool) void {
            if (!selecting) if (self.selection()) |selected| return self.moveTo(if (forward) selected.end else selected.start, false);
            self.moveTo(self.step(forward, by_word), selecting);
        }

        /// The cursor position one codepoint or word away.
        fn step(self: *const Self, comptime forward: bool, by_word: bool) usize {
            return if (by_word)
                if (forward) nextWord(&self.buffer, self.cursor) else previousWord(&self.buffer, self.cursor)
            else if (forward)
                nextCodepoint(&self.buffer, self.cursor)
            else
                previousCodepoint(&self.buffer, self.cursor);
        }

        /// The Ctrl or Cmd shortcuts; false when `key` is not one.
        fn command(self: *Self, key: c.sapp_keycode, selecting: bool) bool {
            switch (key) {
                c.SAPP_KEYCODE_A => {
                    self.selection_anchor = 0;
                    self.cursor = self.buffer.len;
                },
                c.SAPP_KEYCODE_C => self.copySelection(),
                c.SAPP_KEYCODE_X => {
                    self.copySelection();
                    _ = self.deleteSelection();
                },
                c.SAPP_KEYCODE_Z => if (selecting) self.redo() else self.undo(),
                c.SAPP_KEYCODE_Y => self.redo(),
                else => return false,
            }
            return true;
        }

        fn copySelection(self: *Self) void {
            const selected = self.selection() orelse return;
            const following = self.buffer.bytes[selected.end];
            self.buffer.bytes[selected.end] = 0;
            c.sapp_set_clipboard_string(@ptrCast(&self.buffer.bytes[selected.start]));
            self.buffer.bytes[selected.end] = following;
        }

        fn replaceRange(self: *Self, start: usize, end: usize, text: []const u8) void {
            if (start == end and text.len == 0) return;
            self.recordChange(start, end, text);
            self.replace(start, end, text);
            self.cursor = start + text.len;
            self.selection_anchor = null;
        }

        fn undo(self: *Self) void {
            if (self.change_cursor == 0) return;
            self.change_cursor -= 1;
            const change = self.changes[self.change_cursor];
            self.replace(change.start, change.start + change.inserted_len, self.history_text[change.text_offset..][0..change.removed_len]);
            self.cursor = change.cursor_before;
            self.selection_anchor = change.anchor_before;
        }

        fn redo(self: *Self) void {
            if (self.change_cursor == self.change_count) return;
            const change = self.changes[self.change_cursor];
            self.replace(change.start, change.start + change.removed_len, self.history_text[change.text_offset + change.removed_len ..][0..change.inserted_len]);
            self.cursor = change.start + change.inserted_len;
            self.selection_anchor = null;
            self.change_cursor += 1;
        }

        fn recordChange(self: *Self, start: usize, end: usize, inserted: []const u8) void {
            if (self.change_cursor != self.change_count) {
                self.history_text_len = self.changes[self.change_cursor].text_offset;
                self.change_count = self.change_cursor;
            }
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
                .anchor_before = self.selection_anchor,
            };
            self.change_count += 1;
            self.change_cursor = self.change_count;
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

        fn replace(self: *Self, start: usize, end: usize, text: []const u8) void {
            const tail = self.buffer.bytes[end..self.buffer.len];
            const new_end = start + text.len;
            @memmove(self.buffer.bytes[new_end..][0..tail.len], tail);
            @memcpy(self.buffer.bytes[start..new_end], text);
            self.buffer.len = new_end + tail.len;
            self.buffer.bytes[self.buffer.len] = 0;
        }
    };
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
    if (index == buffer.len) return buffer.len;
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

fn skipClass(buffer: anytype, start: usize, comptime forward: bool, class: WordClass) usize {
    var result = start;
    while (if (forward) result < buffer.len else result > 0) {
        const next = if (forward) nextCodepoint(buffer, result) else previousCodepoint(buffer, result);
        if (wordClass(buffer, if (forward) result else next) != class) break;
        result = next;
    }
    return result;
}

fn previousWord(buffer: anytype, index: usize) usize {
    const result = skipClass(buffer, index, false, .whitespace);
    if (result == 0) return 0;
    return skipClass(buffer, result, false, wordClass(buffer, previousCodepoint(buffer, result)));
}

fn nextWord(buffer: anytype, index: usize) usize {
    return skipClass(buffer, skipClass(buffer, index, true, wordClass(buffer, index)), true, .whitespace);
}

fn lineStart(buffer: anytype, index: usize) usize {
    var result = index;
    while (result > 0 and buffer.bytes[result - 1] != '\n') : (result -= 1) {}
    return result;
}

fn lineEnd(buffer: anytype, index: usize) usize {
    var result = index;
    while (result < buffer.len and buffer.bytes[result] != '\n') : (result += 1) {}
    return result;
}

fn floating(x: f32, y: f32, z_index: i16) c.Clay_FloatingElementConfig {
    return .{
        .attachTo = c.CLAY_ATTACH_TO_PARENT,
        .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
        .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_TOP },
        .offset = .{ .x = x, .y = y },
        .zIndex = z_index,
        .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_PASSTHROUGH,
    };
}

pub fn floatingRect(id: []const u8, index: usize, x: f32, y: f32, width: f32, height: f32, color: c.Clay_Color, z_index: i16) void {
    clay.openIndexed(id, index, .{
        .layout = .{ .sizing = .{ .width = clay.size(.fixed, width), .height = clay.size(.fixed, height) } },
        .backgroundColor = color,
        .floating = floating(x, y, z_index),
    });
    c.Clay__CloseElement();
}

const TestEditor = Editor(@import("../text.zig").FixedText(8), .single_line);

test "insertion is atomic and replaces selected text" {
    var editor: TestEditor = undefined;
    editor.init(false);
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
    var editor: TestEditor = undefined;
    editor.init(false);
    try editor.set("aé");
    editor.move(false, false, false);
    try std.testing.expectEqual(@as(usize, 1), editor.cursor);
    editor.move(true, false, false);
    try std.testing.expectEqual(editor.buffer.len, editor.cursor);
}

test "read-only text stays selectable and immutable" {
    var editor: TestEditor = undefined;
    editor.init(true);
    try editor.set("abc");
    _ = try editor.handleEvent(.{ .type = c.SAPP_EVENTTYPE_CHAR, .char_code = 'x' });
    _ = try editor.handleEvent(.{ .type = c.SAPP_EVENTTYPE_KEY_DOWN, .key_code = c.SAPP_KEYCODE_BACKSPACE });
    try std.testing.expectEqualStrings("abc", editor.value());
    _ = try editor.handleEvent(.{ .type = c.SAPP_EVENTTYPE_KEY_DOWN, .key_code = c.SAPP_KEYCODE_LEFT, .modifiers = c.SAPP_MODIFIER_SHIFT });
    try std.testing.expectEqual(@as(usize, 2), editor.selection().?.start);
}

test "word movement and deletion use lexical boundaries" {
    var editor: TestEditor = undefined;
    editor.init(false);
    try editor.set("one two");

    editor.move(false, true, false);
    try std.testing.expectEqual(@as(usize, 4), editor.cursor);
    editor.delete(true, true);
    try std.testing.expectEqualStrings("two", editor.value());
}

test "undo and redo preserve replacements and discard divergent redo" {
    var editor: TestEditor = undefined;
    editor.init(false);
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
    var editor: TestEditor = undefined;
    editor.init(false);
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
