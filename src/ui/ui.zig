const std = @import("std");
const identity_store = @import("../storage/identity_repository.zig");
const script_store = @import("../storage/script_repository.zig");
const storage_model = @import("../storage/model.zig");
const identity_model = @import("../identities/model.zig");
const runtime = @import("../runtime/runtime.zig");
const limits = @import("../limits.zig");
const ui_event = @import("event.zig");
const ui_state = @import("state.zig");
const input_component = @import("components/input.zig");
const editor_component = @import("components/text_editor.zig");
const button_component = @import("components/button.zig");
const select_component = @import("components/select.zig");
const side_panel_view = @import("views/side_panel.zig");
const identities_view = @import("views/identities.zig");
const scripts_view = @import("views/scripts.zig");

const c = @import("c");

const main_min_width: f32 = 640;
const embedded_fonts = @import("font");
const font_data = embedded_fonts.roboto;
const icon_font_data = embedded_fonts.phosphor;

const FormField = enum(usize) {
    label,
    ip,
    prefix,
    interface,
    gateway,
    mac,
    mtu,
};

const Action = ui_event.Action;

const Icon = enum {
    caret_down,
    plus,
};

const Page = ui_event.Page;

const TextInput = input_component.TextBuffer(limits.field_capacity);
const script_buffer_capacity = limits.source_capacity;
const TextArea = editor_component.TextArea;
const ScriptEditor = editor_component.State;

const ScriptingView = struct {
    editor: ScriptEditor = .{},
    name: TextInput = .{},
    name_focused: bool = false,
    form_open: bool = true,
    library_open: bool = false,
    kind_menu_open: bool = false,
    kind: script_store.Kind = .global,
    scripts: script_store.Catalog = .{},
    editing_file_name: ?storage_model.FieldText = null,

    fn deinit(self: *ScriptingView) void {
        deinitScripts(self);
        clearScriptEditing(self);
    }

    pub fn render(self: *ScriptingView, subsystem: *Subsystem) void {
        layoutScriptingView(self, subsystem);
    }
};

const script_font_sizes = [_]u16{ 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40 };

const SidePanel = side_panel_view.State;

const IdentitiesView = struct {
    inputs: [7]TextInput = .{
        TextInput.init(""), TextInput.init(""), TextInput.init(""), TextInput.init(""), TextInput.init(""), TextInput.init(""), TextInput.init(""),
    },
    focused_field: ?FormField = null,
    identities: []const identity_store.Identity = &.{},
    transport_scripts: script_store.Catalog = .{},
    transport_script_menu_identity: ?usize = null,
    transport_script_selection: []?usize = &.{},
    editing_file_name: ?storage_model.IdentityIdText = null,
    interface_selector: select_component.State = .{},

    pub fn render(self: *IdentitiesView, subsystem: *Subsystem) void {
        layoutIdentities(self, subsystem);
    }

    fn deinit(self: *IdentitiesView, allocator: std.mem.Allocator) void {
        deinitIdentities(self, allocator);
        deinitTransportScripts(self);
        clearEditing(self);
    }
};

const MainView = union(enum) {
    identities: IdentitiesView,
    script_editor: ScriptingView,

    fn activePage(self: MainView) Page {
        return switch (self) {
            .identities => .identities,
            .script_editor => .script_editor,
        };
    }

    fn layout(self: *MainView, subsystem: *Subsystem) void {
        switch (self.*) {
            .identities => |*view| identities_view.render(view, subsystem),
            .script_editor => |*view| scripts_view.render(view, subsystem),
        }
    }

    pub fn render(self: *MainView, subsystem: *Subsystem) void {
        self.layout(subsystem);
    }

    fn deinit(self: *MainView, subsystem: *Subsystem) void {
        switch (self.*) {
            .identities => |*view| view.deinit(subsystem.ui.services.storage.allocator),
            .script_editor => |*view| view.deinit(),
        }
    }

    fn select(self: *MainView, subsystem: *Subsystem, page: Page) void {
        if (self.activePage() == page) return;
        self.deinit(subsystem);
        switch (page) {
            .identities => {
                self.* = .{ .identities = .{} };
                reloadIdentities(subsystem, &self.identities);
                reloadTransportScripts(subsystem, &self.identities);
            },
            .script_editor => self.* = .{ .script_editor = .{} },
        }
        switch (self.*) {
            .identities => {},
            .script_editor => |*view| reloadScripts(subsystem, view, view.kind),
        }
    }
};

const UiState = ui_state.UiState(SidePanel, MainView);

pub fn requiredMemory() usize {
    return c.Clay_MinMemorySize();
}

pub const Subsystem = struct {
    ui: UiState = .{ .page = .{ .identities = .{} } },
    fonts: [2]c.sclay_font_t = .{ 0, 0 },
    path_wrap_marker: u8 = 0,

    pub fn init(self: *Subsystem, services: ui_state.Services, clay_memory: []u8) void {
        initializeSubsystem(self, services, clay_memory);
    }

    pub fn frame(self: *Subsystem) void {
        frameApplication(self);
    }

    pub fn event(self: *Subsystem, event_data: [*c]const c.sapp_event) void {
        eventApplication(self, event_data);
    }

    pub fn deinit(self: *Subsystem) void {
        deinitializeSubsystem(self);
    }

    pub fn bindSignal(self: *Subsystem, action: ui_event.SignalAction) void {
        const binding = self.ui.bind(.{ .action = action }) orelse return;
        c.Clay_OnHover(handleHover, @ptrCast(binding));
    }
};

fn fixed(value: f32) c.Clay_SizingAxis {
    return .{
        .size = .{ .minMax = .{ .min = value, .max = value } },
        .type = c.CLAY__SIZING_TYPE_FIXED,
    };
}

fn grow(minimum: f32) c.Clay_SizingAxis {
    return .{
        .size = .{ .minMax = .{ .min = minimum, .max = 0 } },
        .type = c.CLAY__SIZING_TYPE_GROW,
    };
}

fn openElement(id: []const u8, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementId(clayString(id, true)));
    c.Clay__ConfigureOpenElementPtr(&declaration);
}

fn openIndexedElement(id: []const u8, index: usize, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementIdWithIndex(clayString(id, true), @intCast(index)));
    c.Clay__ConfigureOpenElementPtr(&declaration);
}

fn openScrollableElement(id: []const u8, declaration: c.Clay_ElementDeclaration) void {
    c.Clay__OpenElementWithId(c.Clay_GetElementId(clayString(id, true)));
    var scroll_declaration = declaration;
    scroll_declaration.clip.childOffset = c.Clay_GetScrollOffset();
    c.Clay__ConfigureOpenElementPtr(&scroll_declaration);
}

fn pointerOver(id: []const u8) bool {
    return c.Clay_PointerOver(c.Clay_GetElementId(clayString(id, true)));
}

fn bindHover(subsystem: *Subsystem, action: ui_event.SignalAction) void {
    subsystem.bindSignal(action);
}

fn handleHover(_: c.Clay_ElementId, pointer_data: c.Clay_PointerData, user_data: ?*anyopaque) callconv(.c) void {
    const binding: *const ui_event.SignalBinding = @ptrCast(@alignCast(user_data orelse return));
    const owner: *UiState = @ptrCast(@alignCast(binding.owner orelse return));
    owner.enqueue(.{ .signal = .{
        .binding = binding.*,
        .pointer_x = pointer_data.position.x,
        .pointer_state = pointer_data.state,
    } });
}

fn text(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    const config: c.Clay_TextElementConfig = .{
        .fontId = 0,
        .fontSize = font_size,
        .textColor = color,
    };
    c.Clay__OpenTextElement(clayString(value, true), config);
}

fn icon(value: Icon, font_size: u16, color: c.Clay_Color) void {
    const glyph = switch (value) {
        .caret_down => "\u{e136}",
        .plus => "\u{e3d4}",
    };
    const config: c.Clay_TextElementConfig = .{
        .fontId = 1,
        .fontSize = font_size,
        .textColor = color,
    };
    c.Clay__OpenTextElement(clayString(glyph, true), config);
}

fn dynamicText(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    const config: c.Clay_TextElementConfig = .{
        .fontId = 0,
        .fontSize = font_size,
        .textColor = color,
    };
    c.Clay__OpenTextElement(clayString(value, false), config);
}

fn scriptSpan(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    const config: c.Clay_TextElementConfig = .{
        .fontId = 0,
        .fontSize = font_size,
        .lineHeight = font_size + 6,
        .textColor = color,
        .wrapMode = c.CLAY_TEXT_WRAP_NONE,
    };
    c.Clay__OpenTextElement(clayString(value, false), config);
}

const LuaLexState = enum { normal, single_quote, double_quote, long_string, long_comment };

const lua_default_color = c.Clay_Color{ .r = 203, .g = 208, .b = 222, .a = 255 };
const lua_keyword_color = c.Clay_Color{ .r = 194, .g = 137, .b = 255, .a = 255 };
const lua_literal_color = c.Clay_Color{ .r = 242, .g = 183, .b = 104, .a = 255 };
const lua_string_color = c.Clay_Color{ .r = 156, .g = 215, .b = 157, .a = 255 };
const lua_comment_color = c.Clay_Color{ .r = 120, .g = 139, .b = 130, .a = 255 };
const lua_builtin_color = c.Clay_Color{ .r = 118, .g = 187, .b = 242, .a = 255 };
const lua_operator_color = c.Clay_Color{ .r = 211, .g = 218, .b = 233, .a = 255 };

const LuaLineRenderer = struct {
    line: []const u8,
    state: *LuaLexState,
    editor: *ScriptEditor,
    font_size: u16,
    line_index: usize,
    visual_line_base: usize,
    available_width: f32,
    fonts: *[2]c.sclay_font_t,
    visual_line_index: usize = 0,
    row_width: f32 = 0,
    caret_drawn: bool = false,

    fn begin(self: *LuaLineRenderer) void {
        self.openRow();
    }

    fn finish(self: *LuaLineRenderer) void {
        if (!self.caret_drawn and self.editor.focused and self.editor.selection_anchor == null and self.editor.cursor == self.lineCursorEnd()) {
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
            const width = scriptTextWidth(self.fonts, segment, self.font_size);
            if (self.row_width > 0 and self.row_width + width > self.available_width) {
                c.Clay__CloseElement();
                self.visual_line_index += 1;
                self.row_width = 0;
                self.openRow();
                if (whitespace) {
                    start = end;
                    continue;
                }
            }
            self.drawCaretInSegment(segment);
            scriptSpan(segment, self.font_size, color);
            self.row_width += width;
            start = end;
        }
    }

    fn openRow(self: *LuaLineRenderer) void {
        const row_id = self.line_index * (script_buffer_capacity + 1) + self.visual_line_index;
        openIndexedElement("script-visual-line", row_id, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = grow(0), .height = fixed(scriptLineHeight(self.font_size)) },
            },
        });
    }

    fn drawCaretInSegment(self: *LuaLineRenderer, segment: []const u8) void {
        if (self.caret_drawn or !self.editor.focused or self.editor.selection_anchor != null) return;
        const start = @intFromPtr(segment.ptr) - @intFromPtr(self.line.ptr);
        const end = start + segment.len;
        if (self.editor.cursor < self.lineCursorStart()) return;
        const cursor = self.editor.cursor - self.lineCursorStart();
        if (cursor < start or cursor > end) return;
        self.drawCaret(self.row_width + scriptTextWidth(self.fonts, segment[0 .. cursor - start], self.font_size));
    }

    fn drawCaret(self: *LuaLineRenderer, x: f32) void {
        scriptCaretAt(x, self.font_size);
        self.caret_drawn = true;
        self.editor.cursor_visual_line = self.visual_line_base + self.visual_line_index;
    }

    fn lineCursorStart(self: *const LuaLineRenderer) usize {
        return @intFromPtr(self.line.ptr) - @intFromPtr(self.editor.buffer.bytes[0..].ptr);
    }

    fn lineCursorEnd(self: *const LuaLineRenderer) usize {
        return self.lineCursorStart() + self.line.len;
    }
};

fn renderLuaLine(renderer: *LuaLineRenderer) void {
    const line = renderer.line;
    var index: usize = 0;
    while (index < line.len) {
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
    const line = renderer.line;
    const start = index.*;
    while (index.* < line.len) {
        if (line[index.*] == '\\' and index.* + 1 < line.len) {
            index.* += 2;
        } else if (line[index.*] == quote) {
            index.* += 1;
            renderer.state.* = .normal;
            break;
        } else {
            index.* += 1;
        }
    }
    renderer.span(line[start..index.*], lua_string_color);
}

fn renderLuaLong(renderer: *LuaLineRenderer, index: *usize, comment: bool) void {
    const line = renderer.line;
    const start = index.*;
    if (std.mem.indexOfPos(u8, line, index.*, "]]")) |closing| {
        index.* = closing + 2;
        renderer.state.* = .normal;
    } else {
        index.* = line.len;
    }
    renderer.span(line[start..index.*], if (comment) lua_comment_color else lua_string_color);
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
    if (byte == '\'') {
        renderer.span(line[index.* .. index.* + 1], lua_string_color);
        index.* += 1;
        renderer.state.* = .single_quote;
        renderLuaQuoted(renderer, index, '\'');
        return;
    }
    if (byte == '"') {
        renderer.span(line[index.* .. index.* + 1], lua_string_color);
        index.* += 1;
        renderer.state.* = .double_quote;
        renderLuaQuoted(renderer, index, '"');
        return;
    }
    if (isLuaIdentifierStart(byte)) {
        index.* += 1;
        while (index.* < line.len and isLuaIdentifierContinue(line[index.*])) : (index.* += 1) {}
        const identifier = line[start..index.*];
        if (isLuaKeyword(identifier)) renderer.span(identifier, lua_keyword_color) else if (std.mem.eql(u8, identifier, "nil") or std.mem.eql(u8, identifier, "true") or std.mem.eql(u8, identifier, "false")) renderer.span(identifier, lua_literal_color) else if (isLuaBuiltin(identifier)) renderer.span(identifier, lua_builtin_color) else renderer.span(identifier, lua_default_color);
        return;
    }
    if (std.ascii.isDigit(byte)) {
        index.* += 1;
        while (index.* < line.len and (std.ascii.isAlphanumeric(line[index.*]) or line[index.*] == '.' or line[index.*] == '_')) : (index.* += 1) {}
        renderer.span(line[start..index.*], lua_literal_color);
        return;
    }
    index.* += 1;
    if (std.ascii.isWhitespace(byte)) renderer.span(line[start..index.*], lua_default_color) else renderer.span(line[start..index.*], lua_operator_color);
}

fn isLuaIdentifierStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn isLuaIdentifierContinue(byte: u8) bool {
    return isLuaIdentifierStart(byte) or std.ascii.isDigit(byte);
}

fn isLuaKeyword(value: []const u8) bool {
    inline for ([_][]const u8{ "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local", "not", "or", "repeat", "return", "then", "until", "while" }) |keyword| {
        if (std.mem.eql(u8, value, keyword)) return true;
    }
    return false;
}

fn isLuaBuiltin(value: []const u8) bool {
    inline for ([_][]const u8{ "assert", "error", "ipairs", "pairs", "pcall", "print", "require", "select", "tonumber", "tostring", "type", "xpcall" }) |builtin| {
        if (std.mem.eql(u8, value, builtin)) return true;
    }
    return false;
}

fn renderScriptEditorText(subsystem: *Subsystem, editor: *ScriptEditor, text_area_id: []const u8) void {
    const document = editor.buffer.value();
    var line_start: usize = 0;
    var line_index: usize = 0;
    var visual_line_base: usize = 0;
    var lua_state: LuaLexState = .normal;
    const available_width = scriptTextAreaWidth(text_area_id);
    while (line_start <= document.len) {
        const line_end = std.mem.indexOfScalarPos(u8, document, line_start, '\n') orelse document.len;
        openIndexedElement("script-line", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
                .sizing = .{ .width = grow(0) },
            },
        });
        scriptLineNumber(line_index + 1, editor.font_size);
        openIndexedElement("script-line-text", line_index, .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = grow(0) },
                .padding = .{ .left = 14, .right = 14 },
            },
        });
        var renderer = LuaLineRenderer{
            .line = document[line_start..line_end],
            .state = &lua_state,
            .editor = editor,
            .font_size = editor.font_size,
            .line_index = line_index,
            .visual_line_base = visual_line_base,
            .available_width = available_width,
            .fonts = &subsystem.fonts,
        };
        renderer.begin();
        renderLuaLine(&renderer);
        renderer.finish();
        c.Clay__CloseElement();
        c.Clay__CloseElement();
        visual_line_base += renderer.visual_line_index + 1;
        if (line_end == document.len) break;
        line_start = line_end + 1;
        line_index += 1;
    }
}

fn scriptTextAreaWidth(text_area_id: []const u8) f32 {
    const element = c.Clay_GetElementData(c.Clay_GetElementId(clayString(text_area_id, true)));
    if (!element.found) return 600;
    return @max(80, element.boundingBox.width - 52 - 28);
}

fn scriptCaretAt(x: f32, font_size: u16) void {
    openElement("script-caret", .{
        .layout = .{ .sizing = .{ .width = fixed(2), .height = fixed(scriptLineHeight(font_size) - 8) } },
        .backgroundColor = .{ .r = 183, .g = 119, .b = 255, .a = 255 },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_TOP },
            .offset = .{ .x = x, .y = 4 },
            .zIndex = 1,
        },
    });
    c.Clay__CloseElement();
}

fn scriptTextWidth(fonts: *[2]c.sclay_font_t, value: []const u8, font_size: u16) f32 {
    var config: c.Clay_TextElementConfig = .{ .fontId = 0, .fontSize = font_size };
    const measured = c.sclay_measure_text(.{
        .chars = value.ptr,
        .baseChars = value.ptr,
        .length = @intCast(value.len),
    }, &config, @ptrCast(fonts[0..].ptr));
    return measured.width;
}

fn scriptLineHeight(font_size: u16) f32 {
    return @floatFromInt(font_size + 6);
}

fn scriptLineNumber(line_number: usize, font_size: u16) void {
    openIndexedElement("script-line-number", line_number, .{
        .layout = .{
            .layoutDirection = c.CLAY_LEFT_TO_RIGHT,
            .sizing = .{ .width = fixed(52), .height = grow(0) },
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
            text(digitText(digit), @min(font_size, 16), .{ .r = 126, .g = 134, .b = 153, .a = 255 });
            emitted = true;
        }
        remaining %= divisor;
    }
    c.Clay__CloseElement();
}

fn digitText(digit: usize) []const u8 {
    return switch (digit) {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        6 => "6",
        7 => "7",
        8 => "8",
        9 => "9",
        else => unreachable,
    };
}

fn clayString(value: []const u8, is_static: bool) c.Clay_String {
    return .{ .chars = value.ptr, .length = @intCast(value.len), .isStaticallyAllocated = is_static };
}

fn selectInterface(subsystem: *Subsystem, view: *IdentitiesView, index: usize) void {
    const service = subsystem.ui.services.identities;
    const interfaces = service.interfaces();
    if (index >= interfaces.len) return;
    view.inputs[@intFromEnum(FormField.interface)].set(interfaces[index].nameSlice());
    view.interface_selector.open = false;
}

fn deinitIdentities(view: *IdentitiesView, allocator: std.mem.Allocator) void {
    view.identities = &.{};
    if (view.transport_script_selection.len > 0) allocator.free(view.transport_script_selection);
    view.transport_script_selection = &.{};
}

fn deinitTransportScripts(view: *IdentitiesView) void {
    view.transport_scripts.len = 0;
}

fn clearEditing(view: *IdentitiesView) void {
    view.editing_file_name = null;
}

fn reloadIdentities(subsystem: *Subsystem, view: *IdentitiesView) void {
    const allocator = subsystem.ui.services.storage.allocator;
    deinitIdentities(view, allocator);
    const service = subsystem.ui.services.identities;
    view.identities = service.snapshot();
    if (view.identities.len == 0) return;
    view.transport_script_selection = allocator.alloc(?usize, view.identities.len) catch {
        uiLog("Could not allocate identity controls.");
        return;
    };
    @memset(view.transport_script_selection, null);
}

fn reloadTransportScripts(subsystem: *Subsystem, view: *IdentitiesView) void {
    const storage = subsystem.ui.services.storage;
    const store = storage.scripts(.transport);
    var loaded: script_store.Catalog = .{};
    store.load(&loaded) catch {
        uiLog("Could not load transport scripts from disk.");
        return;
    };
    view.transport_scripts = loaded;
}

fn selectedTransportSource(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize) !?runtime.Source {
    if (identity_index >= view.transport_script_selection.len) return null;
    const script_index = view.transport_script_selection[identity_index] orelse return null;
    if (script_index >= view.transport_scripts.len) {
        uiLog("Selected transport script is unavailable.");
        return error.TransportScriptUnavailable;
    }
    const storage = subsystem.ui.services.storage;
    const store = storage.scripts(.transport);
    var contents: script_store.Source = .{};
    store.read(view.transport_scripts.values[script_index].file_name.value(), &contents) catch {
        uiLog("Could not read the selected transport script.");
        return error.TransportScriptUnavailable;
    };
    var source: runtime.Source = .{};
    source.set(contents.value()) catch {
        uiLog("Selected transport script is too large.");
        return error.TransportScriptUnavailable;
    };
    return source;
}

fn drainRuntimeEvents(subsystem: *Subsystem) void {
    const service = subsystem.ui.services.identities;
    service.pumpRuntimeEvents();
    var drained: usize = 0;
    while (drained < limits.identity_event_capacity) : (drained += 1) {
        const event_value = service.nextEvent() orelse break;
        switch (event_value) {
            .overflow => uiLog("Identity event capacity exceeded; an event was dropped."),
            .runtime => |runtime_event| logRuntimeIssue(runtime_event),
        }
    }
}

fn logRuntimeIssue(event_value: runtime.Event) void {
    switch (event_value.kind) {
        .started, .stopped => return,
        .failed, .packet_dropped, .queue_full => {},
    }
    const detail = event_value.message[0..event_value.message_len];
    const action = switch (event_value.kind) {
        .started => "started",
        .stopped => "stopped",
        .failed => "failed",
        .packet_dropped => "dropped a packet",
        .queue_full => "queue is full",
    };
    var buffer: [runtime.text_capacity + 64:0]u8 = undefined;
    const message = if (detail.len > 0)
        std.fmt.bufPrintZ(&buffer, "Slot {d} {s}: {s}", .{ event_value.slot + 1, action, detail }) catch "Runtime status was too long."
    else
        std.fmt.bufPrintZ(&buffer, "Slot {d} {s}.", .{ event_value.slot + 1, action }) catch "Runtime status was too long.";
    uiLog(message);
}

fn deinitScripts(view: *ScriptingView) void {
    view.scripts.len = 0;
}

fn clearScriptEditing(view: *ScriptingView) void {
    view.editing_file_name = null;
}

fn clearScriptForm(view: *ScriptingView) void {
    view.name = .{};
    view.name_focused = false;
    view.form_open = true;
    view.editor.buffer = .{};
    view.editor.focused = false;
    view.editor.cursor = 0;
    view.editor.cursor_visual_line = 0;
    view.editor.selection_anchor = null;
    view.editor.font_size_menu_open = false;
    view.kind_menu_open = false;
    clearScriptEditing(view);
}

fn reloadScripts(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind) void {
    const storage = subsystem.ui.services.storage;
    const store = storage.scripts(kind);
    var loaded: script_store.Catalog = .{};
    store.load(&loaded) catch {
        uiLog("Could not load scripts from disk.");
        return;
    };
    view.scripts = loaded;
}

fn selectScriptKind(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind) void {
    if (view.kind == kind) {
        view.kind_menu_open = false;
        return;
    }
    clearScriptForm(view);
    view.kind = kind;
    view.library_open = false;
    reloadScripts(subsystem, view, kind);
}

fn uiLog(message: [:0]const u8) void {
    c.kraken_log(message.ptr);
}

fn editScript(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind, index: c_int) void {
    if (index < 0) return;
    const script_index: usize = @intCast(index);
    if (script_index >= view.scripts.len) return;
    const script = view.scripts.values[script_index];
    const storage = subsystem.ui.services.storage;
    const store = storage.scripts(kind);
    var source: script_store.Source = .{};
    store.read(script.file_name.value(), &source) catch |err| switch (err) {
        error.StreamTooLong => {
            uiLog("Script is too large to edit.");
            return;
        },
        else => {
            uiLog("Could not load script from disk.");
            return;
        },
    };
    clearScriptEditing(view);
    view.editing_file_name = script.file_name;
    view.name.set(script.name.value());
    view.name_focused = false;
    view.form_open = true;
    view.library_open = false;
    view.editor.buffer.set(source.value());
    view.editor.focused = false;
    view.editor.cursor = 0;
    view.editor.cursor_visual_line = 0;
    view.editor.selection_anchor = null;
}

fn clearForm(view: *IdentitiesView) void {
    for (&view.inputs) |*input| input.* = .{};
    view.focused_field = null;
    view.interface_selector.open = false;
    clearEditing(view);
}

fn setFormFromIdentity(view: *IdentitiesView, identity: identity_store.Identity) void {
    view.inputs[@intFromEnum(FormField.label)].set(identity.label.value());
    view.inputs[@intFromEnum(FormField.ip)].set(identity.ip.value());
    view.inputs[@intFromEnum(FormField.prefix)].set(identity.prefix.value());
    view.inputs[@intFromEnum(FormField.interface)].set(identity.interface.value());
    view.inputs[@intFromEnum(FormField.gateway)].set(identity.gateway.value());
    view.inputs[@intFromEnum(FormField.mac)].set(identity.mac.value());
    view.inputs[@intFromEnum(FormField.mtu)].set(identity.mtu.value());
}

fn currentIdentityDraft(view: *const IdentitiesView) identity_store.Draft {
    return .{
        .label = view.inputs[@intFromEnum(FormField.label)].value(),
        .ip = view.inputs[@intFromEnum(FormField.ip)].value(),
        .prefix = view.inputs[@intFromEnum(FormField.prefix)].value(),
        .interface = view.inputs[@intFromEnum(FormField.interface)].value(),
        .gateway = view.inputs[@intFromEnum(FormField.gateway)].value(),
        .mac = view.inputs[@intFromEnum(FormField.mac)].value(),
        .mtu = view.inputs[@intFromEnum(FormField.mtu)].value(),
    };
}

fn formField(subsystem: *Subsystem, view: *IdentitiesView, id: []const u8, input_id: []const u8, label: []const u8, field: FormField, placeholder: []const u8) void {
    const value = view.inputs[@intFromEnum(field)].value();
    const is_focused = view.focused_field == field;
    openElement(id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(140), .height = fixed(66) },
            .childGap = 6,
        },
    });
    text(label, 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    openElement(input_id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(38) },
            .padding = .{ .left = 14, .right = 12, .top = 0, .bottom = 0 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (is_focused or pointerOver(input_id)) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (is_focused) .{
            .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
    });
    bindHover(subsystem, .{ .focus_input = @intFromEnum(field) });
    if (pointerOver(input_id)) c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_IBEAM);
    if (value.len == 0) {
        text(placeholder, 16, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
    } else {
        dynamicText(value, 16, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn pointerOverIndexed(id: []const u8, index: usize) bool {
    return c.Clay_PointerOver(c.Clay_GetElementIdWithIndex(clayString(id, true), @intCast(index)));
}

fn interfaceSelector(subsystem: *Subsystem, view: *IdentitiesView) void {
    const value = view.inputs[@intFromEnum(FormField.interface)].value();
    const hovered = pointerOver("interface-input");
    openElement("interface-field", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(140), .height = fixed(66) },
            .childGap = 6,
        },
    });
    text("Interface", 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    openElement("interface-input", .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(38) },
            .padding = .{ .left = 14, .right = 12, .top = 0, .bottom = 0 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.interface_selector.open) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (view.interface_selector.open) .{
            .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
    });
    bindHover(subsystem, .toggle_interface_menu);
    if (hovered) c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_POINTING_HAND);
    if (value.len == 0) text("Select interface", 16, .{ .r = 128, .g = 137, .b = 159, .a = 255 }) else dynamicText(value, 16, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
    openElement("interface-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 17, .{ .r = 133, .g = 141, .b = 160, .a = 255 });
    if (view.interface_selector.open) interfaceMenu(subsystem, value);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn interfaceMenu(subsystem: *Subsystem, selected: []const u8) void {
    const interfaces = subsystem.ui.services.identities.interfaces();
    const visible_count: usize = @min(interfaces.len, 8);
    const menu_height: usize = @max(visible_count, 1) * 32 + 8;
    openScrollableElement("interface-menu", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = fixed(260), .height = fixed(@floatFromInt(menu_height)) },
            .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
        },
        .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
        .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
        .clip = .{ .vertical = true },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_BOTTOM },
            .offset = .{ .y = 4 },
            .zIndex = 2,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
        },
    });
    if (interfaces.len == 0) {
        text("No packet capture interfaces discovered.", 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    } else for (interfaces, 0..) |*device, index| {
        const name = device.nameSlice();
        interfaceOption(subsystem, index, name, std.mem.eql(u8, selected, name));
    }
    c.Clay__CloseElement();
}

fn interfaceOption(subsystem: *Subsystem, index: usize, name: []const u8, selected: bool) void {
    const hovered = pointerOverIndexed("interface-option", index);
    openIndexedElement("interface-option", index, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(28) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    bindHover(subsystem, .{ .select_interface = index });
    dynamicText(name, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn identityTransportSelector(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize) void {
    const selected_index = view.transport_script_selection[identity_index];
    const selected_name = if (selected_index) |index| if (index < view.transport_scripts.len) view.transport_scripts.values[index].name.value() else "No transport script" else "No transport script";
    const hovered = pointerOverIndexed("identity-transport-selector", identity_index);
    openIndexedElement("identity-transport-selector", identity_index, .{
        .layout = .{
            .sizing = .{ .width = fixed(172), .height = fixed(38) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 6,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.transport_script_menu_identity == identity_index) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 6, .topRight = 6, .bottomLeft = 6, .bottomRight = 6 },
        .border = if (view.transport_script_menu_identity == identity_index) .{ .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } } else .{},
    });
    bindHover(subsystem, .{ .toggle_identity_transport_menu = identity_index });
    dynamicText(selected_name, 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openIndexedElement("identity-transport-chevron-spacer", identity_index, .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.transport_script_menu_identity == identity_index) identityTransportMenu(subsystem, view, identity_index);
    c.Clay__CloseElement();
}

fn identityTransportMenu(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize) void {
    openIndexedElement("identity-transport-menu", identity_index, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = fixed(240), .height = fixed(@floatFromInt((view.transport_scripts.len + 1) * 32 + 8)) },
            .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
        },
        .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
        .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_BOTTOM },
            .offset = .{ .y = 4 },
            .zIndex = 2,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
        },
    });
    identityTransportOption(subsystem, identity_index, null, "No transport script", view.transport_script_selection[identity_index] == null);
    // Clay retains text pointers until frame submission, so borrow catalog records.
    for (view.transport_scripts.slice(), 0..) |*script, index| {
        identityTransportOption(subsystem, identity_index, index, script.name.value(), view.transport_script_selection[identity_index] != null and view.transport_script_selection[identity_index].? == index);
    }
    c.Clay__CloseElement();
}

fn identityTransportOption(subsystem: *Subsystem, identity_index: usize, script_index: ?usize, label: []const u8, selected: bool) void {
    const option_index = identity_index * 1024 + (if (script_index) |index| index + 1 else 0);
    const hovered = pointerOverIndexed("identity-transport-option", option_index);
    openIndexedElement("identity-transport-option", option_index, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(28) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    bindHover(subsystem, .{ .select_identity_transport_script = .{ .identity = identity_index, .script = script_index } });
    dynamicText(label, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn actionButton(subsystem: *Subsystem, id: []const u8, style: button_component.Style, action: Action, index: c_int) void {
    button_component.render(subsystem, id, style, action, if (index >= 0) @intCast(index) else null);
}

fn identityRow(subsystem: *Subsystem, view: *IdentitiesView, index: usize, identity: *const identity_store.Identity) void {
    var summary_id_buffer: [64]u8 = undefined;
    var address_id_buffer: [64]u8 = undefined;
    var actions_id_buffer: [64]u8 = undefined;
    var edit_id_buffer: [64]u8 = undefined;
    var delete_id_buffer: [64]u8 = undefined;
    var start_id_buffer: [64]u8 = undefined;
    var stop_id_buffer: [64]u8 = undefined;
    const summary_id = std.fmt.bufPrint(&summary_id_buffer, "identity-summary-{d}", .{index}) catch unreachable;
    const address_id = std.fmt.bufPrint(&address_id_buffer, "identity-address-{d}", .{index}) catch unreachable;
    const actions_id = std.fmt.bufPrint(&actions_id_buffer, "identity-actions-{d}", .{index}) catch unreachable;
    const edit_id = std.fmt.bufPrint(&edit_id_buffer, "identity-edit-{d}", .{index}) catch unreachable;
    const delete_id = std.fmt.bufPrint(&delete_id_buffer, "identity-delete-{d}", .{index}) catch unreachable;
    const start_id = std.fmt.bufPrint(&start_id_buffer, "identity-start-{d}", .{index}) catch unreachable;
    const stop_id = std.fmt.bufPrint(&stop_id_buffer, "identity-stop-{d}", .{index}) catch unreachable;
    const slot = subsystem.ui.services.identities.slotFor(identity.file_name.value());
    const state = if (slot) |value_slot| subsystem.ui.services.runtime_instance.state(value_slot) orelse .idle else .idle;

    openElement(identity.file_name.value(), .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(66) },
            .padding = .{ .left = 2, .right = 0, .top = 8, .bottom = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .border = .{ .color = .{ .r = 34, .g = 38, .b = 51, .a = 255 }, .width = .{ .bottom = 1 } },
    });
    openElement(summary_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .childGap = 3,
        },
    });
    dynamicText(identity.label.value(), 17, .{ .r = 232, .g = 236, .b = 246, .a = 255 });
    openElement(address_id, .{ .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(18) }, .childGap = 5 } });
    dynamicText(identity.ip.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    text("/", 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    dynamicText(identity.prefix.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    dynamicText(identity.interface.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    const actions_width: f32 = if (index < view.transport_script_selection.len) 402 else 222;
    openElement(actions_id, .{ .layout = .{ .sizing = .{ .width = fixed(actions_width), .height = fixed(38) }, .childGap = 8 } });
    if (index < view.transport_script_selection.len) identityTransportSelector(subsystem, view, index);
    if (state == .running or state == .starting) {
        actionButton(subsystem, stop_id, .secondary, .stop_identity, @intCast(index));
    } else {
        actionButton(subsystem, start_id, .secondary, .start_identity, @intCast(index));
    }
    actionButton(subsystem, edit_id, .secondary, .edit_identity, @intCast(index));
    actionButton(subsystem, delete_id, .secondary, .delete_identity, @intCast(index));
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn layoutScriptingView(view: *ScriptingView, subsystem: *Subsystem) void {
    openElement("script-editor-content", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(main_min_width), .height = grow(0) },
            .padding = .{ .left = 42, .right = 42, .top = 36, .bottom = 36 },
            .childGap = 24,
        },
    });
    openElement("script-workspace", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .childGap = 8,
        },
    });
    openElement("script-controls", .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(38) },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    scriptKindSelector(subsystem, view);
    if (view.form_open) {
        scriptNameInput(subsystem, "script-name", view);
        actionButton(subsystem, "save-script", .primary, .save_script, -1);
        if (view.kind == .global) {
            actionButton(subsystem, "run-global-script", .secondary, .run_global_script, -1);
            actionButton(subsystem, "stop-global-script", .secondary, .stop_global_script, -1);
        }
        if (view.editing_file_name != null) actionButton(subsystem, "delete-script", .secondary, .delete_script, scriptIndex(view));
    }
    scriptLibrarySelector(subsystem, view);
    c.Clay__CloseElement();
    openElement("script-editor-toolbar", .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(34) },
            .padding = .{ .right = 8 },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = .{ .r = 20, .g = 23, .b = 33, .a = 255 },
        .border = .{ .color = .{ .r = 47, .g = 52, .b = 68, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1 } },
    });
    fontSizeSelector(subsystem, "script-font-size", &view.editor);
    c.Clay__CloseElement();
    if (view.form_open) {
        const hovered = pointerOver("script-text-area");
        openScrollableElement("script-text-area", .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = grow(0), .height = grow(0) },
            },
            .backgroundColor = if (view.editor.focused or hovered) .{ .r = 28, .g = 31, .b = 43, .a = 255 } else .{ .r = 24, .g = 27, .b = 38, .a = 255 },
            .border = .{
                .color = if (view.editor.focused) .{ .r = 139, .g = 82, .b = 207, .a = 255 } else .{ .r = 47, .g = 52, .b = 68, .a = 255 },
                .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
            },
            .clip = .{ .horizontal = true, .vertical = true },
        });
        bindHover(subsystem, .focus_script_area);
        if (hovered) c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_IBEAM);
        renderScriptEditorText(subsystem, &view.editor, "script-text-area");
        c.Clay__CloseElement();
    } else {
        openElement("script-empty-state", .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = grow(0), .height = grow(0) },
                .childAlignment = .{ .x = c.CLAY_ALIGN_X_CENTER, .y = c.CLAY_ALIGN_Y_CENTER },
                .childGap = 8,
            },
            .backgroundColor = .{ .r = 24, .g = 27, .b = 38, .a = 255 },
            .border = .{ .color = .{ .r = 47, .g = 52, .b = 68, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
        });
        text("Choose a script from the library", 19, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
        text("or select New Script to create one.", 15, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn scriptNameInput(subsystem: *Subsystem, id: []const u8, view: *ScriptingView) void {
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(100), .height = fixed(34) },
            .padding = .{ .left = 12, .right = 12 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (view.name_focused or hovered) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (view.name_focused) .{ .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } } else .{},
    });
    bindHover(subsystem, .focus_script_name);
    if (hovered) c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_IBEAM);
    if (view.name.len == 0) {
        text("Script name (.lua)", 15, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
    } else {
        dynamicText(view.name.value(), 15, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
    }
    c.Clay__CloseElement();
}

fn scriptKindLabel(kind: script_store.Kind) []const u8 {
    return switch (kind) {
        .global => "Global",
        .transport => "Transport",
    };
}

fn scriptKindSelector(subsystem: *Subsystem, view: *ScriptingView) void {
    const id = "script-kind";
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = fixed(110), .height = fixed(26) },
            .padding = .{ .left = 8, .right = 6 },
            .childGap = 4,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.kind_menu_open) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 29, .g = 32, .b = 44, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
    });
    bindHover(subsystem, .toggle_script_kind_menu);
    dynamicText(scriptKindLabel(view.kind), 13, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openElement("script-kind-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 14, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.kind_menu_open) {
        openElement("script-kind-menu", .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = fixed(180), .height = fixed(72) },
                .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
            },
            .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
            .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
            .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
            .floating = .{
                .attachTo = c.CLAY_ATTACH_TO_PARENT,
                .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_LEFT_TOP, .parent = c.CLAY_ATTACH_POINT_LEFT_BOTTOM },
                .offset = .{ .y = 4 },
                .zIndex = 2,
                .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
            },
        });
        scriptKindOption(subsystem, "script-kind-global", "Global", .global, view.kind == .global);
        scriptKindOption(subsystem, "script-kind-transport", "Transport", .transport, view.kind == .transport);
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptKindOption(subsystem: *Subsystem, id: []const u8, label: []const u8, kind: script_store.Kind, selected: bool) void {
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(28) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    bindHover(subsystem, .{ .select_script_kind = kind });
    text(label, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn scriptLibrarySelector(subsystem: *Subsystem, view: *ScriptingView) void {
    const id = "script-library";
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = fixed(160), .height = fixed(26) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.library_open) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 29, .g = 32, .b = 44, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
    });
    bindHover(subsystem, .toggle_script_library);
    dynamicText(if (view.editing_file_name != null) view.name.value() else "New Script", 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openElement("script-library-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.library_open) {
        openElement("script-library-menu", .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = fixed(240), .height = fixed(@floatFromInt((view.scripts.len + 1) * 32 + 8)) },
                .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
            },
            .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
            .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
            .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
            .floating = .{
                .attachTo = c.CLAY_ATTACH_TO_PARENT,
                .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_RIGHT_TOP, .parent = c.CLAY_ATTACH_POINT_RIGHT_BOTTOM },
                .offset = .{ .y = 4 },
                .zIndex = 2,
                .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
            },
        });
        scriptLibraryItem(subsystem, "new-script-library-item", "New Script", .new_script, -1, true);
        for (view.scripts.slice(), 0..) |*script, index| {
            var id_buffer: [64]u8 = undefined;
            const item_id = std.fmt.bufPrint(&id_buffer, "script-library-item-{d}", .{index}) catch unreachable;
            scriptLibraryItem(subsystem, item_id, script.name.value(), .edit_script, @intCast(index), false);
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptLibraryItem(subsystem: *Subsystem, id: []const u8, label: []const u8, action: Action, index: c_int, primary: bool) void {
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(32) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    bindHover(subsystem, .{ .form_action = .{ .action = action, .index = if (index >= 0) @intCast(index) else null } });
    if (action == .new_script) icon(.plus, 17, .{ .r = 248, .g = 244, .b = 255, .a = 255 });
    dynamicText(label, 14, if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn scriptIndex(view: *const ScriptingView) c_int {
    const file_name = if (view.editing_file_name) |*value| value.value() else return -1;
    for (view.scripts.slice(), 0..) |script, index| {
        if (std.mem.eql(u8, script.file_name.value(), file_name)) return @intCast(index);
    }
    return -1;
}

fn fontSizeSelector(subsystem: *Subsystem, id: []const u8, editor: *ScriptEditor) void {
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = fixed(104), .height = fixed(26) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or editor.font_size_menu_open) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 29, .g = 32, .b = 44, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
    });
    bindHover(subsystem, .toggle_font_size_menu);
    text(fontSizeLabel(editor.font_size), 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openElement("font-size-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (editor.font_size_menu_open) {
        openElement("font-size-menu", .{
            .layout = .{
                .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
                .sizing = .{ .width = fixed(104), .height = fixed(316) },
                .padding = .{ .left = 4, .right = 4, .top = 4, .bottom = 4 },
            },
            .backgroundColor = .{ .r = 31, .g = 34, .b = 46, .a = 255 },
            .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
            .border = .{ .color = .{ .r = 60, .g = 65, .b = 84, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
            .floating = .{
                .attachTo = c.CLAY_ATTACH_TO_PARENT,
                .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_RIGHT_TOP, .parent = c.CLAY_ATTACH_POINT_RIGHT_BOTTOM },
                .offset = .{ .y = 4 },
                .zIndex = 1,
                .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_CAPTURE,
            },
        });
        for (script_font_sizes) |font_size| {
            fontSizeOption(subsystem, font_size, editor.font_size == font_size);
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn fontSizeOption(subsystem: *Subsystem, font_size: u16, selected: bool) void {
    const id = switch (font_size) {
        20 => "font-size-20",
        22 => "font-size-22",
        24 => "font-size-24",
        26 => "font-size-26",
        28 => "font-size-28",
        30 => "font-size-30",
        32 => "font-size-32",
        34 => "font-size-34",
        36 => "font-size-36",
        38 => "font-size-38",
        40 => "font-size-40",
        else => unreachable,
    };
    const hovered = pointerOver(id);
    openElement(id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(28) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (selected) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    bindHover(subsystem, .{ .select_font_size = font_size });
    text(fontSizeLabel(font_size), 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn fontSizeLabel(font_size: u16) []const u8 {
    return switch (font_size) {
        20 => "20 px",
        22 => "22 px",
        24 => "24 px",
        26 => "26 px",
        28 => "28 px",
        30 => "30 px",
        32 => "32 px",
        34 => "34 px",
        36 => "36 px",
        38 => "38 px",
        40 => "40 px",
        else => "20 px",
    };
}

fn selectFontSize(editor: *ScriptEditor, value: u16) void {
    for (script_font_sizes) |font_size| {
        if (value == font_size) {
            editor.font_size = font_size;
            editor.font_size_menu_open = false;
            return;
        }
    }
}

fn layoutIdentities(view: *IdentitiesView, subsystem: *Subsystem) void {
    openElement("main-content", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(main_min_width), .height = grow(0) },
            .padding = .{ .left = 42, .right = 42, .top = 36, .bottom = 36 },
            .childGap = 24,
        },
    });
    text("Identities", 30, .{ .r = 238, .g = 241, .b = 250, .a = 255 });
    openElement("identity-form", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = fixed(240) },
            .padding = .{ .left = 64, .right = 0, .top = 0, .bottom = 0 },
            .childGap = 14,
        },
    });
    text(if (view.editing_file_name == null) "New identity" else "Edit identity", 19, .{ .r = 231, .g = 234, .b = 243, .a = 255 });
    openElement("identity-primary-fields", .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(66) }, .childGap = 12 },
    });
    formField(subsystem, view, "label-field", "label-input", "Name", .label, "");
    formField(subsystem, view, "ip-field", "ip-input", "IP", .ip, "192.168.56.50");
    formField(subsystem, view, "prefix-field", "prefix-input", "Prefix", .prefix, "24");
    interfaceSelector(subsystem, view);
    c.Clay__CloseElement();
    openElement("identity-secondary-fields", .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(66) }, .childGap = 12 },
    });
    formField(subsystem, view, "gateway-field", "gateway-input", "Gateway", .gateway, "Optional");
    formField(subsystem, view, "mac-field", "mac-input", "MAC", .mac, "Optional");
    formField(subsystem, view, "mtu-field", "mtu-input", "MTU", .mtu, "Optional");
    openElement("secondary-fields-spacer", .{ .layout = .{ .sizing = .{ .width = grow(140), .height = grow(0) } } });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    openElement("identity-actions", .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(42) },
            .padding = .{ .top = 4, .bottom = 0 },
            .childGap = 10,
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    openElement("identity-actions-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    actionButton(subsystem, "save-identity", .primary, .save_identity, -1);
    actionButton(subsystem, "clear-identity", .secondary, .clear_identity, -1);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    openElement("all-identities", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .padding = .{ .left = 64, .right = 0, .top = 8, .bottom = 0 },
            .childGap = 7,
        },
    });
    text("All identities", 19, .{ .r = 231, .g = 234, .b = 243, .a = 255 });
    if (view.identities.len == 0) {
        text("No identities saved yet.", 15, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
    } else {
        for (view.identities, 0..) |*identity, index| identityRow(subsystem, view, index, identity);
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn buildLayout(subsystem: *Subsystem) c.Clay_RenderCommandArray {
    subsystem.ui.beginRender();
    c.Clay_BeginLayout();
    openElement("app", .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } },
        .backgroundColor = .{ .r = 18, .g = 24, .b = 38, .a = 255 },
    });
    side_panel_view.render(&subsystem.ui.side_panel, subsystem.ui.page.activePage(), subsystem.ui.services.storage.config_dir, subsystem);
    subsystem.ui.render(subsystem);
    c.Clay__CloseElement();
    return c.Clay_EndLayout(@floatCast(c.sapp_frame_duration()));
}

fn initializeSubsystem(subsystem: *Subsystem, services: ui_state.Services, memory: []u8) void {
    c.sclay_setup();
    subsystem.ui.init(services, .{ .identities = .{} });
    reloadIdentities(subsystem, &subsystem.ui.page.identities);
    reloadTransportScripts(subsystem, &subsystem.ui.page.identities);
    _ = c.Clay_Initialize(
        c.Clay_CreateArenaWithCapacityAndMemory(memory.len, memory.ptr),
        .{ .width = @floatFromInt(c.sapp_width()), .height = @floatFromInt(c.sapp_height()) },
        .{},
    );
    const font_bytes: []const u8 = font_data;
    subsystem.fonts[0] = c.sclay_add_font_mem(@ptrCast(@constCast(font_bytes.ptr)), @intCast(font_bytes.len));
    const icon_font_bytes: []const u8 = icon_font_data;
    subsystem.fonts[1] = c.sclay_add_font_mem(@ptrCast(@constCast(icon_font_bytes.ptr)), @intCast(icon_font_bytes.len));
    c.Clay_SetMeasureTextFunction(c.sclay_measure_text, subsystem.fonts[0..].ptr);
}

fn frameApplication(subsystem: *Subsystem) void {
    c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_DEFAULT);
    c.sclay_new_frame();
    processUiEvents(subsystem);
    subsystem.ui.side_panel.updateWidth();
    drainRuntimeEvents(subsystem);
    switch (subsystem.ui.page) {
        .identities => {},
        .script_editor => |*view| {
            if (view.editor.focused) keepScriptCursorVisible(&view.editor, "script-text-area");
        },
    }

    c.sg_begin_pass(&.{ .swapchain = c.sglue_swapchain() });
    c.sgl_matrix_mode_modelview();
    c.sgl_load_identity();
    c.sclay_render(buildLayout(subsystem), subsystem.fonts[0..].ptr);
    c.sgl_draw();
    c.sg_end_pass();
    c.sg_commit();
}

fn eventApplication(subsystem: *Subsystem, event_data: [*c]const c.sapp_event) void {
    if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_DOWN) subsystem.ui.pointer_click_generation +%= 1;
    c.sclay_handle_event(event_data);
    enqueueKeyboardEvent(subsystem, event_data.*);
    processUiEvents(subsystem);
}

fn enqueueKeyboardEvent(subsystem: *Subsystem, event_data: c.sapp_event) void {
    switch (subsystem.ui.page) {
        .identities => |*view| {
            const field = view.focused_field orelse return;
            if (event_data.type == c.SAPP_EVENTTYPE_CHAR) {
                if (field != .interface) subsystem.ui.enqueue(.{ .input = .{ .codepoint = event_data.char_code } });
                return;
            }
            if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
            const key: ui_event.InputEvent = switch (event_data.key_code) {
                c.SAPP_KEYCODE_BACKSPACE => .{ .key = .backspace },
                c.SAPP_KEYCODE_TAB => .{ .key = .tab },
                c.SAPP_KEYCODE_ENTER => .{ .key = .enter },
                c.SAPP_KEYCODE_ESCAPE => .{ .key = .escape },
                else => return,
            };
            subsystem.ui.enqueue(.{ .input = key });
        },
        .script_editor => |*view| {
            if (view.name_focused) {
                if (event_data.type == c.SAPP_EVENTTYPE_CHAR) {
                    subsystem.ui.enqueue(.{ .input = .{ .codepoint = event_data.char_code } });
                    return;
                }
                if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
                const key: ui_event.InputEvent = switch (event_data.key_code) {
                    c.SAPP_KEYCODE_BACKSPACE => .{ .key = .backspace },
                    c.SAPP_KEYCODE_TAB => .{ .key = .tab },
                    c.SAPP_KEYCODE_ENTER => .{ .key = .enter },
                    c.SAPP_KEYCODE_ESCAPE => .{ .key = .escape },
                    else => return,
                };
                subsystem.ui.enqueue(.{ .input = key });
                return;
            }
            if (!view.editor.focused) return;
            if (event_data.type == c.SAPP_EVENTTYPE_CLIPBOARD_PASTED) {
                subsystem.ui.enqueue(.{ .editor = .paste });
                return;
            }
            if (event_data.type == c.SAPP_EVENTTYPE_CHAR) {
                if (!commandModifier(event_data.modifiers)) subsystem.ui.enqueue(.{ .editor = .{ .insert = event_data.char_code } });
                return;
            }
            if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
            const extend_selection = event_data.modifiers & c.SAPP_MODIFIER_SHIFT != 0;
            const command = commandModifier(event_data.modifiers);
            const key: ui_event.EditorEvent = .{ .key = .{
                .kind = if (command) switch (event_data.key_code) {
                    c.SAPP_KEYCODE_A => .select_all,
                    c.SAPP_KEYCODE_C => .copy,
                    c.SAPP_KEYCODE_X => .cut,
                    else => return,
                } else switch (event_data.key_code) {
                    c.SAPP_KEYCODE_BACKSPACE => .backspace,
                    c.SAPP_KEYCODE_DELETE => .delete,
                    c.SAPP_KEYCODE_ENTER => .enter,
                    c.SAPP_KEYCODE_TAB => .tab,
                    c.SAPP_KEYCODE_LEFT => .left,
                    c.SAPP_KEYCODE_RIGHT => .right,
                    c.SAPP_KEYCODE_UP => .up,
                    c.SAPP_KEYCODE_DOWN => .down,
                    c.SAPP_KEYCODE_HOME => .home,
                    c.SAPP_KEYCODE_END => .end,
                    c.SAPP_KEYCODE_ESCAPE => .escape,
                    else => return,
                },
                .extend_selection = extend_selection,
            } };
            subsystem.ui.enqueue(.{ .editor = key });
        },
    }
}

const Selection = struct { start: usize, end: usize };

fn commandModifier(modifiers: c_uint) bool {
    return modifiers & (c.SAPP_MODIFIER_CTRL | c.SAPP_MODIFIER_SUPER) != 0;
}

fn scriptSelection(editor: *const ScriptEditor) ?Selection {
    const anchor = editor.selection_anchor orelse return null;
    if (anchor == editor.cursor) return null;
    return if (anchor < editor.cursor) .{ .start = anchor, .end = editor.cursor } else .{ .start = editor.cursor, .end = anchor };
}

fn deleteScriptRange(editor: *ScriptEditor, start: usize, end: usize) void {
    if (start >= end or end > editor.buffer.len) return;
    var index = start;
    while (index + end - start < editor.buffer.len) : (index += 1) {
        editor.buffer.bytes[index] = editor.buffer.bytes[index + end - start];
    }
    editor.buffer.len -= end - start;
    editor.cursor = start;
    editor.selection_anchor = null;
}

fn deleteScriptSelection(editor: *ScriptEditor) bool {
    const selection = scriptSelection(editor) orelse return false;
    deleteScriptRange(editor, selection.start, selection.end);
    return true;
}

fn insertScriptText(editor: *ScriptEditor, text_to_insert: []const u8) void {
    const selection = scriptSelection(editor);
    const replace_start = if (selection) |value| value.start else editor.cursor;
    const replace_end = if (selection) |value| value.end else editor.cursor;
    const available = editor.buffer.bytes.len - (editor.buffer.len - (replace_end - replace_start));
    var insert_len = @min(available, text_to_insert.len);
    while (insert_len > 0 and insert_len < text_to_insert.len and text_to_insert[insert_len] & 0b1100_0000 == 0b1000_0000) : (insert_len -= 1) {}
    deleteScriptRange(editor, replace_start, replace_end);
    if (insert_len == 0) return;
    var index = editor.buffer.len;
    while (index > replace_start) {
        index -= 1;
        editor.buffer.bytes[index + insert_len] = editor.buffer.bytes[index];
    }
    @memcpy(editor.buffer.bytes[replace_start .. replace_start + insert_len], text_to_insert[0..insert_len]);
    editor.buffer.len += insert_len;
    editor.cursor = replace_start + insert_len;
}

fn insertScriptCodepoint(editor: *ScriptEditor, char_code: u32) void {
    if (char_code < 0x20 or char_code > 0x10ffff) return;
    const codepoint: u21 = @intCast(char_code);
    var encoded: [4]u8 = undefined;
    const encoded_len = std.unicode.utf8Encode(codepoint, &encoded) catch return;
    insertScriptText(editor, encoded[0..encoded_len]);
}

fn previousCodepoint(buffer: *const TextArea, index: usize) usize {
    var result = index;
    while (result > 0) {
        result -= 1;
        if (buffer.bytes[result] & 0b1100_0000 != 0b1000_0000) break;
    }
    return result;
}

fn nextCodepoint(buffer: *const TextArea, index: usize) usize {
    if (index >= buffer.len) return buffer.len;
    var result = index + 1;
    while (result < buffer.len and buffer.bytes[result] & 0b1100_0000 == 0b1000_0000) : (result += 1) {}
    return result;
}

fn lineStart(buffer: *const TextArea, index: usize) usize {
    var result = @min(index, buffer.len);
    while (result > 0 and buffer.bytes[result - 1] != '\n') : (result -= 1) {}
    return result;
}

fn lineEnd(buffer: *const TextArea, index: usize) usize {
    var result = @min(index, buffer.len);
    while (result < buffer.len and buffer.bytes[result] != '\n') : (result += 1) {}
    return result;
}

fn focusScriptEditor(subsystem: *Subsystem, editor: *ScriptEditor, scroll_id: []const u8) void {
    editor.focused = true;
    editor.selection_anchor = null;
    editor.font_size_menu_open = false;
    const pointer = c.Clay_GetPointerState().position;
    const document = editor.buffer.value();
    var line_start: usize = 0;
    var line_index: usize = 0;
    while (line_start <= document.len) {
        const line_end = std.mem.indexOfScalarPos(u8, document, line_start, '\n') orelse document.len;
        const line_data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clayString("script-line", true), @intCast(line_index)));
        if (line_data.found and pointer.y >= line_data.boundingBox.y and pointer.y < line_data.boundingBox.y + line_data.boundingBox.height) {
            const text_start = line_data.boundingBox.x + 52 + 14;
            const visual_row = visualRowAtY(line_index, pointer.y);
            editor.cursor = line_start + cursorOffsetInWrappedLine(&subsystem.fonts, document[line_start..line_end], visual_row, pointer.x - text_start, editor.font_size, scriptTextAreaWidth(scroll_id));
            editor.cursor_visual_line = visualRowsBefore(line_index) + visual_row;
            keepScriptCursorVisible(editor, scroll_id);
            return;
        }
        if (line_end == document.len) break;
        line_start = line_end + 1;
        line_index += 1;
    }
    editor.cursor = document.len;
    keepScriptCursorVisible(editor, scroll_id);
}

fn visualRowAtY(line_index: usize, y: f32) usize {
    var visual_row: usize = 0;
    while (visual_row <= script_buffer_capacity) : (visual_row += 1) {
        const row_id = line_index * (script_buffer_capacity + 1) + visual_row;
        const row_data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clayString("script-visual-line", true), @intCast(row_id)));
        if (!row_data.found) break;
        if (y >= row_data.boundingBox.y and y < row_data.boundingBox.y + row_data.boundingBox.height) return visual_row;
    }
    return 0;
}

fn visualRowsBefore(line_index: usize) usize {
    var total: usize = 0;
    var current_line: usize = 0;
    while (current_line < line_index) : (current_line += 1) {
        var row: usize = 0;
        while (row <= script_buffer_capacity) : (row += 1) {
            const row_id = current_line * (script_buffer_capacity + 1) + row;
            const row_data = c.Clay_GetElementData(c.Clay_GetElementIdWithIndex(clayString("script-visual-line", true), @intCast(row_id)));
            if (!row_data.found) break;
            total += 1;
        }
    }
    return total;
}

fn cursorOffsetInWrappedLine(fonts: *[2]c.sclay_font_t, line: []const u8, target_row: usize, x: f32, font_size: u16, available_width: f32) usize {
    var row: usize = 0;
    var row_width: f32 = 0;
    var offset: usize = 0;
    while (offset < line.len) {
        const whitespace = std.ascii.isWhitespace(line[offset]);
        var end = offset + 1;
        while (end < line.len and std.ascii.isWhitespace(line[end]) == whitespace) : (end += 1) {}
        const segment = line[offset..end];
        const width = scriptTextWidth(fonts, segment, font_size);
        if (row_width > 0 and row_width + width > available_width) {
            row += 1;
            row_width = 0;
            if (whitespace) {
                offset = end;
                continue;
            }
        }
        if (row == target_row) {
            const cursor = cursorOffsetInSegment(fonts, segment, x - row_width, font_size);
            if (cursor != segment.len or x <= row_width + width) return offset + cursor;
        }
        row_width += width;
        offset = end;
    }
    return line.len;
}

fn cursorOffsetInSegment(fonts: *[2]c.sclay_font_t, segment: []const u8, x: f32, font_size: u16) usize {
    if (x <= 0) return 0;
    var offset: usize = 0;
    while (offset < segment.len) {
        const next = nextCodepointInSlice(segment, offset);
        const midpoint = (scriptTextWidth(fonts, segment[0..offset], font_size) + scriptTextWidth(fonts, segment[0..next], font_size)) / 2;
        if (x < midpoint) return offset;
        offset = next;
    }
    return segment.len;
}

fn nextCodepointInSlice(value: []const u8, index: usize) usize {
    if (index >= value.len) return value.len;
    var next = index + 1;
    while (next < value.len and value[next] & 0b1100_0000 == 0b1000_0000) : (next += 1) {}
    return next;
}

fn keepScriptCursorVisible(editor: *const ScriptEditor, scroll_id: []const u8) void {
    const scroll_data = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clayString(scroll_id, true)));
    if (!scroll_data.found or scroll_data.scrollPosition == null) return;

    const line_height = scriptLineHeight(editor.font_size);
    const line_top = @as(f32, @floatFromInt(editor.cursor_visual_line)) * line_height;
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

fn moveScriptCursor(editor: *ScriptEditor, target: usize, extend_selection: bool) void {
    if (extend_selection) {
        if (editor.selection_anchor == null) editor.selection_anchor = editor.cursor;
        editor.cursor = target;
        if (editor.selection_anchor == editor.cursor) editor.selection_anchor = null;
        return;
    }
    editor.cursor = target;
    editor.selection_anchor = null;
}

fn moveScriptLeft(editor: *ScriptEditor, extend_selection: bool) void {
    if (!extend_selection) {
        if (scriptSelection(editor)) |selection| {
            moveScriptCursor(editor, selection.start, false);
            return;
        }
    }
    moveScriptCursor(editor, previousCodepoint(&editor.buffer, editor.cursor), extend_selection);
}

fn moveScriptRight(editor: *ScriptEditor, extend_selection: bool) void {
    if (!extend_selection) {
        if (scriptSelection(editor)) |selection| {
            moveScriptCursor(editor, selection.end, false);
            return;
        }
    }
    moveScriptCursor(editor, nextCodepoint(&editor.buffer, editor.cursor), extend_selection);
}

fn moveScriptVertical(editor: *ScriptEditor, down: bool, extend_selection: bool) void {
    const current_start = lineStart(&editor.buffer, editor.cursor);
    const column = editor.cursor - current_start;
    if (down) {
        const current_end = lineEnd(&editor.buffer, editor.cursor);
        if (current_end == editor.buffer.len) return;
        const next_start = current_end + 1;
        const next_end = lineEnd(&editor.buffer, next_start);
        moveScriptCursor(editor, alignCodepointStart(&editor.buffer, @min(next_start + column, next_end)), extend_selection);
    } else {
        if (current_start == 0) return;
        const previous_end = current_start - 1;
        const previous_start = lineStart(&editor.buffer, previous_end);
        moveScriptCursor(editor, alignCodepointStart(&editor.buffer, @min(previous_start + column, previous_end)), extend_selection);
    }
}

fn alignCodepointStart(buffer: *const TextArea, index: usize) usize {
    var result = index;
    while (result > 0 and result < buffer.len and buffer.bytes[result] & 0b1100_0000 == 0b1000_0000) : (result -= 1) {}
    return result;
}

fn backspaceScript(editor: *ScriptEditor) void {
    if (deleteScriptSelection(editor)) return;
    const start = previousCodepoint(&editor.buffer, editor.cursor);
    deleteScriptRange(editor, start, editor.cursor);
}

fn deleteScriptForward(editor: *ScriptEditor) void {
    if (deleteScriptSelection(editor)) return;
    deleteScriptRange(editor, editor.cursor, nextCodepoint(&editor.buffer, editor.cursor));
}

fn copyScriptSelection(editor: *const ScriptEditor) void {
    const selection = scriptSelection(editor) orelse return;
    var clipboard: [script_buffer_capacity + 1]u8 = undefined;
    const contents = editor.buffer.bytes[selection.start..selection.end];
    @memcpy(clipboard[0..contents.len], contents);
    clipboard[contents.len] = 0;
    c.sapp_set_clipboard_string(clipboard[0..].ptr);
}

fn appendCodepoint(input: anytype, char_code: u32) void {
    if (char_code < 0x20 or char_code > 0x10ffff) return;
    const codepoint: u21 = @intCast(char_code);
    const encoded_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch return;
    if (input.len + encoded_len > input.bytes.len) return;
    _ = std.unicode.utf8Encode(codepoint, input.bytes[input.len..]) catch return;
    input.len += encoded_len;
}

fn removeLastCodepoint(input: anytype) void {
    while (input.len > 0) {
        input.len -= 1;
        if (input.bytes[input.len] & 0b1100_0000 != 0b1000_0000) return;
    }
}

fn deinitializeSubsystem(subsystem: *Subsystem) void {
    subsystem.ui.page.deinit(subsystem);
    subsystem.ui.services = undefined;
    c.sclay_shutdown();
}

fn handleIdentityAction(subsystem: *Subsystem, view: *IdentitiesView, action: Action, index: ?usize) void {
    switch (action) {
        .save_identity => {
            const service = subsystem.ui.services.identities;
            const draft = currentIdentityDraft(view);
            if (draft.label.len == 0) {
                uiLog("A name is required to save an identity.");
                return;
            }
            if (view.editing_file_name) |file_name| {
                const id = identity_model.IdentityId.init(file_name.value()) catch {
                    uiLog("Identity identifier is invalid.");
                    return;
                };
                service.execute(.{ .update = .{ .id = id, .draft = draft } }) catch |err| {
                    uiLog(switch (err) {
                        error.IdentityNameInUse => "Identity names must be unique.",
                        error.IdentityInUse => "Stop the identity before renaming it.",
                        else => "Could not save identity to disk.",
                    });
                    return;
                };
            } else {
                service.execute(.{ .create = draft }) catch |err| {
                    uiLog(if (err == error.IdentityNameInUse) "Identity names must be unique." else "Could not save identity to disk.");
                    return;
                };
            }
            clearForm(view);
            reloadIdentities(subsystem, view);
        },
        .clear_identity => {
            clearForm(view);
        },
        .edit_identity => {
            const identity_index = index orelse return;
            if (identity_index >= view.identities.len) return;
            const identity = view.identities[identity_index];
            clearEditing(view);
            view.editing_file_name = identity.file_name;
            setFormFromIdentity(view, identity);
            view.focused_field = .label;
        },
        .delete_identity => {
            const identity_index = index orelse return;
            if (identity_index >= view.identities.len) return;
            const service = subsystem.ui.services.identities;
            const deleted_file_name = view.identities[identity_index].file_name.value();
            const id = identity_model.IdentityId.init(deleted_file_name) catch return;
            service.execute(.{ .delete = id }) catch |err| {
                uiLog(if (err == error.IdentityInUse) "Stop the identity before deleting it." else "Could not delete identity from disk.");
                return;
            };
            if (view.editing_file_name) |file_name| {
                if (std.mem.eql(u8, file_name.value(), id.value())) clearForm(view);
            }
            reloadIdentities(subsystem, view);
        },
        .start_identity => {
            const identity_index = index orelse return;
            if (identity_index >= view.identities.len) return;
            const service = subsystem.ui.services.identities;
            const identity = view.identities[identity_index];
            const transport_source = selectedTransportSource(subsystem, view, identity_index) catch return;
            const id = identity_model.IdentityId.init(identity.file_name.value()) catch return;
            service.execute(.{ .start = .{ .id = id, .transport = transport_source } }) catch |err| {
                uiLog(switch (err) {
                    error.InterfaceRequired => "Select a packet interface before starting the identity.",
                    error.InvalidIpAddress => "Identity IP address is invalid.",
                    error.InvalidPrefixLength => "Identity prefix must be between 0 and 32.",
                    error.InvalidGatewayAddress => "Identity gateway address is invalid.",
                    error.InvalidMacAddress => "Identity MAC must be a unicast address such as 02:00:00:00:00:01.",
                    error.InvalidMtu => "Identity MTU must be between 68 and 1500.",
                    error.IdentityNameInUse => "Identity names must be unique.",
                    else => "Identity slot is unavailable.",
                });
                return;
            };
        },
        .stop_identity => {
            const identity_index = index orelse return;
            if (identity_index >= view.identities.len) return;
            const service = subsystem.ui.services.identities;
            const id = identity_model.IdentityId.init(view.identities[identity_index].file_name.value()) catch return;
            service.execute(.{ .stop = id }) catch {
                uiLog("Identity slot is not running.");
                return;
            };
        },
        else => {},
    }
}

fn handleScriptAction(subsystem: *Subsystem, view: *ScriptingView, action: Action, index: ?usize) void {
    const kind = view.kind;
    switch (action) {
        .save_script => {
            const storage = subsystem.ui.services.storage;
            const store = storage.scripts(kind);
            const previous_file_name = if (view.editing_file_name) |*value| value.value() else null;
            var new_file_name: storage_model.FieldText = .{};
            store.save(view.name.value(), view.editor.buffer.value(), previous_file_name, &new_file_name) catch |err| switch (err) {
                error.NameRequired => {
                    uiLog("A script name is required.");
                    return;
                },
                error.InvalidName => {
                    uiLog("Names cannot contain path separators.");
                    return;
                },
                error.SourceTooLarge => {
                    uiLog("Script is too large to save.");
                    return;
                },
                else => {
                    uiLog("Could not save script to disk.");
                    return;
                },
            };
            clearScriptEditing(view);
            view.editing_file_name = new_file_name;
            view.name_focused = false;
            view.library_open = false;
            reloadScripts(subsystem, view, kind);
        },
        .new_script => {
            clearScriptForm(view);
            view.form_open = true;
            view.name_focused = true;
            view.library_open = false;
        },
        .edit_script => editScript(subsystem, view, kind, if (index) |value| @intCast(value) else -1),
        .delete_script => {
            const script_index = index orelse return;
            if (script_index >= view.scripts.len) return;
            const file_name = view.scripts.values[script_index].file_name.value();
            const storage = subsystem.ui.services.storage;
            const store = storage.scripts(kind);
            store.delete(file_name) catch {
                uiLog("Could not delete script from disk.");
                return;
            };
            if (view.editing_file_name) |editing_file_name| {
                if (std.mem.eql(u8, editing_file_name.value(), file_name)) clearScriptForm(view);
            }
            view.library_open = false;
            reloadScripts(subsystem, view, kind);
        },
        .run_global_script => {
            if (kind != .global) return;
            const value = subsystem.ui.services.runtime_instance;
            var source: runtime.Source = .{};
            source.set(view.editor.buffer.value()) catch {
                uiLog("Script is too large to run.");
                return;
            };
            if (!value.runGlobal(source)) {
                uiLog("Could not start the global program.");
                return;
            }
        },
        .stop_global_script => {
            if (kind != .global) return;
            const value = subsystem.ui.services.runtime_instance;
            _ = value.stopGlobal();
        },
        else => {},
    }
}

fn handleSignalAction(subsystem: *Subsystem, action: ui_event.SignalAction, pointer_x: f32, pointer_state: c_int) void {
    if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
        if (subsystem.ui.handled_pointer_click_generation == subsystem.ui.pointer_click_generation) return;
        subsystem.ui.handled_pointer_click_generation = subsystem.ui.pointer_click_generation;
    }
    switch (action) {
        .resize_sidebar => {
            c.sapp_set_mouse_cursor(c.SAPP_MOUSECURSOR_RESIZE_EW);
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                subsystem.ui.side_panel.resizing = true;
                subsystem.ui.side_panel.drag_offset = pointer_x - subsystem.ui.side_panel.width;
            }
        },
        .focus_input => |field_index| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => |*view| {
                        if (field_index < view.inputs.len) {
                            view.focused_field = @enumFromInt(field_index);
                            view.interface_selector.open = false;
                        }
                    },
                    .script_editor => {},
                }
            }
        },
        .toggle_interface_menu => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => |*view| {
                    view.focused_field = null;
                    view.interface_selector.open = !view.interface_selector.open;
                },
                else => {},
            };
        },
        .select_interface => |interface_index| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => |*view| selectInterface(subsystem, view, interface_index),
                else => {},
            };
        },
        .toggle_identity_transport_menu => |identity_index| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => |*view| {
                    if (identity_index >= view.transport_script_selection.len) return;
                    view.focused_field = null;
                    view.interface_selector.open = false;
                    view.transport_script_menu_identity = if (view.transport_script_menu_identity == identity_index) null else identity_index;
                },
                else => {},
            };
        },
        .select_identity_transport_script => |selection| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => |*view| {
                    if (selection.identity >= view.transport_script_selection.len) return;
                    if (selection.script) |script_index| if (script_index >= view.transport_scripts.len) return;
                    view.transport_script_selection[selection.identity] = selection.script;
                    view.transport_script_menu_identity = null;
                },
                else => {},
            };
        },
        .focus_script_name => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => {},
                    .script_editor => |*view| {
                        view.name_focused = true;
                        view.library_open = false;
                        view.kind_menu_open = false;
                        view.editor.focused = false;
                        view.editor.font_size_menu_open = false;
                    },
                }
            }
        },
        .toggle_script_kind_menu => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => {},
                .script_editor => |*view| {
                    view.kind_menu_open = !view.kind_menu_open;
                    view.library_open = false;
                    view.name_focused = false;
                    view.editor.font_size_menu_open = false;
                },
            };
        },
        .select_script_kind => |script_kind| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) switch (subsystem.ui.page) {
                .identities => {},
                .script_editor => |*view| selectScriptKind(subsystem, view, script_kind),
            };
        },
        .toggle_script_library => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => {},
                    .script_editor => |*view| {
                        view.library_open = !view.library_open;
                        view.kind_menu_open = false;
                        view.editor.font_size_menu_open = false;
                    },
                }
            }
        },
        .focus_script_area => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => {},
                    .script_editor => |*view| {
                        view.name_focused = false;
                        view.library_open = false;
                        view.kind_menu_open = false;
                        focusScriptEditor(subsystem, &view.editor, "script-text-area");
                    },
                }
            }
        },
        .toggle_font_size_menu => {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => {},
                    .script_editor => |*view| {
                        view.editor.font_size_menu_open = !view.editor.font_size_menu_open;
                        view.kind_menu_open = false;
                    },
                }
            }
        },
        .select_font_size => |font_size| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => {},
                    .script_editor => |*view| selectFontSize(&view.editor, font_size),
                }
            }
        },
        .form_action => |form_action| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                switch (subsystem.ui.page) {
                    .identities => |*view| handleIdentityAction(subsystem, view, form_action.action, form_action.index),
                    .script_editor => |*view| handleScriptAction(subsystem, view, form_action.action, form_action.index),
                }
            }
        },
        .select_page => |page| {
            if (pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME) {
                subsystem.ui.page.select(subsystem, page);
            }
        },
    }
}

const DispatchContext = struct {
    subsystem: *Subsystem,

    pub fn handleSignal(self: *DispatchContext, signal: ui_event.SignalEvent) void {
        handleSignalAction(self.subsystem, signal.binding.action, signal.pointer_x, signal.pointer_state);
    }

    pub fn handleInput(self: *DispatchContext, input: ui_event.InputEvent) void {
        switch (self.subsystem.ui.page) {
            .identities => |*view| {
                const field = view.focused_field orelse return;
                const buffer = &view.inputs[@intFromEnum(field)];
                switch (input) {
                    .codepoint => |codepoint| appendCodepoint(buffer, codepoint),
                    .key => |key| switch (key) {
                        .backspace => removeLastCodepoint(buffer),
                        .tab, .enter => view.focused_field = @enumFromInt((@intFromEnum(field) + 1) % view.inputs.len),
                        .escape => view.focused_field = null,
                    },
                }
            },
            .script_editor => |*view| {
                if (!view.name_focused) return;
                switch (input) {
                    .codepoint => |codepoint| appendCodepoint(&view.name, codepoint),
                    .key => |key| switch (key) {
                        .backspace => removeLastCodepoint(&view.name),
                        .tab, .enter => {
                            view.name_focused = false;
                            view.editor.focused = true;
                        },
                        .escape => view.name_focused = false,
                    },
                }
            },
        }
    }

    pub fn handleEditor(self: *DispatchContext, event_value: ui_event.EditorEvent) void {
        const view = switch (self.subsystem.ui.page) {
            .identities => return,
            .script_editor => |*value| value,
        };
        const editor = &view.editor;
        if (!editor.focused) return;
        switch (event_value) {
            .paste => {
                const clipboard = c.sapp_get_clipboard_string();
                if (clipboard != null) insertScriptText(editor, std.mem.span(clipboard));
            },
            .insert => |codepoint| insertScriptCodepoint(editor, codepoint),
            .key => |key| switch (key.kind) {
                .backspace => backspaceScript(editor),
                .delete => deleteScriptForward(editor),
                .enter => insertScriptText(editor, "\n"),
                .tab => insertScriptText(editor, "\t"),
                .left => moveScriptLeft(editor, key.extend_selection),
                .right => moveScriptRight(editor, key.extend_selection),
                .up => moveScriptVertical(editor, false, key.extend_selection),
                .down => moveScriptVertical(editor, true, key.extend_selection),
                .home => moveScriptCursor(editor, lineStart(&editor.buffer, editor.cursor), key.extend_selection),
                .end => moveScriptCursor(editor, lineEnd(&editor.buffer, editor.cursor), key.extend_selection),
                .escape => {
                    editor.selection_anchor = null;
                    editor.focused = false;
                },
                .select_all => {
                    editor.selection_anchor = 0;
                    editor.cursor = editor.buffer.len;
                },
                .copy => copyScriptSelection(editor),
                .cut => {
                    copyScriptSelection(editor);
                    _ = deleteScriptSelection(editor);
                },
            },
        }
        keepScriptCursorVisible(editor, "script-text-area");
    }
};

fn processUiEvents(subsystem: *Subsystem) void {
    var context: DispatchContext = .{ .subsystem = subsystem };
    var processed: usize = 0;
    while (processed < limits.ui_event_capacity) : (processed += 1) {
        const next = subsystem.ui.nextEvent() orelse break;
        subsystem.ui.handle(&context, next);
    }
}
