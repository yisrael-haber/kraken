const std = @import("std");
const builtin = @import("builtin");
const script_store = @import("../storage/script_repository.zig");
const storage_module = @import("../storage/storage.zig");
const text_types = @import("../text.zig");
const command = @import("../command.zig");
const identity_module = @import("../identities/manager.zig");
const identity_types = @import("../identities/identity.zig");
const global = @import("../runtime/global.zig");
const limits = @import("../limits.zig");
const log = @import("../log.zig");
const clay = @import("clay.zig");
const script_editor = @import("script_editor.zig");
const text_editor = @import("text_editor.zig");
const side_panel_view = @import("side_panel.zig");

const c = @import("c");

const main_min_width: f32 = 640;
const embedded_fonts = @import("font");
const linux_text_font_paths = [_][:0]const u8{
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
};

const FormFieldSpec = struct {
    input_id: []const u8,
    label: []const u8,
    placeholder: []const u8,
};

const interface_field = 3;

const form_fields = [_]FormFieldSpec{
    .{ .input_id = "label-input", .label = "Name", .placeholder = "" },
    .{ .input_id = "ip-input", .label = "IP", .placeholder = "192.168.56.50" },
    .{ .input_id = "prefix-input", .label = "Prefix", .placeholder = "24" },
    .{ .input_id = "interface-input", .label = "Interface", .placeholder = "Select interface" },
    .{ .input_id = "gateway-input", .label = "Gateway", .placeholder = "Optional" },
    .{ .input_id = "mac-input", .label = "MAC", .placeholder = "Required" },
    .{ .input_id = "mtu-input", .label = "MTU", .placeholder = "Optional" },
};

const Page = enum { identities, script_editor, logs };

const caret_down = "\u{e136}";
const plus = "\u{e3d4}";

const TextField = text_editor.Editor(text_types.FieldText, .single_line);
const ScriptingFocus = enum { none, name, source };
const ScriptMenu = enum { none, kind, library };

const ScriptingView = struct {
    editor: script_editor.State = .{},
    name: TextField = .{},
    focus: ScriptingFocus = .none,
    menu: ScriptMenu = .none,
    kind: script_store.Kind = .global,
    scripts: std.ArrayList(text_types.FieldText) = .empty,
    editing_file_name: ?text_types.FieldText = null,
};

const log_line_counts = [_]usize{ 50, 100, 250, 500, 1_000, 5_000 };
const log_font_sizes = [_]u16{ 12, 14, 16, 18, 20 };
const log_reload_interval_ns: i96 = std.time.ns_per_ms * 250;

const LogsView = struct {
    contents: std.ArrayList(u8) = .empty,
    line_count: usize = 500,
    menu_open: bool = false,
    font_size: u16 = 14,
    font_menu_open: bool = false,
    next_reload_ns: i96 = 0,

    fn clear(self: *LogsView, allocator: std.mem.Allocator) void {
        self.contents.deinit(allocator);
        self.* = .{};
    }

    fn clearContents(self: *LogsView, allocator: std.mem.Allocator) void {
        self.contents.deinit(allocator);
        self.contents = .empty;
        self.menu_open = false;
        self.font_menu_open = false;
        self.next_reload_ns = 0;
    }
};

const IdentitiesView = struct {
    inputs: [form_fields.len]TextField = [_]TextField{.{}} ** form_fields.len,
    focused_field: ?usize = null,
    transport_scripts: std.ArrayList(text_types.FieldText) = .empty,
    transport_script_menu_identity: ?usize = null,
    editing_identity_id: ?text_types.FieldText = null,
    interface_menu_open: bool = false,
};

const SignalAction = union(enum) {
    focus_input: usize,
    toggle_interface_menu,
    select_interface: usize,
    toggle_identity_transport_menu: usize,
    select_identity_transport_script: struct { identity: usize, script: ?usize },
    focus_script_name,
    toggle_script_kind_menu,
    select_script_kind: script_store.Kind,
    toggle_script_library,
    script_editor: script_editor.Action,
    save_identity,
    clear_identity,
    edit_identity: usize,
    delete_identity: usize,
    start_identity: usize,
    stop_identity: usize,
    save_script,
    new_script,
    edit_script: usize,
    delete_script,
    run_global_script,
    stop_global_script,
    refresh_logs,
    toggle_log_count_menu,
    select_log_count: usize,
    toggle_log_font_menu,
    select_log_font_size: u16,
    select_page: Page,
};

pub const Services = struct {
    storage: *storage_module.Storage,
    identity_manager: *identity_module.Manager,
    interfaces: []const text_types.FieldText,
    global_runner: *global.Runner,
    logger: *log.Logger,
};

var active_subsystem: *Subsystem = undefined;

pub const Subsystem = struct {
    services: Services = undefined,
    page: Page = .identities,
    identities: IdentitiesView = .{},
    scripting: ScriptingView = .{},
    logs: LogsView = .{},
    signals: [limits.ui_signal_capacity]SignalAction = undefined,
    signal_len: usize = 0,
    pointer_click_handled: bool = false,
    fonts: [2]c.sclay_font_t = .{ 0, 0 },

    pub fn init(self: *Subsystem, services: Services, clay_memory: []u8) !void {
        self.* = .{ .services = services };
        active_subsystem = self;
        c.sclay_setup();
        reloadTransportScripts(self, &self.identities);
        _ = c.Clay_Initialize(
            c.Clay_CreateArenaWithCapacityAndMemory(clay_memory.len, clay_memory.ptr),
            .{ .width = @floatFromInt(c.sapp_width()), .height = @floatFromInt(c.sapp_height()) },
            .{},
        );
        self.fonts[0] = try loadSystemTextFont(services.storage.allocator);
        self.fonts[1] = c.sclay_add_font_mem(@ptrCast(@constCast(embedded_fonts.phosphor.ptr)), @intCast(embedded_fonts.phosphor.len));
        c.Clay_SetMeasureTextFunction(c.sclay_measure_text, self.fonts[0..].ptr);
    }

    fn loadSystemTextFont(allocator: std.mem.Allocator) !c.sclay_font_t {
        switch (builtin.os.tag) {
            .linux => {
                for (linux_text_font_paths) |path| {
                    const font = c.sclay_add_font(path.ptr);
                    if (font != -1) return font;
                }
            },
            .windows => {
                const windows_dir = std.c.getenv("WINDIR") orelse return error.SystemFontUnavailable;
                const path = try std.fmt.allocPrintSentinel(allocator, "{s}\\Fonts\\segoeui.ttf", .{std.mem.span(windows_dir)}, 0);
                defer allocator.free(path);
                const font = c.sclay_add_font(path.ptr);
                if (font != -1) return font;
            },
            else => unreachable,
        }
        return error.SystemFontUnavailable;
    }

    pub fn frame(self: *Subsystem) void {
        c.sclay_new_frame();
        refreshLogsDue(self);
        if (self.page == .script_editor and self.scripting.focus == .source) self.scripting.editor.keepCursorVisible();
        c.sg_begin_pass(&.{ .swapchain = c.sglue_swapchain() });
        c.sgl_matrix_mode_modelview();
        c.sgl_load_identity();
        const render_commands = buildLayout(self);
        updateMouseCursor(self);
        c.sclay_render(render_commands, self.fonts[0..].ptr);
        c.sgl_draw();
        c.sg_end_pass();
        c.sg_commit();
    }

    pub fn event(self: *Subsystem, event_data: [*c]const c.sapp_event) void {
        if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_DOWN) self.pointer_click_handled = false;
        if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_UP) endPointerSelections(self);
        c.sclay_handle_event(event_data);
        handleKeyboardEvent(self, event_data.*);
    }

    pub fn deinit(self: *Subsystem) void {
        const allocator = self.services.storage.allocator;
        self.identities.transport_scripts.deinit(allocator);
        self.scripting.scripts.deinit(allocator);
        self.logs.clear(allocator);
        self.services = undefined;
        c.sclay_shutdown();
    }

    pub fn bindSignal(self: *Subsystem, action: SignalAction) void {
        if (self.signal_len == self.signals.len) return;
        const signal = &self.signals[self.signal_len];
        signal.* = action;
        self.signal_len += 1;
        c.kraken_on_hover(@ptrCast(signal));
    }
};

pub export fn kraken_handle_hover(pointer_x: f32, pointer_y: f32, pointer_state: u8, user_data: ?*anyopaque) callconv(.c) void {
    _ = pointer_y;
    const action: *const SignalAction = @ptrCast(@alignCast(user_data.?));
    handleSignalAction(active_subsystem, action.*, pointer_x, pointer_state);
}

fn bindEditorAction(context: *anyopaque, action: script_editor.Action) void {
    const subsystem: *Subsystem = @ptrCast(@alignCast(context));
    subsystem.bindSignal(.{ .script_editor = action });
}

fn glyph(value: []const u8, font_size: u16, color: c.Clay_Color) void {
    const config: c.Clay_TextElementConfig = .{
        .fontId = 1,
        .fontSize = font_size,
        .textColor = color,
    };
    c.Clay__OpenTextElement(clay.string(value, true), config);
}

fn reloadTransportScripts(subsystem: *Subsystem, view: *IdentitiesView) void {
    const storage = subsystem.services.storage;
    storage.scripts(.transport).load(storage.allocator, &view.transport_scripts) catch {
        subsystem.services.logger.err(.ui, "Could not load transport scripts from disk.");
        return;
    };
}

fn clearScriptForm(view: *ScriptingView) void {
    view.name.reset();
    view.focus = .none;
    view.editor.reset();
    view.menu = .none;
    view.editing_file_name = null;
}

fn reloadScripts(subsystem: *Subsystem, view: *ScriptingView) void {
    const storage = subsystem.services.storage;
    storage.scripts(view.kind).load(storage.allocator, &view.scripts) catch {
        subsystem.services.logger.err(.ui, "Could not load scripts from disk.");
        return;
    };
}

fn reloadLogs(subsystem: *Subsystem, view: *LogsView) void {
    subsystem.services.logger.readTail(subsystem.services.storage.allocator, &view.contents, view.line_count) catch {
        subsystem.services.logger.err(.ui, "Could not read the current session log.");
    };
    view.next_reload_ns = nowAwakeNs() + log_reload_interval_ns;
}

fn refreshLogsDue(subsystem: *Subsystem) void {
    if (subsystem.page != .logs) return;
    if (nowAwakeNs() < subsystem.logs.next_reload_ns) return;
    reloadLogs(subsystem, &subsystem.logs);
}

fn nowAwakeNs() i96 {
    return std.Io.Clock.awake.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds;
}

fn selectScriptKind(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind) void {
    if (view.kind == kind) {
        view.menu = .none;
        return;
    }
    clearScriptForm(view);
    view.kind = kind;
    reloadScripts(subsystem, view);
}

fn editScript(subsystem: *Subsystem, view: *ScriptingView, index: usize) void {
    const file_name = view.scripts.items[index].value();
    var source: text_types.FixedText(limits.source_capacity) = .{};
    subsystem.services.storage.scripts(view.kind).read(file_name, &source) catch |err| switch (err) {
        error.StreamTooLong => {
            subsystem.services.logger.err(.ui, "Script is too large to edit.");
            return;
        },
        else => {
            subsystem.services.logger.err(.ui, "Could not load script from disk.");
            return;
        },
    };
    view.editing_file_name = view.scripts.items[index];
    view.name.set(std.mem.cutSuffix(u8, file_name, ".lua").?) catch unreachable;
    view.focus = .none;
    view.menu = .none;
    view.editor.load(source);
}

fn clearForm(view: *IdentitiesView) void {
    for (&view.inputs) |*input| input.reset();
    view.focused_field = null;
    view.interface_menu_open = false;
    view.editing_identity_id = null;
}

fn currentIdentity(view: *const IdentitiesView) identity_types.Identity {
    var value: identity_types.Identity = .{};
    value.id = view.editing_identity_id orelse .{};
    inline for (std.meta.fields(identity_types.Identity)[1..8], 0..) |field, index| @field(value, field.name).set(view.inputs[index].value()) catch unreachable;
    return value;
}

fn formField(subsystem: *Subsystem, view: *IdentitiesView, index: usize, spec: FormFieldSpec) void {
    const is_interface = index == interface_field;
    const is_focused = view.focused_field == index;
    const menu_open = view.interface_menu_open and is_interface;
    clay.open(spec.label, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(140), .height = clay.fixed(66) },
            .childGap = 6,
        },
    });
    clay.text(spec.label, 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    clay.open(spec.input_id, .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(38) },
            .padding = .{ .left = 14, .right = 12, .top = 0, .bottom = 0 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (is_focused or menu_open or clay.pointerOver(spec.input_id)) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (is_focused or menu_open) .{
            .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
        .clip = if (is_interface) .{} else .{ .horizontal = true },
    });
    if (is_interface) {
        const value = view.inputs[index].value();
        subsystem.bindSignal(.toggle_interface_menu);
        if (value.len == 0) clay.text(spec.placeholder, 16, .{ .r = 128, .g = 137, .b = 159, .a = 255 }) else clay.dynamicText(value, 16, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
        clay.open("interface-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
        c.Clay__CloseElement();
        glyph(caret_down, 17, .{ .r = 133, .g = 141, .b = 160, .a = 255 });
        if (menu_open) interfaceMenu(subsystem, value);
    } else {
        subsystem.bindSignal(.{ .focus_input = index });
        view.inputs[index].render(&subsystem.fonts, spec.input_id, index, is_focused, spec.placeholder, 16, 14, 12, 38);
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn interfaceMenu(subsystem: *Subsystem, selected: []const u8) void {
    const interfaces = subsystem.services.interfaces;
    const visible_count: usize = @min(interfaces.len, 8);
    const menu_height: usize = @max(visible_count, 1) * 32 + 8;
    var declaration = clay.menu(260, @floatFromInt(menu_height), .left, 2);
    declaration.clip.vertical = true;
    clay.openScrollable("interface-menu", declaration);
    if (interfaces.len == 0) {
        clay.text("No packet capture interfaces discovered.", 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    } else for (interfaces, 0..) |*device, index| {
        menuOption(subsystem, "interface-option", index, device.value(), std.mem.eql(u8, selected, device.value()), .{ .select_interface = index });
    }
    c.Clay__CloseElement();
}

fn menuOption(subsystem: *Subsystem, id: []const u8, index: usize, label: []const u8, selected: bool, action: SignalAction) void {
    const hovered = clay.pointerOverIndexed(id, index);
    clay.openIndexed(id, index, clay.menuOption(selected, hovered));
    subsystem.bindSignal(action);
    clay.dynamicText(label, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn identityTransportSelector(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize, selected: []const u8) void {
    const selected_name = if (selected.len == 0) "No transport script" else std.mem.cutSuffix(u8, selected, ".lua") orelse selected;
    const hovered = clay.pointerOverIndexed("identity-transport-selector", identity_index);
    clay.openIndexed("identity-transport-selector", identity_index, .{
        .layout = .{
            .sizing = .{ .width = clay.fixed(172), .height = clay.fixed(38) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 6,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.transport_script_menu_identity == identity_index) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 6, .topRight = 6, .bottomLeft = 6, .bottomRight = 6 },
        .border = if (view.transport_script_menu_identity == identity_index) .{ .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } } else .{},
    });
    subsystem.bindSignal(.{ .toggle_identity_transport_menu = identity_index });
    clay.dynamicText(selected_name, 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    clay.openIndexed("identity-transport-chevron-spacer", identity_index, .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    glyph(caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.transport_script_menu_identity == identity_index) identityTransportMenu(subsystem, view, identity_index, selected);
    c.Clay__CloseElement();
}

fn identityTransportMenu(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize, selected: []const u8) void {
    clay.openIndexed("identity-transport-menu", identity_index, clay.menu(240, @floatFromInt((view.transport_scripts.items.len + 1) * 32 + 8), .left, 2));
    const no_script_index = identity_index * 1024;
    menuOption(subsystem, "identity-transport-option", no_script_index, "No transport script", selected.len == 0, .{
        .select_identity_transport_script = .{ .identity = identity_index, .script = null },
    });
    // Clay retains text pointers until frame submission, so borrow catalog records.
    for (view.transport_scripts.items, 0..) |*script, index| {
        menuOption(subsystem, "identity-transport-option", no_script_index + index + 1, std.mem.cutSuffix(u8, script.value(), ".lua").?, std.mem.eql(u8, selected, script.value()), .{
            .select_identity_transport_script = .{ .identity = identity_index, .script = index },
        });
    }
    c.Clay__CloseElement();
}

fn actionButton(subsystem: *Subsystem, id: []const u8, action: SignalAction) void {
    const primary = action == .save_identity or action == .save_script;
    const element_index = actionIndex(action);
    clay.openIndexed(id, element_index, .{
        .layout = .{
            .sizing = .{ .width = clay.fixed(38), .height = clay.fixed(38) },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_CENTER, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary)
            if (clay.pointerOverIndexed(id, element_index)) .{ .r = 122, .g = 54, .b = 190, .a = 255 } else .{ .r = 101, .g = 36, .b = 165, .a = 255 }
        else if (clay.pointerOverIndexed(id, element_index)) .{ .r = 30, .g = 33, .b = 44, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
    });
    subsystem.bindSignal(action);
    const color: c.Clay_Color = if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 171, .g = 180, .b = 202, .a = 255 };
    glyph(actionGlyph(action), 19, color);
    c.Clay__CloseElement();
}

fn actionIndex(action: SignalAction) usize {
    return switch (action) {
        .edit_identity, .delete_identity, .start_identity, .stop_identity, .edit_script => |index| index,
        else => 0,
    };
}

fn actionGlyph(action: SignalAction) []const u8 {
    return switch (action) {
        .save_identity, .save_script => "\u{e248}",
        .clear_identity => "\u{e21e}",
        .edit_identity, .edit_script => "\u{e3b4}",
        .delete_identity, .delete_script => "\u{e4a6}",
        .start_identity, .run_global_script => "\u{e3d0}",
        .stop_identity, .stop_global_script => "\u{e46c}",
        .new_script => "\u{e3d4}",
        .refresh_logs => "\u{e2c4}",
        else => unreachable,
    };
}

fn identityRow(subsystem: *Subsystem, view: *IdentitiesView, index: usize, identity: *const identity_types.Identity) void {
    const active = subsystem.services.identity_manager.isRunning(identity.label.value());

    clay.open(identity.id.value(), .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(66) },
            .padding = .{ .left = 2, .right = 0, .top = 8, .bottom = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .border = .{ .color = .{ .r = 34, .g = 38, .b = 51, .a = 255 }, .width = .{ .bottom = 1 } },
    });
    clay.openIndexed("identity-summary", index, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .childGap = 3,
        },
    });
    clay.dynamicText(identity.label.value(), 17, .{ .r = 232, .g = 236, .b = 246, .a = 255 });
    clay.openIndexed("identity-address", index, .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.fixed(18) }, .childGap = 5 } });
    clay.dynamicText(identity.ip.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    clay.text("/", 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    clay.dynamicText(identity.prefix.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    clay.dynamicText(identity.interface.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    clay.openIndexed("identity-actions", index, .{ .layout = .{ .sizing = .{ .width = clay.fixed(402), .height = clay.fixed(38) }, .childGap = 8 } });
    identityTransportSelector(subsystem, view, index, identity.transport.value());
    if (active) {
        actionButton(subsystem, "identity-stop", .{ .stop_identity = index });
    } else {
        actionButton(subsystem, "identity-start", .{ .start_identity = index });
    }
    actionButton(subsystem, "identity-edit", .{ .edit_identity = index });
    actionButton(subsystem, "identity-delete", .{ .delete_identity = index });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn layoutScriptingView(view: *ScriptingView, subsystem: *Subsystem) void {
    clay.open("script-workspace", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .childGap = 8,
        },
    });
    clay.open("script-controls", .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(38) },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    scriptKindSelector(subsystem, view);
    scriptNameInput(subsystem, "script-name", view);
    actionButton(subsystem, "save-script", .save_script);
    if (view.kind == .global) {
        actionButton(subsystem, "run-global-script", .run_global_script);
        actionButton(subsystem, "stop-global-script", .stop_global_script);
    }
    if (view.editing_file_name != null) actionButton(subsystem, "delete-script", .delete_script);
    scriptLibrarySelector(subsystem, view);
    c.Clay__CloseElement();
    view.editor.render(.{
        .fonts = &subsystem.fonts,
        .focused = view.focus == .source,
        .binding_context = subsystem,
        .bind_action = bindEditorAction,
    });
    c.Clay__CloseElement();
}

fn layoutLogsView(view: *LogsView, subsystem: *Subsystem) void {
    clay.text("Logs", 30, .{ .r = 238, .g = 241, .b = 250, .a = 255 });
    clay.open("logs-workspace", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .childGap = 8,
        },
    });
    clay.open("logs-controls", .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(38) },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    logCountSelector(subsystem, view);
    logFontSelector(subsystem, view);
    actionButton(subsystem, "refresh-logs", .refresh_logs);
    clay.open("logs-session-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    clay.dynamicText(subsystem.services.logger.sessionFileName(), 14, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    c.Clay__CloseElement();
    clay.openScrollable("logs-output", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .padding = .{ .left = 14, .right = 14, .top = 12, .bottom = 12 },
            .childGap = 3,
        },
        .backgroundColor = .{ .r = 24, .g = 27, .b = 38, .a = 255 },
        .border = .{ .color = .{ .r = 47, .g = 52, .b = 68, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } },
        .clip = .{ .horizontal = true, .vertical = true },
    });
    if (view.contents.items.len == 0) {
        clay.text("No session log records are available.", 15, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
    } else {
        var remaining = view.contents.items;
        var index: usize = 0;
        while (remaining.len > 0) : (index += 1) {
            const end = std.mem.indexOfScalar(u8, remaining, '\n') orelse remaining.len;
            if (end > 0) clay.openIndexed("log-line", index, .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.fixed(@floatFromInt(view.font_size + 8)) } } });
            if (end > 0) clay.dynamicText(remaining[0..end], view.font_size, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
            if (end > 0) c.Clay__CloseElement();
            if (end == remaining.len) break;
            remaining = remaining[end + 1 ..];
        }
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn logCountSelector(subsystem: *Subsystem, view: *LogsView) void {
    openScriptSelector(subsystem, "log-count", "log-count-chevron-spacer", 130, logCountLabel(view.line_count), view.menu_open, .toggle_log_count_menu);
    if (view.menu_open) {
        clay.open("log-count-menu", clay.menu(150, @floatFromInt(log_line_counts.len * 28 + 8), .left, 2));
        for (log_line_counts, 0..) |count, index| {
            menuOption(subsystem, "log-count-option", index, logCountLabel(count), count == view.line_count, .{ .select_log_count = count });
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn logCountLabel(count: usize) []const u8 {
    return switch (count) {
        50 => "Latest 50",
        100 => "Latest 100",
        250 => "Latest 250",
        500 => "Latest 500",
        1_000 => "Latest 1,000",
        5_000 => "Latest 5,000",
        else => unreachable,
    };
}

fn logFontSelector(subsystem: *Subsystem, view: *LogsView) void {
    openScriptSelector(subsystem, "log-font-size", "log-font-size-chevron-spacer", 104, logFontSizeLabel(view.font_size), view.font_menu_open, .toggle_log_font_menu);
    if (view.font_menu_open) {
        clay.open("log-font-size-menu", clay.menu(120, @floatFromInt(log_font_sizes.len * 28 + 8), .left, 2));
        for (log_font_sizes, 0..) |size, index| {
            menuOption(subsystem, "log-font-size-option", index, logFontSizeLabel(size), size == view.font_size, .{ .select_log_font_size = size });
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn logFontSizeLabel(size: u16) []const u8 {
    return switch (size) {
        12 => "Text 12 px",
        14 => "Text 14 px",
        16 => "Text 16 px",
        18 => "Text 18 px",
        20 => "Text 20 px",
        else => unreachable,
    };
}

fn scriptNameInput(subsystem: *Subsystem, id: []const u8, view: *ScriptingView) void {
    const hovered = clay.pointerOver(id);
    clay.open(id, .{
        .layout = .{
            .sizing = .{ .width = clay.grow(100), .height = clay.fixed(34) },
            .padding = .{ .left = 12, .right = 12 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (view.focus == .name or hovered) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (view.focus == .name) .{ .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } } else .{},
        .clip = .{ .horizontal = true },
    });
    subsystem.bindSignal(.focus_script_name);
    view.name.render(&subsystem.fonts, id, 7, view.focus == .name, "Script name (.lua)", 15, 12, 12, 34);
    c.Clay__CloseElement();
}

fn openScriptSelector(subsystem: *Subsystem, id: []const u8, spacer_id: []const u8, width: f32, label: []const u8, open: bool, action: SignalAction) void {
    const hovered = clay.pointerOver(id);
    clay.open(id, .{
        .layout = .{
            .sizing = .{ .width = clay.fixed(width), .height = clay.fixed(26) },
            .padding = .{ .left = 10, .right = 8 },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or open) .{ .r = 35, .g = 39, .b = 53, .a = 255 } else .{ .r = 29, .g = 32, .b = 44, .a = 255 },
        .cornerRadius = .{ .topLeft = 5, .topRight = 5, .bottomLeft = 5, .bottomRight = 5 },
    });
    subsystem.bindSignal(action);
    clay.dynamicText(label, 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    clay.open(spacer_id, .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    glyph(caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
}

fn scriptKindSelector(subsystem: *Subsystem, view: *ScriptingView) void {
    openScriptSelector(subsystem, "script-kind", "script-kind-chevron-spacer", 110, switch (view.kind) {
        .global => "Global",
        .transport => "Transport",
        .helpers => "Helpers",
    }, view.menu == .kind, .toggle_script_kind_menu);
    if (view.menu == .kind) {
        clay.open("script-kind-menu", clay.menu(180, 104, .left, 2));
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.global), "Global", view.kind == .global, .{ .select_script_kind = .global });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.transport), "Transport", view.kind == .transport, .{ .select_script_kind = .transport });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.helpers), "Helpers", view.kind == .helpers, .{ .select_script_kind = .helpers });
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptLibrarySelector(subsystem: *Subsystem, view: *ScriptingView) void {
    openScriptSelector(subsystem, "script-library", "script-library-chevron-spacer", 160, if (view.editing_file_name != null) view.name.value() else "New Script", view.menu == .library, .toggle_script_library);
    if (view.menu == .library) {
        clay.open("script-library-menu", clay.menu(240, @floatFromInt((view.scripts.items.len + 1) * 32 + 8), .right, 2));
        scriptLibraryItem(subsystem, "new-script-library-item", "New Script", .new_script, true);
        for (view.scripts.items, 0..) |*script, index| {
            scriptLibraryItem(subsystem, "script-library-item", std.mem.cutSuffix(u8, script.value(), ".lua").?, .{ .edit_script = index }, false);
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptLibraryItem(subsystem: *Subsystem, id: []const u8, label: []const u8, action: SignalAction, primary: bool) void {
    const element_index = actionIndex(action);
    const hovered = clay.pointerOverIndexed(id, element_index);
    clay.openIndexed(id, element_index, .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(32) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    subsystem.bindSignal(action);
    if (action == .new_script) glyph(plus, 17, .{ .r = 248, .g = 244, .b = 255, .a = 255 });
    clay.dynamicText(label, 14, if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn layoutIdentities(view: *IdentitiesView, subsystem: *Subsystem) void {
    const identities = subsystem.services.identity_manager.snapshot();
    clay.text("Identities", 30, .{ .r = 238, .g = 241, .b = 250, .a = 255 });
    clay.open("identity-form", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(240) },
            .padding = .{ .left = 64, .right = 0, .top = 0, .bottom = 0 },
            .childGap = 14,
        },
    });
    clay.text(if (view.editing_identity_id == null) "New identity" else "Edit identity", 19, .{ .r = 231, .g = 234, .b = 243, .a = 255 });
    clay.open("identity-primary-fields", .{
        .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.fixed(66) }, .childGap = 12 },
    });
    for (form_fields[0..4], 0..) |spec, index| formField(subsystem, view, index, spec);
    c.Clay__CloseElement();
    clay.open("identity-secondary-fields", .{
        .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.fixed(66) }, .childGap = 12 },
    });
    for (form_fields[4..], 4..) |spec, index| formField(subsystem, view, index, spec);
    clay.open("secondary-fields-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(140), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    clay.open("identity-actions", .{
        .layout = .{
            .sizing = .{ .width = clay.grow(0), .height = clay.fixed(42) },
            .padding = .{ .top = 4, .bottom = 0 },
            .childGap = 10,
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    clay.open("identity-actions-spacer", .{ .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } } });
    c.Clay__CloseElement();
    actionButton(subsystem, "save-identity", .save_identity);
    actionButton(subsystem, "clear-identity", .clear_identity);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    clay.open("all-identities", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) },
            .padding = .{ .left = 64, .right = 0, .top = 8, .bottom = 0 },
            .childGap = 7,
        },
    });
    clay.text("All identities", 19, .{ .r = 231, .g = 234, .b = 243, .a = 255 });
    if (identities.len == 0) {
        clay.text("No identities saved yet.", 15, .{ .r = 128, .g = 137, .b = 159, .a = 255 });
    } else {
        for (identities, 0..) |*identity, index| identityRow(subsystem, view, index, identity);
    }
    c.Clay__CloseElement();
}

fn buildLayout(subsystem: *Subsystem) c.Clay_RenderCommandArray {
    subsystem.signal_len = 0;
    c.Clay_BeginLayout();
    clay.open("app", .{
        .layout = .{ .sizing = .{ .width = clay.grow(0), .height = clay.grow(0) } },
        .backgroundColor = .{ .r = 18, .g = 24, .b = 38, .a = 255 },
    });
    side_panel_view.render(subsystem.page, subsystem.services.storage.config_dir, subsystem);
    clay.open("main-content", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.grow(main_min_width), .height = clay.grow(0) },
            .padding = .{ .left = 42, .right = 42, .top = 36, .bottom = 36 },
            .childGap = 24,
        },
    });
    switch (subsystem.page) {
        .identities => layoutIdentities(&subsystem.identities, subsystem),
        .script_editor => layoutScriptingView(&subsystem.scripting, subsystem),
        .logs => layoutLogsView(&subsystem.logs, subsystem),
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    return c.Clay_EndLayout(@floatCast(c.sapp_frame_duration()));
}

fn updateMouseCursor(subsystem: *const Subsystem) void {
    const desired: c.sapp_mouse_cursor = switch (subsystem.page) {
        .identities => blk: {
            for (form_fields, 0..) |field, index| {
                if (!clay.pointerOver(field.input_id)) continue;
                break :blk if (index == interface_field) c.SAPP_MOUSECURSOR_POINTING_HAND else c.SAPP_MOUSECURSOR_IBEAM;
            }
            break :blk c.SAPP_MOUSECURSOR_DEFAULT;
        },
        .script_editor => if (clay.pointerOver("script-name") or clay.pointerOver(script_editor.text_area_id))
            c.SAPP_MOUSECURSOR_IBEAM
        else
            c.SAPP_MOUSECURSOR_DEFAULT,
        .logs => c.SAPP_MOUSECURSOR_DEFAULT,
    };
    if (desired != c.sapp_get_mouse_cursor()) c.sapp_set_mouse_cursor(desired);
}

fn endPointerSelections(subsystem: *Subsystem) void {
    for (&subsystem.identities.inputs) |*input| input.endPointerSelection();
    subsystem.scripting.name.endPointerSelection();
    subsystem.scripting.editor.text.endPointerSelection();
}

fn handleKeyboardEvent(subsystem: *Subsystem, event_data: c.sapp_event) void {
    switch (subsystem.page) {
        .identities => {
            const view = &subsystem.identities;
            const field = view.focused_field orelse return;
            if (field == interface_field) {
                if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
                switch (event_data.key_code) {
                    c.SAPP_KEYCODE_TAB, c.SAPP_KEYCODE_ENTER => view.focused_field = interface_field + 1,
                    c.SAPP_KEYCODE_ESCAPE => view.focused_field = null,
                    else => {},
                }
                return;
            }
            const result = view.inputs[field].handleEvent(event_data) catch |err| {
                subsystem.services.logger.err(.ui, if (err == error.MultilineText) "Text fields cannot contain line breaks." else "Text capacity reached.");
                return;
            };
            switch (result) {
                .advance => view.focused_field = (field + 1) % view.inputs.len,
                .blur => view.focused_field = null,
                .ignored, .handled => {},
            }
        },
        .script_editor => {
            const view = &subsystem.scripting;
            if (view.focus == .name) {
                const result = view.name.handleEvent(event_data) catch |err| {
                    subsystem.services.logger.err(.ui, if (err == error.MultilineText) "Script names cannot contain line breaks." else "Text capacity reached.");
                    return;
                };
                switch (result) {
                    .advance => view.focus = .source,
                    .blur => view.focus = .none,
                    .ignored, .handled => {},
                }
                return;
            }
            if (view.focus != .source) return;
            const result = view.editor.handleEvent(&subsystem.fonts, event_data) catch {
                subsystem.services.logger.err(.ui, "Text capacity reached.");
                return;
            };
            if (result == .blur) view.focus = .none;
        },
        .logs => {},
    }
}

fn handleSignalAction(subsystem: *Subsystem, action: SignalAction, pointer_x: f32, pointer_state: c_int) void {
    const pressed = pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME;
    if (pressed) {
        if (subsystem.pointer_click_handled) return;
        subsystem.pointer_click_handled = true;
    }
    const accepted = switch (action) {
        .focus_input, .focus_script_name => pressed or pointer_state == c.CLAY_POINTER_DATA_PRESSED,
        .script_editor => |editor_action| switch (editor_action) {
            .focus => pressed or pointer_state == c.CLAY_POINTER_DATA_PRESSED,
            else => pressed,
        },
        else => pressed,
    };
    if (!accepted) return;

    switch (action) {
        .select_page => |page| {
            if (subsystem.page == page) return;
            if (subsystem.page == .logs) subsystem.logs.clearContents(subsystem.services.storage.allocator);
            subsystem.page = page;
            switch (page) {
                .identities => reloadTransportScripts(subsystem, &subsystem.identities),
                .script_editor => reloadScripts(subsystem, &subsystem.scripting),
                .logs => reloadLogs(subsystem, &subsystem.logs),
            }
        },
        else => switch (subsystem.page) {
            .identities => handleIdentitySignal(subsystem, &subsystem.identities, action, pointer_x, pointer_state, pressed),
            .script_editor => handleScriptSignal(subsystem, &subsystem.scripting, action, pointer_x, pointer_state, pressed),
            .logs => handleLogsSignal(subsystem, &subsystem.logs, action),
        },
    }
}

fn handleIdentitySignal(subsystem: *Subsystem, view: *IdentitiesView, action: SignalAction, pointer_x: f32, pointer_state: c_int, pressed: bool) void {
    const manager = subsystem.services.identity_manager;
    switch (action) {
        .focus_input => |field_index| {
            if (pressed) {
                view.focused_field = field_index;
                view.interface_menu_open = false;
            }
            if (view.focused_field == field_index) view.inputs[field_index].handlePointer(&subsystem.fonts, form_fields[field_index].input_id, pointer_x, pointer_state, 16, 14);
        },
        .toggle_interface_menu => {
            view.focused_field = null;
            view.interface_menu_open = !view.interface_menu_open;
        },
        .select_interface => |interface_index| {
            view.inputs[interface_field].set(subsystem.services.interfaces[interface_index].value()) catch {
                subsystem.services.logger.err(.ui, "Interface name exceeds the input capacity.");
                return;
            };
            view.interface_menu_open = false;
        },
        .toggle_identity_transport_menu => |identity_index| {
            view.focused_field = null;
            view.interface_menu_open = false;
            view.transport_script_menu_identity = if (view.transport_script_menu_identity == identity_index) null else identity_index;
        },
        .select_identity_transport_script => |selection| {
            view.transport_script_menu_identity = null;
            const identity = subsystem.services.identity_manager.snapshot()[selection.identity];
            var script: ?command.Transport = null;
            if (selection.script) |index| {
                var source: text_types.FixedText(limits.source_capacity) = .{};
                const name = view.transport_scripts.items[index];
                subsystem.services.storage.scripts(.transport).read(name.value(), &source) catch {
                    subsystem.services.logger.err(.ui, "Could not load the selected transport script.");
                    return;
                };
                script = .{ .name = name, .source = source };
            }
            subsystem.services.identity_manager.execute(.{ .set_transport = .{ .name = identity.label, .script = script } }) catch |err| subsystem.services.logger.err(.ui, switch (err) {
                error.StorageFailure => "Could not save the transport selection.",
                else => "Could not update the active identity transport script.",
            });
        },
        .save_identity => {
            const value = currentIdentity(view);
            if (value.label.value().len == 0) {
                subsystem.services.logger.err(.ui, "A name is required to save an identity.");
                return;
            }
            manager.execute(.{ .save = value }) catch |err| {
                subsystem.services.logger.err(.ui, switch (err) {
                    error.IdentityNameInUse => "Identity names must be unique.",
                    error.IdentityInUse => "Stop the identity before editing it.",
                    else => "Could not save identity to disk.",
                });
                return;
            };
            clearForm(view);
        },
        .clear_identity => clearForm(view),
        .edit_identity => |identity_index| {
            const identity = manager.snapshot()[identity_index];
            view.editing_identity_id = identity.id;
            inline for (std.meta.fields(identity_types.Identity)[1..8], 0..) |field, index| view.inputs[index].load(@field(identity, field.name));
            view.focused_field = 0;
        },
        .delete_identity => |identity_index| {
            const identity = manager.snapshot()[identity_index];
            manager.execute(.{ .delete = identity.label }) catch |err| {
                subsystem.services.logger.err(.ui, if (err == error.IdentityInUse) "Stop the identity before deleting it." else "Could not delete identity from disk.");
                return;
            };
            if (view.editing_identity_id) |editing_id| if (std.mem.eql(u8, editing_id.value(), identity.id.value())) clearForm(view);
        },
        .start_identity => |identity_index| {
            const identity = manager.snapshot()[identity_index];
            manager.execute(.{ .start = identity.label }) catch |err| {
                subsystem.services.logger.err(.ui, switch (err) {
                    error.InterfaceRequired => "Select a packet interface before starting the identity.",
                    error.InvalidIpAddress => "Identity IP address is invalid.",
                    error.InvalidPrefixLength => "Identity prefix must be between 0 and 32.",
                    error.InvalidGatewayAddress => "Identity gateway address is invalid.",
                    error.InvalidMacAddress => "Identity MAC must use the form 02:00:00:00:00:01.",
                    error.InvalidMtu => "Identity MTU must be between 68 and 1500.",
                    error.TransportScriptUnavailable => "The selected transport script is unavailable.",
                    else => "Identity could not start.",
                });
                return;
            };
        },
        .stop_identity => |identity_index| {
            manager.execute(.{ .stop = manager.snapshot()[identity_index].label }) catch {
                subsystem.services.logger.err(.ui, "Identity is not running.");
                return;
            };
        },
        else => unreachable,
    }
}

fn handleLogsSignal(subsystem: *Subsystem, view: *LogsView, action: SignalAction) void {
    switch (action) {
        .refresh_logs => reloadLogs(subsystem, view),
        .toggle_log_count_menu => {
            view.menu_open = !view.menu_open;
            view.font_menu_open = false;
        },
        .select_log_count => |count| {
            view.line_count = count;
            view.menu_open = false;
            reloadLogs(subsystem, view);
        },
        .toggle_log_font_menu => {
            view.font_menu_open = !view.font_menu_open;
            view.menu_open = false;
        },
        .select_log_font_size => |size| {
            view.font_size = size;
            view.font_menu_open = false;
        },
        else => unreachable,
    }
}

fn handleScriptSignal(subsystem: *Subsystem, view: *ScriptingView, action: SignalAction, pointer_x: f32, pointer_state: c_int, pressed: bool) void {
    const storage = subsystem.services.storage;
    switch (action) {
        .focus_script_name => {
            if (pressed) {
                view.focus = .name;
                view.menu = .none;
                view.editor.font_size_menu_open = false;
            }
            if (view.focus == .name) view.name.handlePointer(&subsystem.fonts, "script-name", pointer_x, pointer_state, 15, 12);
        },
        .toggle_script_kind_menu => {
            view.menu = if (view.menu == .kind) .none else .kind;
            if (view.focus == .name) view.focus = .none;
            view.editor.font_size_menu_open = false;
        },
        .select_script_kind => |script_kind| selectScriptKind(subsystem, view, script_kind),
        .toggle_script_library => {
            view.menu = if (view.menu == .library) .none else .library;
            view.editor.font_size_menu_open = false;
        },
        .script_editor => |editor_action| switch (editor_action) {
            .focus => {
                if (pressed) {
                    view.focus = .source;
                    view.menu = .none;
                    view.editor.font_size_menu_open = false;
                }
                if (view.focus == .source) view.editor.handlePointer(&subsystem.fonts, pointer_state);
            },
            .toggle_font_size_menu => {
                if (view.menu == .kind) view.menu = .none;
                view.editor.handleAction(editor_action);
            },
            .select_font_size => view.editor.handleAction(editor_action),
        },
        .save_script => {
            const store = storage.scripts(view.kind);
            const previous_file_name = if (view.editing_file_name) |*value| value.value() else null;
            const new_file_name = store.save(view.name.value(), view.editor.text.value(), previous_file_name) catch |err| switch (err) {
                error.NameRequired => {
                    subsystem.services.logger.err(.ui, "A script name is required.");
                    return;
                },
                error.InvalidName => {
                    subsystem.services.logger.err(.ui, "Names cannot contain path separators.");
                    return;
                },
                else => {
                    subsystem.services.logger.err(.ui, "Could not save script to disk.");
                    return;
                },
            };
            view.editing_file_name = new_file_name;
            if (view.focus == .name) view.focus = .none;
            view.menu = .none;
            reloadScripts(subsystem, view);
        },
        .new_script => {
            clearScriptForm(view);
            view.focus = .name;
        },
        .edit_script => |script_index| editScript(subsystem, view, script_index),
        .delete_script => {
            const file_name = view.editing_file_name.?.value();
            storage.scripts(view.kind).delete(file_name) catch {
                subsystem.services.logger.err(.ui, "Could not delete script from disk.");
                return;
            };
            if (view.editing_file_name) |editing_file_name| if (std.mem.eql(u8, editing_file_name.value(), file_name)) clearScriptForm(view);
            view.menu = .none;
            reloadScripts(subsystem, view);
        },
        .run_global_script => {
            if (!subsystem.services.global_runner.run(view.editor.text.buffer)) {
                subsystem.services.logger.err(.ui, "Could not start the global program.");
                return;
            }
        },
        .stop_global_script => subsystem.services.global_runner.stop(),
        else => unreachable,
    }
}
