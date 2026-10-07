const std = @import("std");
const builtin = @import("builtin");
const script_store = @import("../storage/script_repository.zig");
const storage_module = @import("../storage/storage.zig");
const text_types = @import("../text.zig");
const identity_types = @import("../identities/identity.zig");
const runtime = @import("../runtime/runtime.zig");
const limits = @import("../limits.zig");
const log = @import("../log.zig");
const clay = @import("clay.zig");
const theme = @import("theme.zig");
const frame_cache = @import("frame_cache.zig");
const script_editor = @import("script_editor.zig");
const text_editor = @import("text_editor.zig");
const side_panel_view = @import("side_panel.zig");

const c = @import("c");

const main_min_width: f32 = 640;
const phosphor = @embedFile("phosphor");
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
const bpf_field = form_fields.len;
const identity_list_id = "identity-list";

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

const plus = "\u{e3d4}";

const TextField = text_editor.Editor(text_types.FieldText, .single_line);
/// The text input that receives keyboard events.
const Focus = union(enum) { none, field: usize, script_name, script_source, logs };
/// The one dropdown that is open; pressing any other control closes it.
const Menu = enum { none, interface, transport, kind, library, font_size };

const ScriptingView = struct {
    editor: script_editor.State = undefined,
    name: TextField = .{},
    kind: script_store.Kind = .global,
    scripts: std.ArrayList(text_types.FieldText) = .empty,
    editing_file_name: ?text_types.FieldText = null,

    fn init(self: *ScriptingView) void {
        self.editor.init(false, 20);
        self.name.init(false);
        self.kind = .global;
        self.scripts = .empty;
        self.editing_file_name = null;
    }
};

const log_reload_interval_ns: i96 = std.time.ns_per_ms * 250;

const LogsView = struct {
    editor: script_editor.State = undefined,
    scroll_to_end: bool = false,
    next_reload_ns: i96 = 0,

    fn init(self: *LogsView) void {
        self.editor.init(true, 14);
        self.scroll_to_end = false;
        self.next_reload_ns = 0;
    }

    fn clearContents(self: *LogsView) void {
        self.editor.reset();
        self.next_reload_ns = 0;
    }
};

const IdentitiesView = struct {
    records: std.ArrayList(runtime.IdentityView) = .empty,
    inputs: [form_fields.len]TextField = [_]TextField{.{}} ** form_fields.len,
    bpf_input: TextField = .{},
    bpf_identity_id: ?text_types.FieldText = null,
    transport_scripts: std.ArrayList(text_types.FieldText) = .empty,
    /// The identity whose transport menu is open, while `Subsystem.menu` is `.transport`.
    transport_menu_identity: text_types.FieldText = .{},
    editing_identity_id: ?text_types.FieldText = null,

    fn init(self: *IdentitiesView) void {
        self.records = .empty;
        for (&self.inputs) |*input| input.init(false);
        self.bpf_input.init(false);
        self.bpf_identity_id = null;
        self.transport_scripts = .empty;
        self.editing_identity_id = null;
    }
};

const Action = union(enum) {
    focus_input: usize,
    toggle_menu: Menu,
    select_interface: usize,
    focus_bpf: text_types.FieldText,
    toggle_identity_transport_menu: usize,
    select_identity_transport_script: struct { identity: usize, script: ?usize },
    focus_script_name,
    select_script_kind: script_store.Kind,
    script_editor: script_editor.Action,
    save_identity,
    apply_bpf: text_types.FieldText,
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
    select_page: Page,
};

pub const Services = struct {
    storage: *storage_module.Storage,
    manager: *runtime.Manager,
    interfaces: []const text_types.FieldText,
};

pub const Subsystem = struct {
    services: Services = undefined,
    page: Page = .identities,
    menu: Menu = .none,
    focus: Focus = .none,
    identities: IdentitiesView = undefined,
    scripting: ScriptingView = undefined,
    logs: LogsView = undefined,
    bindings: [limits.ui_signal_capacity]struct { id: u32, action: Action } = undefined,
    binding_len: usize = 0,
    acknowledged_action: ?Action = null,
    acknowledged_action_until_ns: i96 = 0,
    cache: frame_cache.FrameCache = .{},
    fonts: clay.Fonts = undefined,

    pub fn init(self: *Subsystem, services: Services, clay_memory: []u8) !void {
        self.services = services;
        self.page = .identities;
        self.menu = .none;
        self.focus = .none;
        self.identities.init();
        self.scripting.init();
        self.logs.init();
        self.binding_len = 0;
        self.acknowledged_action = null;
        self.acknowledged_action_until_ns = 0;
        self.cache = .{};
        c.sclay_setup();
        reloadScripts(self, .transport, &self.identities.transport_scripts);
        _ = c.Clay_Initialize(
            c.Clay_CreateArenaWithCapacityAndMemory(clay_memory.len, clay_memory.ptr),
            .{ .width = @floatFromInt(c.sapp_width()), .height = @floatFromInt(c.sapp_height()) },
            .{},
        );
        self.fonts[0] = try loadSystemTextFont(services.storage.allocator);
        self.fonts[1] = c.sclay_add_font_mem(@ptrCast(@constCast(phosphor.ptr)), @intCast(phosphor.len));
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

    /// Keep rendering until the button feedback expires.
    pub fn frame(self: *Subsystem) bool {
        c.sclay_new_frame();
        self.dispatchPointer();
        self.services.manager.snapshot(&self.identities.records) catch log.logger.err(.ui, "Could not refresh identities.");
        refreshLogsDue(self);
        if (self.focus == .script_source) self.scripting.editor.keepCursorVisible();
        const render_commands = buildLayout(self);
        if (self.page == .logs and self.logs.scroll_to_end) {
            const scroll = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clay.string("logs-output", true)));
            if (scroll.scrollPosition) |position| position.*.y = @min(0, scroll.scrollContainerDimensions.height - scroll.contentDimensions.height);
            self.logs.scroll_to_end = false;
        }
        updateMouseCursor(self);
        self.cache.present(render_commands, self.fonts[0..].ptr);
        c.sg_commit();
        return self.acknowledged_action_until_ns > nowAwakeNs();
    }

    pub fn event(self: *Subsystem, event_data: [*c]const c.sapp_event) void {
        if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_UP) endPointerSelections(self);
        c.sclay_handle_event(event_data);
        handleKeyboardEvent(self, event_data.*);
    }

    pub fn deinit(self: *Subsystem) void {
        const allocator = self.services.storage.allocator;
        self.identities.transport_scripts.deinit(allocator);
        self.identities.records.deinit(allocator);
        self.scripting.scripts.deinit(allocator);
        c.sclay_shutdown();
    }

    pub fn bindAction(self: *Subsystem, action: Action) void {
        if (self.binding_len == self.bindings.len) return;
        self.bindings[self.binding_len] = .{ .id = c.Clay_GetOpenElementId(), .action = action };
        self.binding_len += 1;
    }

    fn dispatchPointer(self: *Subsystem) void {
        const pointer = c.Clay_GetPointerState();
        const pressed = pointer.state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME;
        if (!pressed and pointer.state != c.CLAY_POINTER_DATA_PRESSED) return;
        const hovered = c.Clay_GetPointerOverIds();
        for (hovered.internalArray[0..@intCast(hovered.length)]) |element| {
            for (self.bindings[0..self.binding_len]) |binding| {
                if (binding.id != element.id) continue;
                if (!pressed) switch (binding.action) {
                    .focus_input, .focus_bpf, .focus_script_name => {},
                    .script_editor => |action| if (action != .focus) continue,
                    else => continue,
                };
                if (pressed) {
                    self.acknowledged_action = binding.action;
                    self.acknowledged_action_until_ns = nowAwakeNs() + std.time.ns_per_ms * 150;
                }
                handleAction(self, binding.action, pointer.position.x, pointer.state);
                return;
            }
        }
    }

    fn actionAcknowledged(self: *const Subsystem, action: Action) bool {
        return self.acknowledged_action_until_ns > nowAwakeNs() and
            std.meta.eql(self.acknowledged_action, @as(?Action, action));
    }
};

fn clearScriptForm(subsystem: *Subsystem) void {
    const view = &subsystem.scripting;
    view.name.reset();
    subsystem.focus = .none;
    view.editor.reset();
    view.editing_file_name = null;
}

fn reloadScripts(subsystem: *Subsystem, kind: script_store.Kind, scripts: *std.ArrayList(text_types.FieldText)) void {
    const storage = subsystem.services.storage;
    storage.scripts(kind).load(storage.allocator, scripts) catch log.logger.formatted(.err, .ui, "Could not load {s} scripts from disk.", .{@tagName(kind)});
}

fn reloadLogs(view: *LogsView) void {
    const bytes = log.logger.readTail(view.editor.text.buffer.bytes[0..limits.source_capacity]) catch failed: {
        log.logger.err(.ui, "Could not read the current session log.");
        break :failed "";
    };
    view.editor.text.set(bytes) catch unreachable;
    view.scroll_to_end = true;
    view.next_reload_ns = nowAwakeNs() + log_reload_interval_ns;
}

fn refreshLogsDue(subsystem: *Subsystem) void {
    if (subsystem.page != .logs) return;
    if (subsystem.logs.editor.text.dragging or subsystem.logs.editor.text.selection() != null) return;
    const scroll = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clay.string("logs-output", true)));
    if (scroll.found and scroll.scrollPosition != null and scroll.scrollPosition.*.y > @min(0, scroll.scrollContainerDimensions.height - scroll.contentDimensions.height) + 1) return;
    if (nowAwakeNs() < subsystem.logs.next_reload_ns) return;
    reloadLogs(&subsystem.logs);
}

fn nowAwakeNs() i96 {
    return std.Io.Clock.awake.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds;
}

fn editScript(subsystem: *Subsystem, view: *ScriptingView, index: usize) void {
    const file_name = view.scripts.items[index].value();
    var source: text_types.FixedText(limits.source_capacity) = undefined;
    subsystem.services.storage.scripts(view.kind).read(file_name, &source) catch |err| return switch (err) {
        error.CapacityExceeded => log.logger.formatted(.err, .ui, "Script \"{s}\" is too large to edit.", .{file_name}),
        else => log.logger.formatted(.err, .ui, "Could not load script \"{s}\" from disk.", .{file_name}),
    };
    view.editing_file_name = view.scripts.items[index];
    view.name.set(std.mem.cutSuffix(u8, file_name, ".lua").?) catch unreachable;
    subsystem.focus = .none;
    view.editor.load(source);
}

fn clearForm(subsystem: *Subsystem) void {
    const view = &subsystem.identities;
    for (&view.inputs) |*input| input.reset();
    subsystem.focus = .none;
    view.editing_identity_id = null;
}

fn currentIdentity(view: *const IdentitiesView) identity_types.Identity {
    var value: identity_types.Identity = .{};
    value.id = view.editing_identity_id orelse .{};
    inline for (std.meta.fields(identity_types.Identity)[1..8], 0..) |field, index| @field(value, field.name).set(view.inputs[index].value()) catch unreachable;
    return value;
}

fn globalScriptName(view: *const ScriptingView) text_types.FieldText {
    if (view.editing_file_name) |name| return name;
    var name: text_types.FieldText = .{};
    name.set(if (view.name.value().len == 0) "unsaved global script" else view.name.value()) catch unreachable;
    return name;
}

fn reportIdentityFailure(name: []const u8, comptime outcome: []const u8, err: anyerror) void {
    const Failure = struct { level: log.Level, reason: []const u8 };
    const failure: Failure = switch (err) {
        error.InterfaceRequired => .{ .level = .warning, .reason = "no packet interface is selected" },
        error.InvalidIpAddress => .{ .level = .warning, .reason = "the IP address is invalid" },
        error.InvalidPrefixLength => .{ .level = .warning, .reason = "the prefix is not between 0 and 32" },
        error.InvalidGatewayAddress => .{ .level = .warning, .reason = "the gateway address is invalid" },
        error.InvalidMacAddress => .{ .level = .warning, .reason = "the MAC address is invalid" },
        error.InvalidMtu => .{ .level = .warning, .reason = std.fmt.comptimePrint("the MTU is not between 68 and {d}", .{limits.frame_capacity - 14}) },
        error.IdentityNameInUse => .{ .level = .warning, .reason = "the name is already in use" },
        error.IdentityInUse => .{ .level = .warning, .reason = "the identity is running" },
        error.IdentityNotFound => .{ .level = .warning, .reason = "the identity no longer exists" },
        error.RuntimeUnavailable => .{ .level = .warning, .reason = "the identity is not running" },
        error.TransportScriptUnavailable => .{ .level = .err, .reason = "the selected transport script is unavailable" },
        error.StorageFailure => .{ .level = .err, .reason = "the configuration could not be stored on disk" },
        else => .{ .level = .err, .reason = "the packet-capture runtime failed" },
    };
    log.logger.formatted(failure.level, .ui, "Identity \"{s}\" " ++ outcome ++ ": {s}.", .{ name, failure.reason });
}

fn inputBox(min_width: f32, left_padding: u16, highlighted: bool, bordered: bool, clip: c.Clay_ClipElementConfig) c.Clay_ElementDeclaration {
    return .{
        .layout = .{
            .sizing = .{ .width = clay.size(.grow, min_width), .height = clay.size(.fixed, 38) },
            .padding = .{ .left = left_padding, .right = 12 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (highlighted) theme.field_active else theme.field,
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (bordered) .{
            .color = theme.accent,
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
        .clip = clip,
    };
}

fn formField(subsystem: *Subsystem, view: *IdentitiesView, index: usize, spec: FormFieldSpec) void {
    const is_interface = index == interface_field;
    const is_focused = std.meta.eql(subsystem.focus, .{ .field = index });
    const menu_open = subsystem.menu == .interface and is_interface;
    const field_width = (@as(f32, @floatFromInt(c.sapp_width())) - 360) / 4;
    const width = if (is_interface) field_width * 2 + 12 else field_width;
    clay.open(spec.label, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.fixed, width), .height = clay.size(.fixed, 66) },
            .childGap = 6,
        },
    });
    clay.text(spec.label, 14, theme.text);
    clay.open(spec.input_id, inputBox(0, 14, is_focused or menu_open or clay.pointerOver(spec.input_id), is_focused or menu_open, if (is_interface) .{} else .{ .horizontal = true }));
    if (is_interface) {
        const value = view.inputs[index].value();
        subsystem.bindAction(.{ .toggle_menu = .interface });
        if (value.len == 0) clay.text(spec.placeholder, 16, theme.text_muted) else clay.dynamicText(value, 16, theme.text);
        clay.spacer();
        clay.icon(clay.caret_down, 17, theme.text_secondary);
        if (menu_open) interfaceMenu(subsystem, value);
    } else {
        subsystem.bindAction(.{ .focus_input = index });
        view.inputs[index].render(&subsystem.fonts, spec.input_id, index, is_focused, spec.placeholder, 16, 14, 12, 38);
    }
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn identityBpfField(subsystem: *Subsystem, view: *IdentitiesView, index: usize, identity: *const identity_types.Identity, active: bool) bool {
    const selected = if (view.bpf_identity_id) |id| std.mem.eql(u8, id.value(), identity.id.value()) else false;
    const editing = active and selected;
    const focused = editing and std.meta.eql(subsystem.focus, .{ .field = bpf_field });
    const declaration = inputBox(0, 14, active, false, .{});
    if (editing) clay.open("identity-bpf-input", declaration) else clay.openIndexed("identity-bpf-select", index, declaration);
    if (active) subsystem.bindAction(.{ .focus_bpf = identity.id });
    if (editing)
        view.bpf_input.render(&subsystem.fonts, "identity-bpf-input", form_fields.len + index, focused, "Custom BPF filter", 16, 14, 12, 38)
    else
        clay.text("Custom BPF filter", 16, theme.text_muted);
    c.Clay__CloseElement();
    return editing;
}

fn interfaceMenu(subsystem: *Subsystem, selected: []const u8) void {
    const interfaces = subsystem.services.interfaces;
    const visible_count: usize = @min(interfaces.len, 8);
    const menu_height: usize = @max(visible_count, 1) * 28 + 8;
    var declaration = clay.menu(260, @floatFromInt(menu_height), .left, 10);
    declaration.layout.sizing.width = clay.size(.grow, 260);
    declaration.floating.attachPoints = .{
        .element = c.CLAY_ATTACH_POINT_CENTER_TOP,
        .parent = c.CLAY_ATTACH_POINT_CENTER_BOTTOM,
    };
    declaration.clip.vertical = true;
    clay.openScrollable("interface-menu", declaration);
    if (interfaces.len == 0) {
        clay.text("No packet capture interfaces discovered.", 14, theme.text);
    } else for (interfaces, 0..) |*device, index| {
        menuOption(subsystem, "interface-option", index, device.value(), std.mem.eql(u8, selected, device.value()), .{ .select_interface = index });
    }
    c.Clay__CloseElement();
}

fn menuOption(subsystem: *Subsystem, id: []const u8, index: usize, label: []const u8, selected: bool, action: Action) void {
    const hovered = clay.pointerOverIndexed(id, index);
    clay.openIndexed(id, index, clay.menuOption(selected, hovered));
    subsystem.bindAction(action);
    if (action == .new_script) clay.icon(plus, 17, theme.text_bright);
    clay.dynamicText(label, 14, theme.text_bright);
    c.Clay__CloseElement();
}

fn identityTransportSelector(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize, selected: []const u8) void {
    const open = subsystem.menu == .transport and std.mem.eql(u8, view.transport_menu_identity.value(), view.records.items[identity_index].value.id.value());
    const selected_name = if (selected.len == 0) "No transport script" else std.mem.cutSuffix(u8, selected, ".lua") orelse selected;
    clay.selector("identity-transport-selector", identity_index, 172, 38, selected_name, open, .{});
    subsystem.bindAction(.{ .toggle_identity_transport_menu = identity_index });
    if (open) identityTransportMenu(subsystem, view, identity_index, selected);
    c.Clay__CloseElement();
}

fn identityTransportMenu(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize, selected: []const u8) void {
    clay.openIndexed("identity-transport-menu", identity_index, clay.menu(240, @floatFromInt((view.transport_scripts.items.len + 1) * 28 + 8), .left, 2));
    const no_script_index = identity_index * 1024;
    menuOption(subsystem, "identity-transport-option", no_script_index, "No transport script", selected.len == 0, .{
        .select_identity_transport_script = .{ .identity = identity_index, .script = null },
    });
    // Clay retains text pointers until frame submission; these records belong to the UI.
    for (view.transport_scripts.items, 0..) |*script, index| {
        menuOption(subsystem, "identity-transport-option", no_script_index + index + 1, std.mem.cutSuffix(u8, script.value(), ".lua").?, std.mem.eql(u8, selected, script.value()), .{
            .select_identity_transport_script = .{ .identity = identity_index, .script = index },
        });
    }
    c.Clay__CloseElement();
}

fn actionButton(subsystem: *Subsystem, id: []const u8, glyph: []const u8, action: Action) void {
    const enabled = switch (action) {
        .delete_script => subsystem.scripting.editing_file_name != null,
        .run_global_script => !subsystem.services.manager.global.running(),
        .stop_global_script => subsystem.services.manager.global.running(),
        else => true,
    };
    const primary = action == .apply_bpf or action == .save_identity or action == .run_global_script or action == .stop_global_script;
    const element_index = actionIndex(action);
    const acknowledged = subsystem.actionAcknowledged(action);
    clay.openIndexed(id, element_index, .{
        .layout = .{
            .sizing = .{ .width = clay.size(.fixed, if (action == .apply_bpf) 76 else 38), .height = clay.size(.fixed, 38) },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_CENTER, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (!enabled)
            theme.field
        else if (acknowledged)
            theme.option_hover
        else if (primary)
            if (clay.pointerOverIndexed(id, element_index)) theme.accent else theme.primary
        else if (clay.pointerOverIndexed(id, element_index)) theme.field_active else .{},
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
    });
    if (enabled) subsystem.bindAction(action);
    const color: c.Clay_Color = if (!enabled or acknowledged) theme.text_muted else if (primary) theme.text_bright else theme.text_secondary;
    if (action == .apply_bpf) clay.text(glyph, 14, color) else clay.icon(glyph, 19, color);
    c.Clay__CloseElement();
}

fn actionIndex(action: Action) usize {
    return switch (action) {
        .edit_identity, .delete_identity, .start_identity, .stop_identity, .edit_script => |index| index,
        else => 0,
    };
}

fn identityRow(subsystem: *Subsystem, view: *IdentitiesView, index: usize, entry: *const runtime.IdentityView) void {
    const identity = &entry.value;
    const active = entry.active;

    clay.open(identity.id.value(), .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 108) },
            .padding = .{ .left = 2, .top = 8, .bottom = 8 },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .border = .{ .color = theme.border, .width = .{ .bottom = 1 } },
    });
    clay.openIndexed("identity-row-main", index, .{ .layout = .{ .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 38) }, .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER } } });
    clay.dynamicText(identity.label.value(), 17, theme.text_bright);
    clay.spacer();
    clay.openIndexed("identity-row-actions", index, .{ .layout = .{ .sizing = .{ .width = clay.size(.fixed, 130), .height = clay.size(.fixed, 38) }, .childGap = 8, .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT } } });
    if (active) {
        actionButton(subsystem, "identity-stop", "\u{e46c}", .{ .stop_identity = index });
    } else {
        actionButton(subsystem, "identity-start", "\u{e3d0}", .{ .start_identity = index });
    }
    actionButton(subsystem, "identity-edit", "\u{e3b4}", .{ .edit_identity = index });
    actionButton(subsystem, "identity-delete", "\u{e4a6}", .{ .delete_identity = index });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    clay.openIndexed("identity-runtime-controls", index, .{ .layout = .{ .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 38) }, .childGap = 26, .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER } } });
    identityTransportSelector(subsystem, view, index, identity.transport.value());
    if (identityBpfField(subsystem, view, index, identity, active)) actionButton(subsystem, "apply-bpf", "Apply", .{ .apply_bpf = identity.label });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

/// Opens a page workspace and its controls row; the caller closes both.
fn openWorkspace(workspace_id: []const u8, controls_id: []const u8) void {
    clay.open(workspace_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.grow, 0) },
            .childGap = 8,
        },
    });
    clay.open(controls_id, .{
        .layout = .{
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 38) },
            .childGap = 8,
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
}

fn layoutScriptingView(view: *ScriptingView, subsystem: *Subsystem) void {
    openWorkspace("script-workspace", "script-controls");
    scriptKindSelector(subsystem, view);
    scriptNameInput(subsystem, "script-name", view);
    clay.open("script-actions", .{
        .layout = .{
            .sizing = .{ .width = clay.size(.fixed, 176), .height = clay.size(.fixed, 38) },
            .childGap = 8,
        },
    });
    actionButton(subsystem, "save-script", "\u{e248}", .save_script);
    actionButton(subsystem, "delete-script", "\u{e4a6}", .delete_script);
    if (view.kind == .global) {
        actionButton(subsystem, "run-global-script", "\u{e3d0}", .run_global_script);
        actionButton(subsystem, "stop-global-script", "\u{e46c}", .stop_global_script);
    }
    c.Clay__CloseElement();
    scriptLibrarySelector(subsystem, view);
    c.Clay__CloseElement();
    script_editor.render(&view.editor, subsystem, subsystem.focus == .script_source);
    c.Clay__CloseElement();
}

fn layoutLogsView(view: *LogsView, subsystem: *Subsystem) void {
    openWorkspace("logs-workspace", "logs-controls");
    clay.spacer();
    clay.dynamicText(log.logger.sessionFileName(), 14, theme.text_secondary);
    c.Clay__CloseElement();
    script_editor.render(&view.editor, subsystem, subsystem.focus == .logs);
    c.Clay__CloseElement();
}

fn scriptNameInput(subsystem: *Subsystem, id: []const u8, view: *ScriptingView) void {
    const hovered = clay.pointerOver(id);
    clay.open(id, inputBox(100, 12, subsystem.focus == .script_name or hovered, subsystem.focus == .script_name, .{ .horizontal = true }));
    subsystem.bindAction(.focus_script_name);
    view.name.render(&subsystem.fonts, id, 7, subsystem.focus == .script_name, "Script name (.lua)", 15, 12, 12, 38);
    c.Clay__CloseElement();
}

fn scriptKindSelector(subsystem: *Subsystem, view: *ScriptingView) void {
    clay.selector("script-kind", 0, 110, 38, switch (view.kind) {
        .global => "Global",
        .transport => "Transport",
        .helpers => "Helpers",
    }, subsystem.menu == .kind, .{});
    subsystem.bindAction(.{ .toggle_menu = .kind });
    if (subsystem.menu == .kind) {
        clay.open("script-kind-menu", clay.menu(180, 3 * 28 + 8, .left, 2));
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.global), "Global", view.kind == .global, .{ .select_script_kind = .global });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.transport), "Transport", view.kind == .transport, .{ .select_script_kind = .transport });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.helpers), "Helpers", view.kind == .helpers, .{ .select_script_kind = .helpers });
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptLibrarySelector(subsystem: *Subsystem, view: *ScriptingView) void {
    clay.selector("script-library", 0, 160, 38, "Open script…", subsystem.menu == .library, .{});
    subsystem.bindAction(.{ .toggle_menu = .library });
    if (subsystem.menu == .library) {
        clay.open("script-library-menu", clay.menu(240, @floatFromInt((view.scripts.items.len + 1) * 28 + 8), .right, 2));
        menuOption(subsystem, "new-script-library-item", 0, "New Script", true, .new_script);
        for (view.scripts.items, 0..) |*script, index| {
            menuOption(subsystem, "script-library-item", index, std.mem.cutSuffix(u8, script.value(), ".lua").?, false, .{ .edit_script = index });
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn layoutIdentities(view: *IdentitiesView, subsystem: *Subsystem) void {
    const identities = view.records.items;
    clay.open("identity-form", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 240) },
            .childGap = 14,
        },
    });
    clay.text(if (view.editing_identity_id == null) "New identity" else "Edit identity", 19, theme.text_bright);
    clay.open("identity-primary-fields", .{
        .layout = .{ .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 66) }, .childGap = 12 },
    });
    for ([_]usize{ 0, 1, 3 }) |index| formField(subsystem, view, index, form_fields[index]);
    c.Clay__CloseElement();
    clay.open("identity-secondary-fields", .{
        .layout = .{ .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 66) }, .childGap = 12 },
    });
    for ([_]usize{ 5, 2, 4, 6 }) |index| formField(subsystem, view, index, form_fields[index]);
    c.Clay__CloseElement();
    clay.open("identity-actions", .{
        .layout = .{
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.fixed, 42) },
            .padding = .{ .top = 4 },
            .childGap = 10,
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_RIGHT, .y = c.CLAY_ALIGN_Y_CENTER },
        },
    });
    clay.spacer();
    actionButton(subsystem, "save-identity", "\u{e248}", .save_identity);
    actionButton(subsystem, "clear-identity", "\u{e21e}", .clear_identity);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    clay.open("all-identities", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.grow, 0) },
            .padding = .{ .top = 8 },
            .childGap = 7,
        },
    });
    clay.text("Library", 19, theme.text_bright);
    clay.openScrollable(identity_list_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.grow, 0) },
            .childGap = 7,
        },
        .clip = .{ .horizontal = true, .vertical = true },
    });
    if (identities.len == 0) {
        clay.text("No identities saved yet.", 15, theme.text_muted);
    } else {
        for (identities, 0..) |*identity, index| identityRow(subsystem, view, index, identity);
    }
    c.Clay__CloseElement();
    identityScrollThumb();
    c.Clay__CloseElement();
}

fn identityScrollThumb() void {
    const scroll_data = c.Clay_GetScrollContainerData(c.Clay_GetElementId(clay.string(identity_list_id, true)));
    const scroll_position = scroll_data.scrollPosition orelse return;
    const viewport_height = scroll_data.scrollContainerDimensions.height;
    const content_height = scroll_data.contentDimensions.height;
    if (!scroll_data.found or content_height <= viewport_height or viewport_height <= 0) return;

    const height = @min(viewport_height, @max(@as(f32, 24), viewport_height * viewport_height / content_height));
    const offset = -scroll_position.*.y / (content_height - viewport_height) * (viewport_height - height);
    clay.open("identity-scroll-thumb", .{
        .layout = .{ .sizing = .{ .width = clay.size(.fixed, 4), .height = clay.size(.fixed, height) } },
        .backgroundColor = theme.text_muted,
        .cornerRadius = .{ .topLeft = 2, .topRight = 2, .bottomLeft = 2, .bottomRight = 2 },
        .floating = .{
            .attachTo = c.CLAY_ATTACH_TO_ELEMENT_WITH_ID,
            .parentId = c.Clay_GetElementId(clay.string(identity_list_id, true)).id,
            .clipTo = c.CLAY_CLIP_TO_ATTACHED_PARENT,
            .attachPoints = .{ .element = c.CLAY_ATTACH_POINT_RIGHT_TOP, .parent = c.CLAY_ATTACH_POINT_RIGHT_TOP },
            .offset = .{ .x = -4, .y = offset },
            .zIndex = 2,
            .pointerCaptureMode = c.CLAY_POINTER_CAPTURE_MODE_PASSTHROUGH,
        },
    });
    c.Clay__CloseElement();
}

fn buildLayout(subsystem: *Subsystem) c.Clay_RenderCommandArray {
    subsystem.binding_len = 0;
    c.Clay_BeginLayout();
    clay.open("app", .{
        .layout = .{ .sizing = .{ .width = clay.size(.grow, 0), .height = clay.size(.grow, 0) } },
        .backgroundColor = theme.window,
    });
    side_panel_view.render(subsystem.page, subsystem.services.storage.config_dir, subsystem);
    clay.open("main-content", .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = clay.size(.grow, main_min_width), .height = clay.size(.grow, 0) },
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
            if (clay.pointerOver("identity-bpf-input")) break :blk c.SAPP_MOUSECURSOR_IBEAM;
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
        .logs => if (clay.pointerOver("logs-output")) c.SAPP_MOUSECURSOR_IBEAM else c.SAPP_MOUSECURSOR_DEFAULT,
    };
    if (desired != c.sapp_get_mouse_cursor()) c.sapp_set_mouse_cursor(desired);
}

fn endPointerSelections(subsystem: *Subsystem) void {
    for (&subsystem.identities.inputs) |*input| input.endPointerSelection();
    subsystem.identities.bpf_input.endPointerSelection();
    subsystem.scripting.name.endPointerSelection();
    subsystem.scripting.editor.text.endPointerSelection();
    subsystem.logs.editor.text.endPointerSelection();
}

fn handleKeyboardEvent(subsystem: *Subsystem, event_data: c.sapp_event) void {
    switch (subsystem.focus) {
        .none => {},
        .field => |field| {
            const view = &subsystem.identities;
            if (field == interface_field) {
                if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
                switch (event_data.key_code) {
                    c.SAPP_KEYCODE_TAB, c.SAPP_KEYCODE_ENTER => subsystem.focus = .{ .field = interface_field + 1 },
                    c.SAPP_KEYCODE_ESCAPE => subsystem.focus = .none,
                    else => {},
                }
                return;
            }
            const input = if (field == bpf_field) &view.bpf_input else &view.inputs[field];
            const result = input.handleEvent(event_data) catch |err| {
                log.logger.warning(.ui, if (err == error.MultilineText) "Text fields cannot contain line breaks." else "Text capacity reached.");
                return;
            };
            switch (result) {
                .advance => subsystem.focus = if (field == bpf_field) .none else .{ .field = (field + 1) % view.inputs.len },
                .blur => subsystem.focus = .none,
                .ignored, .handled => {},
            }
        },
        .script_name => {
            const result = subsystem.scripting.name.handleEvent(event_data) catch |err| {
                log.logger.warning(.ui, if (err == error.MultilineText) "Script names cannot contain line breaks." else "Text capacity reached.");
                return;
            };
            switch (result) {
                .advance => subsystem.focus = .script_source,
                .blur => subsystem.focus = .none,
                .ignored, .handled => {},
            }
        },
        .script_source => {
            const result = subsystem.scripting.editor.handleEvent(&subsystem.fonts, event_data) catch {
                log.logger.warning(.ui, "Text capacity reached.");
                return;
            };
            if (result == .blur) subsystem.focus = .none;
        },
        .logs => {
            const result = subsystem.logs.editor.handleEvent(&subsystem.fonts, event_data) catch unreachable;
            if (result == .blur) subsystem.focus = .none;
        },
    }
}

fn handleAction(subsystem: *Subsystem, action: Action, pointer_x: f32, pointer_state: c_int) void {
    const pressed = pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME;
    const manager = subsystem.services.manager;
    const storage = subsystem.services.storage;
    const identities = &subsystem.identities;
    const scripting = &subsystem.scripting;
    const logs = &subsystem.logs;
    if (action != .toggle_menu and action != .toggle_identity_transport_menu) subsystem.menu = .none;
    switch (action) {
        .toggle_menu => |menu| {
            subsystem.menu = if (subsystem.menu == menu) .none else menu;
            switch (subsystem.focus) {
                .field, .script_name => subsystem.focus = .none,
                else => {},
            }
        },
        .select_page => |page| {
            if (subsystem.page == page) return;
            if (subsystem.page == .logs) logs.clearContents();
            subsystem.page = page;
            subsystem.focus = .none;
            switch (page) {
                .identities => reloadScripts(subsystem, .transport, &identities.transport_scripts),
                .script_editor => reloadScripts(subsystem, scripting.kind, &scripting.scripts),
                .logs => reloadLogs(logs),
            }
        },
        .focus_input => |field_index| {
            if (pressed) subsystem.focus = .{ .field = field_index };
            if (std.meta.eql(subsystem.focus, .{ .field = field_index })) identities.inputs[field_index].handlePointer(&subsystem.fonts, form_fields[field_index].input_id, pointer_x, pointer_state, 16, 14);
        },
        .focus_bpf => |id| {
            const selected = if (identities.bpf_identity_id) |current| std.mem.eql(u8, current.value(), id.value()) else false;
            if (pressed) {
                if (!selected) {
                    identities.bpf_identity_id = id;
                    identities.bpf_input.reset();
                }
                subsystem.focus = .{ .field = bpf_field };
            }
            if (selected and std.meta.eql(subsystem.focus, .{ .field = bpf_field })) identities.bpf_input.handlePointer(&subsystem.fonts, "identity-bpf-input", pointer_x, pointer_state, 16, 14);
        },
        .select_interface => |interface_index| {
            identities.inputs[interface_field].set(subsystem.services.interfaces[interface_index].value()) catch log.logger.warning(.ui, "Interface name exceeds the input capacity.");
        },
        .toggle_identity_transport_menu => |identity_index| {
            subsystem.focus = .none;
            const id = identities.records.items[identity_index].value.id;
            const open = subsystem.menu == .transport and std.mem.eql(u8, identities.transport_menu_identity.value(), id.value());
            identities.transport_menu_identity = id;
            subsystem.menu = if (open) .none else .transport;
        },
        .select_identity_transport_script => |selection| {
            const identity = identities.records.items[selection.identity].value;
            const script = if (selection.script) |index| identities.transport_scripts.items[index] else null;
            manager.execute(.{ .set_transport = .{ .name = identity.label, .script = script } }) catch |err| reportIdentityFailure(identity.label.value(), "could not change transport", err);
        },
        .save_identity => {
            const value = currentIdentity(identities);
            if (value.label.value().len == 0) return log.logger.warning(.ui, "A name is required to save an identity.");
            manager.execute(.{ .save = value }) catch |err| return reportIdentityFailure(value.label.value(), "was not saved", err);
            clearForm(subsystem);
        },
        .apply_bpf => |name| {
            subsystem.focus = .none;
            manager.execute(.{ .set_bpf = .{ .name = name, .expression = identities.bpf_input.buffer } }) catch log.logger.warning(.ui, "BPF update could not be queued; the identity must be running.");
        },
        .clear_identity => clearForm(subsystem),
        .edit_identity => |identity_index| {
            const identity = identities.records.items[identity_index].value;
            identities.editing_identity_id = identity.id;
            inline for (std.meta.fields(identity_types.Identity)[1..8], 0..) |field, index| identities.inputs[index].set(@field(identity, field.name).value()) catch unreachable;
            subsystem.focus = .{ .field = 0 };
        },
        .delete_identity => |identity_index| {
            const identity = identities.records.items[identity_index].value;
            manager.execute(.{ .delete = identity.label }) catch |err| return reportIdentityFailure(identity.label.value(), "was not deleted", err);
            if (identities.editing_identity_id) |editing_id| if (std.mem.eql(u8, editing_id.value(), identity.id.value())) clearForm(subsystem);
        },
        .start_identity => |identity_index| {
            const identity = identities.records.items[identity_index].value;
            manager.execute(.{ .start = identity.label }) catch |err| reportIdentityFailure(identity.label.value(), "could not start", err);
        },
        .stop_identity => |identity_index| {
            const identity = identities.records.items[identity_index].value;
            manager.execute(.{ .stop = identity.label }) catch |err| return reportIdentityFailure(identity.label.value(), "was not stopped", err);
            if (identities.bpf_identity_id) |id| if (std.mem.eql(u8, id.value(), identity.id.value())) {
                identities.bpf_identity_id = null;
                identities.bpf_input.reset();
                if (std.meta.eql(subsystem.focus, .{ .field = bpf_field })) subsystem.focus = .none;
            };
        },
        .focus_script_name => {
            if (pressed) subsystem.focus = .script_name;
            if (subsystem.focus == .script_name) scripting.name.handlePointer(&subsystem.fonts, "script-name", pointer_x, pointer_state, 15, 12);
        },
        .select_script_kind => |kind| if (scripting.kind != kind) {
            clearScriptForm(subsystem);
            scripting.kind = kind;
            reloadScripts(subsystem, kind, &scripting.scripts);
        },
        .script_editor => |editor_action| switch (editor_action) {
            .focus => if (subsystem.page == .logs) {
                subsystem.focus = .logs;
                logs.editor.handlePointer(&subsystem.fonts, pointer_state);
            } else {
                if (pressed) subsystem.focus = .script_source;
                if (subsystem.focus == .script_source) scripting.editor.handlePointer(&subsystem.fonts, pointer_state);
            },
            .select_font_size => |font_size| (if (subsystem.page == .logs) &logs.editor else &scripting.editor).setFontSize(font_size),
        },
        .save_script => {
            const store = storage.scripts(scripting.kind);
            const previous_file_name = if (scripting.editing_file_name) |*value| value.value() else null;
            const new_file_name = store.save(scripting.name.value(), scripting.editor.text.value(), previous_file_name) catch |err| return switch (err) {
                error.NameRequired => log.logger.warning(.ui, "A script name is required."),
                error.InvalidName => log.logger.warning(.ui, "Script names cannot contain path separators."),
                else => log.logger.formatted(.err, .ui, "Could not save {s} script \"{s}\" to disk.", .{ @tagName(scripting.kind), scripting.name.value() }),
            };
            scripting.editing_file_name = new_file_name;
            if (subsystem.focus == .script_name) subsystem.focus = .none;
            reloadScripts(subsystem, scripting.kind, &scripting.scripts);
            log.logger.formatted(.info, .ui, "{s} script \"{s}\" saved.", .{ @tagName(scripting.kind), new_file_name.value() });
        },
        .new_script => {
            clearScriptForm(subsystem);
            subsystem.focus = .script_name;
        },
        .edit_script => |script_index| editScript(subsystem, scripting, script_index),
        .delete_script => {
            const file_name = scripting.editing_file_name.?.value();
            storage.scripts(scripting.kind).delete(file_name) catch return log.logger.formatted(.err, .ui, "Could not delete {s} script \"{s}\" from disk.", .{ @tagName(scripting.kind), file_name });
            log.logger.formatted(.info, .ui, "{s} script \"{s}\" deleted.", .{ @tagName(scripting.kind), file_name });
            if (scripting.editing_file_name) |editing_file_name| if (std.mem.eql(u8, editing_file_name.value(), file_name)) clearScriptForm(subsystem);
            reloadScripts(subsystem, scripting.kind, &scripting.scripts);
        },
        .run_global_script => {
            const name = globalScriptName(scripting);
            if (!manager.runGlobal(name.value(), scripting.editor.text.value())) log.logger.formatted(.err, .ui, "Global script \"{s}\" could not start.", .{name.value()});
        },
        .stop_global_script => manager.stopGlobal(),
    }
}
