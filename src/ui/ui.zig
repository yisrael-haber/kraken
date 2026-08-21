const std = @import("std");
const script_store = @import("../storage/script_repository.zig");
const storage_module = @import("../storage/storage.zig");
const storage_model = @import("../storage/model.zig");
const identity_service = @import("../identities/service.zig");
const runtime = @import("../runtime/runtime.zig");
const limits = @import("../limits.zig");
const clay = @import("clay.zig");
const script_editor = @import("script_editor.zig");
const text_editor = @import("text_editor.zig");
const side_panel_view = @import("side_panel.zig");

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

const FormFieldSpec = struct {
    field: FormField,
    field_id: []const u8,
    input_id: []const u8,
    label: []const u8,
    placeholder: []const u8,
};

const form_fields = [_]FormFieldSpec{
    .{ .field = .label, .field_id = "label-field", .input_id = "label-input", .label = "Name", .placeholder = "" },
    .{ .field = .ip, .field_id = "ip-field", .input_id = "ip-input", .label = "IP", .placeholder = "192.168.56.50" },
    .{ .field = .prefix, .field_id = "prefix-field", .input_id = "prefix-input", .label = "Prefix", .placeholder = "24" },
    .{ .field = .interface, .field_id = "interface-field", .input_id = "interface-input", .label = "Interface", .placeholder = "Select interface" },
    .{ .field = .gateway, .field_id = "gateway-field", .input_id = "gateway-input", .label = "Gateway", .placeholder = "Optional" },
    .{ .field = .mac, .field_id = "mac-field", .input_id = "mac-input", .label = "MAC", .placeholder = "Optional" },
    .{ .field = .mtu, .field_id = "mtu-field", .input_id = "mtu-input", .label = "MTU", .placeholder = "Optional" },
};

const Page = enum { identities, script_editor };

const Action = enum {
    save_identity,
    clear_identity,
    edit_identity,
    delete_identity,
    save_script,
    new_script,
    edit_script,
    delete_script,
    start_identity,
    stop_identity,
    run_global_script,
    stop_global_script,
};

const ButtonStyle = enum { primary, secondary };

const Icon = enum {
    caret_down,
    plus,
};

const TextInput = storage_model.FieldText;
const TextField = text_editor.Editor(TextInput, .single_line);
const ScriptingFocus = enum { none, name, source };

const ScriptingView = struct {
    editor: script_editor.State = .{},
    name: TextField = .{},
    focus: ScriptingFocus = .none,
    library_open: bool = false,
    kind_menu_open: bool = false,
    kind: script_store.Kind = .global,
    scripts: script_store.Catalog = .{},
    editing_file_name: ?storage_model.FieldText = null,
};

const SidePanel = side_panel_view.State;

const fixed = clay.fixed;
const grow = clay.grow;
const openElement = clay.open;
const openIndexedElement = clay.openIndexed;
const openScrollableElement = clay.openScrollable;
const pointerOver = clay.pointerOver;
const pointerOverIndexed = clay.pointerOverIndexed;
const text = clay.text;
const dynamicText = clay.dynamicText;
const clayString = clay.string;

const IdentitiesView = struct {
    inputs: [7]TextField = [_]TextField{.{}} ** 7,
    focused_field: ?FormField = null,
    identities: []const storage_model.Identity = &.{},
    transport_scripts: script_store.Catalog = .{},
    transport_script_menu_identity: ?usize = null,
    transport_script_selection: []?usize = &.{},
    editing_file_name: ?storage_model.IdentityIdText = null,
    interface_menu_open: bool = false,

    fn deinit(self: *IdentitiesView, allocator: std.mem.Allocator) void {
        if (self.transport_script_selection.len > 0) allocator.free(self.transport_script_selection);
        self.transport_script_selection = &.{};
    }
};

const MainView = union(Page) {
    identities: IdentitiesView,
    script_editor: ScriptingView,

    fn deinit(self: *MainView, subsystem: *Subsystem) void {
        switch (self.*) {
            .identities => |*view| view.deinit(subsystem.services.storage.allocator),
            .script_editor => {},
        }
    }

    fn select(self: *MainView, subsystem: *Subsystem, page: Page) void {
        if (std.meta.activeTag(self.*) == page) return;
        self.deinit(subsystem);
        switch (page) {
            .identities => {
                self.* = .{ .identities = .{} };
                reloadIdentities(subsystem, &self.identities);
                reloadTransportScripts(subsystem, &self.identities);
            },
            .script_editor => {
                self.* = .{ .script_editor = .{} };
                reloadScripts(subsystem, &self.script_editor, self.script_editor.kind);
            },
        }
    }
};

const SignalAction = union(enum) {
    resize_sidebar,
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
    form_action: struct { action: Action, index: ?usize },
    select_page: Page,
};

const SignalBinding = struct { action: SignalAction, owner: ?*anyopaque = null };
const SignalEvent = struct {
    action: SignalAction,
    pointer_x: f32,
    pointer_state: i32,
};

pub const Services = struct {
    storage: *storage_module.Storage,
    identities: *identity_service.Service,
    runtime_instance: *runtime.AppRuntime,
};

const SignalTable = struct {
    values: [limits.ui_signal_capacity]SignalBinding = undefined,
    len: usize = 0,

    fn add(self: *SignalTable, value: SignalBinding) ?*SignalBinding {
        if (self.len == self.values.len) return null;
        const result = &self.values[self.len];
        result.* = value;
        self.len += 1;
        return result;
    }
};

const SignalQueue = struct {
    values: [limits.ui_signal_event_capacity]SignalEvent = undefined,
    read: usize = 0,
    len: usize = 0,

    fn push(self: *SignalQueue, value: SignalEvent) bool {
        if (self.len == self.values.len) return false;
        self.values[(self.read + self.len) % self.values.len] = value;
        self.len += 1;
        return true;
    }

    fn pop(self: *SignalQueue) ?SignalEvent {
        if (self.len == 0) return null;
        const result = self.values[self.read];
        self.read = (self.read + 1) % self.values.len;
        self.len -= 1;
        return result;
    }
};

pub fn requiredMemory() usize {
    return c.Clay_MinMemorySize();
}

pub const Subsystem = struct {
    services: Services = undefined,
    side_panel: SidePanel = .{},
    page: MainView = .{ .identities = .{} },
    signals: SignalTable = .{},
    pending_signals: SignalQueue = .{},
    signal_overflowed: bool = false,
    pointer_click_generation: usize = 0,
    handled_pointer_click_generation: usize = 0,
    fonts: [2]c.sclay_font_t = .{ 0, 0 },
    path_wrap_marker: u8 = 0,

    pub fn init(self: *Subsystem, services: Services, clay_memory: []u8) void {
        self.* = .{ .services = services };
        c.sclay_setup();
        reloadIdentities(self, &self.page.identities);
        reloadTransportScripts(self, &self.page.identities);
        _ = c.Clay_Initialize(
            c.Clay_CreateArenaWithCapacityAndMemory(clay_memory.len, clay_memory.ptr),
            .{ .width = @floatFromInt(c.sapp_width()), .height = @floatFromInt(c.sapp_height()) },
            .{},
        );
        const font_bytes: []const u8 = font_data;
        self.fonts[0] = c.sclay_add_font_mem(@ptrCast(@constCast(font_bytes.ptr)), @intCast(font_bytes.len));
        const icon_font_bytes: []const u8 = icon_font_data;
        self.fonts[1] = c.sclay_add_font_mem(@ptrCast(@constCast(icon_font_bytes.ptr)), @intCast(icon_font_bytes.len));
        c.Clay_SetMeasureTextFunction(c.sclay_measure_text, self.fonts[0..].ptr);
    }

    pub fn frame(self: *Subsystem) void {
        c.sclay_new_frame();
        processSignals(self);
        self.side_panel.updateWidth();
        drainRuntimeEvents(self);
        switch (self.page) {
            .identities => {},
            .script_editor => |*view| if (view.focus == .source) view.editor.keepCursorVisible(),
        }
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
        if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_DOWN) self.pointer_click_generation +%= 1;
        if (event_data.*.type == c.SAPP_EVENTTYPE_MOUSE_UP) endPointerSelections(self);
        c.sclay_handle_event(event_data);
        handleKeyboardEvent(self, event_data.*);
        processSignals(self);
    }

    pub fn deinit(self: *Subsystem) void {
        self.page.deinit(self);
        self.services = undefined;
        c.sclay_shutdown();
    }

    pub fn bindSignal(self: *Subsystem, action: SignalAction) void {
        const binding = self.signals.add(.{ .action = action, .owner = @ptrCast(self) }) orelse {
            self.signal_overflowed = true;
            return;
        };
        c.kraken_on_hover(@ptrCast(binding));
    }
};

export fn kraken_handle_hover(pointer_x: f32, pointer_y: f32, pointer_state: u8, user_data: ?*anyopaque) callconv(.c) void {
    _ = pointer_y;
    const binding: *const SignalBinding = @ptrCast(@alignCast(user_data orelse return));
    const owner: *Subsystem = @ptrCast(@alignCast(binding.owner orelse return));
    if (!owner.pending_signals.push(.{
        .action = binding.action,
        .pointer_x = pointer_x,
        .pointer_state = pointer_state,
    })) owner.signal_overflowed = true;
}

fn bindEditorAction(context: *anyopaque, action: script_editor.Action) void {
    const subsystem: *Subsystem = @ptrCast(@alignCast(context));
    subsystem.bindSignal(.{ .script_editor = action });
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

fn selectInterface(subsystem: *Subsystem, view: *IdentitiesView, index: usize) void {
    const service = subsystem.services.identities;
    const interfaces = service.interfaces();
    if (index >= interfaces.len) return;
    view.inputs[@intFromEnum(FormField.interface)].set(interfaces[index].nameSlice()) catch {
        uiLog("Interface name exceeds the input capacity.");
        return;
    };
    view.interface_menu_open = false;
}

fn reloadIdentities(subsystem: *Subsystem, view: *IdentitiesView) void {
    const allocator = subsystem.services.storage.allocator;
    view.deinit(allocator);
    const service = subsystem.services.identities;
    view.identities = service.snapshot();
    if (view.identities.len == 0) return;
    view.transport_script_selection = allocator.alloc(?usize, view.identities.len) catch {
        uiLog("Could not allocate identity controls.");
        return;
    };
    @memset(view.transport_script_selection, null);
}

fn reloadTransportScripts(subsystem: *Subsystem, view: *IdentitiesView) void {
    const storage = subsystem.services.storage;
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
    const storage = subsystem.services.storage;
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
    const service = subsystem.services.identities;
    var drained: usize = 0;
    while (drained < runtime.event_capacity) : (drained += 1) {
        const event_value = service.nextEvent() orelse break;
        logRuntimeIssue(event_value);
    }
}

fn logRuntimeIssue(event_value: runtime.Event) void {
    switch (event_value.kind) {
        .started, .stopped, .transport_updated => return,
        .failed, .transport_update_failed, .packet_dropped, .queue_full => {},
    }
    const detail = event_value.message[0..event_value.message_len];
    const action = switch (event_value.kind) {
        .started => "started",
        .stopped => "stopped",
        .failed => "failed",
        .transport_updated => "updated its transport script",
        .transport_update_failed => "could not update its transport script",
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

fn clearScriptForm(view: *ScriptingView) void {
    view.name.reset();
    view.focus = .none;
    view.editor.reset();
    view.kind_menu_open = false;
    view.editing_file_name = null;
}

fn reloadScripts(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind) void {
    const storage = subsystem.services.storage;
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

fn editScript(subsystem: *Subsystem, view: *ScriptingView, kind: script_store.Kind, index: ?usize) void {
    const script_index = index orelse return;
    if (script_index >= view.scripts.len) return;
    const script = view.scripts.values[script_index];
    const storage = subsystem.services.storage;
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
    view.editing_file_name = script.file_name;
    view.name.load(script.name);
    view.focus = .none;
    view.library_open = false;
    view.editor.load(source);
}

fn clearForm(view: *IdentitiesView) void {
    for (&view.inputs) |*input| input.reset();
    view.focused_field = null;
    view.interface_menu_open = false;
    view.editing_file_name = null;
}

fn setFormFromIdentity(view: *IdentitiesView, identity: storage_model.Identity) void {
    view.inputs[@intFromEnum(FormField.label)].load(identity.label);
    view.inputs[@intFromEnum(FormField.ip)].load(identity.ip);
    view.inputs[@intFromEnum(FormField.prefix)].load(identity.prefix);
    view.inputs[@intFromEnum(FormField.interface)].load(identity.interface);
    view.inputs[@intFromEnum(FormField.gateway)].load(identity.gateway);
    view.inputs[@intFromEnum(FormField.mac)].load(identity.mac);
    view.inputs[@intFromEnum(FormField.mtu)].load(identity.mtu);
}

fn currentIdentityDraft(view: *const IdentitiesView) storage_model.IdentityDraft {
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

fn formFieldInputId(field: FormField) []const u8 {
    return form_fields[@intFromEnum(field)].input_id;
}

fn formField(subsystem: *Subsystem, view: *IdentitiesView, spec: FormFieldSpec) void {
    const is_focused = view.focused_field == spec.field;
    openElement(spec.field_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(140), .height = fixed(66) },
            .childGap = 6,
        },
    });
    text(spec.label, 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    openElement(spec.input_id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(38) },
            .padding = .{ .left = 14, .right = 12, .top = 0, .bottom = 0 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (is_focused or pointerOver(spec.input_id)) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (is_focused) .{
            .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
        .clip = .{ .horizontal = true },
    });
    subsystem.bindSignal(.{ .focus_input = @intFromEnum(spec.field) });
    view.inputs[@intFromEnum(spec.field)].render(&subsystem.fonts, spec.input_id, @intFromEnum(spec.field), is_focused, spec.placeholder, 16, 14, 12, 38);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn interfaceSelector(subsystem: *Subsystem, view: *IdentitiesView) void {
    const spec = form_fields[@intFromEnum(FormField.interface)];
    const value = view.inputs[@intFromEnum(FormField.interface)].value();
    const hovered = pointerOver(spec.input_id);
    openElement(spec.field_id, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(140), .height = fixed(66) },
            .childGap = 6,
        },
    });
    text(spec.label, 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    openElement(spec.input_id, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(38) },
            .padding = .{ .left = 14, .right = 12, .top = 0, .bottom = 0 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (hovered or view.interface_menu_open) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (view.interface_menu_open) .{
            .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 },
            .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 },
        } else .{},
    });
    subsystem.bindSignal(.toggle_interface_menu);
    if (value.len == 0) text(spec.placeholder, 16, .{ .r = 128, .g = 137, .b = 159, .a = 255 }) else dynamicText(value, 16, .{ .r = 203, .g = 208, .b = 222, .a = 255 });
    openElement("interface-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 17, .{ .r = 133, .g = 141, .b = 160, .a = 255 });
    if (view.interface_menu_open) interfaceMenu(subsystem, value);
    c.Clay__CloseElement();
    c.Clay__CloseElement();
}

fn interfaceMenu(subsystem: *Subsystem, selected: []const u8) void {
    const interfaces = subsystem.services.identities.interfaces();
    const visible_count: usize = @min(interfaces.len, 8);
    const menu_height: usize = @max(visible_count, 1) * 32 + 8;
    var declaration = clay.menu(260, @floatFromInt(menu_height), .left, 2);
    declaration.clip.vertical = true;
    openScrollableElement("interface-menu", declaration);
    if (interfaces.len == 0) {
        text("No packet capture interfaces discovered.", 14, .{ .r = 190, .g = 196, .b = 210, .a = 255 });
    } else for (interfaces, 0..) |*device, index| {
        const name = device.nameSlice();
        menuOption(subsystem, "interface-option", index, name, std.mem.eql(u8, selected, name), .{ .select_interface = index });
    }
    c.Clay__CloseElement();
}

fn menuOption(subsystem: *Subsystem, id: []const u8, index: usize, label: []const u8, selected: bool, action: SignalAction) void {
    const hovered = pointerOverIndexed(id, index);
    openIndexedElement(id, index, clay.menuOption(selected, hovered));
    subsystem.bindSignal(action);
    dynamicText(label, 14, .{ .r = 221, .g = 225, .b = 236, .a = 255 });
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
    subsystem.bindSignal(.{ .toggle_identity_transport_menu = identity_index });
    dynamicText(selected_name, 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openIndexedElement("identity-transport-chevron-spacer", identity_index, .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.transport_script_menu_identity == identity_index) identityTransportMenu(subsystem, view, identity_index);
    c.Clay__CloseElement();
}

fn identityTransportMenu(subsystem: *Subsystem, view: *IdentitiesView, identity_index: usize) void {
    openIndexedElement("identity-transport-menu", identity_index, clay.menu(240, @floatFromInt((view.transport_scripts.len + 1) * 32 + 8), .left, 2));
    const no_script_index = identity_index * 1024;
    menuOption(subsystem, "identity-transport-option", no_script_index, "No transport script", view.transport_script_selection[identity_index] == null, .{
        .select_identity_transport_script = .{ .identity = identity_index, .script = null },
    });
    // Clay retains text pointers until frame submission, so borrow catalog records.
    for (view.transport_scripts.slice(), 0..) |*script, index| {
        menuOption(subsystem, "identity-transport-option", no_script_index + index + 1, script.name.value(), view.transport_script_selection[identity_index] != null and view.transport_script_selection[identity_index].? == index, .{
            .select_identity_transport_script = .{ .identity = identity_index, .script = index },
        });
    }
    c.Clay__CloseElement();
}

fn actionButton(subsystem: *Subsystem, id: []const u8, style: ButtonStyle, action: Action, index: ?usize) void {
    const primary = style == .primary;
    const element_index = index orelse 0;
    openIndexedElement(id, element_index, .{
        .layout = .{
            .sizing = .{ .width = fixed(38), .height = fixed(38) },
            .childAlignment = .{ .x = c.CLAY_ALIGN_X_CENTER, .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary)
            if (pointerOverIndexed(id, element_index)) .{ .r = 122, .g = 54, .b = 190, .a = 255 } else .{ .r = 101, .g = 36, .b = 165, .a = 255 }
        else if (pointerOverIndexed(id, element_index)) .{ .r = 30, .g = 33, .b = 44, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
    });
    subsystem.bindSignal(.{ .form_action = .{ .action = action, .index = index } });
    const color: c.Clay_Color = if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 171, .g = 180, .b = 202, .a = 255 };
    c.Clay__OpenTextElement(clayString(actionGlyph(action), true), .{ .fontId = 1, .fontSize = 19, .textColor = color });
    c.Clay__CloseElement();
}

fn actionGlyph(action: Action) []const u8 {
    return switch (action) {
        .save_identity, .save_script => "\u{e248}",
        .clear_identity => "\u{e21e}",
        .edit_identity, .edit_script => "\u{e3b4}",
        .delete_identity, .delete_script => "\u{e4a6}",
        .start_identity, .run_global_script => "\u{e3d0}",
        .stop_identity, .stop_global_script => "\u{e46c}",
        .new_script => "\u{e3d4}",
    };
}

fn identityRow(subsystem: *Subsystem, view: *IdentitiesView, index: usize, identity: *const storage_model.Identity) void {
    const slot = subsystem.services.identities.slotFor(identity.file_name.value());
    const state = if (slot) |value_slot| subsystem.services.runtime_instance.state(value_slot) orelse .idle else .idle;

    openElement(identity.file_name.value(), .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(66) },
            .padding = .{ .left = 2, .right = 0, .top = 8, .bottom = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .border = .{ .color = .{ .r = 34, .g = 38, .b = 51, .a = 255 }, .width = .{ .bottom = 1 } },
    });
    openIndexedElement("identity-summary", index, .{
        .layout = .{
            .layoutDirection = c.CLAY_TOP_TO_BOTTOM,
            .sizing = .{ .width = grow(0), .height = grow(0) },
            .childGap = 3,
        },
    });
    dynamicText(identity.label.value(), 17, .{ .r = 232, .g = 236, .b = 246, .a = 255 });
    openIndexedElement("identity-address", index, .{ .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(18) }, .childGap = 5 } });
    dynamicText(identity.ip.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    text("/", 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    dynamicText(identity.prefix.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    dynamicText(identity.interface.value(), 15, .{ .r = 143, .g = 161, .b = 197, .a = 255 });
    c.Clay__CloseElement();
    c.Clay__CloseElement();
    const actions_width: f32 = if (index < view.transport_script_selection.len) 402 else 222;
    openIndexedElement("identity-actions", index, .{ .layout = .{ .sizing = .{ .width = fixed(actions_width), .height = fixed(38) }, .childGap = 8 } });
    if (index < view.transport_script_selection.len) identityTransportSelector(subsystem, view, index);
    if (state == .running or state == .starting) {
        actionButton(subsystem, "identity-stop", .secondary, .stop_identity, index);
    } else {
        actionButton(subsystem, "identity-start", .secondary, .start_identity, index);
    }
    actionButton(subsystem, "identity-edit", .secondary, .edit_identity, index);
    actionButton(subsystem, "identity-delete", .secondary, .delete_identity, index);
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
    scriptNameInput(subsystem, "script-name", view);
    actionButton(subsystem, "save-script", .primary, .save_script, null);
    if (view.kind == .global) {
        actionButton(subsystem, "run-global-script", .secondary, .run_global_script, null);
        actionButton(subsystem, "stop-global-script", .secondary, .stop_global_script, null);
    }
    if (view.editing_file_name != null) actionButton(subsystem, "delete-script", .secondary, .delete_script, scriptIndex(view));
    scriptLibrarySelector(subsystem, view);
    c.Clay__CloseElement();
    view.editor.render(.{
        .fonts = &subsystem.fonts,
        .focused = view.focus == .source,
        .binding_context = subsystem,
        .bind_action = bindEditorAction,
    });
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
        .backgroundColor = if (view.focus == .name or hovered) .{ .r = 33, .g = 36, .b = 48, .a = 255 } else .{ .r = 27, .g = 29, .b = 39, .a = 255 },
        .cornerRadius = .{ .topLeft = 8, .topRight = 8, .bottomLeft = 8, .bottomRight = 8 },
        .border = if (view.focus == .name) .{ .color = .{ .r = 139, .g = 82, .b = 207, .a = 255 }, .width = .{ .left = 1, .right = 1, .top = 1, .bottom = 1 } } else .{},
        .clip = .{ .horizontal = true },
    });
    subsystem.bindSignal(.focus_script_name);
    view.name.render(&subsystem.fonts, id, 7, view.focus == .name, "Script name (.lua)", 15, 12, 12, 34);
    c.Clay__CloseElement();
}

fn scriptKindLabel(kind: script_store.Kind) []const u8 {
    return switch (kind) {
        .global => "Global",
        .transport => "Transport",
        .helpers => "Helpers",
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
    subsystem.bindSignal(.toggle_script_kind_menu);
    dynamicText(scriptKindLabel(view.kind), 13, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openElement("script-kind-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 14, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.kind_menu_open) {
        openElement("script-kind-menu", clay.menu(180, 104, .left, 2));
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.global), "Global", view.kind == .global, .{ .select_script_kind = .global });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.transport), "Transport", view.kind == .transport, .{ .select_script_kind = .transport });
        menuOption(subsystem, "script-kind-option", @intFromEnum(script_store.Kind.helpers), "Helpers", view.kind == .helpers, .{ .select_script_kind = .helpers });
        c.Clay__CloseElement();
    }
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
    subsystem.bindSignal(.toggle_script_library);
    dynamicText(if (view.editing_file_name != null) view.name.value() else "New Script", 14, .{ .r = 209, .g = 214, .b = 228, .a = 255 });
    openElement("script-library-chevron-spacer", .{ .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } } });
    c.Clay__CloseElement();
    icon(.caret_down, 16, .{ .r = 147, .g = 155, .b = 175, .a = 255 });
    if (view.library_open) {
        openElement("script-library-menu", clay.menu(240, @floatFromInt((view.scripts.len + 1) * 32 + 8), .right, 2));
        scriptLibraryItem(subsystem, "new-script-library-item", "New Script", .new_script, null, true);
        for (view.scripts.slice(), 0..) |*script, index| {
            scriptLibraryItem(subsystem, "script-library-item", script.name.value(), .edit_script, index, false);
        }
        c.Clay__CloseElement();
    }
    c.Clay__CloseElement();
}

fn scriptLibraryItem(subsystem: *Subsystem, id: []const u8, label: []const u8, action: Action, index: ?usize, primary: bool) void {
    const element_index = index orelse 0;
    const hovered = pointerOverIndexed(id, element_index);
    openIndexedElement(id, element_index, .{
        .layout = .{
            .sizing = .{ .width = grow(0), .height = fixed(32) },
            .padding = .{ .left = 8, .right = 8 },
            .childAlignment = .{ .y = c.CLAY_ALIGN_Y_CENTER },
        },
        .backgroundColor = if (primary) .{ .r = 77, .g = 44, .b = 119, .a = 255 } else if (hovered) .{ .r = 43, .g = 47, .b = 62, .a = 255 } else .{},
        .cornerRadius = .{ .topLeft = 4, .topRight = 4, .bottomLeft = 4, .bottomRight = 4 },
    });
    subsystem.bindSignal(.{ .form_action = .{ .action = action, .index = index } });
    if (action == .new_script) icon(.plus, 17, .{ .r = 248, .g = 244, .b = 255, .a = 255 });
    dynamicText(label, 14, if (primary) .{ .r = 248, .g = 244, .b = 255, .a = 255 } else .{ .r = 221, .g = 225, .b = 236, .a = 255 });
    c.Clay__CloseElement();
}

fn scriptIndex(view: *const ScriptingView) ?usize {
    const file_name = if (view.editing_file_name) |*value| value.value() else return null;
    for (view.scripts.slice(), 0..) |script, index| {
        if (std.mem.eql(u8, script.file_name.value(), file_name)) return index;
    }
    return null;
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
    for (form_fields[0..3]) |spec| formField(subsystem, view, spec);
    interfaceSelector(subsystem, view);
    c.Clay__CloseElement();
    openElement("identity-secondary-fields", .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = fixed(66) }, .childGap = 12 },
    });
    for (form_fields[4..]) |spec| formField(subsystem, view, spec);
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
    actionButton(subsystem, "save-identity", .primary, .save_identity, null);
    actionButton(subsystem, "clear-identity", .secondary, .clear_identity, null);
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
    subsystem.signals.len = 0;
    c.Clay_BeginLayout();
    openElement("app", .{
        .layout = .{ .sizing = .{ .width = grow(0), .height = grow(0) } },
        .backgroundColor = .{ .r = 18, .g = 24, .b = 38, .a = 255 },
    });
    side_panel_view.render(&subsystem.side_panel, std.meta.activeTag(subsystem.page), subsystem.services.storage.config_dir, subsystem);
    switch (subsystem.page) {
        .identities => |*view| layoutIdentities(view, subsystem),
        .script_editor => |*view| layoutScriptingView(view, subsystem),
    }
    c.Clay__CloseElement();
    return c.Clay_EndLayout(@floatCast(c.sapp_frame_duration()));
}

fn updateMouseCursor(subsystem: *const Subsystem) void {
    const desired: c.sapp_mouse_cursor = if (subsystem.side_panel.resizing or pointerOver("sidebar-resize-handle"))
        c.SAPP_MOUSECURSOR_RESIZE_EW
    else switch (subsystem.page) {
        .identities => blk: {
            for (form_fields) |field| {
                if (!pointerOver(field.input_id)) continue;
                break :blk if (field.field == .interface) c.SAPP_MOUSECURSOR_POINTING_HAND else c.SAPP_MOUSECURSOR_IBEAM;
            }
            break :blk c.SAPP_MOUSECURSOR_DEFAULT;
        },
        .script_editor => if (pointerOver("script-name") or pointerOver(script_editor.text_area_id))
            c.SAPP_MOUSECURSOR_IBEAM
        else
            c.SAPP_MOUSECURSOR_DEFAULT,
    };
    if (desired != c.sapp_get_mouse_cursor()) c.sapp_set_mouse_cursor(desired);
}

fn endPointerSelections(subsystem: *Subsystem) void {
    switch (subsystem.page) {
        .identities => |*view| for (&view.inputs) |*input| input.endPointerSelection(),
        .script_editor => |*view| {
            view.name.endPointerSelection();
            view.editor.endPointerSelection();
        },
    }
}

fn handleKeyboardEvent(subsystem: *Subsystem, event_data: c.sapp_event) void {
    switch (subsystem.page) {
        .identities => |*view| {
            const field = view.focused_field orelse return;
            if (field == .interface) {
                if (event_data.type != c.SAPP_EVENTTYPE_KEY_DOWN) return;
                switch (event_data.key_code) {
                    c.SAPP_KEYCODE_TAB, c.SAPP_KEYCODE_ENTER => view.focused_field = .gateway,
                    c.SAPP_KEYCODE_ESCAPE => view.focused_field = null,
                    else => {},
                }
                return;
            }
            const result = view.inputs[@intFromEnum(field)].handleEvent(event_data) catch |err| {
                uiLog(if (err == error.MultilineText) "Text fields cannot contain line breaks." else "Text capacity reached.");
                return;
            };
            switch (result) {
                .advance => view.focused_field = @enumFromInt((@intFromEnum(field) + 1) % view.inputs.len),
                .blur => view.focused_field = null,
                .ignored, .handled => {},
            }
        },
        .script_editor => |*view| {
            if (view.focus == .name) {
                const result = view.name.handleEvent(event_data) catch |err| {
                    uiLog(if (err == error.MultilineText) "Script names cannot contain line breaks." else "Text capacity reached.");
                    return;
                };
                switch (result) {
                    .advance => {
                        view.focus = .source;
                    },
                    .blur => view.focus = .none,
                    .ignored, .handled => {},
                }
                return;
            }
            if (view.focus != .source) return;
            const result = view.editor.handleEvent(&subsystem.fonts, event_data) catch {
                uiLog("Text capacity reached.");
                return;
            };
            if (result == .blur) view.focus = .none;
        },
    }
}

fn handleIdentityAction(subsystem: *Subsystem, view: *IdentitiesView, action: Action, index: ?usize) void {
    switch (action) {
        .save_identity => {
            const service = subsystem.services.identities;
            const draft = currentIdentityDraft(view);
            if (draft.label.len == 0) {
                uiLog("A name is required to save an identity.");
                return;
            }
            if (view.editing_file_name) |file_name| {
                service.execute(.{ .update = .{ .id = file_name, .draft = draft } }) catch |err| {
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
            view.editing_file_name = identity.file_name;
            setFormFromIdentity(view, identity);
            view.focused_field = .label;
        },
        .delete_identity => {
            const identity_index = index orelse return;
            if (identity_index >= view.identities.len) return;
            const service = subsystem.services.identities;
            const id = view.identities[identity_index].file_name;
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
            const service = subsystem.services.identities;
            const identity = view.identities[identity_index];
            const transport_source = selectedTransportSource(subsystem, view, identity_index) catch return;
            service.execute(.{ .start = .{ .id = identity.file_name, .transport = transport_source } }) catch |err| {
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
            const service = subsystem.services.identities;
            service.execute(.{ .stop = view.identities[identity_index].file_name }) catch {
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
            const storage = subsystem.services.storage;
            const store = storage.scripts(kind);
            const previous_file_name = if (view.editing_file_name) |*value| value.value() else null;
            var new_file_name: storage_model.FieldText = .{};
            store.save(view.name.value(), view.editor.value(), previous_file_name, &new_file_name) catch |err| switch (err) {
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
            view.editing_file_name = new_file_name;
            if (view.focus == .name) view.focus = .none;
            view.library_open = false;
            reloadScripts(subsystem, view, kind);
        },
        .new_script => {
            clearScriptForm(view);
            view.focus = .name;
            view.library_open = false;
        },
        .edit_script => editScript(subsystem, view, kind, index),
        .delete_script => {
            const script_index = index orelse return;
            if (script_index >= view.scripts.len) return;
            const file_name = view.scripts.values[script_index].file_name.value();
            const storage = subsystem.services.storage;
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
            const value = subsystem.services.runtime_instance;
            var source: runtime.Source = .{};
            source.set(view.editor.value()) catch {
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
            const value = subsystem.services.runtime_instance;
            _ = value.stopGlobal();
        },
        else => {},
    }
}

fn handleSignalAction(subsystem: *Subsystem, action: SignalAction, pointer_x: f32, pointer_state: c_int) void {
    const pressed = pointer_state == c.CLAY_POINTER_DATA_PRESSED_THIS_FRAME;
    if (pressed) {
        if (subsystem.handled_pointer_click_generation == subsystem.pointer_click_generation) return;
        subsystem.handled_pointer_click_generation = subsystem.pointer_click_generation;
    }
    const accepted = switch (action) {
        .resize_sidebar => true,
        .focus_input, .focus_script_name => pressed or pointer_state == c.CLAY_POINTER_DATA_PRESSED,
        .script_editor => |editor_action| switch (editor_action) {
            .focus => pressed or pointer_state == c.CLAY_POINTER_DATA_PRESSED,
            else => pressed,
        },
        else => pressed,
    };
    if (!accepted) return;

    switch (action) {
        .resize_sidebar => {
            if (pressed) {
                subsystem.side_panel.resizing = true;
                subsystem.side_panel.drag_offset = pointer_x - subsystem.side_panel.width;
            }
        },
        .select_page => |page| subsystem.page.select(subsystem, page),
        else => switch (subsystem.page) {
            .identities => |*view| handleIdentitySignal(subsystem, view, action, pointer_x, pointer_state, pressed),
            .script_editor => |*view| handleScriptSignal(subsystem, view, action, pointer_x, pointer_state, pressed),
        },
    }
}

fn handleIdentitySignal(subsystem: *Subsystem, view: *IdentitiesView, action: SignalAction, pointer_x: f32, pointer_state: c_int, pressed: bool) void {
    switch (action) {
        .focus_input => |field_index| {
            if (field_index >= view.inputs.len) return;
            const field: FormField = @enumFromInt(field_index);
            if (pressed) {
                view.focused_field = field;
                view.interface_menu_open = false;
            }
            if (view.focused_field == field) view.inputs[field_index].handlePointer(&subsystem.fonts, formFieldInputId(field), pointer_x, pointer_state, 16, 14);
        },
        .toggle_interface_menu => {
            view.focused_field = null;
            view.interface_menu_open = !view.interface_menu_open;
        },
        .select_interface => |interface_index| selectInterface(subsystem, view, interface_index),
        .toggle_identity_transport_menu => |identity_index| {
            if (identity_index >= view.transport_script_selection.len) return;
            view.focused_field = null;
            view.interface_menu_open = false;
            view.transport_script_menu_identity = if (view.transport_script_menu_identity == identity_index) null else identity_index;
        },
        .select_identity_transport_script => |selection| {
            if (selection.identity >= view.transport_script_selection.len) return;
            if (selection.script) |script_index| if (script_index >= view.transport_scripts.len) return;
            const previous = view.transport_script_selection[selection.identity];
            view.transport_script_selection[selection.identity] = selection.script;
            view.transport_script_menu_identity = null;
            if (selection.identity >= view.identities.len) return;
            const identity = view.identities[selection.identity];
            const slot = subsystem.services.identities.slotFor(identity.file_name.value()) orelse return;
            const runtime_instance = subsystem.services.runtime_instance;
            const requested = if (selection.script != null) blk: {
                const source = selectedTransportSource(subsystem, view, selection.identity) catch {
                    view.transport_script_selection[selection.identity] = previous;
                    return;
                };
                break :blk runtime_instance.setTransportSource(slot, source orelse {
                    view.transport_script_selection[selection.identity] = previous;
                    return;
                });
            } else runtime_instance.clearTransportSource(slot);
            if (!requested) {
                view.transport_script_selection[selection.identity] = previous;
                uiLog("Could not update the active identity transport script.");
            }
        },
        .form_action => |form_action| handleIdentityAction(subsystem, view, form_action.action, form_action.index),
        else => {},
    }
}

fn handleScriptSignal(subsystem: *Subsystem, view: *ScriptingView, action: SignalAction, pointer_x: f32, pointer_state: c_int, pressed: bool) void {
    switch (action) {
        .focus_script_name => {
            if (pressed) {
                view.focus = .name;
                view.library_open = false;
                view.kind_menu_open = false;
                view.editor.closeMenu();
            }
            if (view.focus == .name) view.name.handlePointer(&subsystem.fonts, "script-name", pointer_x, pointer_state, 15, 12);
        },
        .toggle_script_kind_menu => {
            view.kind_menu_open = !view.kind_menu_open;
            view.library_open = false;
            if (view.focus == .name) view.focus = .none;
            view.editor.closeMenu();
        },
        .select_script_kind => |script_kind| selectScriptKind(subsystem, view, script_kind),
        .toggle_script_library => {
            view.library_open = !view.library_open;
            view.kind_menu_open = false;
            view.editor.closeMenu();
        },
        .script_editor => |editor_action| switch (editor_action) {
            .focus => {
                if (pressed) {
                    view.focus = .source;
                    view.library_open = false;
                    view.kind_menu_open = false;
                }
                if (view.focus == .source) view.editor.handlePointer(&subsystem.fonts, pointer_state);
            },
            .toggle_font_size_menu => {
                view.kind_menu_open = false;
                view.editor.handleAction(editor_action);
            },
            .select_font_size => view.editor.handleAction(editor_action),
        },
        .form_action => |form_action| handleScriptAction(subsystem, view, form_action.action, form_action.index),
        else => {},
    }
}

fn processSignals(subsystem: *Subsystem) void {
    var processed: usize = 0;
    while (processed < limits.ui_signal_event_capacity) : (processed += 1) {
        const signal = subsystem.pending_signals.pop() orelse break;
        handleSignalAction(subsystem, signal.action, signal.pointer_x, signal.pointer_state);
    }
    if (subsystem.signal_overflowed) {
        uiLog("UI signal capacity exhausted.");
        subsystem.signal_overflowed = false;
    }
}
