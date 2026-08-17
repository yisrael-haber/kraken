const script_repository = @import("../storage/script_repository.zig");

pub const Page = enum {
    identities,
    script_editor,
};

pub const Action = enum {
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

pub const InputEvent = union(enum) {
    codepoint: u32,
    key: enum { backspace, tab, enter, escape },
};

pub const EditorEvent = union(enum) {
    insert: u32,
    paste,
    key: struct {
        kind: enum { backspace, delete, enter, tab, left, right, up, down, home, end, escape, select_all, copy, cut },
        extend_selection: bool = false,
    },
};

pub const SignalBinding = struct {
    action: SignalAction,
    owner: ?*anyopaque = null,
};

pub const SignalAction = union(enum) {
    resize_sidebar,
    focus_input: usize,
    toggle_interface_menu,
    select_interface: usize,
    toggle_identity_transport_menu: usize,
    select_identity_transport_script: struct { identity: usize, script: ?usize },
    focus_script_name,
    toggle_script_kind_menu,
    select_script_kind: script_repository.Kind,
    toggle_script_library,
    focus_script_area,
    toggle_font_size_menu,
    select_font_size: u16,
    form_action: struct { action: Action, index: ?usize },
    select_page: Page,
};

pub const SignalEvent = struct {
    binding: SignalBinding,
    pointer_x: f32,
    pointer_state: i32,
};

pub const UiEvent = union(enum) {
    signal: SignalEvent,
    input: InputEvent,
    editor: EditorEvent,
};
