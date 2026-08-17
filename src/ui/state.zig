const limits = @import("../limits.zig");
const event = @import("event.zig");
const dispatch = @import("dispatch.zig");
const storage_module = @import("../storage/storage.zig");
const identity_service = @import("../identities/service.zig");
const runtime = @import("../runtime/runtime.zig");

pub const Services = struct {
    storage: *storage_module.Storage,
    identities: *identity_service.Service,
    runtime_instance: *runtime.AppRuntime,
};

pub const FocusState = union(enum) {
    none,
    identity_field: usize,
    script_name,
    script_editor,
};

pub const Notification = struct {
    bytes: [256]u8 = [_]u8{0} ** 256,
    len: u8 = 0,

    pub fn set(self: *Notification, message: []const u8) void {
        self.len = @intCast(@min(self.bytes.len, message.len));
        @memcpy(self.bytes[0..self.len], message[0..self.len]);
    }

    pub fn value(self: *const Notification) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn UiState(comptime SidePanelState: type, comptime PageState: type) type {
    return struct {
        services: Services = undefined,
        side_panel: SidePanelState = .{},
        page: PageState,
        focus: FocusState = .none,
        signals: SignalTable = .{},
        pending_events: EventQueue = .{},
        notification: ?Notification = null,
        pointer_click_generation: usize = 0,
        handled_pointer_click_generation: usize = 0,

        pub fn init(self: *@This(), services: Services, page: PageState) void {
            self.* = .{ .services = services, .page = page };
        }

        pub fn beginRender(self: *@This()) void {
            self.signals.reset();
        }

        /// The active tagged-union payload selects its renderer by type.
        pub fn render(self: *@This(), context: anytype) void {
            switch (self.page) {
                inline else => |*payload| payload.render(context),
            }
        }

        pub fn bind(self: *@This(), binding: event.SignalBinding) ?*event.SignalBinding {
            var owned = binding;
            owned.owner = @ptrCast(self);
            return self.signals.add(owned);
        }

        pub fn enqueue(self: *@This(), value: event.UiEvent) void {
            if (self.pending_events.push(value)) return;
            var notification: Notification = .{};
            notification.set("UI event capacity exceeded; input was dropped.");
            self.notification = notification;
        }

        pub fn nextEvent(self: *@This()) ?event.UiEvent {
            return self.pending_events.pop();
        }

        pub fn handle(_: *@This(), context: anytype, value: event.UiEvent) void {
            dispatch.dispatch(context, value);
        }
    };
}

const SignalTable = struct {
    values: [limits.ui_signal_capacity]event.SignalBinding = undefined,
    len: usize = 0,

    fn reset(self: *SignalTable) void {
        self.len = 0;
    }

    fn add(self: *SignalTable, value: event.SignalBinding) ?*event.SignalBinding {
        if (self.len == self.values.len) return null;
        const result = &self.values[self.len];
        result.* = value;
        self.len += 1;
        return result;
    }
};

const EventQueue = struct {
    values: [limits.ui_event_capacity]event.UiEvent = undefined,
    read: usize = 0,
    len: usize = 0,

    fn push(self: *EventQueue, value: event.UiEvent) bool {
        if (self.len == self.values.len) return false;
        self.values[(self.read + self.len) % self.values.len] = value;
        self.len += 1;
        return true;
    }

    fn pop(self: *EventQueue) ?event.UiEvent {
        if (self.len == 0) return null;
        const result = self.values[self.read];
        self.read = (self.read + 1) % self.values.len;
        self.len -= 1;
        return result;
    }
};

test "signal and event storage are bounded" {
    const testing = @import("std").testing;
    const DummyPanel = struct {};
    const DummyPage = union(enum) { empty };
    var state: UiState(DummyPanel, DummyPage) = undefined;
    state.init(undefined, .empty);
    const binding = state.bind(.{ .action = .resize_sidebar }).?;
    try testing.expect(binding.owner == @as(?*anyopaque, @ptrCast(&state)));
    state.enqueue(.{ .signal = .{ .binding = .{ .action = .resize_sidebar }, .pointer_x = 3, .pointer_state = 4 } });
    try testing.expect(state.nextEvent() != null);
}
