const std = @import("std");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const identity = @import("identity.zig");
const identity_config = @import("config.zig");
const storage_module = @import("../storage/storage.zig");
const runtime = @import("../runtime/runtime.zig");

pub const Command = union(enum) {
    save: identity.Identity,
    delete: []const u8,
    start: []const u8,
    stop: []const u8,
    set_transport: struct { id: []const u8, script: ?[]const u8 },
};

pub const Error = identity_config.Error || error{
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    RuntimeUnavailable,
    StorageFailure,
    TransportScriptUnavailable,
};

pub const Manager = struct {
    storage: *storage_module.Storage,
    runtime: *runtime.Runtime,
    catalog: std.ArrayList(identity.Identity) = .empty,
    mutex: std.Io.Mutex = .init,

    pub fn init(self: *Manager, storage: *storage_module.Storage, runtime_instance: *runtime.Runtime) !void {
        self.* = .{ .storage = storage, .runtime = runtime_instance };
        try self.storage.identities().load(self.storage.allocator, &self.catalog);
    }

    pub fn deinit(self: *Manager) void {
        self.catalog.deinit(self.storage.allocator);
    }

    pub fn snapshot(self: *const Manager) []const identity.Identity {
        return self.catalog.items;
    }

    pub fn execute(self: *Manager, command: Command) Error!void {
        self.mutex.lockUncancelable(io());
        defer self.mutex.unlock(io());
        switch (command) {
            .save => |submitted| {
                var value = submitted;
                if (value.id.value().len > 0) {
                    const current = self.find(value.id.value()) orelse return error.IdentityNotFound;
                    if (self.runtime.isActive(current.label.value())) return error.IdentityInUse;
                    if (self.findName(value.label.value(), value.id.value()) != null) return error.IdentityNameInUse;
                    value.transport = current.transport;
                } else if (self.findName(value.label.value(), null) != null) return error.IdentityNameInUse;
                self.storage.identities().save(value) catch return error.StorageFailure;
                self.reloadLocked() catch return error.StorageFailure;
            },
            .delete => |id| {
                const value = self.find(id) orelse return error.IdentityNotFound;
                if (self.runtime.isActive(value.label.value())) return error.IdentityInUse;
                self.storage.identities().delete(id) catch return error.StorageFailure;
                self.reloadLocked() catch return error.StorageFailure;
            },
            .start => |id| {
                const value = self.find(id) orelse return error.IdentityNotFound;
                try self.startLocked(value);
            },
            .stop => |id| {
                const value = self.find(id) orelse return error.IdentityNotFound;
                if (!self.runtime.stopNamed(value.label.value())) return error.RuntimeUnavailable;
            },
            .set_transport => |selection| {
                const value = self.find(selection.id) orelse return error.IdentityNotFound;
                var updated = value.*;
                updated.transport.set(selection.script orelse "") catch return error.TransportScriptUnavailable;
                const source = try self.transportSource(&updated);
                self.storage.identities().save(updated) catch return error.StorageFailure;
                value.* = updated;
                if (self.runtime.isActive(value.label.value()) and !self.runtime.setTransport(value.label.value(), source)) return error.RuntimeUnavailable;
            },
        }
    }

    pub fn globalControl(context: ?*anyopaque, action: runtime.GlobalAction) bool {
        const self: *Manager = @ptrCast(@alignCast(context orelse return false));
        return switch (action) {
            .start => |name| {
                self.mutex.lockUncancelable(io());
                defer self.mutex.unlock(io());
                const value = self.findName(name, null) orelse return false;
                self.startLocked(value) catch return false;
                return true;
            },
            .stop => |name| self.runtime.stopNamed(name),
            .send_raw => |send| self.runtime.sendNamed(send.name, send.frame),
        };
    }

    fn find(self: *Manager, id: []const u8) ?*identity.Identity {
        for (self.catalog.items) |*value| if (std.mem.eql(u8, value.id.value(), id)) return value;
        return null;
    }

    fn findName(self: *const Manager, name: []const u8, excluding_id: ?[]const u8) ?*const identity.Identity {
        for (self.catalog.items) |*value| {
            if (!std.mem.eql(u8, value.label.value(), name)) continue;
            if (excluding_id) |excluded| if (std.mem.eql(u8, value.id.value(), excluded)) continue;
            return value;
        }
        return null;
    }

    fn reloadLocked(self: *Manager) !void {
        var loaded: std.ArrayList(identity.Identity) = .empty;
        errdefer loaded.deinit(self.storage.allocator);
        try self.storage.identities().load(self.storage.allocator, &loaded);
        self.catalog.deinit(self.storage.allocator);
        self.catalog = loaded;
    }

    fn startLocked(self: *Manager, value: *const identity.Identity) Error!void {
        if (self.findName(value.label.value(), value.id.value()) != null) return error.IdentityNameInUse;
        const started = self.runtime.start(value.*, try self.transportSource(value)) catch |err| return err;
        if (!started) return error.RuntimeUnavailable;
    }

    fn transportSource(self: *Manager, value: *const identity.Identity) Error!?text.FixedText(limits.source_capacity) {
        if (value.transport.value().len == 0) return null;
        var source: text.FixedText(limits.source_capacity) = .{};
        self.storage.scripts(.transport).read(value.transport.value(), &source) catch return error.TransportScriptUnavailable;
        return source;
    }
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}
