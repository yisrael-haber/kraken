const std = @import("std");
const limits = @import("../limits.zig");
const text = @import("../text.zig");
const command = @import("../command.zig");
const identity = @import("identity.zig");
const storage_module = @import("../storage/storage.zig");
const runtime = @import("../runtime/runtime.zig");
const stack = @import("../runtime/stack.zig");

pub const Error = stack.Error || error{
    IdentityNotFound,
    IdentityNameInUse,
    IdentityInUse,
    RuntimeUnavailable,
    StorageFailure,
    TransportScriptUnavailable,
};

pub const Manager = struct {
    storage: *storage_module.Storage,
    worker_pool: *runtime.WorkerPool,
    catalog: std.ArrayList(identity.Identity) = .empty,

    pub fn init(self: *Manager, storage: *storage_module.Storage, worker_pool: *runtime.WorkerPool) !void {
        self.* = .{ .storage = storage, .worker_pool = worker_pool };
        try self.storage.identities().load(self.storage.allocator, &self.catalog);
    }

    pub fn deinit(self: *Manager) void {
        self.catalog.deinit(self.storage.allocator);
    }

    pub fn snapshot(self: *const Manager) []const identity.Identity {
        return self.catalog.items;
    }

    pub fn isRunning(self: *const Manager, name: []const u8) bool {
        return self.worker_pool.isInUse(name);
    }

    pub fn execute(self: *Manager, request: command.Command) Error!void {
        switch (request) {
            .save => |submitted| {
                var value = submitted;
                if (value.id.value().len > 0) {
                    const current = self.findId(value.id.value()) orelse return error.IdentityNotFound;
                    if (self.worker_pool.isInUse(current.label.value())) return error.IdentityInUse;
                    if (self.findName(value.label.value(), value.id.value()) != null) return error.IdentityNameInUse;
                    value.transport = current.transport;
                } else if (self.findName(value.label.value(), null) != null) return error.IdentityNameInUse;
                self.storage.identities().save(value) catch return error.StorageFailure;
                self.reload() catch return error.StorageFailure;
            },
            .delete => |name| {
                const value = self.findName(name.value(), null) orelse return error.IdentityNotFound;
                if (self.worker_pool.isInUse(value.label.value())) return error.IdentityInUse;
                self.storage.identities().delete(value.id.value()) catch return error.StorageFailure;
                self.reload() catch return error.StorageFailure;
            },
            .start => |name| {
                const value = self.findName(name.value(), null) orelse return error.IdentityNotFound;
                if (self.findName(value.label.value(), value.id.value()) != null) return error.IdentityNameInUse;
                if (!try self.worker_pool.start(value, try self.transportSource(value))) return error.RuntimeUnavailable;
            },
            .stop => |name| {
                _ = self.findName(name.value(), null) orelse return error.IdentityNotFound;
                if (!self.worker_pool.execute(request)) return error.RuntimeUnavailable;
            },
            .set_transport => |selection| {
                const value = self.findName(selection.name.value(), null) orelse return error.IdentityNotFound;
                var updated = value.*;
                updated.transport = if (selection.script) |script| script.name else .{};
                self.storage.identities().save(updated) catch return error.StorageFailure;
                value.* = updated;
                if (self.worker_pool.isInUse(value.label.value()) and !self.worker_pool.execute(request)) return error.RuntimeUnavailable;
            },
            .send_packet => |packet| {
                _ = self.findName(packet.name.value(), null) orelse return error.IdentityNotFound;
                if (!self.worker_pool.execute(request)) return error.RuntimeUnavailable;
            },
        }
    }

    fn findId(self: *Manager, id: []const u8) ?*identity.Identity {
        for (self.catalog.items) |*value| if (std.mem.eql(u8, value.id.value(), id)) return value;
        return null;
    }

    fn findName(self: *Manager, name: []const u8, excluding_id: ?[]const u8) ?*identity.Identity {
        for (self.catalog.items) |*value| {
            if (!std.mem.eql(u8, value.label.value(), name)) continue;
            if (excluding_id) |excluded| if (std.mem.eql(u8, value.id.value(), excluded)) continue;
            return value;
        }
        return null;
    }

    fn reload(self: *Manager) !void {
        var loaded: std.ArrayList(identity.Identity) = .empty;
        errdefer loaded.deinit(self.storage.allocator);
        try self.storage.identities().load(self.storage.allocator, &loaded);
        self.catalog.deinit(self.storage.allocator);
        self.catalog = loaded;
    }

    fn transportSource(self: *Manager, value: *const identity.Identity) Error!?text.FixedText(limits.source_capacity) {
        if (value.transport.value().len == 0) return null;
        var source: text.FixedText(limits.source_capacity) = .{};
        self.storage.scripts(.transport).read(value.transport.value(), &source) catch return error.TransportScriptUnavailable;
        return source;
    }
};
