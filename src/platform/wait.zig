const std = @import("std");
const windows = std.os.windows;
const linux = @import("builtin").os.tag == .linux;

pub const Handle = if (linux) std.c.pollfd else windows.HANDLE;

pub const Wake = struct {
    handle: Handle,

    pub fn init() !Wake {
        if (linux) {
            const fd = std.c.eventfd(0, std.os.linux.EFD.CLOEXEC | std.os.linux.EFD.NONBLOCK);
            if (fd < 0) return error.SystemResources;
            return .{ .handle = .{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 } };
        }
        return .{ .handle = CreateEventA(null, .TRUE, .FALSE, null) orelse return error.SystemResources };
    }

    pub fn deinit(self: Wake) void {
        if (linux) {
            _ = std.c.close(self.handle.fd);
        } else windows.CloseHandle(self.handle);
    }

    pub fn signal(self: Wake) void {
        if (linux) {
            const one: u64 = 1;
            while (std.c.errno(std.c.write(self.handle.fd, std.mem.asBytes(&one).ptr, @sizeOf(u64))) == .INTR) {}
        } else {
            _ = SetEvent(self.handle);
        }
    }

    // Reset before draining the queue, so a concurrent producer cannot lose a wakeup.
    pub fn reset(self: Wake) void {
        if (linux) {
            var count: u64 = undefined;
            _ = std.c.read(self.handle.fd, std.mem.asBytes(&count).ptr, @sizeOf(u64));
        } else {
            _ = ResetEvent(self.handle);
        }
    }
};

pub fn wait(handles: []Handle, milliseconds: ?u64) !void {
    if (linux) {
        const timeout: c_int = if (milliseconds) |ms| @intCast(@min(ms, std.math.maxInt(c_int))) else -1;
        switch (std.c.errno(std.c.poll(handles.ptr, @intCast(handles.len), timeout))) {
            .SUCCESS, .INTR => {},
            else => return error.WaitFailed,
        }
    } else {
        const result = WaitForMultipleObjects(@intCast(handles.len), handles.ptr, .FALSE, if (milliseconds) |ms| @intCast(@min(ms, 0xfffffffe)) else 0xffffffff);
        if (result == 0xffffffff) return error.WaitFailed;
    }
}

extern "kernel32" fn CreateEventA(?*anyopaque, windows.BOOL, windows.BOOL, ?[*:0]const u8) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn SetEvent(windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ResetEvent(windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn WaitForMultipleObjects(windows.DWORD, [*]const windows.HANDLE, windows.BOOL, windows.DWORD) callconv(.winapi) windows.DWORD;
