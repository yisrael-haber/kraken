const std = @import("std");

pub fn get() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn now() std.Io.Timestamp {
    return std.Io.Clock.awake.now(get());
}
