const std = @import("std");

pub fn build(b: *std.Build) void {
    // A plain `zig build` creates both distributable targets under dist/.
    b.resolveInstallPrefix("dist", .{});
    _ = b.option([]const u8, "target", "Ignored: Kraken always builds Linux and Windows");
    _ = b.option([]const u8, "cpu", "Ignored: Kraken always builds its distribution CPU targets");
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Prioritize performance, safety, or binary size") orelse .ReleaseSmall;

    const test_step = b.step("test", "Run headless and application tests on the host target");
    const linux_query: std.Target.Query = .{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .gnu,
    };
    const linux_target = if (b.graph.host.result.cpu.arch == .x86_64 and
        b.graph.host.result.os.tag == .linux and
        b.graph.host.result.abi == .gnu)
        b.graph.host
    else
        b.resolveTargetQuery(linux_query);
    const windows_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
    });
    const linux_app = addApplication(b, linux_target, optimize, test_step);
    const windows_app = addApplication(b, windows_target, optimize, test_step);

    const headless_module = b.createModule(.{
        .root_source_file = b.path("src/headless_tests.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const headless_tests = b.addTest(.{ .root_module = headless_module });
    test_step.dependOn(&b.addRunArtifact(headless_tests).step);

    const linux_install = b.addInstallArtifact(linux_app, .{
        .dest_dir = .{ .override = .{ .custom = "linux/bin" } },
    });
    const windows_install = b.addInstallArtifact(windows_app, .{
        .dest_dir = .{ .override = .{ .custom = "windows/bin" } },
    });
    b.getInstallStep().dependOn(&linux_install.step);
    b.getInstallStep().dependOn(&windows_install.step);
}

fn addApplication(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, test_step: *std.Build.Step) *std.Build.Step.Compile {
    const app_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const font_module = b.createModule(.{
        .root_source_file = b.path("font.zig"),
        .target = target,
        .optimize = optimize,
    });
    const app = b.addExecutable(.{
        .name = "kraken",
        .root_module = app_module,
    });
    const c_bindings = b.addTranslateC(.{
        .root_source_file = b.path("src/kraken.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const pcap_bindings = b.addTranslateC(.{
        .root_source_file = b.path("src/pcap_bindings.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    if (target.result.os.tag == .windows) {
        app.subsystem = .Windows;
    }

    app_module.addIncludePath(b.path("vendor/clay"));
    app_module.addIncludePath(b.path("vendor/clay/renderers/sokol"));
    app_module.addIncludePath(b.path("vendor/sokol"));
    app_module.addIncludePath(b.path("vendor/sokol/util"));
    app_module.addIncludePath(b.path("vendor/fontstash/src"));
    app_module.addIncludePath(b.path("vendor/lua/src"));
    app_module.addIncludePath(b.path("vendor/wolfip"));
    app_module.addIncludePath(b.path("src"));
    c_bindings.addIncludePath(b.path("vendor/clay"));
    c_bindings.addIncludePath(b.path("vendor/clay/renderers/sokol"));
    c_bindings.addIncludePath(b.path("vendor/sokol"));
    c_bindings.addIncludePath(b.path("vendor/sokol/util"));
    c_bindings.addIncludePath(b.path("vendor/fontstash/src"));
    c_bindings.addIncludePath(b.path("vendor/lua/src"));
    c_bindings.addIncludePath(b.path("vendor/wolfip"));
    c_bindings.addIncludePath(b.path("src"));
    pcap_bindings.addIncludePath(b.path("vendor/npcap/include"));
    switch (target.result.os.tag) {
        .linux => {
            app_module.addCMacro("_POSIX_C_SOURCE", "200809L");
            app_module.addCMacro("_DEFAULT_SOURCE", "");
            app_module.addCMacro("SOKOL_GLCORE", "");
            c_bindings.defineCMacro("_POSIX_C_SOURCE", "200809L");
            c_bindings.defineCMacro("_DEFAULT_SOURCE", "");
            c_bindings.defineCMacro("SOKOL_GLCORE", "");
            for ([_][]const u8{ "X11", "Xi", "Xcursor", "GL", "dl", "m", "pthread" }) |library| {
                app_module.linkSystemLibrary(library, .{});
            }
            app_module.linkSystemLibrary("pcap", .{});
        },
        .windows => {
            app_module.addCMacro("SOKOL_D3D11", "");
            c_bindings.defineCMacro("SOKOL_D3D11", "");
            for ([_][]const u8{ "kernel32", "user32", "shell32", "gdi32", "d3d11", "dxgi" }) |library| {
                app_module.linkSystemLibrary(library, .{});
            }
            app_module.addObjectFile(b.path("vendor/npcap/x64/wpcap.lib"));
        },
        else => @panic("This experiment currently supports Linux and Windows targets."),
    }
    app_module.addImport("c", c_bindings.createModule());
    app_module.addImport("pcap_c", pcap_bindings.createModule());
    app_module.addImport("font", font_module);
    app_module.addImport("known-folders", b.dependency("known_folders", .{}).module("known-folders"));
    app_module.addCSourceFiles(.{
        .files = &.{
            "src/clay_impl.c",           "src/sokol.c",               "vendor/lua/src/lapi.c",
            "vendor/lua/src/lauxlib.c",  "vendor/lua/src/lbaselib.c", "vendor/lua/src/lcode.c",
            "vendor/lua/src/lcorolib.c", "vendor/lua/src/lctype.c",   "vendor/lua/src/ldblib.c",
            "vendor/lua/src/ldebug.c",   "vendor/lua/src/ldo.c",      "vendor/lua/src/ldump.c",
            "vendor/lua/src/lfunc.c",    "vendor/lua/src/lgc.c",      "vendor/lua/src/linit.c",
            "vendor/lua/src/liolib.c",   "vendor/lua/src/llex.c",     "vendor/lua/src/lmathlib.c",
            "vendor/lua/src/lmem.c",     "vendor/lua/src/loadlib.c",  "vendor/lua/src/lobject.c",
            "vendor/lua/src/lopcodes.c", "vendor/lua/src/loslib.c",   "vendor/lua/src/lparser.c",
            "vendor/lua/src/lstate.c",   "vendor/lua/src/lstring.c",  "vendor/lua/src/lstrlib.c",
            "vendor/lua/src/ltable.c",   "vendor/lua/src/ltablib.c",  "vendor/lua/src/ltm.c",
            "vendor/lua/src/lundump.c",  "vendor/lua/src/lutf8lib.c", "vendor/lua/src/lvm.c",
            "vendor/lua/src/lzio.c",
        },
        .flags = &.{"-std=c99"},
    });
    app_module.addCSourceFiles(.{
        .files = &.{"vendor/wolfip/src/wolfip.c"},
        .flags = &.{"-std=c11"},
    });
    if (target.result.os.tag == b.graph.host.result.os.tag and target.result.cpu.arch == b.graph.host.result.cpu.arch) {
        const tests = b.addTest(.{ .root_module = app_module });
        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
    }
    return app;
}
