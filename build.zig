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
    enableDeadCodeElimination(headless_tests, optimize);
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

fn addApplication(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
) *std.Build.Step.Compile {
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
    enableDeadCodeElimination(app, optimize);
    const c_bindings = addBindings(b, "src/kraken.h", target, optimize);
    const pcap_bindings = addBindings(b, "src/pcap_bindings.h", target, optimize);
    // Keep vendor socket headers out of kraken.h and translate their APIs separately.
    const cares_bindings = addBindings(b, "src/cares_bindings.h", target, optimize);
    const wolfssl_bindings = addBindings(b, "src/wolfssl_bindings.h", target, optimize);
    const libsmb2_bindings = addBindings(b, "src/libsmb2_bindings.h", target, optimize);
    const yaml_bindings = addBindings(b, "src/yaml_bindings.h", target, optimize);
    const ldap_bindings = addBindings(b, "src/ldap_bindings.h", target, optimize);
    const telnet_bindings = addBindings(b, "src/telnet_bindings.h", target, optimize);
    telnet_bindings.addIncludePath(b.path("vendor/libtelnet"));
    for ([_][]const u8{ "vendor/openldap/kraken", "vendor/openldap/include" }) |path| {
        ldap_bindings.addIncludePath(b.path(path));
    }
    libsmb2_bindings.defineCMacro("KRAKEN_LIBSMB2", "");
    if (target.result.os.tag == .windows) {
        libsmb2_bindings.defineCMacro("_WINDOWS", "");
        libsmb2_bindings.defineCMacro("WIN32_LEAN_AND_MEAN", "");
    }
    if (target.result.os.tag == .windows) {
        app.subsystem = .Windows;
    }

    for ([_][]const u8{
        "vendor/clay",           "vendor/clay/renderers/sokol", "vendor/sokol",
        "vendor/sokol/util",     "vendor/fontstash/src",        "vendor/lua/src",
        "vendor/mpack",          "vendor/tlsf",
        "vendor/picohttpparser", "src",
    }) |path| {
        app_module.addIncludePath(b.path(path));
        c_bindings.addIncludePath(b.path(path));
    }
    const net_types = b.createModule(.{
        .root_source_file = b.path("src/net/types.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lwip_bindings = addBindings(b, "src/net/lwip.h", target, optimize);
    const net_backend = b.createModule(.{
        .root_source_file = b.path("src/net/lwip.zig"),
        .target = target,
        .optimize = optimize,
    });
    net_backend.addImport("net_types", net_types);
    net_backend.addImport("lwip_c", lwip_bindings.createModule());
    app_module.addImport("net_types", net_types);
    app_module.addImport("net_backend", net_backend);
    for ([_][]const u8{ "vendor/c-ares/include", "vendor/c-ares/kraken" }) |path| {
        app_module.addIncludePath(b.path(path));
        cares_bindings.addIncludePath(b.path(path));
    }
    for ([_][]const u8{ "vendor/c-ares/src/lib", "vendor/c-ares/src/lib/include" }) |path| {
        app_module.addIncludePath(b.path(path));
    }
    for ([_][]const u8{ "vendor/wolfssl/kraken", "vendor/wolfssl", "vendor/wolfssh" }) |path| {
        app_module.addIncludePath(b.path(path));
        wolfssl_bindings.addIncludePath(b.path(path));
    }
    for ([_][]const u8{ "vendor/libsmb2/kraken", "vendor/libsmb2/include", "vendor/libsmb2/lib" }) |path| {
        libsmb2_bindings.addIncludePath(b.path(path));
    }
    yaml_bindings.addIncludePath(b.path("vendor/libyaml/include"));
    yaml_bindings.defineCMacro("YAML_DECLARE_STATIC", "");
    app_module.addIncludePath(b.path("vendor/libyaml/include"));
    // Library configuration, seen by their sources and their bindings alike.
    // WOLFSSL_USER_SETTINGS selects kraken/user_settings.h; WOLFSSH_SHELL compiles
    // in the exit-status API; WOLFSSH_USER_IO drops wolfSSH's socket I/O.
    cares_bindings.defineCMacro("CARES_STATICLIB", "");
    app_module.addCMacro("CARES_STATICLIB", "");
    for ([_][]const u8{ "WOLFSSL_USER_SETTINGS", "WOLFSSH_SHELL", "WOLFSSH_USER_IO" }) |macro| {
        wolfssl_bindings.defineCMacro(macro, "");
        app_module.addCMacro(macro, "");
    }
    pcap_bindings.addIncludePath(b.path("vendor/npcap/include"));
    for ([_][]const u8{ "src/net", "vendor/lwip/src/include" }) |path| app_module.addIncludePath(b.path(path));
    switch (target.result.os.tag) {
        .linux => {
            app_module.addIncludePath(b.path("vendor/lwip/contrib/ports/unix/port/include"));
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
            app_module.addIncludePath(b.path("vendor/lwip/contrib/ports/win32/include"));
            app_module.addCMacro("SOKOL_D3D11", "");
            c_bindings.defineCMacro("SOKOL_D3D11", "");
            for ([_][]const u8{ "kernel32", "user32", "shell32", "gdi32", "d3d11", "dxgi", "advapi32", "ws2_32" }) |library| {
                app_module.linkSystemLibrary(library, .{});
            }
            app_module.addObjectFile(b.path("vendor/npcap/x64/wpcap.lib"));
        },
        else => @panic("This experiment currently supports Linux and Windows targets."),
    }
    app_module.addImport("c", c_bindings.createModule());
    app_module.addImport("pcap_c", pcap_bindings.createModule());
    app_module.addImport("cares", cares_bindings.createModule());
    app_module.addImport("wolfssl", wolfssl_bindings.createModule());
    app_module.addImport("libsmb2", libsmb2_bindings.createModule());
    app_module.addImport("yaml", yaml_bindings.createModule());
    app_module.addImport("ldap", ldap_bindings.createModule());
    app_module.addImport("telnet", telnet_bindings.createModule());
    app_module.addImport("font", font_module);
    app_module.addImport("known-folders", b.dependency("known_folders", .{}).module("known-folders"));
    app_module.addCSourceFiles(.{
        .files = &.{
            "src/clay_impl.c",                        "src/sokol.c",               "vendor/lua/src/lapi.c",
            "vendor/lua/src/lauxlib.c",               "vendor/lua/src/lbaselib.c", "vendor/lua/src/lcode.c",
            "vendor/lua/src/lcorolib.c",              "vendor/lua/src/lctype.c",   "vendor/lua/src/ldblib.c",
            "vendor/lua/src/ldebug.c",                "vendor/lua/src/ldo.c",      "vendor/lua/src/ldump.c",
            "vendor/lua/src/lfunc.c",                 "vendor/lua/src/lgc.c",      "vendor/lua/src/linit.c",
            "vendor/lua/src/liolib.c",                "vendor/lua/src/llex.c",     "vendor/lua/src/lmathlib.c",
            "vendor/lua/src/lmem.c",                  "vendor/lua/src/loadlib.c",  "vendor/lua/src/lobject.c",
            "vendor/lua/src/lopcodes.c",              "vendor/lua/src/loslib.c",   "vendor/lua/src/lparser.c",
            "vendor/lua/src/lstate.c",                "vendor/lua/src/lstring.c",  "vendor/lua/src/lstrlib.c",
            "vendor/lua/src/ltable.c",                "vendor/lua/src/ltablib.c",  "vendor/lua/src/ltm.c",
            "vendor/lua/src/lundump.c",               "vendor/lua/src/lutf8lib.c", "vendor/lua/src/lvm.c",
            "vendor/lua/src/lzio.c",                  "src/mpack.c",               "vendor/tlsf/tlsf.c",
            "vendor/picohttpparser/picohttpparser.c",
        },
        .flags = &.{"-std=c99"},
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/c-ares"),
        .files = &.{
            "src/lib/record/ares_dns_mapping.c", "src/lib/record/ares_dns_multistring.c",
            "src/lib/record/ares_dns_name.c",    "src/lib/record/ares_dns_parse.c",
            "src/lib/record/ares_dns_record.c",  "src/lib/record/ares_dns_write.c",
            "src/lib/str/ares_buf.c",            "src/lib/str/ares_str.c",
            "src/lib/dsa/ares_array.c",          "src/lib/dsa/ares_llist.c",
            "src/lib/util/ares_math.c",          "src/lib/ares_free_string.c",
            "src/lib/ares_strerror.c",           "src/lib/ares_library_init.c",
            "kraken/ares_stub.c",
        },
        // Windows uses the upstream config-win32.h, selected when HAVE_CONFIG_H is absent.
        .flags = if (target.result.os.tag == .windows) &.{"-std=c99"} else &.{ "-std=c99", "-DHAVE_CONFIG_H" },
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/libtelnet"),
        .files = &.{"libtelnet.c"},
        .flags = &.{"-std=c99"},
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/libyaml"),
        .files = &.{ "src/api.c", "src/parser.c", "src/reader.c", "src/scanner.c" },
        .flags = &.{
            "-std=c99",
            "-DYAML_DECLARE_STATIC",
            "-DYAML_VERSION_MAJOR=0",
            "-DYAML_VERSION_MINOR=2",
            "-DYAML_VERSION_PATCH=5",
            "-DYAML_VERSION_STRING=\"0.2.5\"",
        },
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/wolfssl"),
        .files = &.{
            "src/internal.c",                "src/keys.c",
            "src/ssl.c",                     "src/tls.c",
            "src/tls13.c",                   "src/wolfio.c",
            "wolfcrypt/src/aes.c",           "wolfcrypt/src/asn.c",
            "wolfcrypt/src/chacha.c",        "wolfcrypt/src/chacha20_poly1305.c",
            "wolfcrypt/src/coding.c",        "wolfcrypt/src/cpuid.c",
            "wolfcrypt/src/curve25519.c",    "wolfcrypt/src/dh.c",
            "wolfcrypt/src/ecc.c",           "wolfcrypt/src/ed25519.c",
            "wolfcrypt/src/error.c",         "wolfcrypt/src/fe_operations.c",
            "wolfcrypt/src/ge_operations.c", "wolfcrypt/src/hash.c",
            "wolfcrypt/src/hmac.c",          "wolfcrypt/src/kdf.c",
            "wolfcrypt/src/logging.c",       "wolfcrypt/src/md5.c",
            "wolfcrypt/src/memory.c",        "wolfcrypt/src/poly1305.c",
            "wolfcrypt/src/random.c",        "wolfcrypt/src/rsa.c",
            "wolfcrypt/src/sha.c",           "wolfcrypt/src/sha256.c",
            "wolfcrypt/src/sha512.c",        "wolfcrypt/src/signature.c",
            "wolfcrypt/src/sp_c32.c",        "wolfcrypt/src/sp_int.c",
            "wolfcrypt/src/wc_encrypt.c",    "wolfcrypt/src/wc_port.c",
            "wolfcrypt/src/wolfmath.c",
        },
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/wolfssh"),
        .files = &.{
            "src/internal.c",    "src/io.c",   "src/log.c",
            "src/misc.c",        "src/port.c", "src/ssh.c",
            "kraken/ssh_shim.c",
        },
    });
    app_module.addCSourceFiles(.{
        .root = b.path("vendor/lwip"),
        .files = &.{
            "src/core/init.c", "src/core/def.c", "src/core/inet_chksum.c",
            "src/core/ip.c", "src/core/mem.c", "src/core/memp.c", "src/core/netif.c",
            "src/core/pbuf.c", "src/core/raw.c", "src/core/stats.c", "src/core/sys.c",
            "src/core/altcp.c", "src/core/altcp_alloc.c", "src/core/altcp_tcp.c",
            "src/core/tcp.c", "src/core/tcp_in.c", "src/core/tcp_out.c",
            "src/core/timeouts.c", "src/core/udp.c",
            "src/core/ipv4/etharp.c", "src/core/ipv4/icmp.c",
            "src/core/ipv4/ip4_frag.c", "src/core/ipv4/ip4.c", "src/core/ipv4/ip4_addr.c",
            "src/api/api_lib.c", "src/api/api_msg.c", "src/api/err.c",
            "src/api/if_api.c", "src/api/netbuf.c",
            "src/api/netifapi.c", "src/api/sockets.c", "src/api/tcpip.c",
            "src/netif/ethernet.c",
        },
        .flags = &.{"-std=c11"},
    });
    app_module.addCSourceFiles(.{
        .files = &.{"src/net/lwip.c"},
        .flags = &.{"-std=c11"},
    });
    app_module.addCSourceFiles(.{
        .files = &.{if (target.result.os.tag == .windows)
            "vendor/lwip/contrib/ports/win32/sys_arch.c"
        else
            "vendor/lwip/contrib/ports/unix/port/sys_arch.c"},
        .flags = &.{"-std=c11"},
    });
    const libsmb2_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    for ([_][]const u8{
        "vendor/libsmb2/kraken",       "vendor/libsmb2/include",
        "vendor/libsmb2/include/smb2", "vendor/libsmb2/lib",
    }) |path| libsmb2_module.addIncludePath(b.path(path));
    libsmb2_module.addCMacro("HAVE_CONFIG_H", "");
    libsmb2_module.addCMacro("KRAKEN_LIBSMB2", "");
    libsmb2_module.addCMacro("_U_", "__attribute__((unused))");
    if (target.result.os.tag == .windows) {
        libsmb2_module.addCMacro("_WINDOWS", "");
        libsmb2_module.addCMacro("WIN32_LEAN_AND_MEAN", "");
        libsmb2_module.addCMacro("NEED_RANDOM", "");
        libsmb2_module.addCMacro("NEED_SRANDOM", "");
        libsmb2_module.addCMacro("NEED_GETLOGIN_R", "");
    }
    libsmb2_module.addCSourceFiles(.{
        .root = b.path("vendor/libsmb2"),
        .files = &.{
            "lib/aes.c",                     "lib/aes_reference.c",             "lib/aes128ccm.c",
            "lib/alloc.c",                   "lib/asn1-ber.c",                  "lib/compat.c",
            "lib/libsmb2-dcerpc.c",          "lib/libsmb2-dcerpc-srvsvc.c",     "lib/errors.c",
            "lib/hmac.c",                    "lib/hmac-md5.c",                  "lib/init.c",
            "lib/libsmb2.c",                 "lib/md4c.c",                      "lib/md5.c",
            "lib/ntlmssp.c",                 "lib/pdu.c",                       "lib/sha1.c",
            "lib/sha224-256.c",              "lib/sha384-512.c",                "lib/smb2-cmd-close.c",
            "lib/smb2-cmd-create.c",         "lib/smb2-cmd-echo.c",             "lib/smb2-cmd-error.c",
            "lib/smb2-cmd-flush.c",          "lib/smb2-cmd-ioctl.c",            "lib/smb2-cmd-lock.c",
            "lib/smb2-cmd-logoff.c",         "lib/smb2-cmd-negotiate.c",        "lib/smb2-cmd-notify-change.c",
            "lib/smb2-cmd-oplock-break.c",   "lib/smb2-cmd-query-directory.c",  "lib/smb2-cmd-query-info.c",
            "lib/smb2-cmd-read.c",           "lib/smb2-cmd-session-setup.c",    "lib/smb2-cmd-set-info.c",
            "lib/smb2-cmd-tree-connect.c",   "lib/smb2-cmd-tree-disconnect.c",  "lib/smb2-cmd-write.c",
            "lib/smb2-data-file-info.c",     "lib/smb2-data-filesystem-info.c", "lib/smb2-data-security-descriptor.c",
            "lib/smb2-data-reparse-point.c", "lib/smb2-share-enum.c",           "lib/smb3-seal.c",
            "lib/smb2-signing.c",            "lib/socket.c",                    "lib/spnego-wrapper.c",
            "lib/sync.c",                    "lib/timestamps.c",                "lib/unicode.c",
            "lib/usha.c",                    "libdcerpc/dcerpc.c",              "libdcerpc/dcerpc-dtyp.c",
            "libdcerpc/dcerpc-epm.c",        "libdcerpc/dcerpc-lsa.c",          "libdcerpc/dcerpc-srvsvc.c",
            "libdcerpc/dcerpc-winreg.c",     "libdcerpc/dcerpc-wkssvc.c",
        },
        .flags = &.{"-std=gnu99"},
    });
    const libsmb2_library = b.addLibrary(.{
        .name = "kraken-smb2",
        .root_module = libsmb2_module,
    });
    enableDeadCodeElimination(libsmb2_library, optimize);
    app_module.linkLibrary(libsmb2_library);

    // OpenLDAP's liblber and libldap with no threads, TLS or SASL. The headers in
    // vendor/openldap/kraken are what its configure script generates, per platform.
    const ldap_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    for ([_][]const u8{
        if (target.result.os.tag == .windows) "vendor/openldap/kraken/windows" else "vendor/openldap/kraken/linux",
        "vendor/openldap/kraken",
        "vendor/openldap/include",
        "vendor/openldap/libraries/libldap",
        "vendor/openldap/libraries/liblber",
    }) |path| ldap_module.addIncludePath(b.path(path));
    ldap_module.addCMacro("LDAP_LIBRARY", "");
    ldap_module.addCMacro("LBER_LIBRARY", "");
    ldap_module.addCSourceFiles(.{
        .root = b.path("vendor/openldap/libraries"),
        .files = &.{
            "liblber/bprint.c",     "liblber/decode.c",   "liblber/encode.c",    "liblber/io.c",
            "liblber/memory.c",     "liblber/options.c",  "liblber/sockbuf.c",   "libldap/abandon.c",
            "libldap/add.c",        "libldap/avl.c",      "libldap/charray.c",   "libldap/compare.c",
            "libldap/controls.c",   "libldap/cyrus.c",    "libldap/delete.c",    "libldap/error.c",
            "libldap/extended.c",   "libldap/fetch.c",    "libldap/filter.c",    "libldap/free.c",
            "libldap/getattr.c",    "libldap/getdn.c",    "libldap/getentry.c",  "libldap/getvalues.c",
            "libldap/init.c",       "libldap/lbase64.c",  "libldap/ldif.c",      "libldap/modify.c",
            "libldap/modrdn.c",     "libldap/open.c",     "libldap/options.c",   "libldap/os-ip.c",
            "libldap/references.c", "libldap/request.c",   "libldap/result.c",   "libldap/sasl.c",      "libldap/schema.c",
            "libldap/search.c",     "libldap/tavl.c",     "libldap/unbind.c",    "libldap/url.c",
            "libldap/utf-8.c",      "libldap/util-int.c",
        },
        .flags = &.{ "-std=gnu99", "-D_DEFAULT_SOURCE" },
    });
    const ldap_library = b.addLibrary(.{
        .name = "kraken-ldap",
        .root_module = ldap_module,
    });
    enableDeadCodeElimination(ldap_library, optimize);
    app_module.linkLibrary(ldap_library);
    if (target.result.os.tag == b.graph.host.result.os.tag and target.result.cpu.arch == b.graph.host.result.cpu.arch) {
        const tests = b.addTest(.{ .root_module = app_module });
        enableDeadCodeElimination(tests, optimize);
        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
    }
    return app;
}

fn enableDeadCodeElimination(artifact: *std.Build.Step.Compile, optimize: std.builtin.OptimizeMode) void {
    if (optimize == .Debug) return;
    artifact.link_function_sections = true;
    artifact.link_data_sections = true;
    artifact.link_gc_sections = true;
}

fn addBindings(b: *std.Build, header: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.TranslateC {
    return b.addTranslateC(.{
        .root_source_file = b.path(header),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
}
