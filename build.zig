const std = @import("std");

const SharedBuildOptions = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};

pub fn build(b: *std.Build) !void {
    const shared_options = SharedBuildOptions{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const config_options = b.addOptions();
    const debug_logs = b.option(bool, "debug_logs", "Whether to enable debug logs for route creation.") orelse (shared_options.optimize == .Debug);

    config_options.addOption(bool, "debug_logs", debug_logs);

    const proj_options = .{
        .name = "zuws",
        .root_source_file = b.path("src/main.zig"),
        .target = shared_options.target,
        .optimize = shared_options.optimize,
    };

    var lib_options: std.Build.StaticLibraryOptions = proj_options;
    const exe_options: std.Build.ExecutableOptions = proj_options;
    const test_options: std.Build.TestOptions = proj_options;

    lib_options.root_source_file = b.path("src/uws.zig");
    _ = b.addModule(lib_options.name, .{
        .root_source_file = lib_options.root_source_file,
    });

    const uWebSockets = try uWebSocketsLib(b, shared_options);
    const exe = b.addExecutable(exe_options);
    exe.root_module.addOptions("config", config_options);
    exe.root_module.addImport("uws", uWebSockets[1].createModule());
    exe.linkLibrary(uWebSockets[0]);
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_exe.step);

    const emit_asm = b.step("asm", "Emit assembly file");
    const waf = b.addWriteFiles();
    waf.step.dependOn(b.getInstallStep());
    waf.addCopyFileToSource(exe.getEmittedAsm(), "main.asm");
    emit_asm.dependOn(&waf.step);

    const check = b.step("check", "Check if zuws compiles");
    const exe_check = b.addExecutable(exe_options);
    exe_check.root_module.addImport("uws", uWebSockets[1].createModule());
    exe_check.linkLibrary(uWebSockets[0]);
    check.dependOn(&exe_check.step);

    const test_step = b.step("test", "Run unit tests");
    const lib_tests = b.addTest(test_options);
    lib_tests.root_module.addOptions("config", config_options);
    lib_tests.root_module.addImport("uws", uWebSockets[1].createModule());
    lib_tests.linkLibrary(uWebSockets[0]);
    const run_lib_tests = b.addRunArtifact(lib_tests);
    test_step.dependOn(&run_lib_tests.step);
}

fn uWebSocketsLib(b: *std.Build, options: SharedBuildOptions) !struct { *std.Build.Step.Compile, *std.Build.Step.TranslateC } {
    const uSockets = try uSocketsLib(b, options);
    const uWebSockets = b.addStaticLibrary(.{
        .name = "uWebSockets",
        .target = options.target,
        .optimize = options.optimize,
    });
    uWebSockets.linkLibCpp();
    uWebSockets.linkLibrary(uSockets);
    uWebSockets.addCSourceFiles(.{ .root = b.path("."), .files = &.{"bindings/uws.cpp"} });
    b.installArtifact(uWebSockets);

    const uWS_c = b.addTranslateC(.{
        .root_source_file = b.path("bindings/uws.h"),
        .target = options.target,
        .optimize = options.optimize,
    });

    return .{ uWebSockets, uWS_c };
}

fn uSocketsLib(b: *std.Build, options: SharedBuildOptions) !*std.Build.Step.Compile {
    const uSockets = b.addStaticLibrary(.{
        .name = "uSockets",
        .target = options.target,
        .optimize = options.optimize,
    });

    uSockets.linkSystemLibrary("zlib");

    uSockets.addIncludePath(b.path("uWebSockets/uSockets/src"));
    uSockets.installHeader(b.path("uWebSockets/uSockets/src/libusockets.h"), "libusockets.h");

    const uSocketsSourceFiles = &[_][]const u8{
        "bsd.c",
        "context.c",
        "loop.c",
        "quic.c",
        "socket.c",
        "udp.c",
        "crypto/sni_tree.cpp",
        "eventing/epoll_kqueue.c",
        "eventing/gcd.c",
        "eventing/libuv.c",
        "io_uring/io_context.c",
        "io_uring/io_loop.c",
        "io_uring/io_socket.c",
    };

    uSockets.addCSourceFiles(.{
        .root = b.path("uWebSockets/uSockets/src/"),
        .files = uSocketsSourceFiles,
        .flags = &.{"-DLIBUS_NO_SSL"},
    });

    return uSockets;
}
