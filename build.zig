const std = @import("std");

const SharedBuildOptions = struct { target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode };

pub fn build(b: *std.Build) !void {
    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    const options = SharedBuildOptions{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const proj_options = std.Build.ExecutableOptions{
        .name = "zuws",
        .root_source_file = b.path("src/main.zig"),
        .target = options.target,
        .optimize = options.optimize,
    };

    const uWebSockets = try uWebSocketsLib(b, options, &flags);
    const exe = b.addExecutable(proj_options);
    exe.linkLibrary(uWebSockets[0]);
    exe.root_module.addImport("uws", uWebSockets[1].createModule());
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
    const exe_check = b.addExecutable(proj_options);
    exe_check.root_module.addImport("uws", uWebSockets[1].createModule());
    exe_check.linkLibrary(uWebSockets[0]);
    check.dependOn(&exe_check.step);
}

fn uWebSocketsLib(b: *std.Build, options: SharedBuildOptions, flags: *std.ArrayList([]const u8)) !struct { *std.Build.Step.Compile, *std.Build.Step.TranslateC } {
    const uSockets = try uSocketsLib(b, options, flags);
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

fn uSocketsLib(b: *std.Build, options: SharedBuildOptions, flags: *std.ArrayList([]const u8)) !*std.Build.Step.Compile {
    const uSockets = b.addStaticLibrary(.{
        .name = "uSockets",
        .target = options.target,
        .optimize = options.optimize,
    });

    uSockets.linkSystemLibrary("zlib");

    if (b.option(bool, "ssl", "Enable SSL support") orelse false) {
        uSockets.linkLibCpp();
    } else try flags.append("-DLIBUS_NO_SSL");

    uSockets.addIncludePath(b.path("uWebSockets/uSockets/src"));
    uSockets.installHeader(b.path("uWebSockets/uSockets/src/libusockets.h"), "libusockets.h");

    const uSocketsSourceFiles = &[_][]const u8{
        "bsd.c",
        "context.c",
        "loop.c",
        "quic.c",
        "socket.c",
        "udp.c",
        "crypto/openssl.c",
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
        .flags = flags.items,
    });

    return uSockets;
}
