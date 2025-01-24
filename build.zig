const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_options = std.Build.ExecutableOptions{
        .name = "zuws",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    };

    const exe = b.addExecutable(exe_options);

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    const ssl = b.option(bool, "ssl", "Enable SSL support") orelse false;

    const uSockets = b.addStaticLibrary(.{ .name = "uSockets", .target = target, .optimize = optimize });
    uSockets.linkSystemLibrary("zlib");

    if (ssl) {
        // add boringssl and flag
        uSockets.linkLibCpp();
    } else {
        try flags.append("-DLIBUS_NO_SSL");
    }

    uSockets.addIncludePath(b.path("uWebSockets/uSockets/src"));
    uSockets.installHeader(b.path("uWebSockets/uSockets/src/libusockets.h"), "libusockets.h");
    uSockets.addCSourceFiles(.{
        .root = b.path("uWebSockets/uSockets/src/"),
        .files = &[_][]const u8{
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
        },
        .flags = flags.items,
    });

    const uWebSockets = b.addStaticLibrary(.{ .name = "uWebSockets", .target = target, .optimize = optimize });
    uWebSockets.linkLibCpp();
    uWebSockets.linkLibrary(uSockets);
    uWebSockets.addCSourceFiles(.{ .root = b.path("."), .files = &.{"bindings/uws.cpp"} });
    b.installArtifact(uWebSockets);

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("bindings/uws.h"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("uws", translate_c.createModule());
    exe.linkLibrary(uWebSockets);

    b.installArtifact(exe);
    const run_exe = b.addRunArtifact(exe);

    run_exe.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_exe.step);

    // Emit ASM
    const emit_asm = b.step("asm", "Emit assembly file");
    const waf = b.addWriteFiles();
    waf.step.dependOn(b.getInstallStep());
    waf.addCopyFileToSource(exe.getEmittedAsm(), "main.asm");
    emit_asm.dependOn(&waf.step);

    // ZLS Checking
    const exe_check = b.addExecutable(exe_options);
    exe_check.root_module.addImport("uws", translate_c.createModule());
    exe_check.linkLibrary(uWebSockets);
    const check = b.step("check", "Check if zuws compiles");
    check.dependOn(&exe_check.step);
}
