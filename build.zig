const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zuws",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const uSockets = b.addStaticLibrary(.{ .name = "uSockets", .target = target, .optimize = optimize });
    uSockets.linkLibC();
    uSockets.linkSystemLibrary("zlib");
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
            "eventing/epoll_kqueue.c",
            "eventing/gcd.c",
            "eventing/libuv.c",
            "io_uring/io_context.c",
            "io_uring/io_loop.c",
            "io_uring/io_socket.c",
        },
        .flags = &.{ "-std=c17", "-DLIBUS_NO_SSL" },
    });

    const uWebSockets = b.addStaticLibrary(.{ .name = "uWebSockets", .target = target, .optimize = optimize });
    uWebSockets.linkLibCpp();
    uWebSockets.linkLibrary(uSockets);
    uWebSockets.addIncludePath(b.path("uWebSockets/src"));
    uWebSockets.installHeader(b.path("uWebSockets/src/App.h"), "uWebSockets/src/App.h");
    uWebSockets.installHeader(b.path("bindings/uws.h"), "uws.h");
    uWebSockets.addCSourceFiles(.{ .root = b.path("."), .files = &.{"bindings/uws.cpp"} });

    b.installArtifact(uWebSockets);
    exe.linkLibrary(uWebSockets);

    b.installArtifact(exe);
    const run_exe = b.addRunArtifact(exe);

    run_exe.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_exe.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_exe.step);
}
