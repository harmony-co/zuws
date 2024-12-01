const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const us = b.addStaticLibrary(.{ .name = "uSockets", .target = target, .optimize = optimize });
    us.linkLibC();
    us.addIncludePath(b.path("uWebSockets/uSockets/src"));
    us.installHeader(b.path("uWebSockets/uSockets/src/libusockets.h"), "libusockets.h");
    us.addCSourceFiles(.{ .root = b.path("uWebSockets/uSockets/src/"), .files = &[_][]const u8{ "bsd.c", "context.c", "loop.c", "quic.c", "socket.c", "udp.c", "crypto/openssl.c", "eventing/epoll_kqueue.c", "eventing/gcd.c", "eventing/libuv.c", "io_uring/io_context.c", "io_uring/io_loop.c", "io_uring/io_socket.c" }, .flags = &.{"-std=c17"} });

    const uws = b.addStaticLibrary(.{ .name = "uWebSockets", .target = target, .optimize = optimize });
    uws.linkLibCpp();
    uws.linkLibrary(us);
    uws.addIncludePath(b.path("uWebSockets/src"));
    uws.installHeader(b.path("uWebSockets/src/App.h"), "uWebSockets/src/App.h");
    uws.installHeader(b.path("uWSZig.h"), "uWSZig.h");
    uws.addCSourceFiles(.{ .root = b.path("."), .files = &.{"uWSZig.cpp"} });
    b.installArtifact(uws);

    const exe = b.addExecutable(.{
        .name = "zuws",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(uws);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
