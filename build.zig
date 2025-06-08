const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const config_options = b.addOptions();
    const debug_logs = b.option(bool, "debug_logs", "Whether to enable debug logs for route creation.") orelse (optimize == .Debug);
    const ssl = b.option(bool, "ssl", "Whether to enable SSL.") orelse false;

    config_options.addOption(bool, "debug_logs", debug_logs);

    const uSockets = b.addLibrary(.{
        .name = "uSockets",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    uSockets.linkSystemLibrary("zlib");
    uSockets.addIncludePath(b.path("uWebSockets/uSockets/src"));
    uSockets.installHeader(b.path("uWebSockets/uSockets/src/libusockets.h"), "libusockets.h");
    uSockets.addCSourceFiles(.{
        .root = b.path("uWebSockets/uSockets/src/"),
        .files = &.{
            "bsd.c",
            "context.c",
            "loop.c",
            "quic.c",
            "socket.c",
            "udp.c",
            "crypto/sni_tree.cpp",
            "crypto/openssl.c",
            "eventing/epoll_kqueue.c",
            "eventing/gcd.c",
            "eventing/libuv.c",
            "io_uring/io_context.c",
            "io_uring/io_loop.c",
            "io_uring/io_socket.c",
        },
        .flags = if (ssl) &.{"-DLIBUS_USE_OPENSSL"} else &.{"-DLIBUS_NO_SSL"},
    });
    if (ssl) {
        uSockets.linkLibCpp();
        uSockets.linkSystemLibrary("ssl");
        uSockets.linkSystemLibrary("crypto");
    }

    const uWebSockets = b.addLibrary(.{
        .name = "uWebSockets",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });
    uWebSockets.linkLibCpp();
    uWebSockets.linkLibrary(uSockets);
    uWebSockets.addCSourceFiles(.{
        .root = b.path("bindings/"),
        .files = &.{"uws.cpp"},
        .flags = if (ssl) &.{"-DZUWS_USE_SSL"} else &.{},
    });

    b.installArtifact(uWebSockets);

    const uws = b.addTranslateC(.{
        .root_source_file = b.path("bindings/uws.h"),
        .target = target,
        .optimize = optimize,
    });

    const uws_module = uws.addModule("uws");

    const zuws = b.addModule("zuws", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    zuws.addOptions("config", config_options);
    zuws.addImport("uws", uws_module);
    zuws.linkLibrary(uWebSockets);
    const libzuws = b.addLibrary(.{
        .name = "zuws",
        .linkage = .static,
        .root_module = zuws,
    });
    b.installArtifact(libzuws);

    const example_step = b.step("example", "Build and run an example.");
    const example_assembly_step = b.step("example-asm", "Build and emit an example's assembly.");

    if (b.args) |args| {
        const example_name = args[0];
        const path = try std.fmt.allocPrint(b.allocator, "examples/{s}/main.zig", .{example_name});
        try std.fs.cwd().access(path, .{});

        const exe = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
            }),
        });

        exe.root_module.addImport("uws", uws_module);
        exe.root_module.addImport("zuws", zuws);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        example_step.dependOn(&run_cmd.step);

        const asm_description = try std.fmt.allocPrint(b.allocator, "Emit the {s} example ASM file", .{example_name});
        const asm_step_name = try std.fmt.allocPrint(b.allocator, "{s}-asm", .{example_name});
        const asm_step = b.step(asm_step_name, asm_description);
        const awf = b.addUpdateSourceFiles();
        awf.step.dependOn(b.getInstallStep());
        awf.addCopyFileToSource(exe.getEmittedAsm(), "main.asm");
        asm_step.dependOn(&awf.step);
        example_assembly_step.dependOn(asm_step);
    }
}
