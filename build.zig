const std = @import("std");
const linkBoringSSL = @import("./build.boringssl.zig").linkBoringSSL;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const config_options = b.addOptions();
    const debug_logs = b.option(bool, "debug_logs", "Whether to enable debug logs for route creation.") orelse (optimize == .Debug);
    const ssl = b.option(bool, "ssl", "Whether to enable SSL.") orelse false;

    config_options.addOption(bool, "debug_logs", debug_logs);
    config_options.addOption(bool, "is_ssl", ssl);

    const zlib_c = b.dependency("zlib", .{});
    const zlib = b.addLibrary(.{
        .name = "z",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    zlib.linkLibC();
    zlib.addCSourceFiles(.{
        .root = zlib_c.path(""),
        .files = &.{
            "adler32.c",
            "crc32.c",
            "deflate.c",
            "infback.c",
            "inffast.c",
            "inflate.c",
            "inftrees.c",
            "trees.c",
            "zutil.c",
            "compress.c",
            "uncompr.c",
            "gzclose.c",
            "gzlib.c",
            "gzread.c",
            "gzwrite.c",
        },
        .flags = &.{
            "-DHAVE_SYS_TYPES_H",
            "-DHAVE_STDINT_H",
            "-DHAVE_STDDEF_H",
            "-DZ_HAVE_UNISTD_H",
        },
    });

    zlib.installHeadersDirectory(zlib_c.path(""), "", .{
        .include_extensions = &.{
            "zconf.h",
            "zlib.h",
        },
    });

    const us = b.dependency("uSockets", .{});
    const uSockets = b.addLibrary(.{
        .name = "uSockets",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    uSockets.linkLibrary(zlib);
    uSockets.addIncludePath(us.path(""));
    uSockets.installHeader(us.path("libusockets.h"), "libusockets.h");

    var uSocketsCFiles = std.ArrayList([]const u8).init(b.allocator);
    try uSocketsCFiles.appendSlice(&.{
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
    });

    if (ssl) {
        uSockets.linkLibCpp();
        try linkBoringSSL(b, uSockets);
        try uSocketsCFiles.append("crypto/openssl.c");
    }

    uSockets.addCSourceFiles(.{
        .root = us.path(""),
        .files = try uSocketsCFiles.toOwnedSlice(),
        .flags = if (ssl) &.{"-DLIBUS_USE_OPENSSL"} else &.{"-DLIBUS_NO_SSL"},
    });

    const uws = b.addTranslateC(.{
        .root_source_file = b.path("bindings/uws.h"),
        .target = target,
        .optimize = optimize,
    });

    uws.defineCMacro("ZUWS_USE_SSL", if (ssl) "1" else "0");

    const uWebSockets = uws.addModule("uws");
    uWebSockets.link_libcpp = true;
    uWebSockets.linkLibrary(uSockets);
    uWebSockets.addCSourceFiles(.{
        .root = b.path("bindings/"),
        .files = &.{"uws.cpp"},
        .flags = if (ssl) &.{"-DZUWS_USE_SSL"} else &.{},
    });

    const zuws = b.addModule("zuws", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    zuws.addOptions("config", config_options);
    zuws.addImport("uws", uWebSockets);
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

        exe.root_module.addImport("uws", uWebSockets);
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
