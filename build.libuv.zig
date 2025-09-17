const std = @import("std");

pub fn linkLibUV(
    b: *std.Build,
    uSockets: *std.Build.Step.Compile,
) !void {
    const target = uSockets.root_module.resolved_target.?;
    const optimize = uSockets.root_module.optimize.?;

    const uv = b.dependency("libuv", .{});

    const libuv = b.addLibrary(.{
        .name = "uv",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    libuv.link_gc_sections = true;
    libuv.link_data_sections = true;
    libuv.link_function_sections = true;

    libuv.root_module.addIncludePath(uv.path("src"));
    libuv.root_module.addIncludePath(uv.path("include"));

    libuv.installHeadersDirectory(uv.path("include"), "", .{
        .include_extensions = &.{ "uv.h", "uv/errno.h", "uv/version.h", "uv/threadpool.h" },
    });

    var sources: std.ArrayList([]const u8) = .empty;
    try sources.appendSlice(b.allocator, libuv_sources);

    if (target.result.os.tag == .windows) {
        libuv.root_module.addIncludePath(uv.path("src/win"));
        libuv.installHeadersDirectory(uv.path("include"), "", .{
            .include_extensions = &.{ "uv/win.h", "uv/tree.h" },
        });
        try sources.appendSlice(b.allocator, windows_sources);
    } else {
        libuv.root_module.addIncludePath(uv.path("src/unix"));
        libuv.installHeadersDirectory(uv.path("include"), "", .{
            .include_extensions = &.{"uv/unix.h"},
        });
        libuv.installHeadersDirectory(uv.path("include"), "", .{
            .include_extensions = switch (target.result.os.tag) {
                .linux => &.{"uv/linux.h"},
                .macos => &.{"uv/darwin.h"},
                .freebsd => &.{"uv/bsd.h"},
                .openbsd => &.{"uv/bsd.h"},
                .netbsd => &.{"uv/bsd.h"},
                .dragonfly => &.{"uv/bsd.h"},
                .aix => &.{"uv/aix.h"},
                .haiku => &.{"uv/posix.h"},
                .hurd => &.{"uv/posix.h"},
                .zos => &.{},
                else => unreachable,
            },
        });
        try sources.appendSlice(b.allocator, unix_sources);
        try sources.appendSlice(b.allocator, switch (target.result.os.tag) {
            .linux => linux_sources,
            .macos => darwin_sources,
            .freebsd => freebsd_sources,
            .openbsd => openbsd_sources,
            .netbsd => netbsd_sources,
            .dragonfly => dragonfly_sources,
            .aix => aix_sources,
            .haiku => haiku_sources,
            .hurd => hurd_sources,
            .zos => zos_sources,
            else => unreachable,
        });
    }

    libuv.root_module.addCSourceFiles(.{
        .files = try sources.toOwnedSlice(b.allocator),
        .root = uv.path(""),
    });

    uSockets.root_module.linkLibrary(libuv);
}

const libuv_sources = &.{
    "src/fs-poll.c",
    "src/idna.c",
    "src/inet.c",
    "src/random.c",
    "src/strscpy.c",
    "src/thread-common.c",
    "src/threadpool.c",
    "src/timer.c",
    "src/uv-data-getter-setters.c",
    "src/uv-common.c",
    "src/version.c",
    "src/strtok.c",
};

const windows_sources = &.{
    "src/win/async.c",
    "src/win/core.c",
    "src/win/detect-wakeup.c",
    "src/win/dl.c",
    "src/win/error.c",
    "src/win/fs-event.c",
    "src/win/fs.c",
    "src/win/getaddrinfo.c",
    "src/win/getnameinfo.c",
    "src/win/handle.c",
    "src/win/loop-watcher.c",
    "src/win/pipe.c",
    "src/win/poll.c",
    "src/win/process-stdio.c",
    "src/win/process.c",
    "src/win/signal.c",
    "src/win/stream.c",
    "src/win/tcp.c",
    "src/win/thread.c",
    "src/win/tty.c",
    "src/win/udp.c",
    "src/win/util.c",
    "src/win/winapi.c",
    "src/win/winsock.c",
};

const unix_sources = &.{
    "src/unix/async.c",
    "src/unix/core.c",
    "src/unix/dl.c",
    "src/unix/fs.c",
    "src/unix/getaddrinfo.c",
    "src/unix/getnameinfo.c",
    "src/unix/loop-watcher.c",
    "src/unix/loop.c",
    "src/unix/pipe.c",
    "src/unix/poll.c",
    "src/unix/process.c",
    "src/unix/random-devurandom.c",
    "src/unix/signal.c",
    "src/unix/stream.c",
    "src/unix/tcp.c",
    "src/unix/thread.c",
    "src/unix/tty.c",
    "src/unix/udp.c",
};

const linux_sources = &.{
    "src/unix/linux.c",
    "src/unix/procfs-exepath.c",
    "src/unix/proctitle.c",
    "src/unix/random-getrandom.c",
    "src/unix/random-sysctl-linux.c",
};

const darwin_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/darwin-proctitle.c",
    "src/unix/darwin.c",
    "src/unix/fsevents.c",
    "src/unix/kqueue.c",
    "src/unix/proctitle.c",
    "src/unix/random-getentropy.c",
};

const freebsd_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/bsd-proctitle.c",
    "src/unix/freebsd.c",
    "src/unix/kqueue.c",
    "src/unix/posix-hrtime.c",
    "src/unix/random-getrandom.c",
};

const openbsd_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/bsd-proctitle.c",
    "src/unix/kqueue.c",
    "src/unix/openbsd.c",
    "src/unix/posix-hrtime.c",
    "src/unix/random-getentropy.c",
};

const netbsd_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/bsd-proctitle.c",
    "src/unix/kqueue.c",
    "src/unix/netbsd.c",
    "src/unix/posix-hrtime.c",
};

const dragonfly_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/bsd-proctitle.c",
    "src/unix/dragonfly.c",
    "src/unix/freebsd.c",
    "src/unix/kqueue.c",
    "src/unix/posix-hrtime.c",
};

const aix_sources = &.{
    "src/unix/aix.c",
    "src/unix/aix-common.c",
};

const haiku_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/haiku.c",
    "src/unix/no-fsevents.c",
    "src/unix/no-proctitle.c",
    "src/unix/posix-hrtime.c",
    "src/unix/posix-poll.c",
};

const hurd_sources = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/no-fsevents.c",
    "src/unix/no-proctitle.c",
    "src/unix/posix-hrtime.c",
    "src/unix/posix-poll.c",
    "src/unix/hurd.c",
};

const zos_sources = &.{
    "src/unix/os390.c",
    "src/unix/os390-syscalls.c",
    "src/unix/proctitle.c",
};

// Unused
const sunos_sources = &.{
    "src/unix/no-proctitle.c",
    "src/unix/sunos.c",
};

// Unused
const cygwin_sources = &.{
    "src/unix/cygwin.c",
    "src/unix/bsd-ifaddrs.c",
    "src/unix/no-fsevents.c",
    "src/unix/no-proctitle.c",
    "src/unix/posix-hrtime.c",
    "src/unix/posix-poll.c",
    "src/unix/procfs-exepath.c",
    "src/unix/sysinfo-loadavg.c",
    "src/unix/sysinfo-memory.c",
};
