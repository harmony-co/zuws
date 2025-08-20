const std = @import("std");

pub fn linkLibUV(
    b: *std.Build,
    uSockets: *std.Build.Step.Compile,
) !void {
    const target = uSockets.root_module.resolved_target.?;
    const optimize = uSockets.root_module.optimize.?;

    const uv = b.dependency("libuv", .{});

    const libuv = b.addStaticLibrary(.{
        .name = "uv",
        .target = target,
        .optimize = optimize,
    });

    libuv.link_function_sections = true;
    libuv.link_data_sections = true;
    libuv.link_gc_sections = true;
    libuv.linkLibC();

    libuv.addIncludePath(uv.path("src"));
    libuv.addIncludePath(uv.path("include"));
    libuv.addIncludePath(uv.path("include/uv"));

    var sources = std.ArrayList([]const u8).init(b.allocator);
    try sources.appendSlice(libuv_sources);

    if (target.result.os.tag == .windows)
        libuv.addIncludePath(uv.path("src/win"))
    else
        libuv.addIncludePath(uv.path("src/unix"));

    switch (target.result.os.tag) {
        .windows => try sources.appendSlice(windows_sources),
        .linux => try sources.appendSlice(linux_sources),
        .macos, .ios => try sources.appendSlice(darwin_sources),
        .freebsd => try sources.appendSlice(freebsd_sources),
        .openbsd => try sources.appendSlice(openbsd_sources),
        .netbsd => try sources.appendSlice(netbsd_sources),
        .dragonfly => try sources.appendSlice(dragonfly_sources),
        .aix => try sources.appendSlice(aix_sources),
        .haiku => try sources.appendSlice(haiku_sources),
        .hurd => try sources.appendSlice(hurd_sources),
        .zos => try sources.appendSlice(zos_sources),
        else => try sources.appendSlice(unix_sources),
    }

    libuv.addCSourceFiles(.{
        .files = try sources.toOwnedSlice(),
        .root = uv.path(""),
    });

    uSockets.linkLibrary(libuv);
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
    "src/strtok.h",
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
