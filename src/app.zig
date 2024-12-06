const std = @import("std");
const c = @import("uws");

pub const uWSError = error{
    CouldNotCreateApp,
};

pub const App = struct {
    ptr: *c.uws_app_s,

    pub fn init() uWSError!App {
        const app = c.uws_create_app();

        if (app) |ptr| {
            return .{ .ptr = ptr };
        }

        return uWSError.CouldNotCreateApp;
    }

    pub fn deinit(app: *const App) void {
        c.uws_app_destroy(app.ptr);
    }

    /// This also calls `run` and starts the app
    pub fn listen(app: *const App, port: u16, handler: c.uws_listen_handler) !void {
        const addr = try std.net.Address.parseIp4("127.0.0.1", port);
        const sock_fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
        try std.posix.bind(sock_fd, &addr.any, addr.getOsSockLen());
        std.posix.close(sock_fd);

        c.uws_app_listen(app.ptr, port, handler);
        c.uws_app_run(app.ptr);
    }

    pub fn get(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_get(app.ptr, pattern, handler);
        return app;
    }

    pub fn post(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_post(app.ptr, pattern, handler);
        return app;
    }

    pub fn put(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_put(app.ptr, pattern, handler);
        return app;
    }

    pub fn options(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_options(app.ptr, pattern, handler);
        return app;
    }

    pub fn del(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_del(app.ptr, pattern, handler);
        return app;
    }

    pub fn patch(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_patch(app.ptr, pattern, handler);
        return app;
    }

    pub fn head(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_head(app.ptr, pattern, handler);
        return app;
    }

    pub fn connect(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_connect(app.ptr, pattern, handler);
        return app;
    }

    pub fn trace(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_trace(app.ptr, pattern, handler);
        return app;
    }

    pub fn any(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_any(app.ptr, pattern, handler);
        return app;
    }
};
