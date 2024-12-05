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
    pub fn listen(app: *const App, port: i32, handler: c.uws_listen_handler) void {
        c.uws_app_listen(app.ptr, port, handler);
        c.uws_app_run(app.ptr);
    }

    pub fn get(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) *const App {
        c.uws_app_get(app.ptr, pattern, handler);
        return app;
    }
};
