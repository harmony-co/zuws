const std = @import("std");
const c = @import("uws");

const Response = @import("./Response.zig");
const Request = @import("./Request.zig");

const App = @This();

pub const uWSError = error{
    CouldNotCreateApp,
};

pub const MethodHandler = *const fn (*Response, *Request) void;

ptr: *c.uws_app_s,
logs_enabled: bool,

pub const Group = struct {
    list: []const ListType = &.{},
    base_path: [:0]const u8,

    const ListType = struct {
        method: Method,
        pattern: [:0]const u8,
        handler: MethodHandler,
    };

    const Method = enum {
        Get,
        Post,
        Put,
        Options,
        Del,
        Patch,
        Head,
        Connect,
        Trace,
        Any,
    };

    pub const get = CreateGroupFn(.Get);
    pub const post = CreateGroupFn(.Post);
    pub const put = CreateGroupFn(.Put);
    pub const options = CreateGroupFn(.Options);
    pub const del = CreateGroupFn(.Del);
    pub const patch = CreateGroupFn(.Patch);
    pub const head = CreateGroupFn(.Head);
    pub const connect = CreateGroupFn(.Connect);
    pub const trace = CreateGroupFn(.Trace);
    pub const any = CreateGroupFn(.Any);

    pub fn group(comptime self: *Group, grp: Group) *Group {
        comptime {
            for (grp.list) |item| {
                self.list = self.list ++ .{ListType{
                    .method = item.method,
                    .pattern = self.base_path ++ item.pattern,
                    .handler = item.handler,
                }};
            }
            return self;
        }
    }
};

pub fn init(enable_logs: bool) uWSError!App {
    const app = c.uws_create_app();
    if (app) |ptr| return .{ .ptr = ptr, .logs_enabled = enable_logs };
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

pub const get = CreateMethodFn("get");
pub const post = CreateMethodFn("post");
pub const put = CreateMethodFn("put");
pub const options = CreateMethodFn("options");
pub const del = CreateMethodFn("del");
pub const patch = CreateMethodFn("patch");
pub const head = CreateMethodFn("head");
pub const connect = CreateMethodFn("connect");
pub const trace = CreateMethodFn("trace");
pub const any = CreateMethodFn("any");

pub fn group(app: *const App, comptime g: Group) *const App {
    inline for (g.list) |item| {
        switch (item.method) {
            .Get => _ = app.get(item.pattern, item.handler),
            .Post => _ = app.post(item.pattern, item.handler),
            .Put => _ = app.put(item.pattern, item.handler),
            .Options => _ = app.options(item.pattern, item.handler),
            .Del => _ = app.del(item.pattern, item.handler),
            .Patch => _ = app.patch(item.pattern, item.handler),
            .Head => _ = app.head(item.pattern, item.handler),
            .Connect => _ = app.connect(item.pattern, item.handler),
            .Trace => _ = app.trace(item.pattern, item.handler),
            .Any => _ = app.any(item.pattern, item.handler),
        }
    }
    return app;
}

pub fn ws(app: *const App, pattern: [:0]const u8, behavior: c.uws_socket_behavior_t) *const App {
    if (app.logs_enabled) {
        std.log.info("Registering WebSocket route: {s}", .{pattern});
    }
    c.uws_ws(app.ptr, pattern, behavior);
    return app;
}

fn handlerWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_s) callconv(.C) void {
    const handler_ptr: MethodHandler = @ptrCast(@alignCast(ptr));
    var res = Response{ .ptr = rawRes orelse return };
    var req = Request{ .ptr = rawReq orelse return };
    handler_ptr(&res, &req);
}

fn CreateGroupFn(comptime method: App.Group.Method) fn (comptime self: *App.Group, comptime pattern: [:0]const u8, handler: MethodHandler) *App.Group {
    return struct {
        fn temp(comptime self: *App.Group, comptime pattern: [:0]const u8, handler: MethodHandler) *App.Group {
            self.list = self.list ++ .{App.Group.ListType{ .method = method, .pattern = self.base_path ++ pattern, .handler = handler }};
            return self;
        }
    }.temp;
}

/// **Args**:
/// * `method` - A ***lowercase*** http method; refers to `bindings/uws.h:69:9`
fn CreateMethodFn(comptime method: []const u8) fn (app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
    var temp_up: [10]u8 = undefined;
    const upper_method = std.ascii.upperString(&temp_up, method);
    const log_str = std.fmt.comptimePrint("Registering {s} route: ", .{upper_method}) ++ "{s}";

    return struct {
        fn temp(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
            if (app.logs_enabled) {
                std.log.info(log_str, .{pattern});
            }
            @field(c, std.fmt.comptimePrint("uws_app_{s}", .{method}))(app.ptr, pattern, handlerWrapper, @constCast(handler));
            return app;
        }
    }.temp;
}
