const c = @import("uws");
const std = @import("std");
const config = @import("config");
const Request = @import("./Request.zig");
const Response = @import("./Response.zig");
const WebSocket = @import("./WebSocket.zig");

const info = std.log.scoped(.uws_debug).info;

const App = @This();

pub const MethodHandler = *const fn (*Response, *Request) void;

ptr: *c.uws_app_s,

pub const Method = enum {
    GET,
    POST,
    PUT,
    OPTIONS,
    DELETE,
    PATCH,
    HEAD,
    CONNECT,
    TRACE,
    /// Never possible to receive it, purely for internal purposes
    ANY,
};

pub const Group = struct {
    list: []const ListType = &.{},
    base_path: [:0]const u8,

    const ListType = struct {
        method: Method,
        pattern: [:0]const u8,
        handler: MethodHandler,
    };

    pub fn init(comptime path: [:0]const u8) Group {
        std.debug.assert(path.len > 0);
        std.debug.assert(!std.mem.containsAtLeast(u8, path, 1, &std.ascii.whitespace));

        return .{ .base_path = path };
    }

    pub const get = CreateGroupFn(.GET);
    pub const post = CreateGroupFn(.POST);
    pub const put = CreateGroupFn(.PUT);
    pub const options = CreateGroupFn(.OPTIONS);
    pub const del = CreateGroupFn(.DELETE);
    pub const patch = CreateGroupFn(.PATCH);
    pub const head = CreateGroupFn(.HEAD);
    pub const connect = CreateGroupFn(.CONNECT);
    pub const trace = CreateGroupFn(.TRACE);
    pub const any = CreateGroupFn(.ANY);

    pub fn group(comptime self: *Group, grp: Group) *Group {
        comptime {
            for (grp.list) |item| {
                self.list = self.list ++ .{ListType{
                    .method = item.method,
                    .pattern = grp.base_path ++ item.pattern,
                    .handler = item.handler,
                }};
            }
            return self;
        }
    }

    pub fn merge(comptime self: *Group, grp: Group) *Group {
        comptime {
            for (grp.list) |item| {
                self.list = self.list ++ .{ListType{
                    .method = item.method,
                    .pattern = item.pattern,
                    .handler = item.handler,
                }};
            }
            return self;
        }
    }

    fn CreateGroupFn(comptime method: App.Method) fn (comptime self: *App.Group, comptime pattern: [:0]const u8, handler: MethodHandler) *App.Group {
        return struct {
            fn temp(comptime self: *App.Group, comptime pattern: [:0]const u8, handler: MethodHandler) *App.Group {
                self.list = self.list ++ .{App.Group.ListType{ .method = method, .pattern = pattern, .handler = handler }};
                return self;
            }
        }.temp;
    }
};

pub fn init() !App {
    const app = c.uws_create_app();
    if (app) |ptr| return .{ .ptr = ptr };
    return error.CouldNotCreateApp;
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

pub fn close(app: *const App) void {
    c.uws_app_close(app.ptr);
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
            .GET => _ = app.get(g.base_path ++ item.pattern, item.handler),
            .POST => _ = app.post(g.base_path ++ item.pattern, item.handler),
            .PUT => _ = app.put(g.base_path ++ item.pattern, item.handler),
            .OPTIONS => _ = app.options(g.base_path ++ item.pattern, item.handler),
            .DELETE => _ = app.del(g.base_path ++ item.pattern, item.handler),
            .PATCH => _ = app.patch(g.base_path ++ item.pattern, item.handler),
            .HEAD => _ = app.head(g.base_path ++ item.pattern, item.handler),
            .CONNECT => _ = app.connect(g.base_path ++ item.pattern, item.handler),
            .TRACE => _ = app.trace(g.base_path ++ item.pattern, item.handler),
            .ANY => _ = app.any(g.base_path ++ item.pattern, item.handler),
        }
    }
    return app;
}

pub fn ws(app: *const App, pattern: [:0]const u8, behavior: WebSocketBehavior) *const App {
    if (config.debug_logs) {
        info("Registering WebSocket route: {s}", .{pattern});
    }

    var b: c.uws_socket_behavior_t = .{
        .compression = @intFromEnum(behavior.compression),
        .maxPayloadLength = behavior.maxPayloadLength,
        .idleTimeout = behavior.idleTimeout,
        .maxBackpressure = behavior.maxBackpressure,
        .closeOnBackpressureLimit = behavior.closeOnBackpressureLimit,
        .resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend,
        .sendPingsAutomatically = behavior.sendPingsAutomatically,
        .maxLifetime = behavior.maxLifetime,
    };

    if (behavior.upgrade) |f| b.upgrade = .{ .handler = upgradeWrapper, .ptr = @constCast(f) };
    if (behavior.open) |f| b.open = .{ .handler = openWrapper, .ptr = @constCast(f) };
    if (behavior.message) |f| b.message = .{ .handler = messageWrapper, .ptr = @constCast(f) };
    if (behavior.dropped) |f| b.dropped = .{ .handler = messageWrapper, .ptr = @constCast(f) };
    if (behavior.drain) |f| b.drain = .{ .handler = drainWrapper, .ptr = @constCast(f) };
    if (behavior.ping) |f| b.ping = .{ .handler = pingWrapper, .ptr = @constCast(f) };
    if (behavior.pong) |f| b.pong = .{ .handler = pingWrapper, .ptr = @constCast(f) };
    if (behavior.close) |f| b.close = .{ .handler = closeWrapper, .ptr = @constCast(f) };
    if (behavior.subscription) |f| b.subscription = .{ .handler = subscriptionWrapper, .ptr = @constCast(f) };

    c.uws_ws(app.ptr, pattern, b);
    return app;
}

fn handlerWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_s) callconv(.C) void {
    const handler_ptr: MethodHandler = @ptrCast(@alignCast(ptr));
    var res = Response{ .ptr = rawRes orelse return };
    var req = Request{ .ptr = rawReq orelse return };
    handler_ptr(&res, &req);
}

// https://github.com/uNetworking/uWebSockets/blob/b9b59b2b164489f3788223fec5821f77f7962d43/src/App.h#L234-L259
pub const WebSocketBehavior = struct {
    compression: WebSocket.CompressOptions = .DISABLED,
    maxPayloadLength: u32 = 16 * 1024,
    /// In seconds
    idleTimeout: u16 = 120,
    maxBackpressure: u32 = 64 * 1024,
    closeOnBackpressureLimit: bool = false,
    resetIdleTimeoutOnSend: bool = false,
    sendPingsAutomatically: bool = true,
    maxLifetime: u16 = 0,
    upgrade: ?*const fn (res: *Response, req: *Request) void = null,
    open: ?*const fn (ws: *WebSocket) void = null,
    message: ?*const fn (ws: *WebSocket, message: []const u8, opcode: WebSocket.Opcode) void = null,
    dropped: ?*const fn (ws: *WebSocket, message: []const u8, opcode: WebSocket.Opcode) void = null,
    drain: ?*const fn (ws: *WebSocket) void = null,
    ping: ?*const fn (ws: *WebSocket, message: []const u8) void = null,
    pong: ?*const fn (ws: *WebSocket, message: []const u8) void = null,
    close: ?*const fn (ws: *WebSocket, code: i32, message: []const u8) void = null,
    subscription: ?*const fn (ws: *WebSocket, topic: []const u8, newNumberOfSubscribers: i32, oldNumberOfSubscribers: i32) void = null,
};

fn upgradeWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.C) void {
    const handler_ptr: *const fn (*Response, *Request) void = @ptrCast(@alignCast(ptr));
    var res = Response{ .ptr = rawRes orelse return };
    var req = Request{ .ptr = rawReq orelse return };
    handler_ptr(&res, &req);
    res.upgrade(&req, context);
}

fn openWrapper(ptr: ?*anyopaque, rawWs: ?*c.uws_websocket_t) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s);
}

fn drainWrapper(ptr: ?*anyopaque, rawWs: ?*c.uws_websocket_t) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s);
}

fn messageWrapper(ptr: ?*anyopaque, rawWs: ?*c.uws_websocket_t, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket, message: []const u8, opcode: WebSocket.Opcode) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s, message[0..length], @enumFromInt(opcode));
}

fn pingWrapper(ptr: ?*anyopaque, rawWs: ?*c.uws_websocket_t, message: [*c]const u8, length: usize) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket, message: []const u8) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s, message[0..length]);
}

fn closeWrapper(ptr: ?*anyopaque, rawWs: ?*c.uws_websocket_t, code: c_int, message: [*c]const u8, length: usize) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket, code: i32, message: []const u8) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s, code, message[0..length]);
}

fn subscriptionWrapper(
    ptr: ?*anyopaque,
    rawWs: ?*c.uws_websocket_t,
    topic_name: [*c]const u8,
    topic_name_length: usize,
    new_number_of_subscriber: c_int,
    old_number_of_subscriber: c_int,
) callconv(.C) void {
    const handler_ptr: *const fn (ws: *WebSocket, topic: []const u8, new_number_of_subscriber: i32, old_number_of_subscriber: i32) void = @ptrCast(@alignCast(ptr));
    var w_s = WebSocket{ .ptr = rawWs orelse return };
    handler_ptr(&w_s, topic_name[0..topic_name_length], new_number_of_subscriber, old_number_of_subscriber);
}

/// **Args**:
/// * `method` - A ***lowercase*** http method; refers to `bindings/uws.h:69:9`
fn CreateMethodFn(comptime method: []const u8) fn (app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
    var temp_up: [8]u8 = undefined;
    const upper_method = std.ascii.upperString(&temp_up, method);
    const log_str = std.fmt.comptimePrint("Registering {s} route: ", .{upper_method}) ++ "{s}";

    return struct {
        fn temp(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
            if (config.debug_logs) {
                info(log_str, .{pattern});
            }
            @field(c, std.fmt.comptimePrint("uws_app_{s}", .{method}))(app.ptr, pattern, handlerWrapper, @constCast(handler));
            return app;
        }
    }.temp;
}
