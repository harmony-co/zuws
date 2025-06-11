const c = @import("uws");
const std = @import("std");
const config = @import("config");
const Request = @import("./Request.zig");
const Response = @import("./Response.zig");
const WebSocket = @import("./WebSocket.zig");

pub const Group = @import("./Group.zig");
const info = std.log.scoped(.uws_debug).info;

const App = @This();

pub const MethodHandler = *const fn (*Response, *Request) void;

ptr: *c.uws_app_t,

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

pub const init = if (config.is_ssl) initSSL else initNoSSL;

fn initSSL(opt: c.struct_us_socket_context_options_t) !App {
    const app = c.uws_create_app(opt);
    if (app) |ptr| return .{ .ptr = ptr };
    return error.CouldNotCreateApp;
}

fn initNoSSL() !App {
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

pub const get = CreateMethodFn("get", true).f;
pub const post = CreateMethodFn("post", true).f;
pub const put = CreateMethodFn("put", true).f;
pub const options = CreateMethodFn("options", true).f;
pub const del = CreateMethodFn("del", true).f;
pub const patch = CreateMethodFn("patch", true).f;
pub const head = CreateMethodFn("head", true).f;
pub const connect = CreateMethodFn("connect", true).f;
pub const trace = CreateMethodFn("trace", true).f;
pub const any = CreateMethodFn("any", true).f;

pub const rawGet = CreateMethodFn("get", false).f;
pub const rawPost = CreateMethodFn("post", false).f;
pub const rawPut = CreateMethodFn("put", false).f;
pub const rawOptions = CreateMethodFn("options", false).f;
pub const rawDel = CreateMethodFn("del", false).f;
pub const rawPatch = CreateMethodFn("patch", false).f;
pub const rawHead = CreateMethodFn("head", false).f;
pub const rawConnect = CreateMethodFn("connect", false).f;
pub const rawTrace = CreateMethodFn("trace", false).f;
pub const rawAny = CreateMethodFn("any", false).f;

pub fn group(app: *const App, g: *Group.Group) !void {
    for (g.list.items) |item| {
        const pattern = try std.mem.concatWithSentinel(g.alloc, u8, &.{ g.base_path, item.pattern }, 0);
        switch (item.method) {
            .GET => app.rawGet(pattern, item.handler),
            .POST => app.rawPost(pattern, item.handler),
            .PUT => app.rawPut(pattern, item.handler),
            .OPTIONS => app.rawOptions(pattern, item.handler),
            .DELETE => app.rawDel(pattern, item.handler),
            .PATCH => app.rawPatch(pattern, item.handler),
            .HEAD => app.rawHead(pattern, item.handler),
            .CONNECT => app.rawConnect(pattern, item.handler),
            .TRACE => app.rawTrace(pattern, item.handler),
            .ANY => app.rawAny(pattern, item.handler),
        }
    }
}

pub inline fn comptimeGroup(app: *const App, g: *const Group.ComptimeGroup) void {
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
}

pub fn ws(app: *const App, pattern: [:0]const u8, comptime behavior: WebSocketBehavior) *const App {
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

    if (behavior.upgrade) |f| b.upgrade = upgradeWrapper(f);
    if (behavior.open) |f| b.open = openWrapper(f);
    if (behavior.message) |f| b.message = messageWrapper(f);
    if (behavior.dropped) |f| b.dropped = messageWrapper(f);
    if (behavior.drain) |f| b.drain = drainWrapper(f);
    if (behavior.ping) |f| b.ping = pingWrapper(f);
    if (behavior.pong) |f| b.pong = pingWrapper(f);
    if (behavior.close) |f| b.close = closeWrapper(f);
    if (behavior.subscription) |f| b.subscription = subscriptionWrapper(f);

    c.uws_ws(app.ptr, pattern, b);
    return app;
}

fn handlerWrapper(handler: MethodHandler) fn (rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_s) callconv(.c) void {
    return struct {
        fn handlerWrapper(rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_s) callconv(.c) void {
            var res = Response{ .ptr = rawRes orelse return };
            var req = Request{ .ptr = rawReq orelse return };
            handler(&res, &req);
        }
    }.handlerWrapper;
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
    message: ?*const fn (ws: *WebSocket, message: [:0]const u8, opcode: WebSocket.Opcode) void = null,
    dropped: ?*const fn (ws: *WebSocket, message: [:0]const u8, opcode: WebSocket.Opcode) void = null,
    drain: ?*const fn (ws: *WebSocket) void = null,
    ping: ?*const fn (ws: *WebSocket, message: [:0]const u8) void = null,
    pong: ?*const fn (ws: *WebSocket, message: [:0]const u8) void = null,
    close: ?*const fn (ws: *WebSocket, code: i32, message: [:0]const u8) void = null,
    subscription: ?*const fn (ws: *WebSocket, topic: [:0]const u8, newNumberOfSubscribers: i32, oldNumberOfSubscribers: i32) void = null,
};

fn upgradeWrapper(handler: *const fn (res: *Response, req: *Request) void) fn (
    rawRes: ?*c.uws_res_s,
    rawReq: ?*c.uws_req_t,
    context: ?*c.uws_socket_context_t,
) callconv(.c) void {
    return struct {
        fn upgradeHandler(rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.c) void {
            var res = Response{ .ptr = rawRes orelse return };
            var req = Request{ .ptr = rawReq orelse return };
            handler(&res, &req);
            res.upgrade(&req, context);
        }
    }.upgradeHandler;
}

fn openWrapper(handler: *const fn (ws: *WebSocket) void) fn (rawWs: ?*c.uws_websocket_t) callconv(.c) void {
    return struct {
        fn openHandler(rawWs: ?*c.uws_websocket_t) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s);
        }
    }.openHandler;
}

fn drainWrapper(handler: *const fn (ws: *WebSocket) void) fn (rawWs: ?*c.uws_websocket_t) callconv(.c) void {
    return struct {
        fn drainHandler(rawWs: ?*c.uws_websocket_t) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s);
        }
    }.drainHandler;
}

fn messageWrapper(handler: *const fn (ws: *WebSocket, message: [:0]const u8, opcode: WebSocket.Opcode) void) fn (
    rawWs: ?*c.uws_websocket_t,
    message: [*c]const u8,
    length: usize,
    opcode: c.uws_opcode_t,
) callconv(.c) void {
    return struct {
        fn messageHandler(rawWs: ?*c.uws_websocket_t, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s, message[0..length :0], @enumFromInt(opcode));
        }
    }.messageHandler;
}

fn pingWrapper(handler: *const fn (ws: *WebSocket, message: [:0]const u8) void) fn (rawWs: ?*c.uws_websocket_t, message: [*c]const u8, length: usize) callconv(.c) void {
    return struct {
        fn pingHandler(rawWs: ?*c.uws_websocket_t, message: [*c]const u8, length: usize) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s, message[0..length :0]);
        }
    }.pingHandler;
}

fn closeWrapper(handler: *const fn (ws: *WebSocket, code: i32, message: [:0]const u8) void) fn (
    rawWs: ?*c.uws_websocket_t,
    code: c_int,
    message: [*c]const u8,
    length: usize,
) callconv(.c) void {
    return struct {
        fn closeHandler(rawWs: ?*c.uws_websocket_t, code: c_int, message: [*c]const u8, length: usize) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s, code, message[0..length :0]);
        }
    }.closeHandler;
}

fn subscriptionWrapper(handler: *const fn (ws: *WebSocket, topic: [:0]const u8, newNumberOfSubscribers: i32, oldNumberOfSubscribers: i32) void) fn (
    rawWs: ?*c.uws_websocket_t,
    topic_name: [*c]const u8,
    topic_name_length: usize,
    new_number_of_subscriber: c_int,
    old_number_of_subscriber: c_int,
) callconv(.c) void {
    return struct {
        fn subscriptionHandler(
            rawWs: ?*c.uws_websocket_t,
            topic_name: [*c]const u8,
            topic_name_length: usize,
            new_number_of_subscriber: c_int,
            old_number_of_subscriber: c_int,
        ) callconv(.c) void {
            var w_s = WebSocket{ .ptr = rawWs orelse return };
            handler(&w_s, topic_name[0..topic_name_length :0], new_number_of_subscriber, old_number_of_subscriber);
        }
    }.subscriptionHandler;
}

/// **Args**:
/// * `method` - A ***lowercase*** http method; refers to `bindings/uws.h` -- `HTTP_METHODS`
fn CreateMethodFn(comptime method: [:0]const u8, comptime useWrapper: bool) type {
    var temp_up: [8]u8 = undefined;
    const upper_method = std.ascii.upperString(&temp_up, method);
    const log_str = std.fmt.comptimePrint(if (useWrapper) "Registering {s} route: " else "Registering raw {s} route: ", .{upper_method}) ++ "{s}";

    return if (useWrapper) struct {
        fn f(app: *const App, pattern: [:0]const u8, comptime handler: MethodHandler) *const App {
            if (config.debug_logs) {
                info(log_str, .{pattern});
            }
            @field(c, std.fmt.comptimePrint("uws_app_{s}", .{method}))(app.ptr, pattern, handlerWrapper(handler));
            return app;
        }
    } else struct {
        fn f(app: *const App, pattern: [:0]const u8, handler: c.uws_method_handler) void {
            if (config.debug_logs) {
                info(log_str, .{pattern});
            }
            @field(c, std.fmt.comptimePrint("uws_app_{s}", .{method}))(app.ptr, pattern, handler);
        }
    };
}
