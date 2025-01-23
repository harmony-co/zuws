const std = @import("std");
const c = @import("uws");

pub const uWSError = error{
    CouldNotCreateApp,
};

pub const MethodHandler = *const fn (*Response, *Request) void;

fn handlerWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_s) callconv(.C) void {
    const handler_ptr: MethodHandler = @ptrCast(@alignCast(ptr));
    var res = Response{ .ptr = rawRes orelse return };
    var req = Request{ .ptr = rawReq orelse return };
    handler_ptr(&res, &req);
}

pub const Response = struct {
    ptr: *c.uws_res_s,

    pub fn close(res: *const Response) void {
        c.uws_res_close(res.ptr);
    }

    pub fn end(res: *const Response, data: [:0]const u8, length: usize, close_connection: bool) void {
        c.uws_res_end(res.ptr, data, length, close_connection);
    }

    pub fn cork(res: *const Response, callback: ?*const fn (*const Response) callconv(.C) void) void {
        c.uws_res_cork(res.ptr, callback);
    }

    pub fn pause(res: *const Response) void {
        c.uws_res_pause(res.ptr);
    }

    pub fn restart(res: *const Response) void {
        c.uws_res_resume(res.ptr);
    }

    pub fn writeContinue(res: *const Response) void {
        c.uws_res_write_continue(res.ptr);
    }

    pub fn writeStatus(res: *const Response, status: [:0]const u8, length: usize) void {
        c.uws_res_write_status(res.ptr, status, length);
    }

    pub fn writeHeader(res: *const Response, key: [:0]const u8, key_length: usize, value: [:0]const u8, value_length: usize) void {
        c.uws_res_write_header(res.ptr, key, key_length, value, value_length);
    }

    pub fn writeHeaderInt(res: *const Response, key: [:0]const u8, key_length: usize, value: u64) void {
        c.uws_res_write_header_int(res.ptr, key, key_length, value);
    }

    pub fn endWithoutBody(res: *const Response, close_connection: bool) void {
        c.uws_res_end_without_body(res.ptr, close_connection);
    }

    pub fn write(res: *const Response, data: [:0]const u8, length: usize) bool {
        return c.uws_res_write(res.ptr, data, length);
    }

    pub fn overrideWriteOffset(res: *const Response, offset: c_ulong) void {
        c.uws_res_override_write_offset(res.ptr, offset);
    }

    pub fn hasResponded(res: *const Response) bool {
        return c.uws_res_has_responded(res.ptr);
    }

    pub fn onWritable(res: *const Response, handler: c.uws_res_on_writable_handler) void {
        c.uws_res_on_writable(res.ptr, handler);
    }

    pub fn onAborted(res: *const Response, handler: c.uws_res_on_aborted_handler) void {
        c.uws_res_on_aborted(res.ptr, handler);
    }

    pub fn onData(res: *const Response, handler: c.uws_res_on_data_handler) void {
        c.uws_res_on_data(res.ptr, handler);
    }

    pub fn upgrade(
        res: *const Response,
        req: *const Request,
        ws: ?*c.uws_socket_context_t,
    ) void {
        var ws_key: [*c]const u8 = undefined;
        var ws_protocol: [*c]const u8 = undefined;
        var ws_extensions: [*c]const u8 = undefined;
        const ws_key_len = c.uws_req_get_header(req.ptr, "sec-websocket-key", 17, &ws_key);
        const ws_protocol_len = c.uws_req_get_header(req.ptr, "sec-websocket-protocol", 22, &ws_protocol);
        const ws_extensions_len = c.uws_req_get_header(req.ptr, "sec-websocket-extensions", 24, &ws_extensions);

        c.uws_res_upgrade(
            res.ptr,
            null,
            ws_key,
            ws_key_len,
            ws_protocol,
            ws_protocol_len,
            ws_extensions,
            ws_extensions_len,
            ws,
        );
    }

    pub fn tryEnd(res: *const Response, data: [:0]const u8, length: usize, totalSize: c_ulong, close_connection: bool) c.uws_try_end_result_t {
        return c.uws_res_try_end(res.ptr, data, length, totalSize, close_connection);
    }

    pub fn getWriteOffset(res: *const Response) c_ulong {
        return c.uws_res_get_write_offset(res.ptr);
    }

    pub fn getRemoteAddress(res: *const Response, dest: *[:0]const u8) usize {
        return c.uws_res_get_remote_address(res.ptr, dest);
    }

    pub fn getRemoteAddressAsText(res: *const Response, dest: *[:0]const u8) usize {
        return c.uws_res_get_remote_address_as_text(res.ptr, dest);
    }
};

pub const Request = struct {
    ptr: *c.uws_req_s,

    pub fn isAncient(res: *const Request) bool {
        return c.uws_req_is_ancient(res.ptr);
    }

    pub fn getYield(res: *const Request) bool {
        return c.uws_req_get_yield(res.ptr);
    }

    pub fn setYield(res: *const Request, yield: bool) void {
        c.uws_req_set_yield(res.ptr, yield);
    }

    pub fn forEachHeader(res: *const Request, handler: c.uws_get_headers_server_handler) void {
        c.uws_req_for_each_header(res.ptr, handler);
    }

    pub fn getUrl(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_url(res.ptr, dest);
    }

    pub fn getFullUrl(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_full_url(res.ptr, dest);
    }

    pub fn getMethod(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_method(res.ptr, dest);
    }

    pub fn getCaseSensitiveMethod(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_case_sensitive_method(res.ptr, dest);
    }

    pub fn getHeader(res: *const Request, lowerCaseHeader: [:0]const u8, lower_case_header_length: usize, dest: *[:0]const u8) usize {
        return c.uws_req_get_header(res.ptr, lowerCaseHeader, lower_case_header_length, dest);
    }

    pub fn getQuery(res: *const Request, key: [:0]const u8, key_length: usize, dest: *[:0]const u8) usize {
        return c.uws_req_get_query(res.ptr, key, key_length, dest);
    }

    pub fn getParameter(res: *const Request, index: c_ushort, dest: *[:0]const u8) usize {
        return c.uws_req_get_parameter(res.ptr, index, dest);
    }
};

pub const App = struct {
    ptr: *c.uws_app_s,

    const Method = enum { Get, Put };
    const ListType = struct {
        method: Method,
        base: []const u8,
        handler: MethodHandler,
    };
    pub const Group = struct {
        list: []const ListType = &.{},
        base_path: []const u8,

        pub fn get(comptime self: *Group, comptime pattern: []const u8, handler: MethodHandler) *const Group {
            self.list = self.list ++ .{.{
                .method = .Get,
                .base = self.base_path ++ pattern,
                .handler = handler,
            }};
            return self;
        }
    };

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

    pub fn get(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_get(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn post(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_post(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn put(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_put(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn options(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_options(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn del(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_del(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn patch(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_patch(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn head(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_head(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn connect(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_connect(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn trace(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_trace(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn any(app: *const App, pattern: [:0]const u8, handler: MethodHandler) *const App {
        c.uws_app_any(app.ptr, pattern, handlerWrapper, @constCast(handler));
        return app;
    }

    pub fn group(app: *const App, comptime g: *const Group) void {
        inline for (g.list) |item| {
            switch (item.method) {
                .Get => {
                    std.debug.print("Adding GET method on path: {s}\n", .{item[1]});
                    _ = app.get(item.base, item.handler);
                },
                else => unreachable,
            }
        }
    }

    pub fn ws(app: *const App, pattern: [:0]const u8, behavior: c.uws_socket_behavior_t) *const App {
        c.uws_ws(app.ptr, pattern, behavior);
        return app;
    }
};
