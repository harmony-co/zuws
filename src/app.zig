const std = @import("std");
const c = @import("uws");

pub const uWSError = error{
    CouldNotCreateApp,
};

const method_handler = *const fn (Response, Request) void;

pub const Response = struct {
    ptr: *c.uws_res_s,

    pub fn close(res: *const Response) void {
        return c.uws_res_close(res.ptr);
    }
    pub fn end(res: *const Response, data: [:0]const u8, length: usize, close_connection: bool) void {
        return c.uws_res_end(res.ptr, data, length, close_connection);
    }
    pub fn cork(res: *const Response, callback: ?*const fn (*const Response, ?*anyopaque) callconv(.C) void, user_data: ?*anyopaque) void {
        return c.uws_res_cork(res.ptr, callback, user_data);
    }
    pub fn pause(res: *const Response) void {
        return c.uws_res_pause(res.ptr);
    }
    pub fn restart(res: *const Response) void {
        return c.uws_res_resume(res.ptr);
    }
    pub fn write_continue(res: *const Response) void {
        return c.uws_res_write_continue(res.ptr);
    }
    pub fn write_status(res: *const Response, status: [:0]const u8, length: usize) void {
        return c.uws_res_write_status(res.ptr, status, length);
    }
    pub fn write_header(res: *const Response, key: [:0]const u8, key_length: usize, value: [:0]const u8, value_length: usize) void {
        return c.uws_res_write_header(res.ptr, key, key_length, value, value_length);
    }
    pub fn write_header_int(res: *const Response, key: [:0]const u8, key_length: usize, value: u64) void {
        return c.uws_res_write_header_int(res.ptr, key, key_length, value);
    }
    pub fn end_without_body(res: *const Response, close_connection: bool) void {
        return c.uws_res_end_without_body(res.ptr, close_connection);
    }
    pub fn write(res: *const Response, data: [:0]const u8, length: usize) bool {
        return c.uws_res_write(res.ptr, data, length);
    }
    pub fn override_write_offset(res: *const Response, offset: c_ulong) void {
        return c.uws_res_override_write_offset(res.ptr, offset);
    }
    pub fn has_responded(res: *const Response) bool {
        return c.uws_res_has_responded(res.ptr);
    }
    pub fn on_writable(res: *const Response, handler: c.uws_res_on_writable_handler, user_data: ?*anyopaque) void {
        return c.uws_res_on_writable(res.ptr, handler, user_data);
    }
    pub fn on_aborted(res: *const Response, handler: c.uws_res_on_aborted_handler, optional_data: ?*anyopaque) void {
        return c.uws_res_on_aborted(res.ptr, handler, optional_data);
    }
    pub fn on_data(res: *const Response, handler: c.uws_res_on_data_handler, optional_data: ?*anyopaque) void {
        return c.uws_res_on_data(res.ptr, handler, optional_data);
    }
    pub fn upgrade(res: *const Response, data: ?*anyopaque, sec_web_socket_key: [:0]const u8, sec_web_socket_key_length: usize, sec_web_socket_protocol: [:0]const u8, sec_web_socket_protocol_length: usize, sec_web_socket_extensions: [:0]const u8, sec_web_socket_extensions_length: usize, ws: ?*c.uws_socket_context_t) void {
        return c.uws_res_upgrade(res.ptr, data, sec_web_socket_key, sec_web_socket_key_length, sec_web_socket_protocol, sec_web_socket_protocol_length, sec_web_socket_extensions, sec_web_socket_extensions_length, ws);
    }
    pub fn try_end(res: *const Response, data: [:0]const u8, length: usize, total_size: c_ulong, close_connection: bool) c.uws_try_end_result_t {
        return c.uws_res_try_end(res.ptr, data, length, total_size, close_connection);
    }
    pub fn get_write_offset(res: *const Response) c_ulong {
        return c.uws_res_get_write_offset(res.ptr);
    }
    pub fn get_remote_address(res: *const Response, dest: *[:0]const u8) usize {
        return c.uws_res_get_remote_address(res.ptr, dest);
    }
    pub fn get_remote_address_as_text(res: *const Response, dest: *[:0]const u8) usize {
        return c.uws_res_get_remote_address_as_text(res.ptr, dest);
    }
};

pub const Request = struct {
    ptr: *c.uws_req_s,

    pub fn is_ancient(res: *const Request) bool {
        return c.uws_req_is_ancient(res);
    }
    pub fn get_yield(res: *const Request) bool {
        return c.uws_req_get_yield(res);
    }
    pub fn set_yield(res: *const Request, yield: bool) void {
        return c.uws_req_set_yield(res, yield);
    }
    pub fn for_each_header(res: *const Request, handler: c.uws_get_headers_server_handler, user_data: ?*anyopaque) void {
        return c.uws_req_for_each_header(res, handler, user_data);
    }
    pub fn get_url(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_url(res, dest);
    }
    pub fn get_full_url(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_full_url(res, dest);
    }
    pub fn get_method(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_method(res, dest);
    }
    pub fn get_case_sensitive_method(res: *const Request, dest: *[:0]const u8) usize {
        return c.uws_req_get_case_sensitive_method(res, dest);
    }
    pub fn get_header(res: *const Request, lower_case_header: [:0]const u8, lower_case_header_length: usize, dest: *[:0]const u8) usize {
        return c.uws_req_get_header(res, lower_case_header, lower_case_header_length, dest);
    }
    pub fn get_query(res: *const Request, key: [:0]const u8, key_length: usize, dest: *[:0]const u8) usize {
        return c.uws_req_get_query(res, key, key_length, dest);
    }
    pub fn get_parameter(res: *const Request, index: c_ushort, dest: *[:0]const u8) usize {
        return c.uws_req_get_parameter(res, index, dest);
    }
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

    pub fn ws(app: *const App, pattern: [:0]const u8, behavior: c.uws_socket_behavior_t) *const App {
        c.uws_ws(app.ptr, pattern, behavior);
        return app;
    }
};
