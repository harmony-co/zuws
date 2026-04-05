const c = @import("uws");

const uWSApp = @import("./app.zig").uWSApp;
const Response = @import("./response.zig").Response;
const Request = @import("./request.zig").Request;
const WebSocket = @import("./ws.zig").uWSWebSocket;

pub const ListenSocket = extern struct {
    s: void align(16),
    socket_ext_size: u32,
};

pub const MethodHandler = *const fn (*Response, *Request) callconv(.c) void;
pub const ListenHandler = *const fn (*ListenSocket) callconv(.c) void;

pub extern fn uws_create_app(...) ?*uWSApp;
pub extern fn uws_app_destroy(app: *uWSApp) void;
pub extern fn uws_app_run(app: *uWSApp) void;
pub extern fn uws_app_listen(app: *uWSApp, port: u16, handler: ?ListenHandler) void;
pub extern fn uws_app_close(app: *uWSApp) void;

pub extern fn uws_app_get(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_post(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_put(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_options(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_del(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_patch(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_head(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_connect(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_trace(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;
pub extern fn uws_app_any(app: *uWSApp, pattern: [*c]const u8, handler: MethodHandler) *uWSApp;

pub extern fn uws_res_close(res: *Response) void;
pub extern fn uws_res_end(res: *Response, data: [*c]const u8, length: usize, close_connection: bool) void;
pub extern fn uws_res_cork(res: *Response, callback: ?*const fn (*Response) callconv(.c) void) void;
pub extern fn uws_res_pause(res: *Response) void;
pub extern fn uws_res_resume(res: *Response) void;
pub extern fn uws_res_write_continue(res: *Response) void;
pub extern fn uws_res_write_status(res: *Response, status: [*c]const u8, length: usize) void;
pub extern fn uws_res_write_header(res: *Response, key: [*c]const u8, key_length: usize, value: [*c]const u8, value_length: usize) void;
pub extern fn uws_res_write_header_int(res: *Response, key: [*c]const u8, key_length: usize, value: u64) void;
pub extern fn uws_res_end_without_body(res: *Response, close_connection: bool) void;
pub extern fn uws_res_write(res: *Response, data: [*c]const u8, length: usize) bool;
pub extern fn uws_res_override_write_offset(res: *Response, offset: c.uintmax_t) void;
pub extern fn uws_res_has_responded(res: *Response) bool;
pub extern fn uws_res_on_writable(res: *Response, handler: c.uws_res_on_writable_handler) void;
pub extern fn uws_res_on_aborted(res: *Response, handler: c.uws_res_on_aborted_handler) void;
pub extern fn uws_res_on_data(res: *Response, ctx: ?*anyopaque, handler: c.uws_res_on_data_handler) void;
pub extern fn uws_res_upgrade(res: *Response, data: ?*anyopaque, sec_web_socket_key: [*c]const u8, sec_web_socket_key_length: usize, sec_web_socket_protocol: [*c]const u8, sec_web_socket_protocol_length: usize, sec_web_socket_extensions: [*c]const u8, sec_web_socket_extensions_length: usize, ws: ?*c.uws_socket_context_t) void;
pub extern fn uws_res_try_end(res: *Response, data: [*c]const u8, length: usize, total_size: c.uintmax_t, close_connection: bool) c.uws_try_end_result_t;
pub extern fn uws_res_get_write_offset(res: *Response) c.uintmax_t;
pub extern fn uws_res_get_remote_address(res: *Response, dest: [*c][*c]const u8) usize;
pub extern fn uws_res_get_remote_address_as_text(res: *Response, dest: [*c][*c]const u8) usize;

pub extern fn uws_req_is_ancient(res: *Request) bool;
pub extern fn uws_req_get_yield(res: *Request) bool;
pub extern fn uws_req_set_yield(res: *Request, yield: bool) void;
pub extern fn uws_req_for_each_header(res: *Request, ctx: ?*anyopaque, handler: c.uws_get_headers_server_handler) u8;
pub extern fn uws_req_get_url(res: *Request, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_full_url(res: *Request, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_method(res: *Request, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_case_sensitive_method(res: *Request, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_header(res: *Request, lower_case_header: [*c]const u8, lower_case_header_length: usize, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_query(res: *Request, key: [*c]const u8, key_length: usize, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_parameter_name(res: *Request, key: [*c]const u8, key_length: usize, dest: [*c][*c]const u8) usize;
pub extern fn uws_req_get_parameter_index(res: *Request, index: c_ushort, dest: [*c][*c]const u8) usize;

pub const CompressOptions = enum(u16) {
    disabled = c.DISABLED,
    shared_compressor = c.SHARED_COMPRESSOR,
    shared_decompressor = c.SHARED_DECOMPRESSOR,
    dedicated_decompressor_512b = c.DEDICATED_DECOMPRESSOR_512B,
    dedicated_decompressor_1kb = c.DEDICATED_DECOMPRESSOR_1KB,
    dedicated_decompressor_2kb = c.DEDICATED_DECOMPRESSOR_2KB,
    dedicated_decompressor_4kb = c.DEDICATED_DECOMPRESSOR_4KB,
    dedicated_decompressor_8kb = c.DEDICATED_DECOMPRESSOR_8KB,
    dedicated_decompressor_16kb = c.DEDICATED_DECOMPRESSOR_16KB,
    dedicated_decompressor_32kb = c.DEDICATED_DECOMPRESSOR_32KB,
    dedicated_compressor_3kb = c.DEDICATED_COMPRESSOR_3KB,
    dedicated_compressor_4kb = c.DEDICATED_COMPRESSOR_4KB,
    dedicated_compressor_8kb = c.DEDICATED_COMPRESSOR_8KB,
    dedicated_compressor_16kb = c.DEDICATED_COMPRESSOR_16KB,
    dedicated_compressor_32kb = c.DEDICATED_COMPRESSOR_32KB,
    dedicated_compressor_64kb = c.DEDICATED_COMPRESSOR_64KB,
    dedicated_compressor_128kb = c.DEDICATED_COMPRESSOR_128KB,
    dedicated_compressor_256kb = c.DEDICATED_COMPRESSOR_256KB,
};

pub const Opcode = enum(u8) {
    continuation = c.CONTINUATION,
    text = c.TEXT,
    binary = c.BINARY,
    close = c.CLOSE,
    ping = c.PING,
    pong = c.PONG,
};

pub const Status = enum(u8) {
    backpressure,
    success,
    dropped,
};

pub const UpgradeHandler = *const fn (*Response, *Request) callconv(.c) void;
pub const OpenHandler = *const fn (ws: *WebSocket) callconv(.c) void;
pub const DrainHandler = *const fn (ws: *WebSocket) callconv(.c) void;

// This callbacks need to be wrapped so strings can be used the zig way
pub const MessageHandler = *const fn (ws: *WebSocket, message: []const u8, opcode: Opcode) void;
pub const uws_websocket_message = *const fn (*WebSocket, [*c]const u8, usize, c.uws_opcode_t) callconv(.c) void;

pub const PingPongHandler = *const fn (ws: *WebSocket, message: []const u8) void;
pub const uws_websocket_ping_pong = *const fn (*WebSocket, [*c]const u8, usize) callconv(.c) void;

pub const CloseHandler = *const fn (ws: *WebSocket, code: i32, message: ?[]const u8) void;
pub const uws_websocket_close = *const fn (*WebSocket, c_int, [*c]const u8, usize) callconv(.c) void;

pub const SubscriptionHandler = *const fn (ws: *WebSocket, topic: []const u8, new_sub_num: i32, old_sub_num: i32) void;
pub const uws_websocket_subscription = *const fn (*WebSocket, [*c]const u8, usize, c_int, c_int) callconv(.c) void;

// https://github.com/uNetworking/uWebSockets/blob/b9b59b2b164489f3788223fec5821f77f7962d43/src/App.h#L234-L259
pub const WebSocketBehavior = extern struct {
    compression: CompressOptions = .disabled,
    maxPayloadLength: u32 = 16 * 1024,
    /// In seconds
    idleTimeout: u16 = 120,
    maxBackpressure: u32 = 64 * 1024,
    closeOnBackpressureLimit: bool = false,
    resetIdleTimeoutOnSend: bool = false,
    sendPingsAutomatically: bool = true,
    maxLifetime: u16 = 0,
    upgrade: ?UpgradeHandler = null,
    open: ?OpenHandler = null,
    message: ?uws_websocket_message = null,
    dropped: ?uws_websocket_message = null,
    drain: ?DrainHandler = null,
    ping: ?uws_websocket_ping_pong = null,
    pong: ?uws_websocket_ping_pong = null,
    close: ?uws_websocket_close = null,
    subscription: ?uws_websocket_subscription = null,
};

pub const WrappedWebSocketBehavior = extern struct {
    compression: CompressOptions = .disabled,
    max_payload_length: u32 = 16 * 1024,
    /// In seconds
    idle_timeout: u16 = 120,
    max_backpressure: u32 = 64 * 1024,
    close_on_backpressure_limit: bool = false,
    reset_idle_timeout_on_send: bool = false,
    send_pings_automatically: bool = true,
    max_lifetime: u16 = 0,
    upgrade: ?UpgradeHandler = null,
    open: ?OpenHandler = null,
    message: ?MessageHandler = null,
    dropped: ?MessageHandler = null,
    drain: ?DrainHandler = null,
    ping: ?PingPongHandler = null,
    pong: ?PingPongHandler = null,
    close: ?CloseHandler = null,
    subscription: ?SubscriptionHandler = null,
};

pub extern fn uws_ws(app: *uWSApp, pattern: [*c]const u8, behavior: WebSocketBehavior) *uWSApp;
pub extern fn uws_ws_close(ws: *WebSocket) void;
pub extern fn uws_ws_send(ws: *WebSocket, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t) c.uws_sendstatus_t;
pub extern fn uws_ws_send_with_options(ws: *WebSocket, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t, compress: bool, fin: bool) c.uws_sendstatus_t;
pub extern fn uws_ws_send_fragment(ws: *WebSocket, message: [*c]const u8, length: usize, compress: bool) c.uws_sendstatus_t;
pub extern fn uws_ws_send_first_fragment(ws: *WebSocket, message: [*c]const u8, length: usize, compress: bool) c.uws_sendstatus_t;
pub extern fn uws_ws_send_first_fragment_with_opcode(ws: *WebSocket, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t, compress: bool) c.uws_sendstatus_t;
pub extern fn uws_ws_send_last_fragment(ws: *WebSocket, message: [*c]const u8, length: usize, compress: bool) c.uws_sendstatus_t;
pub extern fn uws_ws_end(ws: *WebSocket, code: c_int, message: [*c]const u8, length: usize) void;
pub extern fn uws_ws_cork(ws: *WebSocket, handler: ?*const fn (...) callconv(.c) void) void;
pub extern fn uws_ws_subscribe(ws: *WebSocket, topic: [*c]const u8, length: usize) bool;
pub extern fn uws_ws_unsubscribe(ws: *WebSocket, topic: [*c]const u8, length: usize) bool;
pub extern fn uws_ws_is_subscribed(ws: *WebSocket, topic: [*c]const u8, length: usize) bool;
pub extern fn uws_ws_iterate_topics(ws: *WebSocket, callback: ?*const fn ([*c]const u8, usize) callconv(.c) void) void;
pub extern fn uws_ws_publish(ws: *WebSocket, topic: [*c]const u8, topic_length: usize, message: [*c]const u8, message_length: usize) bool;
pub extern fn uws_ws_publish_with_options(ws: *WebSocket, topic: [*c]const u8, topic_length: usize, message: [*c]const u8, message_length: usize, opcode: c.uws_opcode_t, compress: bool) bool;
pub extern fn uws_ws_get_buffered_amount(ws: *WebSocket) c_uint;
pub extern fn uws_ws_get_remote_address(ws: *WebSocket, dest: [*c][*c]const u8) usize;
pub extern fn uws_ws_get_remote_address_as_text(ws: *WebSocket, dest: [*c][*c]const u8) usize;
