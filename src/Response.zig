const c = @import("uws");
const std = @import("std");
const Request = @import("./Request.zig");

const Response = @This();

ptr: *c.uws_res_s,

/// As per: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
pub const StatusCode = enum(u16) {
    Continue = 100,
    SwitchingProtocols,
    Processing,
    EarlyHints,
    OK = 200,
    Created,
    Accepted,
    @"Non-AuthoritativeInformation",
    NoContent,
    ResetContent,
    PartialContent,
    @"Multi-Status",
    AlreadyReported,
    @"IM Used" = 226,
    MultipleChoices = 300,
    MovedPermanently,
    Found,
    SeeOther,
    NotModified,
    UseProxy,
    TemporaryRedirect = 307,
    PermanentRedirect,
    BadRequest = 400,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    ProxyAuthenticationRequired,
    RequestTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconditionFailed,
    ContentTooLarge,
    URITooLong,
    UnsupportedMediaType,
    RangeNotSatisfiable,
    ExpectationFailed,
    @"I'm a teapot",
    MisdirectedRequest = 421,
    UnprocessableContent,
    Locked,
    FailedDependency,
    TooEarly,
    UpgradeRequired,
    PreconditionRequired = 428,
    TooManyRequests,
    RequestHeaderFieldsTooLarge = 431,
    UnavailableForLegalReasons = 451,
    InternalServerError = 500,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    @"HTTP Version Not Supported",
    VariantAlsoNegotiates,
    InsufficientStorage,
    LoopDetected,
    NotExtended = 510,
    NetworkAuthenticationRequired,

    pub fn toString(comptime self: StatusCode) []const u8 {
        const text = comptime blk: {
            const status = @tagName(self);
            var temp: []const u8 = &.{ status[0], status[1] };
            if (status.len < 3) break :blk temp;
            var i: usize = 2;
            while (i < status.len) : (i += 1) {
                if (i > 2 and std.ascii.isUpper(status[i]) and (status[i - 1] != '-' or status[i - 1] == ' ')) {
                    temp = temp ++ [1]u8{' '};
                }
                temp = temp ++ [1]u8{status[i]};
            }
            break :blk temp;
        };
        return std.fmt.comptimePrint("{d} {s}", .{ @intFromEnum(self), text });
    }
};

pub fn close(res: *const Response) void {
    c.uws_res_close(res.ptr);
}

pub fn end(res: *const Response, data: []const u8, close_connection: bool) void {
    c.uws_res_end(res.ptr, data.ptr, data.len, close_connection);
}

pub fn cork(res: *const Response, callback: fn (Response) void) void {
    const callbackWrapper = struct {
        fn cW(uws_res: ?*const c.uws_res_t) callconv(.c) void {
            callback(Response{ .ptr = @constCast(uws_res) orelse return });
        }
    }.cW;
    c.uws_res_cork(res.ptr, callbackWrapper);
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

pub fn writeStatus(res: *const Response, status: []const u8) void {
    c.uws_res_write_status(res.ptr, status.ptr, status.len);
}

pub fn writeStatusCode(res: *const Response, comptime status: StatusCode) void {
    const status_text = comptime status.toString();
    res.writeStatus(status_text);
}

pub fn writeHeader(res: *const Response, key: []const u8, value: [:0]const u8) void {
    c.uws_res_write_header(res.ptr, key.ptr, key.len, value, value.len);
}

pub fn writeHeaderInt(res: *const Response, key: []const u8, value: u64) void {
    c.uws_res_write_header_int(res.ptr, key.ptr, key.len, value);
}

pub fn endWithoutBody(res: *const Response, close_connection: bool) void {
    c.uws_res_end_without_body(res.ptr, close_connection);
}

pub fn write(res: *const Response, data: []const u8) bool {
    return c.uws_res_write(res.ptr, data.ptr, data.len);
}

pub fn overrideWriteOffset(res: *const Response, offset: u64) void {
    c.uws_res_override_write_offset(res.ptr, offset);
}

pub fn hasResponded(res: *const Response) bool {
    return c.uws_res_has_responded(res.ptr);
}

// TODO: Look into implementing wrappers for these
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

pub fn tryEnd(res: *const Response, data: []const u8, totalSize: u64, close_connection: bool) c.uws_try_end_result_t {
    return c.uws_res_try_end(res.ptr, data.ptr, data.len, totalSize, close_connection);
}

pub fn getWriteOffset(res: *const Response) u64 {
    return c.uws_res_get_write_offset(res.ptr);
}

pub fn getRemoteAddress(res: *const Response) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_res_get_remote_address(res.ptr, &temp);
    return temp[0..len];
}

pub fn getRemoteAddressAsText(res: *const Response) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_res_get_remote_address_as_text(res.ptr, &temp);
    return temp[0..len];
}
