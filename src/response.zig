const std = @import("std");

const c = @import("./bindings.zig");

const Request = @import("./request.zig").Request;

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

pub const Response = opaque {
    pub const close = c.uws_res_close;
    pub const pause = c.uws_res_pause;
    pub const restart = c.uws_res_resume;
    pub const writeContinue = c.uws_res_write_continue;

    pub fn end(self: *Response, data: []const u8, close_connection: bool) void {
        c.uws_res_end(self, data.ptr, data.len, close_connection);
    }

    pub fn cork(self: *Response, callback: fn (*Response) void) void {
        const callbackWrapper = struct {
            fn cW(uws_res: ?*const c.uws_res_t) callconv(.c) void {
                var res = Response{ .ptr = @constCast(uws_res) orelse return };
                callback(&res);
            }
        }.cW;
        c.uws_res_cork(self, callbackWrapper);
    }

    pub fn writeStatus(self: *Response, status: []const u8) void {
        c.uws_res_write_status(self, status.ptr, status.len);
    }

    pub fn writeStatusCode(self: *Response, status: StatusCode) void {
        var buf: [8]u8 = undefined;
        self.writeStatus(std.fmt.bufPrint(&buf, "{d}", .{status}) catch unreachable);
    }

    pub fn writeStatusCodeWithText(self: *Response, comptime status: StatusCode) void {
        const status_text = comptime status.toString();
        self.writeStatus(status_text);
    }

    pub fn writeHeader(self: *Response, key: []const u8, value: []const u8) void {
        c.uws_res_write_header(self, key.ptr, key.len, value.ptr, value.len);
    }

    pub fn writeHeaderInt(self: *Response, key: []const u8, value: u64) void {
        c.uws_res_write_header_int(self, key.ptr, key.len, value);
    }

    pub fn endWithoutBody(self: *Response, close_connection: bool) void {
        c.uws_res_end_without_body(self, close_connection);
    }

    pub fn write(self: *Response, data: []const u8) bool {
        return c.uws_res_write(self, data.ptr, data.len);
    }

    pub fn overrideWriteOffset(self: *Response, offset: u64) void {
        c.uws_res_override_write_offset(self, offset);
    }

    pub fn hasResponded(self: *Response) bool {
        return c.uws_res_has_responded(self);
    }

    // TODO: Look into implementing wrappers for these
    pub fn onWritable(self: *Response, handler: c.uws_res_on_writable_handler) void {
        c.uws_res_on_writable(self, handler);
    }

    pub fn onAborted(self: *Response, handler: c.uws_res_on_aborted_handler) void {
        c.uws_res_on_aborted(self, handler);
    }

    const OnDataCallback = fn (*Response, *anyopaque, []const u8, bool) void;

    pub fn onData(self: *Response, ctx: *anyopaque, callback: OnDataCallback) void {
        c.uws_res_on_data(self, ctx, callback);
    }

    pub fn upgrade(
        self: *Response,
        req: *Request,
        ws: ?*c.SocketContext,
    ) void {
        const ws_key = req.getHeader("sec-websocket-key");
        const ws_protocol = req.getHeader("sec-websocket-protocol");
        const ws_extensions = req.getHeader("sec-websocket-extensions");

        c.uws_res_upgrade(
            self,
            null,
            ws_key.ptr,
            ws_key.len,
            ws_protocol.ptr,
            ws_protocol.len,
            ws_extensions.ptr,
            ws_extensions.len,
            ws,
        );
    }

    pub fn tryEnd(self: *Response, data: []const u8, totalSize: u64, close_connection: bool) c.uws_try_end_result_t {
        return c.uws_res_try_end(self, data.ptr, data.len, totalSize, close_connection);
    }

    pub fn getWriteOffset(self: *Response) u64 {
        return c.uws_res_get_write_offset(self);
    }

    pub fn getRemoteAddress(self: *Response) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_res_get_remote_address(self, &temp);
        return temp[0..len];
    }

    pub fn getRemoteAddressAsText(self: *Response) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_res_get_remote_address_as_text(self, &temp);
        return temp[0..len];
    }
};
