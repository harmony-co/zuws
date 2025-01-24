const c = @import("uws");
const Request = @import("./Request.zig");

const Response = @This();

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
