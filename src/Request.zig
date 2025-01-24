const c = @import("uws");

const Request = @This();

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

pub fn getParameterByIndex(res: *const Request, index: u16) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_parameter_index(res.ptr, @as(c_ushort, index), &temp);
    return temp[0..len];
}

pub fn getParameterByName(res: *const Request, name: [:0]const u8) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_parameter_name(res.ptr, name, name.len, &temp);
    return temp[0..len];
}
