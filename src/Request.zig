const c = @import("uws");
const std = @import("std");
const App = @import("./App.zig");

const Request = @This();

ptr: *c.uws_req_s,

pub fn getUrl(res: *const Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_url(res.ptr, &temp);
    return temp[0..len];
}

pub fn getFullUrl(res: *const Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_full_url(res.ptr, &temp);
    return temp[0..len];
}

pub fn getMethod(res: *const Request) !App.Method {
    var method = @constCast(res.getCaseSensitiveMethod());
    method[0] = std.ascii.toUpper(method[0]);

    var i: u8 = 1;
    while (method.len > i) : (i += 1) {
        method[i] = std.ascii.toLower(method[i]);
    }

    return std.meta.stringToEnum(App.Method, method) orelse error.UnknownMethod;
}

pub fn getCaseSensitiveMethod(res: *const Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_case_sensitive_method(res.ptr, &temp);
    return temp[0..len];
}

pub fn getHeader(res: *const Request, lowerCaseHeader: [:0]const u8) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_header(res.ptr, lowerCaseHeader, lowerCaseHeader.len, &temp);
    return temp[0..len];
}

pub fn getQueryParam(res: *const Request, name: [:0]const u8) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_query(res.ptr, name, name.len, &temp);
    return temp[0..len];
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
