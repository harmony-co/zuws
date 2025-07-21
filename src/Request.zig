const c = @import("uws");
const std = @import("std");
const App = @import("./App.zig");

const Request = @This();

pub fn getUrl(self: Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_url(@ptrCast(@alignCast(self)), &temp);
    return temp[0..len];
}

pub fn getFullUrl(self: Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_full_url(@ptrCast(@alignCast(self)), &temp);
    return temp[0..len];
}

pub fn getMethod(self: Request) !App.Method {
    const method = @constCast(self.getCaseSensitiveMethod());

    for (method) |*char| {
        char.* = std.ascii.toUpper(char.*);
    }

    return std.meta.stringToEnum(App.Method, method) orelse error.UnknownMethod;
}

pub fn getCaseSensitiveMethod(self: Request) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_case_sensitive_method(@ptrCast(@alignCast(self)), &temp);
    return temp[0..len];
}

pub fn getHeader(self: Request, lower_case_header: []const u8) ?[]const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_header(@ptrCast(@alignCast(self)), lower_case_header.ptr, lower_case_header.len, &temp);
    return if (temp == null) null else temp[0..len];
}

pub fn getQueryParam(self: Request, name: []const u8) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_query(@ptrCast(@alignCast(self)), name.ptr, name.len, &temp);
    return temp[0..len];
}

pub fn getParameter(self: Request, index: u16) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_req_get_parameter_index(@ptrCast(@alignCast(self)), @as(c_ushort, index), &temp);
    return temp[0..len];
}
