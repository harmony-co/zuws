const std = @import("std");

const c = @import("bindings.zig");

const App = @import("./app.zig").uWSApp;

pub const Request = opaque {
    pub fn getUrl(self: *Request) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_url(self, &temp);
        return temp[0..len];
    }

    pub fn getFullUrl(self: *Request) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_full_url(self, &temp);
        return temp[0..len];
    }

    pub fn getMethod(self: *Request) !App.Method {
        const method = @constCast(self.getCaseSensitiveMethod());

        for (method) |*char| {
            char.* = std.ascii.toUpper(char.*);
        }

        return std.meta.stringToEnum(App.Method, method) orelse error.UnknownMethod;
    }

    pub fn getCaseSensitiveMethod(self: *Request) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_case_sensitive_method(self, &temp);
        return temp[0..len];
    }

    pub const Headers = std.StringHashMap([]const u8);

    pub fn getAllHeaders(self: *Request, gpa: std.mem.Allocator) !Headers {
        var map: Headers = .init(gpa);
        errdefer map.deinit();
        const did_error = c.uws_req_for_each_header(self, &map, headerIterator);
        if (did_error == 1) return error.OutOfMemory;
        return try map.clone();
    }

    fn headerIterator(ctx: ?*anyopaque, key: [*c]const u8, key_len: usize, value: [*c]const u8, value_len: usize) callconv(.c) u8 {
        const map: *Headers = @ptrCast(@alignCast(ctx));
        map.put(key[0..key_len], value[0..value_len]) catch return 1;
        return 0;
    }

    pub fn getHeader(self: *Request, lower_case_header: []const u8) ?[]const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_header(self, lower_case_header.ptr, lower_case_header.len, &temp);
        return if (temp == null) null else temp[0..len];
    }

    pub fn getQueryParam(self: *Request, name: []const u8) ?[]const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_query(self, name.ptr, name.len, &temp);
        return if (temp == null) null else temp[0..len];
    }

    pub fn getParameter(self: *Request, index: u16) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_req_get_parameter_index(self, @as(c_ushort, index), &temp);
        return temp[0..len];
    }
};
