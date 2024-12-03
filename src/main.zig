const std = @import("std");
const c = @cImport({
    @cInclude("uws.h");
});

pub fn main() !void {
    const app = c.uws_create_app();
    defer c.uws_app_destroy(app);

    c.uws_app_get(app, "/*", hello);
    c.uws_app_listen(app, 3000, null);
}

fn hello(res: ?*c.uws_res_t, req: ?*c.uws_req_t) callconv(.C) void {
    _ = req;
    const str = "Hello World!";
    c.uws_res_end(res, str, str.len);
}
