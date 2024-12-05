const std = @import("std");
const App = @import("./app.zig").App;

const c = @import("uws");

pub fn main() !void {
    const app = try App.init();
    defer app.deinit();

    app.get("/*", hello)
        .listen(3001, null);
}

fn hello(res: ?*c.uws_res_t, req: ?*c.uws_req_t) callconv(.C) void {
    _ = req;
    const str = "Hello World!\n";
    c.uws_res_end(res, str, str.len, false);
}
