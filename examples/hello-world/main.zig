const zuws = @import("zuws");
const std = @import("std");

const App = zuws.App;
const Request = zuws.Request;
const Response = zuws.Response;

pub fn main() !void {
    const app: App = try .init();
    defer app.deinit();

    _ = app.get("/*", struct {
        fn f(res: *Response, _: *Request) void {
            res.end("Hello World!\n", false);
        }
    }.f);

    app.listen(3000, listen);
    app.run();
}

fn listen(socket: ?*App.ListenSocket) void {
    if (socket == null) {
        @panic("Failed to listen");
    }

    std.debug.print("Listening on port 3000\n", .{});
}
