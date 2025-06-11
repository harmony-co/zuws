const zuws = @import("zuws");
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

    try app.listen(3000, null);
}
