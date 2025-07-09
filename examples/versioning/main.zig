const zuws = @import("zuws");
const App = zuws.App;
const Request = zuws.Request;
const Response = zuws.Response;

pub fn main() !void {
    const app: App = try .init();
    defer app.deinit();

    const api = App.Group.initComptime("/api");
    const v1 = App.Group.initComptime("/v1")
        .get("/hello", helloWorld);

    const v2 = App.Group.initComptime("/v2")
        .merge(v1)
        .get("/hello2", helloWorld2);

    _ = api.group(v1)
        .group(v2);

    app.comptimeGroup(api);

    app.listen(3000, null);
    app.run();
}

fn helloWorld(res: *Response, _: *Request) void {
    res.end("Hello World!\n", false);
}

fn helloWorld2(res: *Response, _: *Request) void {
    res.end("Hello World! (The second)\n", false);
}
