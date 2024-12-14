const std = @import("std");
const App = @import("./app.zig").App;
const Response = @import("./app.zig").Response;
const Request = @import("./app.zig").Request;
const handlerWrapper = @import("./app.zig").handlerWrapper;

const c = @import("uws");

pub fn main() !void {
    const app = try App.init();
    defer app.deinit();

    try app.get("/get", hello)
        .ws("/ws", .{
        .maxPayloadLength = 1024,
        .upgrade = .{ .handler = handlerWrapper, .ptr = on_upgrade },
        .open = on_open,
        .close = on_close,
        .message = on_message,
    }).listen(3000, null);
}

fn hello(res: *Response, req: *Request) void {
    _ = req;
    const str = "Hello World!\n";
    res.end(str, str.len, false);
}

fn on_upgrade(res: *Response, req: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.C) void {
    res.upgrade(req, .{}, context);
}

fn on_open(ws: ?*c.uws_websocket_t) callconv(.C) void {
    std.debug.print("Opened with {any}\n", .{ws});
}

fn on_close(ws: ?*c.uws_websocket_t, code: c_int, message: [*c]const u8, length: usize) callconv(.C) void {
    c.uws_ws_close(ws);
    std.debug.print("Closed with {s} | {d} | {d}\n", .{ message, length, code });
}

fn on_message(ws: ?*c.uws_websocket_t, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t) callconv(.C) void {
    _ = c.uws_ws_send(ws, message, length, opcode);
}
