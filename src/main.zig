const std = @import("std");
const App = @import("./app.zig").App;
const Response = @import("./app.zig").Response;
const Request = @import("./app.zig").Request;
const MethodHandler = @import("./app.zig").MethodHandler;

const c = @import("uws");

pub fn main() !void {
    const app = try App.init();
    defer app.deinit();

    try app.get("/get", hello)
        .ws("/ws", .{
        .maxPayloadLength = 1024,
        .upgrade = .{ .handler = upgradeWrapper, .ptr = @constCast(&on_upgrade) },
        .open = .{ .handler = &on_open, .ptr = null },
        .close = .{ .handler = &on_close, .ptr = null },
        .message = .{ .handler = &on_message, .ptr = null },
    }).listen(3000, null);
}

fn upgradeWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.C) void {
    const handler_ptr: *const fn (*Response, *Request, ?*c.uws_socket_context_t) void = @ptrCast(@alignCast(ptr));
    // WTF ZIG PLS FIX
    // if (rawRes == null or rawReq == null) return;
    var res = Response{ .ptr = if (rawRes) |r| r else return };
    var req = Request{ .ptr = if (rawReq) |r| r else return };
    handler_ptr(&res, &req, context);
}

fn hello(res: *Response, req: *Request) void {
    _ = req;
    const str = "Hello World!\n";
    res.end(str, str.len, false);
}

fn on_upgrade(res: *Response, req: *Request, context: ?*c.uws_socket_context_t) void {
    res.upgrade(req, context);
}

fn on_open(ptr: ?*anyopaque, ws: ?*c.uws_websocket_t) callconv(.C) void {
    _ = ptr;
    std.debug.print("Opened with {any}\n", .{ws});
}

fn on_close(ptr: ?*anyopaque, ws: ?*c.uws_websocket_t, code: c_int, message: [*c]const u8, length: usize) callconv(.C) void {
    _ = ptr;
    c.uws_ws_close(ws);
    std.debug.print("Closed with {s} | {d} | {d}\n", .{ message, length, code });
}

fn on_message(ptr: ?*anyopaque, ws: ?*c.uws_websocket_t, message: [*c]const u8, length: usize, opcode: c.uws_opcode_t) callconv(.C) void {
    _ = ptr;
    _ = c.uws_ws_send(ws, message, length, opcode);
}
