const std = @import("std");
const App = @import("./App.zig");
const Request = @import("./Request.zig");
const Response = @import("./Response.zig");
const MethodHandler = App.MethodHandler;

const c = @import("uws");

pub fn main() !void {
    const app = try App.init();
    defer app.deinit();

    const api: App.Group = comptime blk: {
        var g = App.Group{ .base_path = "/api" };
        var v1 = App.Group{ .base_path = "/v1" };

        // Maybe methods should not return self...
        _ = v1.get("/me", hello);
        _ = g.get("/user", hello)
            .group(v1);

        break :blk g;
    };

    try app.group(api)
        .ws("/ws", .{
        // zig fmt: off
            .maxPayloadLength = 1024,
            .upgrade = .{ .handler = upgradeWrapper, .ptr = @constCast(&on_upgrade) },
            .open = .{ .handler = &on_open, .ptr = null },
            .close = .{ .handler = &on_close, .ptr = null },
            .message = .{ .handler = &on_message, .ptr = null },
        })
        // zig fmt: on
        .get("/get", hello)
        .get("/get/:id", hello2)
        .listen(3001, null);
}

fn upgradeWrapper(ptr: ?*anyopaque, rawRes: ?*c.uws_res_s, rawReq: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.C) void {
    const handler_ptr: *const fn (*Response, *Request, ?*c.uws_socket_context_t) void = @ptrCast(@alignCast(ptr));
    var res = Response{ .ptr = rawRes orelse return };
    var req = Request{ .ptr = rawReq orelse return };
    handler_ptr(&res, &req, context);
}

fn hello(res: *Response, req: *Request) void {
    _ = req;
    const str = "Hello World!\n";
    res.end(str, false);
}

fn hello2(res: *Response, req: *Request) void {
    std.debug.print("{s}\n", .{req.getMethod()});
    std.debug.print("{s}\n", .{req.getParameterByIndex(0)});
    const str = "Hello World!\n";
    res.end(str, false);
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
