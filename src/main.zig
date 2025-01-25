const std = @import("std");
const App = @import("./App.zig");
const Request = @import("./Request.zig");
const Response = @import("./Response.zig");
const WebSocket = @import("./WebSocket.zig");
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
            .upgrade = on_upgrade,
            .open = on_open,
            .message = on_message,
            .dropped = on_message,
            .drain = on_drain,
            .ping = on_ping,
            .pong = on_pong,
            .close = on_close,
            .subscription = on_subscription,
        })
        // zig fmt: on
        .get("/get", hello)
        .get("/get/:id", hello2)
        .listen(3001, null);
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

fn on_upgrade(res: *Response, req: *Request) void {
    std.debug.print("Upgrade: {any} | {any}\n", .{ res, req });
}
fn on_open(ws: *WebSocket) void {
    std.debug.print("Open: {any}\n", .{ws});
    _ = ws.subscribe("NonsensicalTest");
}
fn on_message(ws: *WebSocket, message: []const u8, opcode: WebSocket.Opcode) void {
    std.debug.print("Message: {any} | {any} | {any}\n", .{ ws, message, opcode });
}
fn on_drain(ws: *WebSocket) void {
    std.debug.print("Drain: {any}\n", .{ws});
}
fn on_ping(ws: *WebSocket, message: []const u8) void {
    std.debug.print("Ping: {any} | {any}\n", .{ ws, message });
}
fn on_pong(ws: *WebSocket, message: []const u8) void {
    std.debug.print("Pong: {any} | {any}\n", .{ ws, message });
}
fn on_close(ws: *WebSocket, code: i32, message: []const u8) void {
    std.debug.print("Close: {any} | {any} | {any}\n", .{ ws, code, message });
}
fn on_subscription(ws: *WebSocket, topic: []const u8, newNumberOfSubscribers: i32, oldNumberOfSubscribers: i32) void {
    std.debug.print("Subscription: {any} | {any} | {any} | {any}\n", .{ ws, topic, newNumberOfSubscribers, oldNumberOfSubscribers });
}
