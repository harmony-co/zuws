const std = @import("std");
const zuws = @import("zuws");
const App = zuws.App;
const Request = zuws.Request;
const Response = zuws.Response;
const WebSocket = zuws.WebSocket;

pub fn main() !void {
    const app: App = try .init();
    defer app.deinit();

    _ = app.ws("/ws", .{
        // zig fmt: off
            .upgrade = upgrade,
            .open = open,
            .message = on_message,
            .dropped = on_message,
            .drain = drain,
            .ping = ping,
            .pong = pong,
            .close = close,
            .subscription = subscription,
        });

    try app.listen(3000, null);
}

fn upgrade(res: *Response, req: *Request) void {
    std.debug.print("Upgrade: {any} | {any}\n", .{ res, req });
}

fn open(ws: *WebSocket) void {
    std.debug.print("Open: {any}\n", .{ws});
    _ = ws.subscribe("NonsensicalTest");
}

fn on_message(ws: *WebSocket, message: []const u8, opcode: WebSocket.Opcode) void {
    std.debug.print("Message: {any} | {s} | {any}\n", .{ ws, message, opcode });
    _ = ws.send("zuws", .text);
}

fn drain(ws: *WebSocket) void {
    std.debug.print("Drain: {any}\n", .{ws});
}

fn ping(ws: *WebSocket, message: []const u8) void {
    std.debug.print("Ping: {any} | {s}\n", .{ ws, message });
}

fn pong(ws: *WebSocket, message: []const u8) void {
    std.debug.print("Pong: {any} | {s}\n", .{ ws, message });
}

fn close(ws: *WebSocket, code: i32, message: ?[]const u8) void {
    std.debug.print("Close: {any} | {any} | {?s}\n", .{ ws, code, message });
}

fn subscription(ws: *WebSocket, topic: []const u8, newNumberOfSubscribers: i32, oldNumberOfSubscribers: i32) void {
    std.debug.print("Subscription: {any} | {s} | {any} | {any}\n", .{ ws, topic, newNumberOfSubscribers, oldNumberOfSubscribers });
}
