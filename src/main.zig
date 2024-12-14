const std = @import("std");
const App = @import("./app.zig");

const c = @import("uws");

pub fn main() !void {
    const app = try App.App.init();
    defer app.deinit();

    try app
        .get("/get", hello)
        .ws("/ws", .{ .maxPayloadLength = 1024, .upgrade = on_upgrade, .open = on_open, .close = on_close, .message = on_message })
        .listen(3000, null);
}

fn hello(res: App.Response, req: App.Request) void {
    _ = req;
    const str = "Hello World!\n";
    res.end(str, str.len, false);
}

fn on_upgrade(res: ?*c.uws_res_t, req: ?*c.uws_req_t, context: ?*c.uws_socket_context_t) callconv(.C) void {
    var ws_key: [*c]const u8 = null;
    var ws_protocol: [*c]const u8 = null;
    var ws_extensions: [*c]const u8 = null;

    const ws_key_length: usize = c.uws_req_get_header(req, "sec-websocket-key", 17, &ws_key);
    const ws_protocol_length: usize = c.uws_req_get_header(req, "sec-websocket-protocol", 22, &ws_protocol);
    const ws_extensions_length: usize = c.uws_req_get_header(req, "sec-websocket-extensions", 24, &ws_extensions);

    c.uws_res_upgrade(
        res,
        null,
        ws_key,
        ws_key_length,
        ws_protocol,
        ws_protocol_length,
        ws_extensions,
        ws_extensions_length,
        context,
    );
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
