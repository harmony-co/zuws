const c = @import("uws");

const WebSocket = @This();

pub const CompressOptions = enum(u16) {
    disabled = c.DISABLED,
    shared_compressor = c.SHARED_COMPRESSOR,
    shared_decompressor = c.SHARED_DECOMPRESSOR,
    dedicated_decompressor_512b = c.DEDICATED_DECOMPRESSOR_512B,
    dedicated_decompressor_1kb = c.DEDICATED_DECOMPRESSOR_1KB,
    dedicated_decompressor_2kb = c.DEDICATED_DECOMPRESSOR_2KB,
    dedicated_decompressor_4kb = c.DEDICATED_DECOMPRESSOR_4KB,
    dedicated_decompressor_8kb = c.DEDICATED_DECOMPRESSOR_8KB,
    dedicated_decompressor_16kb = c.DEDICATED_DECOMPRESSOR_16KB,
    dedicated_decompressor_32kb = c.DEDICATED_DECOMPRESSOR_32KB,
    dedicated_compressor_3kb = c.DEDICATED_COMPRESSOR_3KB,
    dedicated_compressor_4kb = c.DEDICATED_COMPRESSOR_4KB,
    dedicated_compressor_8kb = c.DEDICATED_COMPRESSOR_8KB,
    dedicated_compressor_16kb = c.DEDICATED_COMPRESSOR_16KB,
    dedicated_compressor_32kb = c.DEDICATED_COMPRESSOR_32KB,
    dedicated_compressor_64kb = c.DEDICATED_COMPRESSOR_64KB,
    dedicated_compressor_128kb = c.DEDICATED_COMPRESSOR_128KB,
    dedicated_compressor_256kb = c.DEDICATED_COMPRESSOR_256KB,
};

pub const Opcode = enum(u8) {
    continuation = c.CONTINUATION,
    text = c.TEXT,
    binary = c.BINARY,
    close = c.CLOSE,
    ping = c.PING,
    pong = c.PONG,
};

pub const Status = enum(u8) {
    backpressure,
    success,
    dropped,
};

ptr: *c.uws_websocket_t,

pub fn close(self: *const WebSocket) void {
    c.uws_ws_close(self.ptr);
}

pub fn send(self: *const WebSocket, message: []const u8, opcode: Opcode) Status {
    return @enumFromInt(c.uws_ws_send(self.ptr, message.ptr, message.len, @intFromEnum(opcode)));
}

pub fn sendWithOptions(self: *const WebSocket, message: []const u8, opcode: Opcode, compress: bool, fin: bool) Status {
    return @enumFromInt(c.uws_ws_send_with_options(self.ptr, message.ptr, message.len, @intFromEnum(opcode), compress, fin));
}

pub fn sendFragment(self: *const WebSocket, message: []const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_fragment(self.ptr, message.ptr, message.len, compress));
}

pub fn sendFirstFragment(self: *const WebSocket, message: []const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_first_fragment(self.ptr, message.ptr, message.len, compress));
}

pub fn sendFirstFragmentWithOpcode(self: *const WebSocket, message: []const u8, opcode: Opcode, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_first_fragment_with_opcode(self.ptr, message.ptr, message.len, @intFromEnum(opcode), compress));
}

pub fn sendLastFragment(self: *const WebSocket, message: []const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_last_fragment(self.ptr, message.ptr, message.len, compress));
}

pub fn end(self: *const WebSocket, code: i16, message: []const u8) void {
    c.uws_ws_end(self.p, code, message.ptr, message.len);
}

pub fn cork(self: *const WebSocket, handler: fn () void) void {
    const handlerWrapper = struct {
        fn hW() callconv(.c) void {
            handler();
        }
    }.hW;
    c.uws_ws_cork(self.ptr, handlerWrapper);
}

pub fn subscribe(self: *const WebSocket, topic: []const u8) bool {
    return c.uws_ws_subscribe(self.ptr, topic.ptr, topic.len);
}

pub fn unsubscribe(self: *const WebSocket, topic: []const u8) bool {
    return c.uws_ws_unsubscribe(self.ptr, topic.ptr, topic.len);
}

pub fn isSubscribed(self: *const WebSocket, topic: []const u8) bool {
    return c.uws_ws_is_subscribed(self.ptr, topic.ptr, topic.len);
}

pub fn publish(self: *const WebSocket, topic: []const u8, message: []const u8) bool {
    return c.uws_ws_publish(self.ptr, topic.ptr, topic.len, message.ptr, message.len);
}

pub fn publishWithOptions(self: *const WebSocket, topic: []const u8, message: []const u8, opcode: Opcode, compress: bool) bool {
    return c.uws_ws_publish_with_options(self.ptr, topic.ptr, topic.len, message.ptr, message.len, opcode, compress);
}

pub fn getBufferedAmount(self: *const WebSocket) u16 {
    return c.uws_ws_get_buffered_amount(self.ptr);
}

pub fn getRemoteAddress(self: *const WebSocket) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_ws_get_remote_address(self.ptr, &temp);
    return temp[0..len];
}

pub fn getRemoteAddressAsText(self: *const WebSocket) []const u8 {
    var temp: [*c]const u8 = undefined;
    const len = c.uws_ws_get_remote_address_as_text(self.ptr, &temp);
    return temp[0..len];
}
