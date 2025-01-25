const c = @import("uws");
const std = @import("std");

const WebSocket = @This();

pub const CompressOptions = enum(u16) {
    _COMPRESSOR_MASK = c._COMPRESSOR_MASK,
    DISABLED = c.DISABLED,
    SHARED_COMPRESSOR = c.SHARED_COMPRESSOR,
    SHARED_DECOMPRESSOR = c.SHARED_DECOMPRESSOR,
    DEDICATED_DECOMPRESSOR_512B = c.DEDICATED_DECOMPRESSOR_512B,
    DEDICATED_DECOMPRESSOR_1KB = c.DEDICATED_DECOMPRESSOR_1KB,
    DEDICATED_DECOMPRESSOR_2KB = c.DEDICATED_DECOMPRESSOR_2KB,
    DEDICATED_DECOMPRESSOR_8KB = c.DEDICATED_DECOMPRESSOR_8KB,
    DEDICATED_DECOMPRESSOR_4KB = c.DEDICATED_DECOMPRESSOR_4KB,
    DEDICATED_DECOMPRESSOR_16KB = c.DEDICATED_DECOMPRESSOR_16KB,
    DEDICATED_DECOMPRESSOR_32KB = c.DEDICATED_DECOMPRESSOR_32KB,
    DEDICATED_COMPRESSOR_3KB = c.DEDICATED_COMPRESSOR_3KB,
    DEDICATED_COMPRESSOR_4KB = c.DEDICATED_COMPRESSOR_4KB,
    DEDICATED_COMPRESSOR_8KB = c.DEDICATED_COMPRESSOR_8KB,
    DEDICATED_COMPRESSOR_16KB = c.DEDICATED_COMPRESSOR_16KB,
    DEDICATED_COMPRESSOR_32KB = c.DEDICATED_COMPRESSOR_32KB,
    DEDICATED_COMPRESSOR_64KB = c.DEDICATED_COMPRESSOR_64KB,
    DEDICATED_COMPRESSOR_128KB = c.DEDICATED_COMPRESSOR_128KB,
    DEDICATED_COMPRESSOR_256KB = c.DEDICATED_COMPRESSOR_256KB,
};

pub const Opcode = enum(u8) {
    CONTINUATION = c.CONTINUATION,
    TEXT = c.TEXT,
    BINARY = c.BINARY,
    CLOSE = c.CLOSE,
    PING = c.PING,
    PONG = c.PONG,
};

pub const Status = enum(u8) {
    BACKPRESSURE,
    SUCCESS,
    DROPPED,
};

ptr: *c.uws_websocket_t,

pub fn close(self: *const WebSocket) void {
    c.uws_ws_close(self.ptr);
}

pub fn send(self: *const WebSocket, message: [:0]const u8, opcode: Opcode) Status {
    return @enumFromInt(c.uws_ws_send(self.ptr, message, message.len, @intFromEnum(opcode)));
}

pub fn sendWithOptions(self: *const WebSocket, message: [:0]const u8, opcode: Opcode, compress: bool, fin: bool) Status {
    return @enumFromInt(c.uws_ws_send_with_options(self.ptr, message, message.len, @intFromEnum(opcode), compress, fin));
}

pub fn sendFragment(self: *const WebSocket, message: [:0]const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_fragment(self.ptr, message, message.len, compress));
}

pub fn sendFirstFragment(self: *const WebSocket, message: [:0]const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_first_fragment(self.ptr, message, message.len, compress));
}

pub fn sendFirstFragmentWithOpcode(self: *const WebSocket, message: [:0]const u8, opcode: Opcode, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_first_fragment_with_opcode(self.ptr, message, message.len, @intFromEnum(opcode), compress));
}

pub fn sendLastFragment(self: *const WebSocket, message: [:0]const u8, compress: bool) Status {
    return @enumFromInt(c.uws_ws_send_last_fragment(self.ptr, message, message.len, compress));
}

pub fn end(self: *const WebSocket, code: i16, message: [:0]const u8) void {
    c.uws_ws_end(self.p, code, message, message.len);
}

// pub fn cork(self: *const WebSocket, void(*handler)()) void {}

pub fn subscribe(self: *const WebSocket, topic: [:0]const u8) bool {
    return c.uws_ws_subscribe(self.ptr, topic, topic.len);
}

pub fn unsubscribe(self: *const WebSocket, topic: [:0]const u8) bool {
    return c.uws_ws_unsubscribe(self.ptr, topic, topic.len);
}

pub fn isSubscribed(self: *const WebSocket, topic: [:0]const u8) bool {
    return c.uws_ws_is_subscribed(self.ptr, topic, topic.len);
}

// pub fn iterate_topics(self: *const WebSocket, void (*callback)(const char *topic)) void {}

pub fn publish(self: *const WebSocket, topic: [:0]const u8, message: [:0]const u8) bool {
    return c.uws_ws_publish(self.ptr, topic, topic.len, message, message.len);
}

pub fn publishWithOptions(self: *const WebSocket, topic: [:0]const u8, message: [:0]const u8, opcode: Opcode, compress: bool) bool {
    return c.uws_ws_publish_with_options(self.ptr, topic, topic.len, message, message.len, opcode, compress);
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
