const c = @import("./bindings.zig");

pub const uWSWebSocket = opaque {
    pub const close = c.uws_ws_close;
    pub const cork = c.uws_ws_cork;
    pub const getBufferedAmount = c.uws_ws_get_buffered_amount;

    pub fn send(self: *uWSWebSocket, message: []const u8, opcode: c.Opcode) c.Status {
        return c.uws_ws_send(self, message.ptr, message.len, @intFromEnum(opcode));
    }

    pub fn sendWithOptions(self: *uWSWebSocket, message: []const u8, opcode: c.Opcode, compress: bool, fin: bool) c.Status {
        return c.uws_ws_send_with_options(self, message.ptr, message.len, @intFromEnum(opcode), compress, fin);
    }

    pub fn sendFragment(self: *uWSWebSocket, message: []const u8, compress: bool) c.Status {
        return c.uws_ws_send_fragment(self, message.ptr, message.len, compress);
    }

    pub fn sendFirstFragment(self: *uWSWebSocket, message: []const u8, compress: bool) c.Status {
        return c.uws_ws_send_first_fragment(self, message.ptr, message.len, compress);
    }

    pub fn sendFirstFragmentWithOpcode(self: *uWSWebSocket, message: []const u8, opcode: c.Opcode, compress: bool) c.Status {
        return c.uws_ws_send_first_fragment_with_opcode(self, message.ptr, message.len, @intFromEnum(opcode), compress);
    }

    pub fn sendLastFragment(self: *uWSWebSocket, message: []const u8, compress: bool) c.Status {
        return c.uws_ws_send_last_fragment(self, message.ptr, message.len, compress);
    }

    pub fn end(self: *uWSWebSocket, code: i16, message: []const u8) void {
        c.uws_ws_end(self.p, code, message.ptr, message.len);
    }

    pub fn subscribe(self: *uWSWebSocket, topic: []const u8) bool {
        return c.uws_ws_subscribe(self, topic.ptr, topic.len);
    }

    pub fn unsubscribe(self: *uWSWebSocket, topic: []const u8) bool {
        return c.uws_ws_unsubscribe(self, topic.ptr, topic.len);
    }

    pub fn isSubscribed(self: *uWSWebSocket, topic: []const u8) bool {
        return c.uws_ws_is_subscribed(self, topic.ptr, topic.len);
    }

    pub fn publish(self: *uWSWebSocket, topic: []const u8, message: []const u8) bool {
        return c.uws_ws_publish(self, topic.ptr, topic.len, message.ptr, message.len);
    }

    pub fn publishWithOptions(self: *uWSWebSocket, topic: []const u8, message: []const u8, opcode: c.Opcode, compress: bool) bool {
        return c.uws_ws_publish_with_options(self, topic.ptr, topic.len, message.ptr, message.len, opcode, compress);
    }

    pub fn getRemoteAddress(self: *uWSWebSocket) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_ws_get_remote_address(self, &temp);
        return temp[0..len];
    }

    pub fn getRemoteAddressAsText(self: *uWSWebSocket) []const u8 {
        var temp: [*c]const u8 = undefined;
        const len = c.uws_ws_get_remote_address_as_text(self, &temp);
        return temp[0..len];
    }
};
