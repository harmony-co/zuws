const std = @import("std");
const config = @import("config");

const c = @import("./bindings.zig");

const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const WebSocket = @import("./ws.zig").uWSWebSocket;

const InternalMethod = @import("./internal.zig").InternalMethod;

const info = std.log.scoped(.uws_debug).info;

pub const Method = enum(u8) {
    GET,
    POST,
    PUT,
    OPTIONS,
    DELETE,
    PATCH,
    HEAD,
    CONNECT,
    TRACE,
};

pub const uWSApp = opaque {
    pub const Group = @import("./Group.zig");

    pub const init = if (config.is_ssl) initSSL else initNoSSL;

    pub const deinit = c.uws_app_destroy;
    pub const run = c.uws_app_run;
    pub const close = c.uws_app_close;

    pub const get = AppMethod(.GET);
    pub const post = AppMethod(.POST);
    pub const put = AppMethod(.PUT);
    pub const options = AppMethod(.OPTIONS);
    pub const del = AppMethod(.DEL);
    pub const patch = AppMethod(.PATCH);
    pub const head = AppMethod(.HEAD);
    pub const connect = AppMethod(.CONNECT);
    pub const trace = AppMethod(.TRACE);
    pub const any = AppMethod(.ANY);

    fn initSSL(opt: c.struct_us_socket_context_options_t) !*uWSApp {
        const app = c.uws_create_app(opt);
        if (app) |ptr| return ptr;
        return error.CouldNotCreateApp;
    }

    fn initNoSSL() !*uWSApp {
        const app = c.uws_create_app();
        if (app) |ptr| return ptr;
        return error.CouldNotCreateApp;
    }

    pub fn listen(self: *uWSApp, port: u16, handler: ?c.ListenHandler) void {
        c.uws_app_listen(self, port, handler);
    }

    pub fn group(self: *uWSApp, g: *Group.Group) !void {
        for (g.list.items) |item| {
            const pattern = try std.mem.concatWithSentinel(g.alloc, u8, &.{ g.base_path, item.pattern }, 0);
            switch (item.method) {
                .GET => self.rawGet(pattern, item.handler),
                .POST => self.rawPost(pattern, item.handler),
                .PUT => self.rawPut(pattern, item.handler),
                .OPTIONS => self.rawOptions(pattern, item.handler),
                .DELETE => self.rawDel(pattern, item.handler),
                .PATCH => self.rawPatch(pattern, item.handler),
                .HEAD => self.rawHead(pattern, item.handler),
                .CONNECT => self.rawConnect(pattern, item.handler),
                .TRACE => self.rawTrace(pattern, item.handler),
                .ANY => self.rawAny(pattern, item.handler),
            }
        }
    }

    pub inline fn comptimeGroup(self: *uWSApp, g: *const Group.ComptimeGroup) void {
        inline for (g.list) |item| {
            switch (item.method) {
                .GET => _ = self.get(g.base_path ++ item.pattern, item.handler),
                .POST => _ = self.post(g.base_path ++ item.pattern, item.handler),
                .PUT => _ = self.put(g.base_path ++ item.pattern, item.handler),
                .OPTIONS => _ = self.options(g.base_path ++ item.pattern, item.handler),
                .DELETE => _ = self.del(g.base_path ++ item.pattern, item.handler),
                .PATCH => _ = self.patch(g.base_path ++ item.pattern, item.handler),
                .HEAD => _ = self.head(g.base_path ++ item.pattern, item.handler),
                .CONNECT => _ = self.connect(g.base_path ++ item.pattern, item.handler),
                .TRACE => _ = self.trace(g.base_path ++ item.pattern, item.handler),
                .ANY => _ = self.any(g.base_path ++ item.pattern, item.handler),
            }
        }
    }

    pub fn ws(self: *uWSApp, pattern: [:0]const u8, comptime behavior: c.WebSocketBehavior) *uWSApp {
        if (comptime config.debug_logs) {
            info("Registering WebSocket route: {s}", .{pattern});
        }

        return c.uws_ws(self, pattern, behavior);
    }

    fn AppMethod(comptime method: InternalMethod) fn (self: *uWSApp, pattern: [:0]const u8, handler: c.MethodHandler) *uWSApp {
        comptime {
            const upper_method = @tagName(method);
            const lower_method: [8]u8, const len: usize = blk: {
                var temp_down: [8]u8 = undefined;
                var i: usize = 0;
                for (upper_method) |char| {
                    temp_down[i] = std.ascii.toLower(char);
                    i += 1;
                }
                break :blk .{ temp_down, i };
            };

            const log_str = std.fmt.comptimePrint("Registering {s} route: ", .{upper_method}) ++ "{s}";

            return struct {
                fn f(self: *uWSApp, pattern: [:0]const u8, handler: c.MethodHandler) *uWSApp {
                    if (comptime config.debug_logs) {
                        info(log_str, .{pattern});
                    }

                    return @field(c, "uws_app_" ++ lower_method[0..len])(self, pattern, handler);
                }
            }.f;
        }
    }
};
