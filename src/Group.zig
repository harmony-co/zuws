const c = @import("uws");
const std = @import("std");
const App = @import("./App.zig");
const InternalMethod = @import("./internal.zig").InternalMethod;

const ListType = struct {
    method: InternalMethod,
    pattern: [:0]const u8,
    handler: c.uws_method_handler,
};

const ArrayList = std.ArrayListUnmanaged(ListType);

pub const ComptimeGroup = struct {
    const InternalListType = struct {
        method: InternalMethod,
        pattern: [:0]const u8,
        handler: App.MethodHandler,
    };

    base_path: [:0]const u8,
    list: []const InternalListType,

    pub const get = CreateGroupFn(.GET);
    pub const post = CreateGroupFn(.POST);
    pub const put = CreateGroupFn(.PUT);
    pub const options = CreateGroupFn(.OPTIONS);
    pub const del = CreateGroupFn(.DELETE);
    pub const patch = CreateGroupFn(.PATCH);
    pub const head = CreateGroupFn(.HEAD);
    pub const connect = CreateGroupFn(.CONNECT);
    pub const trace = CreateGroupFn(.TRACE);
    pub const any = CreateGroupFn(.ANY);

    pub inline fn group(comptime self: *const ComptimeGroup, grp: *const ComptimeGroup) *const ComptimeGroup {
        comptime {
            var s = @constCast(self);
            for (grp.list) |item| {
                s.list = s.list ++ .{InternalListType{
                    .method = item.method,
                    .pattern = grp.base_path ++ item.pattern,
                    .handler = item.handler,
                }};
            }
            return self;
        }
    }

    pub inline fn merge(comptime self: *const ComptimeGroup, grp: *const ComptimeGroup) *const ComptimeGroup {
        comptime {
            var s = @constCast(self);
            for (grp.list) |item| {
                s.list = s.list ++ .{InternalListType{
                    .method = item.method,
                    .pattern = item.pattern,
                    .handler = item.handler,
                }};
            }
            return self;
        }
    }

    pub inline fn toConst(comptime self: *const ComptimeGroup) ComptimeGroup {
        return .{
            .base_path = self.base_path,
            .list = self.list,
        };
    }

    fn CreateGroupFn(comptime method: InternalMethod) fn (self: *const ComptimeGroup, comptime pattern: [:0]const u8, handler: App.MethodHandler) callconv(.@"inline") *const ComptimeGroup {
        return struct {
            inline fn temp(self: *const ComptimeGroup, comptime pattern: [:0]const u8, handler: App.MethodHandler) *const ComptimeGroup {
                comptime {
                    var s = @constCast(self);
                    s.list = s.list ++ .{InternalListType{ .method = method, .pattern = pattern, .handler = handler }};
                    return self;
                }
            }
        }.temp;
    }
};

pub const Group = struct {
    base_path: [:0]const u8,
    list: ArrayList,
    alloc: std.mem.Allocator,

    pub const get = CreateGroupFn(.GET);
    pub const post = CreateGroupFn(.POST);
    pub const put = CreateGroupFn(.PUT);
    pub const options = CreateGroupFn(.OPTIONS);
    pub const del = CreateGroupFn(.DELETE);
    pub const patch = CreateGroupFn(.PATCH);
    pub const head = CreateGroupFn(.HEAD);
    pub const connect = CreateGroupFn(.CONNECT);
    pub const trace = CreateGroupFn(.TRACE);
    pub const any = CreateGroupFn(.ANY);

    pub fn group(self: *Group, grp: Group) !void {
        for (grp.list.items) |item| {
            try self.list.append(self.alloc, .{
                .method = item.method,
                .pattern = try std.mem.concatWithSentinel(self.alloc, u8, &.{ grp.base_path, item.pattern }, 0),
                .handler = item.handler,
            });
        }
    }

    pub fn merge(self: *Group, grp: Group) !void {
        for (grp.list.items) |item| {
            try self.list.append(self.alloc, .{
                .method = item.method,
                .pattern = item.pattern,
                .handler = item.handler,
            });
        }
    }

    pub fn deinit(self: *Group) void {
        self.list.deinit(self.alloc);
    }

    fn CreateGroupFn(comptime method: InternalMethod) fn (self: *Group, pattern: [:0]const u8, handler: c.uws_method_handler) std.mem.Allocator.Error!void {
        return struct {
            fn temp(self: *Group, pattern: [:0]const u8, handler: c.uws_method_handler) !void {
                try self.list.append(self.alloc, .{ .method = method, .pattern = pattern, .handler = handler });
            }
        }.temp;
    }
};

pub inline fn initComptime(comptime path: [:0]const u8) *const ComptimeGroup {
    comptime {
        std.debug.assert(path.len > 0);
        std.debug.assert(!std.mem.containsAtLeast(u8, path, 1, &std.ascii.whitespace));

        const grp = &ComptimeGroup{
            .base_path = path,
            .list = &.{},
        };

        var g = grp.*;
        return &g;
    }
}

pub fn init(allocator: std.mem.Allocator, comptime path: [:0]const u8) Group {
    std.debug.assert(path.len > 0);
    std.debug.assert(!std.mem.containsAtLeast(u8, path, 1, &std.ascii.whitespace));

    return .{
        .base_path = path,
        .list = .empty,
        .alloc = allocator,
    };
}
