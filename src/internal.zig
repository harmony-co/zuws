const std = @import("std");
const Method = @import("./App.zig").Method;

pub const InternalMethod = blk: {
    const fields = std.meta.fields(Method);
    break :blk @Type(.{
        .@"enum" = .{
            .tag_type = u8,
            .fields = fields ++ [1]std.builtin.Type.EnumField{.{ .name = "ANY", .value = fields[fields.len - 1].value + 1 }},
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
};
