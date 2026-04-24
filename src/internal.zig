const std = @import("std");
const Method = @import("./app.zig").Method;

pub const InternalMethod = blk: {
    const fields = std.meta.fields(Method);

    var field_names: []const []const u8 = &.{};
    var field_values: []const u8 = &.{};

    for (fields) |field| {
        field_names = field_names ++ [1][]const u8{field.name};
        field_values = field_values ++ [1]u8{field.value};
    }

    field_names = field_names ++ [1][]const u8{"ANY"};
    field_values = field_values ++ [1]u8{field_values[field_values.len - 1] + 1};

    break :blk @Enum(u8, .exhaustive, field_names, field_values[0..field_names.len]);
};
