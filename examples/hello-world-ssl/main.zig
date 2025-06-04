const std = @import("std");
const uws = @import("uws");

fn handler(rawRes: ?*uws.uws_ssl_res_s, _: ?*uws.uws_req_s) callconv(.c) void {
    uws.uws_ssl_res_end(rawRes.?, "Hello World!\n", 13, false);
}

pub fn main() !void {
    const app = uws.uws_create_ssl_app(.{
        .key_file_name = "misc/key.pem",
        .cert_file_name = "misc/cert.pem",
        .passphrase = "1234",
    }) orelse return error.CouldNotCreateApp;

    const port = 3000;
    defer uws.uws_ssl_app_destroy(app);

    { //? Test for open port
        const addr = try std.net.Address.parseIp4("127.0.0.1", port);
        const sock_fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
        try std.posix.bind(sock_fd, &addr.any, addr.getOsSockLen());
        std.posix.close(sock_fd);
    }

    uws.uws_ssl_app_get(app, "/*", handler);

    uws.uws_ssl_app_listen(app, port, null);
    uws.uws_ssl_app_run(app);
}
