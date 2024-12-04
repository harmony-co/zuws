#include "uws.h"

#include "../uWebSockets/src/App.h"

#pragma region uWS-app

#define METHOD(name)                                                                                                        \
    void uws_app_##name(uws_app_t *app, const char *pattern, uws_method_handler handler)                                    \
    {                                                                                                                       \
        ((uWS::App *)app)->name(pattern, [handler](auto *res, auto *req) { handler((uws_res_t *)res, (uws_req_t *)req); }); \
    };
HTTP_METHODS
#undef METHOD

uws_app_t *uws_create_app()
{
    return (uws_app_t *)new uWS::App();
}

void uws_app_destroy(uws_app_t *app)
{
    delete ((uWS::App *)app);
}

void uws_app_run(uws_app_t *app)
{
    ((uWS::App *)app)->run();
}

void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler)
{
    if (!handler)
        handler = [](auto) {};

    uws_app_listen_config_t config;
    config.port = port;
    config.host = nullptr;
    config.options = 0;

    ((uWS::App *)app)->listen(port, [handler, config](struct us_listen_socket_t *listen_socket)
                              { handler((struct us_listen_socket_t *)listen_socket); });
}

void uws_app_close(uws_app_t *app)
{
    ((uWS::App *)app)->close();
}

#pragma endregion
#pragma region uWS-Response

void uws_res_close(uws_res_t *res)
{
    ((uWS::HttpResponse<false> *)res)->close();
}

void uws_res_end(uws_res_t *res, const char *data, size_t length, bool close_connection)
{
    ((uWS::HttpResponse<false> *)res)->end(std::string_view(data, length), close_connection);
}

void uws_res_cork(uws_res_t *res, void (*callback)(uws_res_t *res, void *user_data), void *user_data)
{
    ((uWS::HttpResponse<false> *)res)->cork([=]()
                                            { callback(res, user_data); });
}

void uws_res_pause(uws_res_t *res)
{
    ((uWS::HttpResponse<false> *)res)->pause();
}

void uws_res_resume(uws_res_t *res)
{
    ((uWS::HttpResponse<false> *)res)->resume();
}

void uws_res_write_continue(uws_res_t *res)
{
    ((uWS::HttpResponse<false> *)res)->writeContinue();
}

void uws_res_write_status(uws_res_t *res, const char *status, size_t length)
{
    ((uWS::HttpResponse<false> *)res)->writeStatus(std::string_view(status, length));
}

void uws_res_write_header(uws_res_t *res, const char *key, size_t key_length, const char *value, size_t value_length)
{
    ((uWS::HttpResponse<false> *)res)->writeHeader(std::string_view(key, key_length), std::string_view(value, value_length));
}

void uws_res_write_header_int(uws_res_t *res, const char *key, size_t key_length, uint64_t value)
{
    ((uWS::HttpResponse<false> *)res)->writeHeader(std::string_view(key, key_length), value);
}

void uws_res_end_without_body(uws_res_t *res, bool close_connection)
{
    ((uWS::HttpResponse<false> *)res)->endWithoutBody(std::nullopt, close_connection);
}

bool uws_res_write(uws_res_t *res, const char *data, size_t length)
{
    return ((uWS::HttpResponse<false> *)res)->write(std::string_view(data, length));
}

void uws_res_override_write_offset(uws_res_t *res, uintmax_t offset)
{
    ((uWS::HttpResponse<false> *)res)->overrideWriteOffset(offset);
}

bool uws_res_has_responded(uws_res_t *res)
{
    return ((uWS::HttpResponse<false> *)res)->hasResponded();
}

void uws_res_on_writable(uws_res_t *res, uws_res_on_writable_handler handler, void *optional_data)
{
    ((uWS::HttpResponse<false> *)res)->onWritable([handler, res, optional_data](uintmax_t a)
                                                  { return handler(res, a, optional_data); });
}

void uws_res_on_aborted(uws_res_t *res, uws_res_on_aborted_handler handler, void *optional_data)
{
    ((uWS::HttpResponse<false> *)res)->onAborted([handler, res, optional_data]
                                                 { handler(res, optional_data); });
}

void uws_res_on_data(uws_res_t *res, uws_res_on_data_handler handler, void *optional_data)
{
    ((uWS::HttpResponse<false> *)res)->onData([handler, res, optional_data](auto chunk, bool is_end)
                                              { handler(res, chunk.data(), chunk.length(), is_end, optional_data); });
}

void uws_res_upgrade(uws_res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws)
{
    ((uWS::HttpResponse<false> *)res)->template upgrade<void *>(data ? std::move(data) : NULL, std::string_view(sec_web_socket_key, sec_web_socket_key_length), std::string_view(sec_web_socket_protocol, sec_web_socket_protocol_length), std::string_view(sec_web_socket_extensions, sec_web_socket_extensions_length), (struct us_socket_context_t *)ws);
}

uws_try_end_result_t uws_res_try_end(uws_res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection)
{

    std::pair<bool, bool> result = ((uWS::HttpResponse<false> *)res)->tryEnd(std::string_view(data, length), total_size);
    return uws_try_end_result_t{
        .ok = result.first,
        .has_responded = result.second,
    };
}

uintmax_t uws_res_get_write_offset(uws_res_t *res)
{
    return ((uWS::HttpResponse<false> *)res)->getWriteOffset();
}

size_t uws_res_get_remote_address(uws_res_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpResponse<false> *)res)->getRemoteAddress();
    *dest = value.data();
    return value.length();
}

size_t uws_res_get_remote_address_as_text(uws_res_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpResponse<false> *)res)->getRemoteAddressAsText();
    *dest = value.data();
    return value.length();
}

#pragma endregion
#pragma region uWS-Request

bool uws_req_is_ancient(uws_req_t *res)
{
    return ((uWS::HttpRequest *)res)->isAncient();
}

bool uws_req_get_yield(uws_req_t *res)
{
    return ((uWS::HttpRequest *)res)->getYield();
}

void uws_req_set_yield(uws_req_t *res, bool yield)
{
    return ((uWS::HttpRequest *)res)->setYield(yield);
}

void uws_req_for_each_header(uws_req_t *res, uws_get_headers_server_handler handler, void *user_data)
{
    for (auto header : *((uWS::HttpRequest *)res))
    {
        handler(header.first.data(), header.first.length(), header.second.data(), header.second.length(), user_data);
    }
}

size_t uws_req_get_url(uws_req_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getUrl();
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_full_url(uws_req_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getFullUrl();
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_method(uws_req_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getMethod();
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_case_sensitive_method(uws_req_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getCaseSensitiveMethod();
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_header(uws_req_t *res, const char *lower_case_header, size_t lower_case_header_length, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getHeader(std::string_view(lower_case_header, lower_case_header_length));
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_query(uws_req_t *res, const char *key, size_t key_length, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getQuery(std::string_view(key, key_length));
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_parameter(uws_req_t *res, unsigned short index, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getParameter(index);
    *dest = value.data();
    return value.length();
}

#pragma endregion

void uws_loop_defer(us_loop_t *loop, void(cb(void *user_data)), void *user_data)
{
    ((uWS::Loop *)loop)->defer([cb, user_data]()
                               { cb(user_data); });
}

struct us_loop_t *uws_get_loop()
{
    return (struct us_loop_t *)uWS::Loop::get();
}

struct us_loop_t *uws_get_loop_with_native(void *existing_native_loop)
{
    return (struct us_loop_t *)uWS::Loop::get(existing_native_loop);
}