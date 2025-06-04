#include "uws.h"

#include "../uWebSockets/src/App.h"

#pragma region uWS-App

#define METHOD(name)                                                                                                               \
    void uws_app_##name(uws_app_t *app, const char *pattern, uws_method_handler handler)                                           \
    {                                                                                                                              \
        ((uWS::App *)app)->name(pattern, [handler](auto *res, auto *req) { handler((uws_res_t *)res, (uws_req_t *)req); });        \
    };                                                                                                                             \
    void uws_ssl_app_##name(uws_ssl_app_t *app, const char *pattern, uws_ssl_method_handler handler)                               \
    {                                                                                                                              \
        ((uWS::SSLApp *)app)->name(pattern, [handler](auto *res, auto *req) { handler((uws_ssl_res_t *)res, (uws_req_t *)req); }); \
    };
HTTP_METHODS
#undef METHOD

#define APP(prefix, protocol, _)                                                                                                                                 \
    uws_##prefix##app_t *uws_create_##prefix##app(struct us_socket_context_options_t options = {})                                                               \
    {                                                                                                                                                            \
        uWS::SocketContextOptions sco;                                                                                                                           \
        memcpy(&sco, &options, sizeof(struct us_socket_context_options_t));                                                                                      \
        return (uws_##prefix##app_t *)new uWS::protocol##App(sco);                                                                                               \
    }                                                                                                                                                            \
                                                                                                                                                                 \
    void uws_##prefix##app_destroy(uws_##prefix##app_t *app)                                                                                                     \
    {                                                                                                                                                            \
        delete ((uWS::protocol##App *)app);                                                                                                                      \
    }                                                                                                                                                            \
                                                                                                                                                                 \
    void uws_##prefix##app_run(uws_##prefix##app_t *app)                                                                                                         \
    {                                                                                                                                                            \
        ((uWS::protocol##App *)app)->run();                                                                                                                      \
    }                                                                                                                                                            \
                                                                                                                                                                 \
    void uws_##prefix##app_listen(uws_##prefix##app_t *app, int port, uws_listen_handler handler)                                                                \
    {                                                                                                                                                            \
        if (!handler)                                                                                                                                            \
            handler = [](auto) {};                                                                                                                               \
                                                                                                                                                                 \
        ((uWS::protocol##App *)app)->listen(port, [handler](struct us_listen_socket_t *listen_socket) { handler((struct us_listen_socket_t *)listen_socket); }); \
    }                                                                                                                                                            \
                                                                                                                                                                 \
    void uws_##prefix##app_close(uws_##prefix##app_t *app)                                                                                                       \
    {                                                                                                                                                            \
        ((uWS::protocol##App *)app)->close();                                                                                                                    \
    }
PROTOCOLS
#undef APP

#pragma endregion
#pragma region uWS-Response

#define APP(prefix, protocol, is_ssl)                                                                                                                                                                                                                                                                                                                             \
    void uws_##prefix##res_close(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                                        \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->close();                                                                                                                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_end(uws_##prefix##res_t *res, const char *data, size_t length, bool close_connection)                                                                                                                                                                                                                                                  \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->end(std::string_view(data, length), close_connection);                                                                                                                                                                                                                                                                \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_cork(uws_##prefix##res_t *res, void (*callback)(uws_##prefix##res_t * res))                                                                                                                                                                                                                                                            \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->cork([=]() { callback(res); });                                                                                                                                                                                                                                                                                       \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_pause(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                                        \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->pause();                                                                                                                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_resume(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->resume();                                                                                                                                                                                                                                                                                                             \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_write_continue(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                               \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->writeContinue();                                                                                                                                                                                                                                                                                                      \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_write_status(uws_##prefix##res_t *res, const char *status, size_t length)                                                                                                                                                                                                                                                              \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->writeStatus(std::string_view(status, length));                                                                                                                                                                                                                                                                        \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_write_header(uws_##prefix##res_t *res, const char *key, size_t key_length, const char *value, size_t value_length)                                                                                                                                                                                                                     \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->writeHeader(std::string_view(key, key_length), std::string_view(value, value_length));                                                                                                                                                                                                                                \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_write_header_int(uws_##prefix##res_t *res, const char *key, size_t key_length, uint64_t value)                                                                                                                                                                                                                                         \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->writeHeader(std::string_view(key, key_length), value);                                                                                                                                                                                                                                                                \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_end_without_body(uws_##prefix##res_t *res, bool close_connection)                                                                                                                                                                                                                                                                      \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->endWithoutBody(std::nullopt, close_connection);                                                                                                                                                                                                                                                                       \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    bool uws_##prefix##res_write(uws_##prefix##res_t *res, const char *data, size_t length)                                                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                                                                                                                                             \
        return ((uWS::HttpResponse<is_ssl> *)res)->write(std::string_view(data, length));                                                                                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_override_write_offset(uws_##prefix##res_t *res, uintmax_t offset)                                                                                                                                                                                                                                                                      \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->overrideWriteOffset(offset);                                                                                                                                                                                                                                                                                          \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    bool uws_##prefix##res_has_responded(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                                \
    {                                                                                                                                                                                                                                                                                                                                                             \
        return ((uWS::HttpResponse<is_ssl> *)res)->hasResponded();                                                                                                                                                                                                                                                                                                \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_on_writable(uws_##prefix##res_t *res, uws_##prefix##res_on_writable_handler handler)                                                                                                                                                                                                                                                   \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->onWritable([handler, res](uintmax_t a) { return handler(res, a); });                                                                                                                                                                                                                                                  \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_on_aborted(uws_##prefix##res_t *res, uws_##prefix##res_on_aborted_handler handler)                                                                                                                                                                                                                                                     \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->onAborted([handler, res] { handler(res); });                                                                                                                                                                                                                                                                          \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_on_data(uws_##prefix##res_t *res, uws_##prefix##res_on_data_handler handler)                                                                                                                                                                                                                                                           \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->onData([handler, res](auto chunk, bool is_end) { handler(res, chunk.data(), chunk.length(), is_end); });                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_upgrade(uws_##prefix##res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws)                                  \
    {                                                                                                                                                                                                                                                                                                                                                             \
        ((uWS::HttpResponse<is_ssl> *)res)->template upgrade<void *>(data ? std::move(data) : NULL, std::string_view(sec_web_socket_key, sec_web_socket_key_length), std::string_view(sec_web_socket_protocol, sec_web_socket_protocol_length), std::string_view(sec_web_socket_extensions, sec_web_socket_extensions_length), (struct us_socket_context_t *)ws); \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    uws_try_end_result_t uws_##prefix##res_try_end(uws_##prefix##res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection)                                                                                                                                                                                                        \
    {                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
        std::pair<bool, bool> result = ((uWS::HttpResponse<is_ssl> *)res)->tryEnd(std::string_view(data, length), total_size);                                                                                                                                                                                                                                    \
        return uws_try_end_result_t{                                                                                                                                                                                                                                                                                                                              \
            .ok = result.first,                                                                                                                                                                                                                                                                                                                                   \
            .has_responded = result.second,                                                                                                                                                                                                                                                                                                                       \
        };                                                                                                                                                                                                                                                                                                                                                        \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    uintmax_t uws_##prefix##res_get_write_offset(uws_##prefix##res_t *res)                                                                                                                                                                                                                                                                                        \
    {                                                                                                                                                                                                                                                                                                                                                             \
        return ((uWS::HttpResponse<is_ssl> *)res)->getWriteOffset();                                                                                                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    size_t uws_##prefix##res_get_remote_address(uws_##prefix##res_t *res, const char **dest)                                                                                                                                                                                                                                                                      \
    {                                                                                                                                                                                                                                                                                                                                                             \
        std::string_view value = ((uWS::HttpResponse<is_ssl> *)res)->getRemoteAddress();                                                                                                                                                                                                                                                                          \
        *dest = value.data();                                                                                                                                                                                                                                                                                                                                     \
        return value.length();                                                                                                                                                                                                                                                                                                                                    \
    }                                                                                                                                                                                                                                                                                                                                                             \
                                                                                                                                                                                                                                                                                                                                                                  \
    size_t uws_##prefix##res_get_remote_address_as_text(uws_##prefix##res_t *res, const char **dest)                                                                                                                                                                                                                                                              \
    {                                                                                                                                                                                                                                                                                                                                                             \
        std::string_view value = ((uWS::HttpResponse<is_ssl> *)res)->getRemoteAddressAsText();                                                                                                                                                                                                                                                                    \
        *dest = value.data();                                                                                                                                                                                                                                                                                                                                     \
        return value.length();                                                                                                                                                                                                                                                                                                                                    \
    }
PROTOCOLS
#undef APP

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

void uws_req_for_each_header(uws_req_t *res, uws_get_headers_server_handler handler)
{
    for (auto header : *((uWS::HttpRequest *)res))
    {
        handler(header.first.data(), header.first.length(), header.second.data(), header.second.length());
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

size_t uws_req_get_parameter_name(uws_req_t *res, const char *key, size_t key_length, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getParameter(std::string_view(key, key_length));
    *dest = value.data();
    return value.length();
}

size_t uws_req_get_parameter_index(uws_req_t *res, unsigned short index, const char **dest)
{
    std::string_view value = ((uWS::HttpRequest *)res)->getParameter(index);
    *dest = value.data();
    return value.length();
}

#pragma endregion
#pragma region uWS-Websockets

#define WEBSOCKET_HANDLER(field, lambda_args, lambda_body)         \
    if (behavior.field)                                            \
    {                                                              \
        auto handler = behavior.field;                             \
        generic_handler.field = [handler] lambda_args lambda_body; \
    }

#define APP(prefix, protocol, is_ssl)                                                                                                                                                                 \
    void uws_##prefix##ws(uws_##prefix##app_t *app, const char *pattern, uws_##prefix##socket_behavior_t behavior)                                                                                    \
    {                                                                                                                                                                                                 \
        auto generic_handler = uWS::protocol##App::WebSocketBehavior<void *>{                                                                                                                         \
            .compression = (uWS::CompressOptions)(uint64_t)behavior.compression,                                                                                                                      \
            .maxPayloadLength = behavior.maxPayloadLength,                                                                                                                                            \
            .idleTimeout = behavior.idleTimeout,                                                                                                                                                      \
            .maxBackpressure = behavior.maxBackpressure,                                                                                                                                              \
            .closeOnBackpressureLimit = behavior.closeOnBackpressureLimit,                                                                                                                            \
            .resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend,                                                                                                                                \
            .sendPingsAutomatically = behavior.sendPingsAutomatically,                                                                                                                                \
            .maxLifetime = behavior.maxLifetime,                                                                                                                                                      \
        };                                                                                                                                                                                            \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(upgrade, (auto *res, auto *req, auto *context), {                                                                                                                           \
            handler((uws_##prefix##res_t *)res, (uws_req_t *)req, (uws_socket_context_t *)context);                                                                                                   \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(open, (auto *ws), {                                                                                                                                                         \
            handler((uws_##prefix##websocket_t *)ws);                                                                                                                                                 \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(message, (auto *ws, auto message, auto opcode), {                                                                                                                           \
            handler((uws_##prefix##websocket_t *)ws, message.data(), message.length(), (uws_opcode_t)opcode);                                                                                         \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(dropped, (auto *ws, auto message, auto opcode), {                                                                                                                           \
            handler((uws_##prefix##websocket_t *)ws, message.data(), message.length(), (uws_opcode_t)opcode);                                                                                         \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(drain, (auto *ws), {                                                                                                                                                        \
            handler((uws_##prefix##websocket_t *)ws);                                                                                                                                                 \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(ping, (auto *ws, auto message), {                                                                                                                                           \
            handler((uws_##prefix##websocket_t *)ws, message.data(), message.length());                                                                                                               \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(pong, (auto *ws, auto message), {                                                                                                                                           \
            handler((uws_##prefix##websocket_t *)ws, message.data(), message.length());                                                                                                               \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(close, (auto *ws, int code, auto message), {                                                                                                                                \
            handler((uws_##prefix##websocket_t *)ws, code, message.data(), message.length());                                                                                                         \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        WEBSOCKET_HANDLER(subscription, (auto *ws, auto topic, int subscribers, int old_subscribers), {                                                                                               \
            handler((uws_##prefix##websocket_t *)ws, topic.data(), topic.length(), subscribers, old_subscribers);                                                                                     \
        });                                                                                                                                                                                           \
                                                                                                                                                                                                      \
        uWS::protocol##App *uwsApp = (uWS::protocol##App *)app;                                                                                                                                       \
        uwsApp->ws<void *>(pattern, std::move(generic_handler));                                                                                                                                      \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    void uws_##prefix##ws_close(uws_##prefix##websocket_t *ws)                                                                                                                                        \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        uws->close();                                                                                                                                                                                 \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode)                                                                    \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->send(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode);                                                                                    \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send_with_options(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress, bool fin)                              \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->send(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode, compress, fin);                                                                     \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress)                                                                 \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->sendFragment(std::string_view(message, length), compress);                                                                                                      \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send_first_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress)                                                           \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->sendFirstFragment(std::string_view(message, length), uWS::OpCode::BINARY, compress);                                                                            \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send_first_fragment_with_opcode(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress)                          \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->sendFirstFragment(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode, compress);                                                             \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    uws_sendstatus_t uws_##prefix##ws_send_last_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress)                                                            \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return (uws_sendstatus_t)uws->sendLastFragment(std::string_view(message, length), compress);                                                                                                  \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    void uws_##prefix##ws_end(uws_##prefix##websocket_t *ws, int code, const char *message, size_t length)                                                                                            \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        uws->end(code, std::string_view(message, length));                                                                                                                                            \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    void uws_##prefix##ws_cork(uws_##prefix##websocket_t *ws, void (*handler)())                                                                                                                      \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        uws->cork([handler]() { handler(); });                                                                                                                                                        \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    bool uws_##prefix##ws_subscribe(uws_##prefix##websocket_t *ws, const char *topic, size_t length)                                                                                                  \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->subscribe(std::string_view(topic, length));                                                                                                                                       \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    bool uws_##prefix##ws_unsubscribe(uws_##prefix##websocket_t *ws, const char *topic, size_t length)                                                                                                \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->unsubscribe(std::string_view(topic, length));                                                                                                                                     \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    bool uws_##prefix##ws_is_subscribed(uws_##prefix##websocket_t *ws, const char *topic, size_t length)                                                                                              \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->isSubscribed(std::string_view(topic, length));                                                                                                                                    \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    void uws_##prefix##ws_iterate_topics(uws_##prefix##websocket_t *ws, void (*callback)(const char *topic, size_t length))                                                                           \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        uws->iterateTopics([callback](auto topic)                                                                                                                                                     \
                           { callback(topic.data(), topic.length()); });                                                                                                                              \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    bool uws_##prefix##ws_publish(uws_##prefix##websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length)                                                  \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->publish(std::string_view(topic, topic_length), std::string_view(message, message_length));                                                                                        \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    bool uws_##prefix##ws_publish_with_options(uws_##prefix##websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length, uws_opcode_t opcode, bool compress) \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->publish(std::string_view(topic, topic_length), std::string_view(message, message_length), (uWS::OpCode)(unsigned char)opcode, compress);                                          \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    unsigned int uws_##prefix##ws_get_buffered_amount(uws_##prefix##websocket_t *ws)                                                                                                                  \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        return uws->getBufferedAmount();                                                                                                                                                              \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    size_t uws_##prefix##ws_get_remote_address(uws_##prefix##websocket_t *ws, const char **dest)                                                                                                      \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        std::string_view value = uws->getRemoteAddress();                                                                                                                                             \
        *dest = value.data();                                                                                                                                                                         \
        return value.length();                                                                                                                                                                        \
    }                                                                                                                                                                                                 \
                                                                                                                                                                                                      \
    size_t uws_##prefix##ws_get_remote_address_as_text(uws_##prefix##websocket_t *ws, const char **dest)                                                                                              \
    {                                                                                                                                                                                                 \
        uWS::WebSocket<is_ssl, true, void *> *uws = (uWS::WebSocket<is_ssl, true, void *> *)ws;                                                                                                       \
        std::string_view value = uws->getRemoteAddressAsText();                                                                                                                                       \
        *dest = value.data();                                                                                                                                                                         \
        return value.length();                                                                                                                                                                        \
    }
PROTOCOLS
#undef APP

#pragma endregion

void uws_loop_defer(us_loop_t *loop, void(cb()))
{
    ((uWS::Loop *)loop)->defer([cb]()
                               { cb(); });
}

struct us_loop_t *uws_get_loop()
{
    return (struct us_loop_t *)uWS::Loop::get();
}

struct us_loop_t *uws_get_loop_with_native(void *existing_native_loop)
{
    return (struct us_loop_t *)uWS::Loop::get(existing_native_loop);
}