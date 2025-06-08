#ifdef ZUWS_USE_SSL
#define IS_SSL true
#else
#define IS_SSL false
#endif

#include "uws.h"

#include "../uWebSockets/src/App.h"

#pragma region uWS-App

#define METHOD(name)                                                                                                        \
    void uws_app_##name(uws_app_t *app, const char *pattern, uws_method_handler handler)                                    \
    {                                                                                                                       \
        ((uWS::TemplatedApp<IS_SSL> *)app)->name(pattern, [handler](auto *res, auto *req) { handler((uws_res_t *)res, (uws_req_t *)req); }); \
    };
HTTP_METHODS
#undef METHOD

uws_app_t *uws_create_app(struct us_socket_context_options_t options = {})
{
    uWS::SocketContextOptions sco;
    memcpy(&sco, &options, sizeof(struct us_socket_context_options_t));
    return (uws_app_t *)new uWS::TemplatedApp<IS_SSL>(sco);
}

void uws_app_destroy(uws_app_t *app)
{
    delete ((uWS::TemplatedApp<IS_SSL> *)app);
}

void uws_app_run(uws_app_t *app)
{
    ((uWS::TemplatedApp<IS_SSL> *)app)->run();
}

void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler)
{
    if (!handler)
        handler = [](auto) {};

    ((uWS::TemplatedApp<IS_SSL> *)app)->listen(port, [handler](struct us_listen_socket_t *listen_socket)
                              { handler((struct us_listen_socket_t *)listen_socket); });
}

void uws_app_close(uws_app_t *app)
{
    ((uWS::TemplatedApp<IS_SSL> *)app)->close();
}

#pragma endregion
#pragma region uWS-Response

void uws_res_close(uws_res_t *res)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->close();
}

void uws_res_end(uws_res_t *res, const char *data, size_t length, bool close_connection)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->end(std::string_view(data, length), close_connection);
}

void uws_res_cork(uws_res_t *res, void (*callback)(uws_res_t *res))
{
    ((uWS::HttpResponse<IS_SSL> *)res)->cork([=]()
                                          { callback(res); });
}

void uws_res_pause(uws_res_t *res)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->pause();
}

void uws_res_resume(uws_res_t *res)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->resume();
}

void uws_res_write_continue(uws_res_t *res)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->writeContinue();
}

void uws_res_write_status(uws_res_t *res, const char *status, size_t length)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->writeStatus(std::string_view(status, length));
}

void uws_res_write_header(uws_res_t *res, const char *key, size_t key_length, const char *value, size_t value_length)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->writeHeader(std::string_view(key, key_length), std::string_view(value, value_length));
}

void uws_res_write_header_int(uws_res_t *res, const char *key, size_t key_length, uint64_t value)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->writeHeader(std::string_view(key, key_length), value);
}

void uws_res_end_without_body(uws_res_t *res, bool close_connection)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->endWithoutBody(std::nullopt, close_connection);
}

bool uws_res_write(uws_res_t *res, const char *data, size_t length)
{
    return ((uWS::HttpResponse<IS_SSL> *)res)->write(std::string_view(data, length));
}

void uws_res_override_write_offset(uws_res_t *res, uintmax_t offset)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->overrideWriteOffset(offset);
}

bool uws_res_has_responded(uws_res_t *res)
{
    return ((uWS::HttpResponse<IS_SSL> *)res)->hasResponded();
}

void uws_res_on_writable(uws_res_t *res, uws_res_on_writable_handler handler)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->onWritable([handler, res](uintmax_t a)
                                                { return handler(res, a); });
}

void uws_res_on_aborted(uws_res_t *res, uws_res_on_aborted_handler handler)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->onAborted([handler, res]
                                               { handler(res); });
}

void uws_res_on_data(uws_res_t *res, uws_res_on_data_handler handler)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->onData([handler, res](auto chunk, bool is_end)
                                            { handler(res, chunk.data(), chunk.length(), is_end); });
}

void uws_res_upgrade(uws_res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws)
{
    ((uWS::HttpResponse<IS_SSL> *)res)->template upgrade<void *>(data ? std::move(data) : NULL, std::string_view(sec_web_socket_key, sec_web_socket_key_length), std::string_view(sec_web_socket_protocol, sec_web_socket_protocol_length), std::string_view(sec_web_socket_extensions, sec_web_socket_extensions_length), (struct us_socket_context_t *)ws);
}

uws_try_end_result_t uws_res_try_end(uws_res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection)
{

    std::pair<bool, bool> result = ((uWS::HttpResponse<IS_SSL> *)res)->tryEnd(std::string_view(data, length), total_size);
    return uws_try_end_result_t{
        .ok = result.first,
        .has_responded = result.second,
    };
}

uintmax_t uws_res_get_write_offset(uws_res_t *res)
{
    return ((uWS::HttpResponse<IS_SSL> *)res)->getWriteOffset();
}

size_t uws_res_get_remote_address(uws_res_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpResponse<IS_SSL> *)res)->getRemoteAddress();
    *dest = value.data();
    return value.length();
}

size_t uws_res_get_remote_address_as_text(uws_res_t *res, const char **dest)
{
    std::string_view value = ((uWS::HttpResponse<IS_SSL> *)res)->getRemoteAddressAsText();
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

void uws_ws(uws_app_t *app, const char *pattern, uws_socket_behavior_t behavior)
{
    auto generic_handler = uWS::TemplatedApp<IS_SSL>::WebSocketBehavior<void *>{
        .compression = (uWS::CompressOptions)(uint64_t)behavior.compression,
        .maxPayloadLength = behavior.maxPayloadLength,
        .idleTimeout = behavior.idleTimeout,
        .maxBackpressure = behavior.maxBackpressure,
        .closeOnBackpressureLimit = behavior.closeOnBackpressureLimit,
        .resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend,
        .sendPingsAutomatically = behavior.sendPingsAutomatically,
        .maxLifetime = behavior.maxLifetime,
    };

    WEBSOCKET_HANDLER(upgrade, (auto *res, auto *req, auto *context), {
        handler((uws_res_t *)res, (uws_req_t *)req, (uws_socket_context_t *)context);
    });

    WEBSOCKET_HANDLER(open, (auto *ws), {
        handler((uws_websocket_t *)ws);
    });

    WEBSOCKET_HANDLER(message, (auto *ws, auto message, auto opcode), {
        handler((uws_websocket_t *)ws, message.data(), message.length(), (uws_opcode_t)opcode);
    });

    WEBSOCKET_HANDLER(dropped, (auto *ws, auto message, auto opcode), {
        handler((uws_websocket_t *)ws, message.data(), message.length(), (uws_opcode_t)opcode);
    });

    WEBSOCKET_HANDLER(drain, (auto *ws), {
        handler((uws_websocket_t *)ws);
    });

    WEBSOCKET_HANDLER(ping, (auto *ws, auto message), {
        handler((uws_websocket_t *)ws, message.data(), message.length());
    });

    WEBSOCKET_HANDLER(pong, (auto *ws, auto message), {
        handler((uws_websocket_t *)ws, message.data(), message.length());
    });

    WEBSOCKET_HANDLER(close, (auto *ws, int code, auto message), {
        handler((uws_websocket_t *)ws, code, message.data(), message.length());
    });

    WEBSOCKET_HANDLER(subscription, (auto *ws, auto topic, int subscribers, int old_subscribers), {
        handler((uws_websocket_t *)ws, topic.data(), topic.length(), subscribers, old_subscribers);
    });

    uWS::TemplatedApp<IS_SSL> *uwsApp = (uWS::TemplatedApp<IS_SSL> *)app;
    uwsApp->ws<void *>(pattern, std::move(generic_handler));
}

void uws_ws_close(uws_websocket_t *ws)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    uws->close();
}

uws_sendstatus_t uws_ws_send(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->send(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode);
}

uws_sendstatus_t uws_ws_send_with_options(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress, bool fin)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->send(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode, compress, fin);
}

uws_sendstatus_t uws_ws_send_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->sendFragment(std::string_view(message, length), compress);
}

uws_sendstatus_t uws_ws_send_first_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->sendFirstFragment(std::string_view(message, length), uWS::OpCode::BINARY, compress);
}

uws_sendstatus_t uws_ws_send_first_fragment_with_opcode(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->sendFirstFragment(std::string_view(message, length), (uWS::OpCode)(unsigned char)opcode, compress);
}

uws_sendstatus_t uws_ws_send_last_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return (uws_sendstatus_t)uws->sendLastFragment(std::string_view(message, length), compress);
}

void uws_ws_end(uws_websocket_t *ws, int code, const char *message, size_t length)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    uws->end(code, std::string_view(message, length));
}

void uws_ws_cork(uws_websocket_t *ws, void (*handler)())
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    uws->cork([handler]()
              { handler(); });
}

bool uws_ws_subscribe(uws_websocket_t *ws, const char *topic, size_t length)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->subscribe(std::string_view(topic, length));
}

bool uws_ws_unsubscribe(uws_websocket_t *ws, const char *topic, size_t length)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->unsubscribe(std::string_view(topic, length));
}

bool uws_ws_is_subscribed(uws_websocket_t *ws, const char *topic, size_t length)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->isSubscribed(std::string_view(topic, length));
}

void uws_ws_iterate_topics(uws_websocket_t *ws, void (*callback)(const char *topic, size_t length))
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    uws->iterateTopics([callback](auto topic)
                       { callback(topic.data(), topic.length()); });
}

bool uws_ws_publish(uws_websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->publish(std::string_view(topic, topic_length), std::string_view(message, message_length));
}

bool uws_ws_publish_with_options(uws_websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length, uws_opcode_t opcode, bool compress)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->publish(std::string_view(topic, topic_length), std::string_view(message, message_length), (uWS::OpCode)(unsigned char)opcode, compress);
}

unsigned int uws_ws_get_buffered_amount(uws_websocket_t *ws)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    return uws->getBufferedAmount();
}

size_t uws_ws_get_remote_address(uws_websocket_t *ws, const char **dest)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    std::string_view value = uws->getRemoteAddress();
    *dest = value.data();
    return value.length();
}

size_t uws_ws_get_remote_address_as_text(uws_websocket_t *ws, const char **dest)
{
    uWS::WebSocket<IS_SSL, true, void *> *uws = (uWS::WebSocket<IS_SSL, true, void *> *)ws;
    std::string_view value = uws->getRemoteAddressAsText();
    *dest = value.data();
    return value.length();
}

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