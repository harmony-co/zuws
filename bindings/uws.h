#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "../uWebSockets/uSockets/src/libusockets.h"

#ifdef __cplusplus
extern "C"
{
#endif

    struct uws_websocket_s;
    typedef struct uws_websocket_s uws_websocket_t;
    struct uws_socket_context_s;
    typedef struct uws_socket_context_s uws_socket_context_t;

    typedef struct
    {
        int port;
        const char *host;
        int options;
    } uws_app_listen_config_t;

    typedef enum
    {
        /* These are not actual compression options */
        _COMPRESSOR_MASK = 0x00FF,
        _DECOMPRESSOR_MASK = 0x0F00,
        /* Disabled, shared, shared are "special" values */
        DISABLED = 0,
        SHARED_COMPRESSOR = 1,
        SHARED_DECOMPRESSOR = 1 << 8,
        /* Highest 4 bits describe decompressor */
        DEDICATED_DECOMPRESSOR_32KB = 15 << 8,
        DEDICATED_DECOMPRESSOR_16KB = 14 << 8,
        DEDICATED_DECOMPRESSOR_8KB = 13 << 8,
        DEDICATED_DECOMPRESSOR_4KB = 12 << 8,
        DEDICATED_DECOMPRESSOR_2KB = 11 << 8,
        DEDICATED_DECOMPRESSOR_1KB = 10 << 8,
        DEDICATED_DECOMPRESSOR_512B = 9 << 8,
        /* Same as 32kb */
        DEDICATED_DECOMPRESSOR = 15 << 8,
        /* Lowest 8 bit describe compressor */
        DEDICATED_COMPRESSOR_3KB = 9 << 4 | 1,
        DEDICATED_COMPRESSOR_4KB = 9 << 4 | 2,
        DEDICATED_COMPRESSOR_8KB = 10 << 4 | 3,
        DEDICATED_COMPRESSOR_16KB = 11 << 4 | 4,
        DEDICATED_COMPRESSOR_32KB = 12 << 4 | 5,
        DEDICATED_COMPRESSOR_64KB = 13 << 4 | 6,
        DEDICATED_COMPRESSOR_128KB = 14 << 4 | 7,
        DEDICATED_COMPRESSOR_256KB = 15 << 4 | 8,
        /* Same as 256kb */
        DEDICATED_COMPRESSOR = 15 << 4 | 8
    } uws_compress_options_t;

#pragma region uWS-App

    struct uws_app_s;
    typedef struct uws_app_s uws_app_t;
    struct uws_res_s;
    typedef struct uws_res_s uws_res_t;
    struct uws_req_s;
    typedef struct uws_req_s uws_req_t;
    typedef void (*uws_method_handler)(uws_res_t *response, uws_req_t *request);
    typedef void (*uws_listen_handler)(struct us_listen_socket_t *listen_socket);

#define HTTP_METHODS \
    METHOD(get)      \
    METHOD(post)     \
    METHOD(put)      \
    METHOD(options)  \
    METHOD(del)      \
    METHOD(patch)    \
    METHOD(head)     \
    METHOD(connect)  \
    METHOD(trace)    \
    METHOD(any)

#define METHOD(name) \
    void uws_app_##name(uws_app_t *app, const char *pattern, uws_method_handler handler);
    HTTP_METHODS
#undef METHOD

#if ZUWS_USE_SSL
    uws_app_t *uws_create_app(struct us_socket_context_options_t options);
#else
uws_app_t *uws_create_app();
#endif

    void uws_app_destroy(uws_app_t *app);
    void uws_app_run(uws_app_t *app);
    void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler);
    void uws_app_close(uws_app_t *app);

#pragma endregion
#pragma region uWs-Response

    typedef struct
    {
        bool ok;
        bool has_responded;
    } uws_try_end_result_t;

    typedef bool (*uws_res_on_writable_handler)(uws_res_t *res, uintmax_t);
    typedef bool (*uws_res_on_aborted_handler)(uws_res_t *res);
    typedef void (*uws_res_on_data_handler)(uws_res_t *res, const char *chunk, size_t chunk_length, bool is_end);

    void uws_res_close(uws_res_t *res);
    void uws_res_end(uws_res_t *res, const char *data, size_t length, bool close_connection);
    void uws_res_cork(uws_res_t *res, void (*callback)(uws_res_t *res));
    void uws_res_pause(uws_res_t *res);
    void uws_res_resume(uws_res_t *res);
    void uws_res_write_continue(uws_res_t *res);
    void uws_res_write_status(uws_res_t *res, const char *status, size_t length);
    void uws_res_write_header(uws_res_t *res, const char *key, size_t key_length, const char *value, size_t value_length);
    void uws_res_write_header_int(uws_res_t *res, const char *key, size_t key_length, uint64_t value);
    void uws_res_end_without_body(uws_res_t *res, bool close_connection);
    bool uws_res_write(uws_res_t *res, const char *data, size_t length);
    void uws_res_override_write_offset(uws_res_t *res, uintmax_t offset);
    bool uws_res_has_responded(uws_res_t *res);
    void uws_res_on_writable(uws_res_t *res, uws_res_on_writable_handler handler);
    void uws_res_on_aborted(uws_res_t *res, uws_res_on_aborted_handler handler);
    void uws_res_on_data(uws_res_t *res, uws_res_on_data_handler handler);
    void uws_res_upgrade(uws_res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws);

    uws_try_end_result_t uws_res_try_end(uws_res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection);
    uintmax_t uws_res_get_write_offset(uws_res_t *res);
    size_t uws_res_get_remote_address(uws_res_t *res, const char **dest);
    size_t uws_res_get_remote_address_as_text(uws_res_t *res, const char **dest);

#pragma endregion
#pragma region uWS-Request

    typedef void (*uws_get_headers_server_handler)(const char *header_name, size_t header_name_size, const char *header_value, size_t header_value_size);

    bool uws_req_is_ancient(uws_req_t *res);
    bool uws_req_get_yield(uws_req_t *res);
    void uws_req_set_yield(uws_req_t *res, bool yield);
    void uws_req_for_each_header(uws_req_t *res, uws_get_headers_server_handler handler);
    size_t uws_req_get_url(uws_req_t *res, const char **dest);
    size_t uws_req_get_full_url(uws_req_t *res, const char **dest);
    size_t uws_req_get_method(uws_req_t *res, const char **dest);
    size_t uws_req_get_case_sensitive_method(uws_req_t *res, const char **dest);
    size_t uws_req_get_header(uws_req_t *res, const char *lower_case_header, size_t lower_case_header_length, const char **dest);
    size_t uws_req_get_query(uws_req_t *res, const char *key, size_t key_length, const char **dest);
    size_t uws_req_get_parameter_name(uws_req_t *res, const char *key, size_t key_length, const char **dest);
    size_t uws_req_get_parameter_index(uws_req_t *res, unsigned short index, const char **dest);

#pragma endregion
#pragma region uWS-Websockets

    typedef enum
    {
        CONTINUATION = 0,
        TEXT = 1,
        BINARY = 2,
        CLOSE = 8,
        PING = 9,
        PONG = 10
    } uws_opcode_t;

    typedef enum
    {
        BACKPRESSURE,
        SUCCESS,
        DROPPED
    } uws_sendstatus_t;

    typedef void (*uws_websocket_upgrade)(uws_res_t *response, uws_req_t *request, uws_socket_context_t *context);
    typedef void (*uws_websocket_open)(uws_websocket_t *ws);
    typedef void (*uws_websocket_message)(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode);
    typedef void (*uws_websocket_dropped)(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode);
    typedef void (*uws_websocket_drain)(uws_websocket_t *ws);
    typedef void (*uws_websocket_ping)(uws_websocket_t *ws, const char *message, size_t length);
    typedef void (*uws_websocket_pong)(uws_websocket_t *ws, const char *message, size_t length);
    typedef void (*uws_websocket_close)(uws_websocket_t *ws, int code, const char *message, size_t length);
    typedef void (*uws_websocket_subscription)(uws_websocket_t *ws, const char *topic_name, size_t topic_name_length, int new_number_of_subscriber, int old_number_of_subscriber);

    typedef struct
    {
        uws_compress_options_t compression;
        unsigned int maxPayloadLength;
        unsigned short idleTimeout;
        unsigned int maxBackpressure;
        bool closeOnBackpressureLimit;
        bool resetIdleTimeoutOnSend;
        bool sendPingsAutomatically;
        unsigned short maxLifetime;
        uws_websocket_upgrade upgrade;
        uws_websocket_open open;
        uws_websocket_message message;
        uws_websocket_dropped dropped;
        uws_websocket_drain drain;
        uws_websocket_ping ping;
        uws_websocket_pong pong;
        uws_websocket_close close;
        uws_websocket_subscription subscription;
    } uws_socket_behavior_t;

    void uws_ws(uws_app_t *app, const char *pattern, uws_socket_behavior_t behavior);
    void uws_ws_close(uws_websocket_t *ws);
    uws_sendstatus_t uws_ws_send(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode);
    uws_sendstatus_t uws_ws_send_with_options(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress, bool fin);
    uws_sendstatus_t uws_ws_send_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress);
    uws_sendstatus_t uws_ws_send_first_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress);
    uws_sendstatus_t uws_ws_send_first_fragment_with_opcode(uws_websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress);
    uws_sendstatus_t uws_ws_send_last_fragment(uws_websocket_t *ws, const char *message, size_t length, bool compress);
    void uws_ws_end(uws_websocket_t *ws, int code, const char *message, size_t length);
    void uws_ws_cork(uws_websocket_t *ws, void (*handler)());
    bool uws_ws_subscribe(uws_websocket_t *ws, const char *topic, size_t length);
    bool uws_ws_unsubscribe(uws_websocket_t *ws, const char *topic, size_t length);
    bool uws_ws_is_subscribed(uws_websocket_t *ws, const char *topic, size_t length);
    void uws_ws_iterate_topics(uws_websocket_t *ws, void (*callback)(const char *topic, size_t length));
    bool uws_ws_publish(uws_websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length);
    bool uws_ws_publish_with_options(uws_websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length, uws_opcode_t opcode, bool compress);
    unsigned int uws_ws_get_buffered_amount(uws_websocket_t *ws);
    size_t uws_ws_get_remote_address(uws_websocket_t *ws, const char **dest);
    size_t uws_ws_get_remote_address_as_text(uws_websocket_t *ws, const char **dest);

#pragma endregion

    void uws_loop_defer(struct us_loop_t *loop, void(cb()));
    struct us_loop_t *uws_get_loop();
    struct us_loop_t *uws_get_loop_with_native(void *existing_native_loop);

#ifdef __cplusplus
} // extern "C"
#endif
