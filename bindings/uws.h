#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "../uWebSockets/uSockets/src/libusockets.h"

#ifdef __cplusplus
extern "C"
{
#endif
    struct uws_req_s;
    typedef struct uws_req_s uws_req_t;
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

    typedef void (*uws_listen_handler)(struct us_listen_socket_t *listen_socket);

#define PROTOCOLS        \
    APP(ssl_, SSL, true) \
    APP(, , false)

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

#define APP(prefix, _, __)                                                                             \
    struct uws_##prefix##res_s;                                                                        \
    typedef struct uws_##prefix##res_s uws_##prefix##res_t;                                            \
    typedef void (*uws_##prefix##method_handler)(uws_##prefix##res_t * response, uws_req_t * request); \
                                                                                                       \
    struct uws_##prefix##app_s;                                                                        \
    typedef struct uws_##prefix##app_s uws_##prefix##app_t;                                            \
    uws_##prefix##app_t *uws_create_##prefix##app(struct us_socket_context_options_t options);         \
    void uws_##prefix##app_destroy(uws_##prefix##app_t *app);                                          \
    void uws_##prefix##app_run(uws_##prefix##app_t *app);                                              \
    void uws_##prefix##app_listen(uws_##prefix##app_t *app, int port, uws_listen_handler handler);     \
    void uws_##prefix##app_close(uws_##prefix##app_t *app);
    PROTOCOLS
#undef APP

#define METHOD(name)                                                                      \
    void uws_app_##name(uws_app_t *app, const char *pattern, uws_method_handler handler); \
    void uws_ssl_app_##name(uws_ssl_app_t *app, const char *pattern, uws_ssl_method_handler handler);
    HTTP_METHODS
#undef METHOD

#pragma endregion
#pragma region uWs-Response

    typedef struct
    {
        bool ok;
        bool has_responded;
    } uws_try_end_result_t;

#define APP(prefix, _, __)                                                                                                                                                                                                                                                                                                        \
    typedef bool (*uws_##prefix##res_on_writable_handler)(uws_##prefix##res_t * res, uintmax_t);                                                                                                                                                                                                                                  \
    typedef bool (*uws_##prefix##res_on_aborted_handler)(uws_##prefix##res_t * res);                                                                                                                                                                                                                                              \
    typedef void (*uws_##prefix##res_on_data_handler)(uws_##prefix##res_t * res, const char *chunk, size_t chunk_length, bool is_end);                                                                                                                                                                                            \
                                                                                                                                                                                                                                                                                                                                  \
    void uws_##prefix##res_close(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                                       \
    void uws_##prefix##res_end(uws_##prefix##res_t *res, const char *data, size_t length, bool close_connection);                                                                                                                                                                                                                 \
    void uws_##prefix##res_cork(uws_##prefix##res_t *res, void (*callback)(uws_##prefix##res_t * res));                                                                                                                                                                                                                           \
    void uws_##prefix##res_pause(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                                       \
    void uws_##prefix##res_resume(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                                      \
    void uws_##prefix##res_write_continue(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                              \
    void uws_##prefix##res_write_status(uws_##prefix##res_t *res, const char *status, size_t length);                                                                                                                                                                                                                             \
    void uws_##prefix##res_write_header(uws_##prefix##res_t *res, const char *key, size_t key_length, const char *value, size_t value_length);                                                                                                                                                                                    \
    void uws_##prefix##res_write_header_int(uws_##prefix##res_t *res, const char *key, size_t key_length, uint64_t value);                                                                                                                                                                                                        \
    void uws_##prefix##res_end_without_body(uws_##prefix##res_t *res, bool close_connection);                                                                                                                                                                                                                                     \
    bool uws_##prefix##res_write(uws_##prefix##res_t *res, const char *data, size_t length);                                                                                                                                                                                                                                      \
    void uws_##prefix##res_override_write_offset(uws_##prefix##res_t *res, uintmax_t offset);                                                                                                                                                                                                                                     \
    bool uws_##prefix##res_has_responded(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                               \
    void uws_##prefix##res_on_writable(uws_##prefix##res_t *res, uws_##prefix##res_on_writable_handler handler);                                                                                                                                                                                                                  \
    void uws_##prefix##res_on_aborted(uws_##prefix##res_t *res, uws_##prefix##res_on_aborted_handler handler);                                                                                                                                                                                                                    \
    void uws_##prefix##res_on_data(uws_##prefix##res_t *res, uws_##prefix##res_on_data_handler handler);                                                                                                                                                                                                                          \
    void uws_##prefix##res_upgrade(uws_##prefix##res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws); \
                                                                                                                                                                                                                                                                                                                                  \
    uws_try_end_result_t uws_##prefix##res_try_end(uws_##prefix##res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection);                                                                                                                                                                       \
    uintmax_t uws_##prefix##res_get_write_offset(uws_##prefix##res_t *res);                                                                                                                                                                                                                                                       \
    size_t uws_##prefix##res_get_remote_address(uws_##prefix##res_t *res, const char **dest);                                                                                                                                                                                                                                     \
    size_t uws_##prefix##res_get_remote_address_as_text(uws_##prefix##res_t *res, const char **dest);
    PROTOCOLS
#undef APP

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

#define APP(prefix, _, __)                                                                                                                                                                              \
    struct uws_##prefix##websocket_s;                                                                                                                                                                   \
    typedef struct uws_##prefix##websocket_s uws_##prefix##websocket_t;                                                                                                                                 \
                                                                                                                                                                                                        \
    typedef void (*uws_##prefix##websocket_upgrade)(uws_##prefix##res_t * response, uws_req_t * request, uws_socket_context_t * context);                                                               \
    typedef void (*uws_##prefix##websocket_open)(uws_##prefix##websocket_t * ws);                                                                                                                       \
    typedef void (*uws_##prefix##websocket_message)(uws_##prefix##websocket_t * ws, const char *message, size_t length, uws_opcode_t opcode);                                                           \
    typedef void (*uws_##prefix##websocket_dropped)(uws_##prefix##websocket_t * ws, const char *message, size_t length, uws_opcode_t opcode);                                                           \
    typedef void (*uws_##prefix##websocket_drain)(uws_##prefix##websocket_t * ws);                                                                                                                      \
    typedef void (*uws_##prefix##websocket_ping)(uws_##prefix##websocket_t * ws, const char *message, size_t length);                                                                                   \
    typedef void (*uws_##prefix##websocket_pong)(uws_##prefix##websocket_t * ws, const char *message, size_t length);                                                                                   \
    typedef void (*uws_##prefix##websocket_close)(uws_##prefix##websocket_t * ws, int code, const char *message, size_t length);                                                                        \
    typedef void (*uws_##prefix##websocket_subscription)(uws_##prefix##websocket_t * ws, const char *topic_name, size_t topic_name_length, int new_number_of_subscriber, int old_number_of_subscriber); \
                                                                                                                                                                                                        \
    typedef struct                                                                                                                                                                                      \
    {                                                                                                                                                                                                   \
        uws_compress_options_t compression;                                                                                                                                                             \
        unsigned int maxPayloadLength;                                                                                                                                                                  \
        unsigned short idleTimeout;                                                                                                                                                                     \
        unsigned int maxBackpressure;                                                                                                                                                                   \
        bool closeOnBackpressureLimit;                                                                                                                                                                  \
        bool resetIdleTimeoutOnSend;                                                                                                                                                                    \
        bool sendPingsAutomatically;                                                                                                                                                                    \
        unsigned short maxLifetime;                                                                                                                                                                     \
        uws_##prefix##websocket_upgrade upgrade;                                                                                                                                                        \
        uws_##prefix##websocket_open open;                                                                                                                                                              \
        uws_##prefix##websocket_message message;                                                                                                                                                        \
        uws_##prefix##websocket_dropped dropped;                                                                                                                                                        \
        uws_##prefix##websocket_drain drain;                                                                                                                                                            \
        uws_##prefix##websocket_ping ping;                                                                                                                                                              \
        uws_##prefix##websocket_pong pong;                                                                                                                                                              \
        uws_##prefix##websocket_close close;                                                                                                                                                            \
        uws_##prefix##websocket_subscription subscription;                                                                                                                                              \
    } uws_##prefix##socket_behavior_t;                                                                                                                                                                  \
                                                                                                                                                                                                        \
    void uws_##prefix##ws(uws_##prefix##app_t *app, const char *pattern, uws_##prefix##socket_behavior_t behavior);                                                                                     \
    void uws_##prefix##ws_close(uws_##prefix##websocket_t *ws);                                                                                                                                         \
    uws_sendstatus_t uws_##prefix##ws_send(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode);                                                                     \
    uws_sendstatus_t uws_##prefix##ws_send_with_options(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress, bool fin);                               \
    uws_sendstatus_t uws_##prefix##ws_send_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress);                                                                  \
    uws_sendstatus_t uws_##prefix##ws_send_first_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress);                                                            \
    uws_sendstatus_t uws_##prefix##ws_send_first_fragment_with_opcode(uws_##prefix##websocket_t *ws, const char *message, size_t length, uws_opcode_t opcode, bool compress);                           \
    uws_sendstatus_t uws_##prefix##ws_send_last_fragment(uws_##prefix##websocket_t *ws, const char *message, size_t length, bool compress);                                                             \
    void uws_##prefix##ws_end(uws_##prefix##websocket_t *ws, int code, const char *message, size_t length);                                                                                             \
    void uws_##prefix##ws_cork(uws_##prefix##websocket_t *ws, void (*handler)());                                                                                                                       \
    bool uws_##prefix##ws_subscribe(uws_##prefix##websocket_t *ws, const char *topic, size_t length);                                                                                                   \
    bool uws_##prefix##ws_unsubscribe(uws_##prefix##websocket_t *ws, const char *topic, size_t length);                                                                                                 \
    bool uws_##prefix##ws_is_subscribed(uws_##prefix##websocket_t *ws, const char *topic, size_t length);                                                                                               \
    void uws_##prefix##ws_iterate_topics(uws_##prefix##websocket_t *ws, void (*callback)(const char *topic, size_t length));                                                                            \
    bool uws_##prefix##ws_publish(uws_##prefix##websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length);                                                   \
    bool uws_##prefix##ws_publish_with_options(uws_##prefix##websocket_t *ws, const char *topic, size_t topic_length, const char *message, size_t message_length, uws_opcode_t opcode, bool compress);  \
    unsigned int uws_##prefix##ws_get_buffered_amount(uws_##prefix##websocket_t *ws);                                                                                                                   \
    size_t uws_##prefix##ws_get_remote_address(uws_##prefix##websocket_t *ws, const char **dest);                                                                                                       \
    size_t uws_##prefix##ws_get_remote_address_as_text(uws_##prefix##websocket_t *ws, const char **dest);
    PROTOCOLS
#undef APP

#pragma endregion

    void uws_loop_defer(struct us_loop_t *loop, void(cb()));
    struct us_loop_t *uws_get_loop();
    struct us_loop_t *uws_get_loop_with_native(void *existing_native_loop);

#ifdef __cplusplus
} // extern "C"
#endif
