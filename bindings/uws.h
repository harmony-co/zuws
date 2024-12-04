#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


#ifndef uws
#define uws

#ifdef __cplusplus
extern "C"
{
#endif
    struct uws_app_s;
    struct uws_req_s;
    struct uws_res_s;
    struct uws_socket_context_s;
    typedef struct uws_app_s uws_app_t;
    typedef struct uws_req_s uws_req_t;
    typedef struct uws_res_s uws_res_t;
    typedef struct uws_socket_context_s uws_socket_context_t;

    typedef struct
    {
        int port;
        const char *host;
        int options;
    } uws_app_listen_config_t;

#pragma region uWS-app

    typedef void (*uws_listen_handler)(struct us_listen_socket_t *listen_socket);
    typedef void (*uws_method_handler)(uws_res_t *response, uws_req_t *request);

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

    uws_app_t *uws_create_app();
    void uws_app_destroy(uws_app_t *app);
    void uws_app_run(uws_app_t *);
    void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler);
    void uws_app_close(uws_app_t *app);

#pragma endregion
#pragma region uWs-Response

    typedef struct
    {
        bool ok;
        bool has_responded;
    } uws_try_end_result_t;

    typedef bool (*uws_res_on_writable_handler)(uws_res_t *res, uintmax_t, void *optional_data);
    typedef bool (*uws_res_on_aborted_handler)(uws_res_t *res, void *optional_data);
    typedef void (*uws_res_on_data_handler)(uws_res_t *res, const char *chunk, size_t chunk_length, bool is_end, void *optional_data);

    void uws_res_close(uws_res_t *res);
    void uws_res_end(uws_res_t *res, const char *data, size_t length, bool close_connection);
    void uws_res_cork(uws_res_t *res, void (*callback)(uws_res_t *res, void *user_data), void *user_data);
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
    void uws_res_on_writable(uws_res_t *res, uws_res_on_writable_handler handler, void *user_data);
    void uws_res_on_aborted(uws_res_t *res, uws_res_on_aborted_handler handler, void *optional_data);
    void uws_res_on_data(uws_res_t *res, uws_res_on_data_handler handler, void *optional_data);
    void uws_res_upgrade(uws_res_t *res, void *data, const char *sec_web_socket_key, size_t sec_web_socket_key_length, const char *sec_web_socket_protocol, size_t sec_web_socket_protocol_length, const char *sec_web_socket_extensions, size_t sec_web_socket_extensions_length, uws_socket_context_t *ws);

    uws_try_end_result_t uws_res_try_end(uws_res_t *res, const char *data, size_t length, uintmax_t total_size, bool close_connection);
    uintmax_t uws_res_get_write_offset(uws_res_t *res);
    size_t uws_res_get_remote_address(uws_res_t *res, const char **dest);
    size_t uws_res_get_remote_address_as_text(uws_res_t *res, const char **dest);

#pragma endregion
#pragma region uWS-Request

    typedef void (*uws_get_headers_server_handler)(const char *header_name, size_t header_name_size, const char *header_value, size_t header_value_size, void *user_data);

    bool uws_req_is_ancient(uws_req_t *res);
    bool uws_req_get_yield(uws_req_t *res);
    void uws_req_set_yield(uws_req_t *res, bool yield);
    void uws_req_for_each_header(uws_req_t *res, uws_get_headers_server_handler handler, void *user_data);
    size_t uws_req_get_url(uws_req_t *res, const char **dest);
    size_t uws_req_get_full_url(uws_req_t *res, const char **dest);
    size_t uws_req_get_method(uws_req_t *res, const char **dest);
    size_t uws_req_get_case_sensitive_method(uws_req_t *res, const char **dest);
    size_t uws_req_get_header(uws_req_t *res, const char *lower_case_header, size_t lower_case_header_length, const char **dest);
    size_t uws_req_get_query(uws_req_t *res, const char *key, size_t key_length, const char **dest);
    size_t uws_req_get_parameter(uws_req_t *res, unsigned short index, const char **dest);

#pragma endregion

    void uws_loop_defer(struct us_loop_t *loop, void(cb(void *user_data)), void *user_data);
    struct us_loop_t *uws_get_loop();
    struct us_loop_t *uws_get_loop_with_native(void *existing_native_loop);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // uws
