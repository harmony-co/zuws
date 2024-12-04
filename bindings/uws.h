#pragma once

#include <stddef.h>

#ifndef uws
#define uws

#ifdef __cplusplus
extern "C"
{
#endif
    struct uws_app_s;
    struct uws_req_s;
    struct uws_res_s;
    typedef struct uws_app_s uws_app_t;
    typedef struct uws_req_s uws_req_t;
    typedef struct uws_res_s uws_res_t;

    typedef struct
    {
        int port;
        const char *host;
        int options;
    } uws_app_listen_config_t;

    typedef void (*uws_listen_handler)(struct us_listen_socket_t *listen_socket);
    typedef void (*uws_method_handler)(uws_res_t *response, uws_req_t *request);

    uws_app_t *uws_create_app();
    void uws_app_destroy(uws_app_t *app);
    void uws_app_get(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_post(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_options(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_delete(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_patch(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_put(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_head(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_connect(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_trace(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_any(uws_app_t *app, const char *pattern, uws_method_handler handler);
    void uws_app_run(uws_app_t *);
    void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler);

    void uws_res_end(uws_res_t *res, const char *data, size_t length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // uws
