#include "uws.h"

#include "../uWebSockets/src/App.h"

uws_app_t *uws_create_app()
{
    return (uws_app_t *)new uWS::App();
}

void uws_app_destroy(uws_app_t *app)
{
    uWS::App *uwsApp = (uWS::App *)app;
    delete uwsApp;
}

void uws_app_get(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->get(pattern, [handler](auto *res, auto *req)
                { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_post(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->post(pattern, [handler](auto *res, auto *req)
                 { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_options(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->options(pattern, [handler](auto *res, auto *req)
                    { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_delete(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->del(pattern, [handler](auto *res, auto *req)
                { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_patch(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->patch(pattern, [handler](auto *res, auto *req)
                  { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_put(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->put(pattern, [handler](auto *res, auto *req)
                { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_head(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->head(pattern, [handler](auto *res, auto *req)
                 { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_connect(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->connect(pattern, [handler](auto *res, auto *req)
                    { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_trace(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->trace(pattern, [handler](auto *res, auto *req)
                  { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_any(uws_app_t *app, const char *pattern, uws_method_handler handler)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->any(pattern, [handler](auto *res, auto *req)
                { handler((uws_res_t *)res, (uws_req_t *)req); });
}

void uws_app_run(uws_app_t *app)
{
    uWS::App *uwsApp = (uWS::App *)app;
    uwsApp->run();
}

void uws_app_listen(uws_app_t *app, int port, uws_listen_handler handler)
{
    uws_app_listen_config_t config;
    config.port = port;
    config.host = nullptr;
    config.options = 0;

    uWS::App *uwsApp = (uWS::App *)app;

    uwsApp->listen(port, [handler, config](struct us_listen_socket_t *listen_socket)
                   { handler((struct us_listen_socket_t *)listen_socket); });
}

void uws_res_end(uws_res_t *res, const char *data, size_t length)
{
    uWS::HttpResponse<false> *uwsRes = (uWS::HttpResponse<false> *)res;
    uwsRes->end(std::string_view(data, length), false);
}