#include "uWebSockets/src/App.h"
#include "uWS.h"

extern "C"
{
    uWS::App uws_app() { return uWS::App(); }
}