#include "uWebSockets/src/App.h"
#include "uWSZig.h"

void *uws_app() { return new uWS::App(); }
