#if defined(_WIN32)
#include "OTSocket.h"
static int initialization_error;

static BOOL CALLBACK initialize_winsock(PINIT_ONCE once, void *parameter, void **context);

int otsocket_initialize(void)
{
    static INIT_ONCE once;
    InitOnceExecuteOnce(&once, initialize_winsock, NULL, NULL);
    if (initialization_error) errno = otsocket_error(initialization_error);
    return initialization_error ? -1 : 0;
}

static BOOL CALLBACK initialize_winsock(PINIT_ONCE once, void *parameter, void **context)
{
    (void)once; (void)parameter; (void)context;
    WSADATA data;
    initialization_error = WSAStartup(MAKEWORD(2, 2), &data);
    return TRUE;
}

#endif
