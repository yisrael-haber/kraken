#include "lwip/etharp.h"
#include "lwip/netifapi.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include <errno.h>

static inline int kraken_lwip_errno(void) { return errno; }
