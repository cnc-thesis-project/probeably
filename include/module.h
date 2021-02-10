#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"
#include "socket.h"

#define PRB_MODULE_REQUIRES_RAW_SOCKET (1 << 0)

struct prb_request {
	char *ip;
	int port;
	int timestamp;
};

struct prb_module {
	char *name;
	int flags;
	void (*init)(struct probeably *p);
	void (*cleanup)(struct probeably *p);
	int (*run)(struct probeably *p, struct prb_request *r, struct prb_socket *s);
};

#endif
