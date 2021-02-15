#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"
#include "socket.h"

#define PRB_MODULE_REQUIRES_RAW_SOCKET (1 << 0)
#define PRB_MODULE_REQUIRES_SSL_SOCKET (1 << 1)
#define PRB_MODULE_IS_APP_LAYER        (1 << 2)

struct prb_request {
	char *ip;
	int port;
	int timestamp;
};

extern struct probeably prb;

struct prb_request;

struct prb_module {
	char *name;
	int flags;
	void (*init)(struct probeably *p);
	void (*cleanup)(struct probeably *p);
	int (*run)(struct probeably *p, struct prb_request *r, struct prb_socket *s);
};

void init_modules();
void cleanup_modules();
void run_modules(struct prb_request *r);

void init_ip_modules();
void cleanup_ip_modules();
void run_ip_modules(struct prb_request *r);

#endif
