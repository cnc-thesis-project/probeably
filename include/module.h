#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"
#include "module-http.h"

#define MODULE_REQUIRES_NEW_CONNECTION (1 << 0)

extern struct probeably prb;

struct prb_request;

struct prb_module {
	char *name;
	int flags;
	void (*init)(struct probeably *p);
	void (*cleanup)(struct probeably *p);
	int (*run)(struct probeably *p, struct prb_request *r);
};

struct prb_request {
	char *ip;
	int port;
	int timestamp;
};

void init_modules();
void cleanup_modules();
void run_modules(struct prb_request *r);

void init_ip_modules();
void cleanup_ip_modules();
void run_ip_modules(struct prb_request *r);

#endif
