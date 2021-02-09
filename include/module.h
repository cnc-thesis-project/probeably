#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"

#define MODULE_REQUIRES_NEW_CONNECTION (1 << 0)

struct prb_module {
	char *name;
	int flags;
	void (*init)(struct probeably *p);
	void (*cleanup)(struct probeably *p);
	int (*run)(struct probeably *p, char *ip, int port);
};

#endif
