#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"

#define MODULE_REQUIRES_NEW_CONNECTION (1 << 0)

struct module {
	char *name;
	int flags;
	void (*init)(struct probeable *p);
	void (*cleanup)(struct probeable *p);
	void (*run)(struct probeable *p);
};

#endif
