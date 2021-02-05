#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeable.h"

struct module {
	char *name;
	void (*init)(struct probeable *p);
	void (*cleanup)(struct probeable *p);
	void (*run)(struct probeable *p);
};

#endif
