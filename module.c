#include "module.h"

struct probeably prb;

#define NUM_MODULES (sizeof(modules) / sizeof(*modules))
#define NUM_IP_MODULES (sizeof(ip_modules) / sizeof(*ip_modules))

struct prb_module *modules[] = {
	&module_http,
};

struct prb_module *ip_modules[] = {
};

void init_modules()
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->init(&prb);
	}
}

void cleanup_modules()
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->cleanup(&prb);
	}
}

void run_modules(struct prb_request *r)
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->run(&prb, r);
	}

	PRB_DEBUG("main", "fake probing go brrrrrrrrrrrrr (%s:%d)\n", r->ip, r->port);
}

void init_ip_modules()
{
	for (int i = 0; i < NUM_IP_MODULES; i++) {
		ip_modules[i]->init(&prb);
	}
}

void cleanup_ip_modules()
{
	for (int i = 0; i < NUM_IP_MODULES; i++) {
		ip_modules[i]->cleanup(&prb);
	}
}

void run_ip_modules(struct prb_request *r)
{
	for (int i = 0; i < NUM_IP_MODULES; i++) {
		ip_modules[i]->run(&prb, r);
	}

	PRB_DEBUG("main", "fake ip module go brrrrrrrrrrrrr (%s)\n", r->ip);
}

