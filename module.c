#include "module.h"
#include "module-http.h"
#include "module-ssh.h"
#include "module-geoip.h"
#include "module-tls.h"
#include "database.h"

struct probeably prb;

#define NUM_MODULES (sizeof(modules) / sizeof(*modules))
#define NUM_IP_MODULES (sizeof(ip_modules) / sizeof(*ip_modules))

struct prb_module *modules[] = {
	&module_tls,
	&module_http,
	&module_ssh,
};

struct prb_module *ip_modules[] = {
	&module_geoip,
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
	struct prb_socket s = {0};
	s.type = PRB_SOCKET_UNKNOWN;
	for (int i = 0; i < NUM_MODULES; i++) {
		struct prb_module *mod = modules[i];
		if (s.type != PRB_SOCKET_UNKNOWN) {
			if ((s.type == PRB_SOCKET_RAW && mod->flags & PRB_MODULE_REQUIRES_SSL_SOCKET)
			||  (s.type == PRB_SOCKET_SSL && mod->flags & PRB_MODULE_REQUIRES_RAW_SOCKET)) {
				PRB_DEBUG("module", "Module '%s' cannot operate on a socket of this type\n", mod->name);
				// Socket is of the wrong type for this module.
				continue;
			}
		}
			mod->run(&prb, r, &s);
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
	prb_write_data(&prb, r, "port", "open", 0, 0, PRB_DB_SUCCESS);

	for (int i = 0; i < NUM_IP_MODULES; i++) {
		ip_modules[i]->run(&prb, r, 0);
	}

	PRB_DEBUG("main", "fake ip module go brrrrrrrrrrrrr (%s)\n", r->ip);
}

