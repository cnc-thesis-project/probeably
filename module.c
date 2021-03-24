#include "module.h"
#include "module-http.h"
#include "module-ssh.h"
#include "module-geoip.h"
#include "module-rdns.h"
#include "module-tls.h"
#include "module-default.h"
#include "database.h"


const char *worker_status_color[] = {
	"",
	"\x1b[41m",
	"\x1b[42m",
	"\x1b[43m",
	"\x1b[44m",
	"\x1b[45m",
	"\x1b[46m",
	"\x1b[47m\x1b[30m",
};

const char *worker_status_name[] = {
	"IDLE",
	"BUSY",
	"DB_WRITE",
	"SOCKET_CON",
	"SOCKET_WRITE",
	"SOCKET_READ",
	"CON_WAIT",
	"LOCK",
};

#define NUM_MODULES (int)(sizeof(modules) / sizeof(*modules))
#define NUM_IP_MODULES (int)(sizeof(ip_modules) / sizeof(*ip_modules))

static struct prb_module *modules[] = {
	&module_tls,
	&module_http,
	&module_ssh,

	// This module needs to be placed last since it is designed
	// to always pass the protocol check.
	// This has the effect that it will always run in order to perhaps
	// get at least some data from the host.
	&module_default,
};

// Default module to use for test probing to find out the protocol.
// Should this really be the HTTP mod???
static struct prb_module *default_test_module = &module_http;

static struct prb_module *ip_modules[] = {
	&module_geoip,
	&module_rdns,
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

void run_modules(struct probeably *p, struct prb_request *r)
{
	struct prb_socket s = {0};
	s.type = PRB_SOCKET_UNKNOWN;
	int app_layer_found = 0;

	char response[1024];
	struct prb_module *test_module = default_test_module;
	struct prb_module *guess_module = p->ports_to_modules[r->port];
	if (guess_module) {
		test_module = guess_module;
	}
	int response_len = test_module->test(p, r, &s, response, sizeof(response));
	if (response_len < 0) {
		prb_write_data(&prb, r, "port", "closed", 0, 0, 0);
		return;
	}

	for (int i = 0; i < NUM_MODULES; i++) {
		struct prb_module *mod = modules[i];

		// We have already found the application layer on this port.
		if (app_layer_found && mod->flags & PRB_MODULE_IS_APP_LAYER) {
			PRB_DEBUG("module", "Application layer found. Skipping module %s", mod->name);
			continue;
		}

		if (s.type != PRB_SOCKET_UNKNOWN) {
			if ((s.type == PRB_SOCKET_RAW && mod->flags & PRB_MODULE_REQUIRES_SSL_SOCKET)
			||  (s.type == PRB_SOCKET_SSL && mod->flags & PRB_MODULE_REQUIRES_RAW_SOCKET)) {
				// Socket is of wrong type for this module.
				PRB_DEBUG("module", "Module '%s' cannot operate on a socket of this type", mod->name);
				continue;
			}
		}

		// make sure response from test probing matches the module's protocol
		if (response_len > 0 && mod->check(response, response_len) == -1) {
			PRB_DEBUG("module", "Test probe response did not match with module '%s'", mod->name);
			continue;
		}

		// if response length is 0, skip the module if it expects the server to initiate the communication
		if (response_len == 0 && mod->flags & PRB_MODULE_REQUIRES_TEST_RESPONSE) {
			PRB_DEBUG("module", "Module '%s' expects response from test probing, skipping", mod->name);
			continue;
		}

		PRB_DEBUG("module", "Running module '%s'", mod->name);
		int res = mod->run(p, r, &s);
		if (res == 0)
			PRB_DEBUG("module", "Succeeded running module '%s'", mod->name);
		else
			PRB_ERROR("module", "Module '%s' returned with error %d", mod->name, res);

		// This module found the application layer.
		if (!res && mod->flags & PRB_MODULE_IS_APP_LAYER) {
			PRB_DEBUG("module", "Application layer found in module %s", mod->name);
			app_layer_found = 1;
		}
	}

	// TODO: Is this required?
	//prb_write_data(&prb, r, "port", "open", mod_name, strlen(mod_name), PRB_DB_SUCCESS);
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

void run_ip_modules(struct probeably *p, struct prb_request *r)
{
	(void) p;

	for (int i = 0; i < NUM_IP_MODULES; i++) {
		struct prb_module *mod = ip_modules[i];

		PRB_DEBUG("module", "Running module '%s'", mod->name);

		int res = mod->run(p, r, 0);
		if (res == 0)
			PRB_DEBUG("module", "Succeeded running module '%s'", mod->name);
		else
			PRB_ERROR("module", "Module '%s' returned with error %d", mod->name, res);
	}
}
