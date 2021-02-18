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

static int test_probe(struct prb_request *r, struct prb_socket *s, char *response, int size)
{
	PRB_DEBUG("module", "Test probing");

	if (prb_socket_connect(s, r->ip, r->port) < 0)
		return -1;

	// hope the server initiates the communication
	size_t total = 0;
	while (total < size - 1) {
		int len = prb_socket_read(s, response + total, size - 1 - total);
		if (len <= 0)
			break;

		total += len;
	}

	if (total <= 0) {
		// probably the client needs to initiate communication
		PRB_DEBUG("module", "Server not initiating communication, sending test request\n");

		char *request = "GET / HTTP/1.1\r\nHost: www\r\n\r\n";
		prb_socket_write(s, request, strlen(request));

		size_t total = 0;
		while (total < size - 1) {
			int len = prb_socket_read(s, response + total, size - 1 - total);
			if (len <= 0)
				break;

			total += len;
		}
	}

	if (total <= 0) {
		// no response at all, boring
		PRB_DEBUG("module", "Got no response from server, cannot identify service\n");

		prb_socket_shutdown(s);
		return 0;
	}

	// got response, return

	response[total] = 0;
	PRB_DEBUG("module", "Got response:\n%s\n", response);

	return total;
}

void run_modules(struct prb_request *r)
{
	struct prb_socket s = {0};
	s.type = PRB_SOCKET_UNKNOWN;
	int app_layer_found = 0;
	char *mod_name = 0;

	char response[1024];
	int response_len = test_probe(r, &s, response, sizeof(response));
	if (response_len < 0)
		return;

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
				PRB_DEBUG("module", "Module '%s' cannot operate on a socket of this type", mod->name);
				// Socket is of the wrong type for this module.
				continue;
			}
		}

		// make sure response from test probing matches the module's protocol
		if (response_len > 0 && mod->check(response, response_len) == -1) {
			PRB_DEBUG("module", "Test probe response did not match with module '%s' protocol\n", mod->name);
			continue;
		}

		// if response length is 0, skip the module if it expects the server to initiate the communication
		if (response_len == 0 && mod->flags & PRB_MODULE_SERVER_INITIATE) {
			PRB_DEBUG("module", "Module '%s' expects the server to initiate the communication, skipping\n", mod->name);
			continue;
		}

		int res = mod->run(&prb, r, &s);

		// This module found the application layer.
		if (!res && mod->flags & PRB_MODULE_IS_APP_LAYER) {
			PRB_DEBUG("module", "Application layer found in module %s", mod->name);
			app_layer_found = 1;
			mod_name = mod->name;
		}
	}

	if (!mod_name) {
		mod_name = "unknown";

		// if it contains anything, save the test probe response
		if (response_len > 0)
			prb_write_data(&prb, r, mod_name, "response", response, response_len, PRB_DB_SUCCESS);
	}

	prb_write_data(&prb, r, "port", "open", mod_name, strlen(mod_name), PRB_DB_SUCCESS);

	PRB_DEBUG("main", "fake probing go brrrrrrrrrrrrr (%s:%d)", r->ip, r->port);
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
		ip_modules[i]->run(&prb, r, 0);
	}

	PRB_DEBUG("main", "fake ip module go brrrrrrrrrrrrr (%s)", r->ip);
}
