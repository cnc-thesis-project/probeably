#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-ssh.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define TELNET_BUFFER_SIZE (16*1024)
static char telnet_buffer[TELNET_BUFFER_SIZE];

/*static char *handle_command(char cmd) {
	(void) cmd;
	// TODO?
}*/

static int telnet_module_check(const char *response, int len)
{
	(void) response;
	(void) len;
	// Always pass module check.
	return 0;
}

static int telnet_module_test(struct probeably *p, struct prb_request *r,
		struct prb_socket *s, char *response, size_t size)
{
	// TODO: how the fuck?
	return 0;
}

static void telnet_module_init(struct probeably *p)
{
	p->ports_to_modules[23] = &module_telnet;
}

static void telnet_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int telnet_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	prb_socket_connect(s, r->ip, r->port);

	int read_len = prb_socket_read(s, telnet_buffer, TELNET_BUFFER_SIZE);
	if (read_len < 0) {
		return -1;
	}

	// Send AYT.
	prb_socket_write(s, "\xff\xf6", 2);

	read_len = prb_socket_read(s, &telnet_buffer[read_len], TELNET_BUFFER_SIZE);
	if (read_len <= 0) {
		return -1;
	}

	// TODO?
	// Handle telnet commands.
	/*int is_cmd = 0;
	int data_idx = 0;
	for (int i = 0; i < read_len; i++) {
		if (telnet_buffer[i] == '\xff') {
			// Treat next byte as command.
			is_cmd = 1;
		}
		else if (is_cmd) {
			handle_command(telnet_buffer[i]);
			is_cmd = 0;
		}
		else {
			data_buffer[data_idx++] = telnet_buffer[i];
		}
	}*/


	prb_write_data(p, r, "telnet", "response", telnet_buffer, read_len, PRB_DB_SUCCESS);

	prb_socket_shutdown(s);
	return 0;
}

struct prb_module module_telnet = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER
		| PRB_MODULE_REQUIRES_TEST_RESPONSE,
	.name = "telnet",
	.init = telnet_module_init,
	.cleanup = telnet_module_cleanup,
	.run = telnet_module_run,
	.check = telnet_module_check,
	.test = telnet_module_test,
};
