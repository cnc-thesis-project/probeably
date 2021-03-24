#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-default.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define BUFFER_SIZE (16*1024)
static char buffer[BUFFER_SIZE];

// TODO: What to send?
// Send some data followed by CR LF in hoping that the protocol is text based.
#define PROBE_PACKET "AAAAAAAAAAAAAAAAAAAA\r\nAAAAAAAAAAAAAAAAAAAAAAAA\r\nAAAAAAAAAAA\r\n"

static int default_module_check(const char *response, int len)
{
	(void) response;
	(void) len;

	// Always pass module check.
	return 0;
}

static int default_module_test(struct probeably *p, struct prb_request *r,
		struct prb_socket *s, char *response, size_t size)
{
	(void) p;
	(void) r;
	(void) s;
	(void) response;
	(void) size;

	// TODO: how the fuck?
	return 0;
}

static void default_module_init(struct probeably *p)
{
	(void) p;
}

static void default_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int default_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	int result;

	result = prb_socket_connect(s, r->ip, r->port);
	if (result < 0) {
		return -1;
	}
	size_t read_len = 0;
	prb_socket_write(s, PROBE_PACKET, strlen(PROBE_PACKET));
	while (read_len < sizeof(buffer) && (result = prb_socket_read(s, buffer, sizeof(buffer) - read_len)) > 0) {
		read_len += result;
	}

	prb_write_data(p, r, "unknown", "response", buffer, read_len, PRB_DB_SUCCESS);
	prb_socket_shutdown(s);

	return 0;
}

struct prb_module module_default = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER
		| PRB_MODULE_REQUIRES_TEST_RESPONSE,
	.name = "default",
	.init = default_module_init,
	.cleanup = default_module_cleanup,
	.run = default_module_run,
	.check = default_module_check,
	.test = default_module_test,
};
