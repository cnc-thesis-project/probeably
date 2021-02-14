#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-tls.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

static void tls_module_init(struct probeably *p)
{

}

static void tls_module_cleanup(struct probeably *p)
{

}

static int tls_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	PRB_DEBUG("tls", "Running TLS prober\n");
	int bytes_read = 0;

	PRB_DEBUG("tls", "Grabbing certificate\n");
	/*if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);*/

	PRB_DEBUG("tls", "Running JARM\n");

	char jarm_cmd[512];
	// TODO: do not use relative path
	snprintf(jarm_cmd, 512, "python ./jarm/jarm.py -p %d %s", r->port, r->ip);
	system(jarm_cmd);

	return 0;
}

struct prb_module module_tls = {
	.name = "tls",
	.flags = PRB_MODULE_REQUIRES_SSL_SOCKET,
	.init = tls_module_init,
	.cleanup = tls_module_cleanup,
	.run = tls_module_run,
};
