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

	int pfd[2];
	if (pipe(pfd)) {
		PRB_DEBUG("tls", "Failed creating pipe\n");
		return -1;
	}

	char jarm_hash[64] = {0};
	int jarm_pid = fork();
	switch (jarm_pid) {
		case -1:
			close(pfd[0]);
			close(pfd[1]);
			PRB_DEBUG("tls", "Failed fork\n");
			return -1;
		case 0:
			close(pfd[0]);
			dup2(pfd[1], 1);
			dup2(pfd[1], 2);
			char jarm_cmd[256];
			snprintf(jarm_cmd, 512, "python ./jarm/jarm.py -s -p %d %s", r->port, r->ip);
			system(jarm_cmd);
			exit(EXIT_SUCCESS);
		default:
			sleep(3);
			close(pfd[1]);
			int size = read(pfd[0], jarm_hash, 62);
			if (size != 62) {
				PRB_DEBUG("tls", "Failed getting JARM hash: %s\n", jarm_hash);
				return -1;
			}
			jarm_hash[62] = '\0';
			close(pfd[0]);
	}

	PRB_DEBUG("tls", "JARM hash for %s:%d: %s\n", r->ip, r->port, jarm_hash);

	return 0;
}

struct prb_module module_tls = {
	.name = "tls",
	.flags = PRB_MODULE_REQUIRES_SSL_SOCKET,
	.init = tls_module_init,
	.cleanup = tls_module_cleanup,
	.run = tls_module_run,
};
