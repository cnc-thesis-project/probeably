#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-ssh.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define SSH_BUFFER_SIZE (16*1024)
static char ssh_buffer[SSH_BUFFER_SIZE];

#define SSH_BANNER "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214\r\n"

static void ssh_module_init(struct probeably *p)
{

}

static void ssh_module_cleanup(struct probeably *p)
{

}

static int ssh_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	PRB_DEBUG("ssh", "Running SSH prober\n");
	int bytes_read = 0;
	int read_len = 0;

	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);
	bytes_read = read_len;

	if (strncmp(ssh_buffer, "SSH", 3)) {
		PRB_DEBUG("ssh", "Not an SSH protocol\n");
		return -1;
	}

	prb_socket_write(s, SSH_BANNER, strlen(SSH_BANNER));
	bytes_read += prb_socket_read(s, &ssh_buffer[read_len], SSH_BUFFER_SIZE - read_len);

	prb_socket_shutdown(s);
	prb_write_data(p, r, "ssh", "response", ssh_buffer, bytes_read, PRB_DB_SUCCESS);
	return 0;
}

struct prb_module module_ssh = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER,
	.name = "ssh",
	.init = ssh_module_init,
	.cleanup = ssh_module_cleanup,
	.run = ssh_module_run,
};
