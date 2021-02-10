#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sha.h>
#include "module.h"
#include "module-ssh.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define SSH_BUFFER_SIZE 512
static char ssh_buffer[SSH_BUFFER_SIZE];
static void ssh_module_init(struct probeably *p)
{

}

static void ssh_module_cleanup(struct probeably *p)
{

}

static int ssh_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	int len;
	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE - 1);
	ssh_buffer[len] = '\0';

	if (strncmp(ssh_buffer, "SSH", 3)) {
		PRB_DEBUG("ssh", "Not an SSH protocol");
		return -1;
	}

	PRB_DEBUG("ssh", "SSH banner: '%s'\n", ssh_buffer);

	prb_socket_write(s, ssh_buffer, len);
	len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE - 1);
	ssh_buffer[len] = '\0';

	PRB_DEBUG("ssh", "SSH ciphers: '%s'\n", ssh_buffer + 26);

	prb_socket_shutdown(s);
	return 0;
}

struct prb_module module_ssh = {
	.init = ssh_module_init,
	.cleanup = ssh_module_cleanup,
	.run = ssh_module_run,
};
