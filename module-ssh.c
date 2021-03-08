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

static const char key_exchange[48] =
	// ssh packet length
	"\x00\x00\x00\x2c"
	// ssh padding length
	"\x06"
	// key exchange method something
	"\x1e"
	// size of something (random number?)
	"\x00\x00\x00\x20"
	// 32 bytes random number? (made in /dev/random)
	"\x8e\xd4\xc3\x70\xe6\x97\x61\x78\x8b\xfe\xcf\x7f\xa3\xf2\xe4\x54"
	"\xd7\x7a\xaf\x3b\x87\x22\x92\x66\xd6\xc4\x6a\xe2\xca\x5a\x77\x81"
	// padding
	"\x00\x00\x00\x00\x00\x00";

static int ssh_module_check(const char *response, int len)
{
	(void) len;
	if (strncmp(response, "SSH-", 4))
		return -1;
	return 0;
}

static void ssh_module_init(struct probeably *p)
{
	(void) p;
}

static void ssh_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int ssh_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	int read_len = 0;

	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);

	if (ssh_module_check(ssh_buffer, read_len)) {
		PRB_ERROR("ssh", "Not an SSH protocol");
		prb_socket_shutdown(s);
		return -1;
	}

	int string_len = 0;
	for (int i = 0; i < read_len; i++) {
		if (ssh_buffer[i] == '\r') {
			ssh_buffer[i] = '\0';
			string_len = i;
		}
	}

	prb_write_data(p, r, "ssh", "string", ssh_buffer, string_len, PRB_DB_SUCCESS);

	// Check if we need to read again to get the ciphers list
	char *ciphers;
	int ciphers_len;
	// + 2 for CR LF
	if (string_len + 2 == read_len) {
		PRB_DEBUG("ssh", "Reading ciphers");
		prb_socket_write(s, SSH_BANNER, strlen(SSH_BANNER));
		read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);
		ciphers = ssh_buffer;
		ciphers_len = read_len;
	} else {
		ciphers = &ssh_buffer[string_len + 2];
		ciphers_len = read_len - string_len - 2;
		PRB_DEBUG("ssh", "Ciphers packet of size %d already received, presumably...", ciphers_len);
	}

	prb_write_data(p, r, "ssh", "ciphers", ciphers, ciphers_len, PRB_DB_SUCCESS);

	// resend servers cipher list
	prb_socket_write(s, ciphers, ciphers_len);

	// key exchange, pretty useless but necessary to get public key from the server
	prb_socket_write(s, key_exchange, sizeof(key_exchange));
	read_len = prb_socket_read(s, ssh_buffer, SSH_BUFFER_SIZE);
	prb_socket_shutdown(s);

	prb_write_data(p, r, "ssh", "keys", ssh_buffer, read_len, PRB_DB_SUCCESS);

	return 0;
}

struct prb_module module_ssh = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER
		| PRB_MODULE_REQUIRES_TEST_RESPONSE,
	.name = "ssh",
	.init = ssh_module_init,
	.cleanup = ssh_module_cleanup,
	.run = ssh_module_run,
	.check = ssh_module_check,
};
