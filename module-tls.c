#include <stdio.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <sys/wait.h>
#include "module.h"
#include "module-tls.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

static int tls_module_check(const char *response, int len)
{
	// whether the tls module should run or not is decided based on sock type
	return 0;
}

static void tls_module_init(struct probeably *p)
{

}

static void tls_module_cleanup(struct probeably *p)
{

}

static int tls_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	int bytes_read = 0;

	PRB_DEBUG("tls", "Grabbing certificate");
	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}
	WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(s->ssl);

	if (!cert) {
		PRB_DEBUG("tls", "Failed grabbing peer certificate");
		return -1;
	}

	int der_len = 0;
	const unsigned char *der_cert = wolfSSL_X509_get_der(cert, &der_len);

	prb_write_data(p, r, "tls", "certificate", der_cert, der_len, PRB_DB_SUCCESS);

	if (!der_cert) {
		PRB_DEBUG("tls", "Failed getting peer certificate in DER format");
		return -1;
	}

	PRB_DEBUG("tls", "Running JARM");

	int pfd[2];
	if (pipe(pfd)) {
		PRB_ERROR("tls", "Failed creating pipe: %s", strerror(errno));
		return -1;
	}

	char jarm_hash[64] = {0};
	pid_t jarm_pid = fork();
	switch (jarm_pid) {
		case -1:
			close(pfd[0]);
			close(pfd[1]);
			PRB_ERROR("tls", "Failed forking JARM process: %s", strerror(errno));
			return -1;
		case 0:
			close(pfd[0]);
			dup2(pfd[1], 1);
			dup2(pfd[1], 2);
			char jarm_cmd[256];
			snprintf(jarm_cmd, 256, "python3 ./jarm/jarm.py -s -p %d %s", r->port, r->ip);
			int res = system(jarm_cmd);
			exit(EXIT_SUCCESS);
		default:
			close(pfd[1]);
			int size = read(pfd[0], jarm_hash, 62);
			if (size != 62) {
				PRB_ERROR("tls", "Failed getting JARM hash: %s", jarm_hash);
				return -1;
			}
			jarm_hash[62] = '\0';
			close(pfd[0]);
			waitpid(jarm_pid, NULL, 0);
	}

	PRB_DEBUG("tls", "JARM hash for %s:%d: %s", r->ip, r->port, jarm_hash);

	prb_write_data(p, r, "tls", "jarm", jarm_hash, 63, PRB_DB_SUCCESS);

	return 0;
}

struct prb_module module_tls = {
	.name = "tls",
	.flags = PRB_MODULE_REQUIRES_SSL_SOCKET,
	.init = tls_module_init,
	.cleanup = tls_module_cleanup,
	.run = tls_module_run,
	.check = tls_module_check,
};
