#include <stdio.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include "module.h"
#include "module-tls.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"
#include "config.h"

extern char **environ;

static pid_t jarm_pid = 0;

static int tls_module_check(const char *response, int len)
{
	(void) response;
	(void) len;
	// whether the tls module should run or not is decided based on sock type
	return 0;
}

static void tls_module_init(struct probeably *p)
{
	(void) p;

	jarm_pid = fork();
	if (jarm_pid == -1) {
		PRB_ERROR("tls", "Failed forking JARM process: %s", strerror(errno));
		return;
	} else if (jarm_pid == 0) {
		char jarm_workers_str[8];
		snprintf(jarm_workers_str, sizeof(jarm_workers_str), "%d", prb_config.jarm_workers);
		char *jarm_argv[] = {prb_config.jarm_script, prb_config.jarm_socket, jarm_workers_str, 0};

		PRB_INFO("tls", "Starting JARM process");
		execve(jarm_argv[0], jarm_argv, environ);

		// reached only when execve fails
		PRB_ERROR("tls", "failed to execve JARM process: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	sleep(1);
	if (waitpid(jarm_pid, NULL, WNOHANG) != 0) {
		PRB_ERROR("tls", "JARM process not alive, exiting");
		exit(EXIT_FAILURE);
	}
}

static void tls_module_cleanup(struct probeably *p)
{
	(void) p;
	if (WORKER_INDEX == -1) {
		kill(jarm_pid, SIGTERM);
	}
}

static int tls_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	PRB_DEBUG("tls", "Grabbing certificate");
	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}
	WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(s->ssl);
	if (!cert) {
		PRB_DEBUG("tls", "Failed grabbing peer certificate");
		prb_socket_shutdown(s);
		return -1;
	}

	int der_len = 0;
	const unsigned char *der_cert = wolfSSL_X509_get_der(cert, &der_len);

	if (!der_cert) {
		PRB_DEBUG("tls", "Failed getting peer certificate in DER format");
		wolfSSL_X509_free(cert);
		prb_socket_shutdown(s);
		return -1;
	}

	prb_write_data(p, r, "tls", "certificate", der_cert, der_len, PRB_DB_SUCCESS);
	wolfSSL_X509_free(cert);
	prb_socket_shutdown(s);

	PRB_DEBUG("tls", "Running JARM");

	int sd;
	struct sockaddr_un addr;

	if ((sd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		PRB_ERROR("tls", "Error creating socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", prb_config.jarm_socket);

	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		PRB_ERROR("ipc", "Failed to connect to JARM socket");
		close(sd);
		return -1;
	}

	char ip_port[64] = {0};
	char jarm_hash[64] = {0};

	snprintf(ip_port, sizeof(ip_port), "%s %d", r->ip, r->port);
	send(sd, ip_port, strlen(ip_port), 0);
	recv(sd, jarm_hash, sizeof(jarm_hash), 0);

	close(sd);

	PRB_DEBUG("tls", "JARM hash for %s:%d: %s", r->ip, r->port, jarm_hash);

	prb_write_data(p, r, "tls", "jarm", jarm_hash, 62, PRB_DB_SUCCESS);

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
