#include <stdio.h>
#include <wolfssl/ssl.h>
#include "module-tls.h"
#include "module.h"
#include "probeable.h"



static void tls_module_init(struct probeable *p)
{
	wolfSSL_Init();
}

static void tls_module_cleanup(struct probeable *p)
{
	wolfSSL_Cleanup();
}

static void tls_module_run(struct probeable *p)
{

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	inet_pton(AF_INET, "192.168.1.1", &addr.sin_addr);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	WOLFSSL_CTX* ctx;
	if ( (ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL){
		fprintf(stderr, "wolfSSL_CTX_new error.\n");
		exit(EXIT_FAILURE);
	}

	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

	WOLFSSL *ssl;
	if( (ssl = wolfSSL_new(ctx)) == NULL) {
		fprintf(stderr, "wolfSSL_new error.\n");
		exit(EXIT_FAILURE);
	}

	wolfSSL_set_fd(ssl, sock);

	int err = wolfSSL_connect(ssl);
	if (err == SSL_SUCCESS) {
		printf("successfully connected to SSL server.\n");
	} else {
		char err_buf[80];// TODO: use MAX_ERROR_SZ
		printf("failed connecting to SSL server: %d: %s\n", wolfSSL_get_error(ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, err), err_buf));
	}

	wolfSSL_shutdown(ssl);
	wolfSSL_CTX_free(ctx);
}

struct module module_tls = {
	.init = tls_module_init,
	.cleanup = tls_module_cleanup,
	.run = tls_module_run,
};
