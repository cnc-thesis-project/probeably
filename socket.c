#include <wolfssl/ssl.h>
#include "socket.h"

struct prb_socket {
	int type;
	WOLFSSL ssl;
	int sock;
};

void prb_socket_connect(struct prb_socket *s, char *ip, int port)
{
	int sock;
	int err;
	WOLFSSL_CTX* ctx;
	WOLFSSL *ssl;

	switch s->type {
		case SOCKET_RAW:
			s->sock = prb_socket(AF_INET, SOCK_STREAM, 0);
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			inet_pton(AF_INET, ip, &addr.sin_addr);

			if (connect(s->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				perror("connect");
				return;
			}

			/* TODO: FIX THIS SHIT HAHA */
		case SOCKET_SSL:
			if ( (ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL){
				fprintf(stderr, "wolfSSL_CTX_new error.\n");
				exit(EXIT_FAILURE);
			}

			wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

			if( (ssl = wolfSSL_new(ctx)) == NULL) {
				fprintf(stderr, "wolfSSL_new error.\n");
				exit(EXIT_FAILURE);
			}

			wolfSSL_set_fd(ssl, s->sock);

			err = wolfSSL_connect(ssl);
			if (err != SSL_SUCCESS) {
				char err_buf[80];// TODO: use MAX_ERROR_SZ
				printf("failed connecting to SSL server: %d: %s\n", wolfSSL_get_error(ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, err), err_buf));
				return;
			}
			break;
	}
}

void prb_socket_close(struct prb_socket *s)
{
	switch(s->type) {
		case SOCKET_SSL:
			wolfSSL_shutdown(ssl);
			wolfSSL_CTX_free(ctx);

			/* fallthrough */
		case SOCKET_RAW:
			shutdown(s->sock);
			break;
	}
}

ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count)
{
	switch(s->type) {
		case SOCKET_SSL:
			// todo
			break;
		case SOCKET_RAW:
			return write(s->sock, buf, count);
			break;
	}
}

ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count)
{
	switch(s->type) {
		case SOCKET_SSL:
			// todo
			break;
		case SOCKET_RAW:
			return read(s->sock, buf, count);
			break;
	}
}
