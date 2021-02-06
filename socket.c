#include <wolfssl/ssl.h>
#include "probeably.h"
#include "socket.h"

int prb_socket_connect(struct prb_socket *s, char *ip, int port)
{
	PRB_DEBUG("connect", "Initializing connection to %s:%d\n", ip, port);

	int sock;
	int err;
	WOLFSSL_CTX* ctx;
	WOLFSSL *ssl;

	switch (s->type) {
		case PRB_SOCKET_RAW:
			PRB_DEBUG("connect", "Connecting raw socket\n");

			s->sock = socket(AF_INET, SOCK_STREAM, 0);
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			inet_pton(AF_INET, ip, &addr.sin_addr);

			if (connect(s->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
				perror("connect");
				return -1;
			}

			PRB_DEBUG("connect", "Connecting raw socket successful\n");
			break;

			/* TODO: FIX THIS SHIT HAHA */
		case PRB_SOCKET_SSL:
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
				return -1;
			}
			break;
	}

	PRB_DEBUG("connect", "Connection was successful\n");
	return 0;
}

void prb_socket_close(struct prb_socket *s)
{
	switch(s->type) {
		case PRB_SOCKET_SSL:
			wolfSSL_shutdown(s->ssl);
			//wolfSSL_CTX_free(ctx);

			/* fallthrough */
		case PRB_SOCKET_RAW:
			//shutdown(s->sock);
			break;
	}
}

ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count)
{
	PRB_DEBUG("write", "Attempting write\n");
	switch(s->type) {
		case PRB_SOCKET_SSL:
			// todo
			PRB_DEBUG("write", "Writing data to SSL socket\n");
			break;
		case PRB_SOCKET_RAW:
			PRB_DEBUG("write", "Writing data to raw socket\n");
			return write(s->sock, buf, count);
			break;
	}
}

ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count)
{
	switch(s->type) {
		case PRB_SOCKET_SSL:
			// todo
			break;
		case PRB_SOCKET_RAW:
			return read(s->sock, buf, count);
			break;
	}
}
