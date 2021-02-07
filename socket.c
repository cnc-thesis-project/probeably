#include <wolfssl/ssl.h>
#include <fcntl.h>
#include <sys/time.h>
#include "probeably.h"
#include "socket.h"

#define TIMEOUT 3

char err_buf[80];// TODO: use MAX_ERROR_SZ

void prb_socket_init()
{
	wolfSSL_Init();
}

void prb_socket_cleanup()
{
	wolfSSL_Cleanup();
}

static int connect_raw(struct prb_socket *s, char *ip, int port)
{
	int sock;
	int err;
	PRB_DEBUG("connect", "Connecting raw socket\n");
	s->sock = socket(AF_INET, SOCK_STREAM, 0);
	fcntl(s->sock, F_SETFL, fcntl(s->sock, F_GETFL, 0) | O_NONBLOCK);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	while (( err = connect(s->sock, (struct sockaddr *) &addr, sizeof(addr))) & EINPROGRESS & EALREADY & EAGAIN);
	if (err < 0) {
		perror("connect");
		return -1;
	}

	PRB_DEBUG("connect", "Connecting raw socket successful\n");
	return 0;
}

int prb_socket_connect(struct prb_socket *s, char *ip, int port)
{
	PRB_DEBUG("connect", "Initializing connection to %s:%d\n", ip, port);

	connect_raw(s, ip, port);

	int err;
	WOLFSSL_CTX* ctx;
	wolfSSL_CTX_set_timeout(ctx, TIMEOUT);

	if (s->type == PRB_SOCKET_SSL || s->type == PRB_SOCKET_UNKNOWN) {
		PRB_DEBUG("connect", "Attempting to perform SSL handshake\n");
		if ( (ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL){
			fprintf(stderr, "wolfSSL_CTX_new error.\n");
			exit(EXIT_FAILURE);
		}

		wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

		if( (s->ssl = wolfSSL_new(ctx)) == NULL) {
			fprintf(stderr, "wolfSSL_new error.\n");
			exit(EXIT_FAILURE);
		}

		wolfSSL_set_using_nonblock(s->ssl, 1);
		wolfSSL_set_timeout(s->ssl, TIMEOUT);

		wolfSSL_set_fd(s->ssl, s->sock);

		struct timeval start_time, end_time;
		gettimeofday(&start_time, NULL);
		while ((err = wolfSSL_connect(s->ssl)) & SSL_ERROR_WANT_READ & SSL_ERROR_WANT_WRITE) {
			gettimeofday(&end_time, NULL);
			if ((end_time.tv_sec - start_time.tv_sec) > TIMEOUT) {
				break;
			}
		}
		if (err != SSL_SUCCESS) {
			PRB_DEBUG("connect", "SSL handshake failed\n");
			printf("failed connecting to SSL server: %d: %s\n", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
			if(connect_raw(s, ip, port) < 0) {
				return -1;
			}
			fcntl(s->sock, F_SETFL, fcntl(s->sock, F_GETFL, 0) & ~O_NONBLOCK);
			s->type = PRB_SOCKET_RAW;
			return 0;
		}
		s->type = PRB_SOCKET_SSL;
		PRB_DEBUG("connect", "SSL handshake was successful\n");
		wolfSSL_set_using_nonblock(s->ssl, 0);
	}

	fcntl(s->sock, F_SETFL, fcntl(s->sock, F_GETFL, 0) & ~O_NONBLOCK);

	PRB_DEBUG("connect", "Connection was successful\n");
	return 0;
}

void prb_socket_close(struct prb_socket *s)
{
	switch(s->type) {
		case PRB_SOCKET_SSL:
			wolfSSL_shutdown(s->ssl);
			//wolfSSL_CTX_free(ctx);

		case PRB_SOCKET_RAW:
			//shutdown(s->sock);
			break;
	}
}

ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count)
{
	int err;
	switch(s->type) {
		case PRB_SOCKET_SSL:
			PRB_DEBUG("write", "Writing data to SSL socket\n");
			err = wolfSSL_write(s->ssl, buf, (int) count);
			if (err < 0) {
				printf("Failed writing to SSL socket: %d: %s\n", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
				return -1;
			}
			break;
		case PRB_SOCKET_RAW:
			PRB_DEBUG("write", "Writing data to raw socket\n");
			return write(s->sock, buf, count);
			break;
		default:
			return -1;
	}
}

ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count)
{
	int err;
	switch(s->type) {
		case PRB_SOCKET_SSL:
			PRB_DEBUG("read", "Reading data from SSL socket\n");
			err = wolfSSL_read(s->ssl, buf, (int) count);
			if (err < 0) {
				printf("Failed reading from SSL socket: %d: %s\n", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
				return -1;
			}
			break;
		case PRB_SOCKET_RAW:
			PRB_DEBUG("read", "Reading data from raw socket\n");
			err = read(s->sock, buf, count);
			if (err < 0) {
				perror("read");
				return -1;
			}
			break;
	}
}
