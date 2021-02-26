/*
 * TODO: Do internal buffering in the read and write routines.
 */

#include <wolfssl/ssl.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdlib.h>
#include "probeably.h"
#include "config.h"
#include "log.h"
#include "socket.h"

#define TIMEOUT 15

char err_buf[80];// TODO: use MAX_ERROR_SZ

void prb_socket_init()
{
	wolfSSL_Init();
}

void prb_socket_cleanup()
{
	wolfSSL_Cleanup();
}

static int connect_raw(struct prb_socket *s, const char *ip, int port)
{
	int err;
	PRB_DEBUG("socket", "Connecting raw socket");
	s->sock = socket(AF_INET, SOCK_STREAM, 0);

	int read_timeout = prb_config.read_timeout;
	int write_timeout = prb_config.write_timeout;

	struct timeval read_timeout_val = {
		.tv_sec = read_timeout,
		.tv_usec = 0,
	};
	
	struct timeval write_timeout_val = {
		.tv_sec = write_timeout,
		.tv_usec = 0,
	};

	if (setsockopt (s->sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout_val, sizeof(read_timeout_val)) < 0) {
		PRB_ERROR("socket", "Failed setting receive timeout: %s", strerror(errno));
		close(s->sock);
		return -1;
	}

    if (setsockopt (s->sock, SOL_SOCKET, SO_SNDTIMEO, &write_timeout_val, sizeof(write_timeout_val)) < 0) {
		PRB_ERROR("socket", "Failed setting send timeout: %s", strerror(errno));
		close(s->sock);
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	err = connect(s->sock, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		PRB_ERROR("socket", "Connection failed: %s", strerror(errno));
		close(s->sock);
		return -1;
	}

	PRB_DEBUG("socket", "Connecting raw socket successful");
	return 0;
}

int prb_socket_connect(struct prb_socket *s, const char *ip, int port)
{
	PRB_DEBUG("socket", "Initializing connection to %s:%d", ip, port);

	if (connect_raw(s, ip, port) == -1) {
		return -1;
	}

	int err;

	if (s->type == PRB_SOCKET_SSL || s->type == PRB_SOCKET_UNKNOWN) {
		PRB_DEBUG("socket", "Attempting to perform SSL handshake");
		if ( (s->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL){
			PRB_ERROR("socket", "Failed creating WolfSSL context");
			exit(EXIT_FAILURE);
		}

		wolfSSL_CTX_set_timeout(s->ctx, TIMEOUT);
		wolfSSL_CTX_set_verify(s->ctx, SSL_VERIFY_NONE, 0);

		if( (s->ssl = wolfSSL_new(s->ctx)) == NULL) {
			PRB_ERROR("socket", "Failed initiating WolfSSL");
			exit(EXIT_FAILURE);
		}

		wolfSSL_set_timeout(s->ssl, TIMEOUT);

		wolfSSL_set_fd(s->ssl, s->sock);

		err = wolfSSL_connect(s->ssl);
		if (err != SSL_SUCCESS) {
			PRB_ERROR("socket", "SSL handshake failed: %d: %s", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
			wolfSSL_CTX_free(s->ctx);
			wolfSSL_free(s->ssl);
			shutdown(s->sock, SHUT_RDWR);
			close(s->sock);
			if(connect_raw(s, ip, port) < 0) {
				return -1;
			}
			s->type = PRB_SOCKET_RAW;
			return 0;
		}
		s->type = PRB_SOCKET_SSL;
		PRB_DEBUG("socket", "SSL handshake was successful");
	}

	PRB_DEBUG("socket", "Connection was successful");
	return 0;
}

void prb_socket_shutdown(struct prb_socket *s)
{
	switch(s->type) {
		case PRB_SOCKET_SSL:
			PRB_DEBUG("socket", "Shutting down SSL socket");
			wolfSSL_shutdown(s->ssl);
			wolfSSL_CTX_free(s->ctx);
			wolfSSL_free(s->ssl);
			/* fallthrough */
		case PRB_SOCKET_RAW:
			PRB_DEBUG("socket", "Shutting down raw socket");
			shutdown(s->sock, SHUT_RDWR);
			close(s->sock);
			break;
	}
}

ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count)
{
	int err;
	switch(s->type) {
		case PRB_SOCKET_SSL:
			PRB_DEBUG("socket", "Writing data to SSL socket");
			err = wolfSSL_write(s->ssl, buf, (int) count);
			if (err < 0) {
				PRB_ERROR("socket", "Failed writing to SSL socket: %d: %s", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
				return -1;
			}
			PRB_DEBUG("socket", "Wrote %d bytes to SSL socket", err);
			return err;
		case PRB_SOCKET_RAW:
			PRB_DEBUG("socket", "Writing data to raw socket");
			PRB_DEBUG("socket", "sock=%d, buf=%.4s, buf_addr=%p, count=%d", s->sock, buf, buf, count);
			//err = write(s->sock, buf, count);
			err = send(s->sock, buf, count, MSG_NOSIGNAL);
			if (err < 0) {
				PRB_ERROR("socket", "Error writing to socket: %s", strerror(errno));
				return -1;
			}
			PRB_DEBUG("socket", "Wrote %d bytes to raw socket", err);
			return err;
		default:
			return -1;
	}
}

ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count)
{
	int err;
	switch(s->type) {
		case PRB_SOCKET_SSL:
			PRB_DEBUG("socket", "Reading data from SSL socket");
			err = wolfSSL_recv(s->ssl, buf, (int) count, 0);
			if (err < 0) {
				PRB_ERROR("socket", "Failed reading from SSL socket: %d: %s", wolfSSL_get_error(s->ssl, err), wolfSSL_ERR_error_string(wolfSSL_get_error(s->ssl, err), err_buf));
				return -1;
			}
			PRB_DEBUG("socket", "Read %d bytes from SSL socket", err);
			return err;
		case PRB_SOCKET_RAW:
			PRB_DEBUG("socket", "Reading data from raw socket");
			err = read(s->sock, buf, count);
			if (err < 0) {
				PRB_ERROR("socket", "Failed reading from raw socket: %s", strerror(errno));
				return -1;
			}
			PRB_DEBUG("socket", "Read %d bytes from raw socket", err);
			return err;
		default:
			return -1;
	}
}
