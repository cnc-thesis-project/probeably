#ifndef _PROBEABLY_SOCKET_H
#define _PROBEABLY_SOCKET_H
#include <wolfssl/ssl.h>

#define PRB_SOCKET_RAW (1 << 0)
#define PRB_SOCKET_SSL (1 << 1)

struct prb_socket {
	int type;
	WOLFSSL *ssl;
	int sock;
};

int prb_socket_connect(struct prb_socket *s, char *ip, int port);
ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count);
ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count);

#endif
