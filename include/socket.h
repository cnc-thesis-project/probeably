#ifndef _PROBEABLY_SOCKET_H
#define _PROBEABLY_SOCKET_H
#include <wolfssl/ssl.h>

#define PRB_SOCKET_UNKNOWN (1 << 0)
#define PRB_SOCKET_RAW (1 << 1)
#define PRB_SOCKET_SSL (1 << 2)

struct prb_socket {
	int type;
	WOLFSSL *ssl;
	WOLFSSL_CTX* ctx;
	int sock;
};

void prb_socket_init();
void prb_socket_cleanup();
int prb_socket_connect(struct prb_socket *s, const char *ip, int port);
ssize_t prb_socket_read(struct prb_socket *s, void *buf, size_t count);
ssize_t prb_socket_write(struct prb_socket *s, const void *buf, size_t count);
void prb_socket_shutdown(struct prb_socket *s);

#endif
