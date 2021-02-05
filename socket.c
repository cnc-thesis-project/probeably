#include <wolfssl/ssl.h>
#include "socket.h"

struct socket {
	int type;
	union {
		WOLFSSL s_ssl;
		int s_raw;
	};
};

write(struct socket, const void *buf, size_t count) {

}

read(struct socket, void *buf, size_t count) {

}

#endif
