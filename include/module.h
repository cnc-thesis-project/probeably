#ifndef _PROBEABLY_MODULE_H
#define _PROBEABLY_MODULE_H
#include "probeably.h"
#include "socket.h"

#define PRB_MODULE_REQUIRES_RAW_SOCKET    (1 << 0)
#define PRB_MODULE_REQUIRES_SSL_SOCKET    (1 << 1)
#define PRB_MODULE_IS_APP_LAYER           (1 << 2)
#define PRB_MODULE_REQUIRES_TEST_RESPONSE (1 << 3)

// worker status

#define WORKER_STATUS_IDLE            0
#define WORKER_STATUS_BUSY            1
#define WORKER_STATUS_DB_WRITE        2
#define WORKER_STATUS_SOCKET_CONNECT  3
#define WORKER_STATUS_SOCKET_WRITE    4
#define WORKER_STATUS_SOCKET_READ     5
#define WORKER_STATUS_CON_WAIT        6
#define WORKER_STATUS_LOCK            7
#define WORKER_STATUS_LEN             8

// worker status color
extern const char *worker_status_color[];
extern const char *worker_status_name[];

struct prb_request {
	char *ip;
	int port;
	int timestamp;
};

extern struct probeably prb;

struct prb_request;

struct prb_module {
	char *name;
	int flags;
	void (*init)(struct probeably *p);
	void (*cleanup)(struct probeably *p);
	int (*run)(struct probeably *p, struct prb_request *r, struct prb_socket *s);
	int (*check)(const char *response, int len);
};

void init_modules();
void cleanup_modules();
void run_modules(struct prb_request *r);

void init_ip_modules();
void cleanup_ip_modules();
void run_ip_modules(struct prb_request *r);

#endif
