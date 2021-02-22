#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-rdns.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

static void rdns_module_init(struct probeably *p)
{
	(void) p;
}

static void rdns_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int rdns_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	(void)p;
	(void)s;

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;

	if(!inet_pton(AF_INET, r->ip, &sa.sin_addr))
		return -1;

	char host[NI_MAXHOST];

	int res = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), 0, 0, NI_NAMEREQD);
	if (!res) {
		PRB_DEBUG("rdns", "Reverse DNS lookup of %s: %s", r->ip, host);
		prb_write_data(&prb, r, "rdns", "name", host, strlen(host), PRB_DB_SUCCESS);
	} else {
		PRB_DEBUG("rdns", "Reverse DNS lookup of %s not found", r->ip);
	}

	return 0;
}

struct prb_module module_rdns = {
	.name = "rdns",
	.init = rdns_module_init,
	.cleanup = rdns_module_cleanup,
	.run = rdns_module_run,
};
