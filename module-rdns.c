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

	struct hostent *hent;
	struct in_addr addr;

	if(!inet_aton(r->ip, &addr))
		return -1;

	if((hent = gethostbyaddr((char *)&(addr.s_addr), sizeof(addr.s_addr), AF_INET)))
	{
		PRB_DEBUG("rdns", "Reverse DNS lookup of %s: %s", r->ip, hent->h_name);
		prb_write_data(&prb, r, "rdns", "name", hent->h_name, strlen(hent->h_name), PRB_DB_SUCCESS);
	} else {
		PRB_DEBUG("rdns", "Reverse DNS lookup of %s not found", r ->ip);
	}

	return 0;
}

struct prb_module module_rdns = {
	.name = "rdns",
	.init = rdns_module_init,
	.cleanup = rdns_module_cleanup,
	.run = rdns_module_run,
};
