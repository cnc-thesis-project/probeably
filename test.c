#include <stdio.h>
#include <stdlib.h>
#include "socket.h"
#include "probeably.h"
#include "module.h"
#include "module-tls.h"
#include "module-http.h"

int main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("usage: test [ip] [port]\n");
		exit(EXIT_FAILURE);
	}

	prb_socket_init();

	struct module *mod = &module_http;
	struct probeably p;

	mod->init(&p);
	mod->run(&p, argv[1], atoi(argv[2]));
	mod->cleanup(&p);

	prb_socket_cleanup();
}
