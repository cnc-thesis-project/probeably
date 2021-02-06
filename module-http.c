#include <stdio.h>
#include "module-http.h"
#include "module.h"
#include "socket.h"
#include "probeably.h"

#define HTTP_BUFFER_SIZE
static char http_buffer[HTTP_BUFFER_SIZE];

static void http_module_init(struct probeable *p)
{

}

static void http_module_cleanup(struct probeable *p)
{

}

static void http_module_run(struct probeable *p, char *ip, int port)
{
	struct prb_socket sock;
	sock.type = PRB_SOCKET_RAW;
	prb_socket_connect(&sock, ip, port;

	int count = prb_socket_read(&sock, buf, 1024);
	buf[count] = '\0';
	printf("HTTP module read '%s'\n", buf);
}

struct module module_http = {
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
};
