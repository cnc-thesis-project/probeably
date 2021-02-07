#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
#include "probeably.h"

#define HTTP_BUFFER_SIZE 512
static char http_buffer[HTTP_BUFFER_SIZE];

static void http_module_init(struct probeably *p)
{

}

static void http_module_cleanup(struct probeably *p)
{

}

static void http_module_run(struct probeably *p, char *ip, int port)
{
	PRB_DEBUG("http", "running module on %s:%d\n", ip, port);

	struct prb_socket sock = {0};
	sock.type = PRB_SOCKET_UNKNOWN;
	if (prb_socket_connect(&sock, ip, port) < 0) {
		return;
	}

	strcpy(http_buffer, "GET / HTTP/1.1\r\nHost: www\r\n\r\n");

	int count;
	PRB_DEBUG("http", "Sending request '%s'\n", http_buffer);
	count = prb_socket_write(&sock, http_buffer, strlen(http_buffer));
	PRB_DEBUG("http", "Wrote %d bytes\n", count);
	PRB_DEBUG("http", "Attempting to read response\n");
	count = prb_socket_read(&sock, http_buffer, 1024);
	PRB_DEBUG("http", "Read %d bytes\n", count);
	http_buffer[count] = '\0';
	printf("HTTP module read '%s'\n", http_buffer);
}

struct module module_http = {
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
};
