#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define HTTP_BUFFER_SIZE (16*1024)

static void http_module_init(struct probeably *p)
{

}

static void http_module_cleanup(struct probeably *p)
{

}

static int http_send_request(	struct probeably *p, struct prb_request *r, struct prb_socket *sock,
								const char *request, const char *type)
{
	char *ip = r->ip;
	int port = r->port;
	int timestamp = r->timestamp;

	if (prb_socket_connect(sock, ip, port) < 0) {
		return -1;
	}

	PRB_DEBUG("http", "Sending request '%s'\n", request);
	prb_socket_write(sock, request, strlen(request));

	char *http_buffer = malloc(HTTP_BUFFER_SIZE);

	int total = 0;
	while (total < HTTP_BUFFER_SIZE - 1) {
		int len = prb_socket_read(sock, http_buffer + total, HTTP_BUFFER_SIZE - 1 - total);
		if (len <= 0)
			break;

		total += len;
	}

	http_buffer[total] = 0;
	if (strncmp("HTTP/", http_buffer, 5)) {
		PRB_DEBUG("http", "Not a HTTP protocol\n");

		// TODO: add a flag that can differentiate normal reponse from this fail response
		prb_write_data(p, r, "http", type, http_buffer, total);

		free(http_buffer);
		prb_socket_shutdown(sock);
		return -1;
	}

	prb_write_data(p, r, "http", type, http_buffer, total);

	free(http_buffer);
	prb_socket_shutdown(sock);

	return 0;
}

static int http_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *sock)
{
	PRB_DEBUG("http", "running module on %s:%d\n", r->ip, r->port);

	// get root, if it fails it's not a HTTP protocol
	if (http_send_request(p, r, sock, "GET / HTTP/1.1\r\nHost: www\r\n\r\n", "get_root") == -1)
		return -1;

	// the rest of the requests don't return if it fails
	// because we already know that it worked for GET request

	// head root
	http_send_request(p, r, sock, "HEAD / HTTP/1.1\r\nHost: www\r\n\r\n", "head_root");

	// get non existing file
	http_send_request(p, r, sock, "GET /this_should_not_exist_bd8a3 HTTP/1.1\r\nHost: www\r\n\r\n", "not_exist");

	// get root with invalid http version
	http_send_request(p, r, sock, "GET / HTTP/1.999\r\nHost: www\r\n\r\n", "invalid_version");

	// get root with invalid protocol
	http_send_request(p, r, sock, "GET / PTTH/1.1\r\nHost: www\r\n\r\n", "invalid_protocol");

	// get very long path (1000 characters)
	char request_buffer[2048];
	char aaaaa[1001];
	memset(aaaaa, 'a', sizeof(aaaaa)-1);
	sprintf(request_buffer, "GET /%s HTTP/1.1\r\nHost: www\r\n\r\n", aaaaa);
	http_send_request(p, r, sock, request_buffer, "long_path");

	// get favicon
	http_send_request(p, r, sock, "GET /favicon.ico HTTP/1.1\r\nHost: www\r\n\r\n", "get_favicon");

	// get robots.txt
	http_send_request(p, r, sock, "GET /robots.txt HTTP/1.1\r\nHost: www\r\n\r\n", "get_robots");

	// delete root
	http_send_request(p, r, sock, "DELETE / HTTP/1.1\r\nHost: www\r\n\r\n", "delete_root");

	return 0;
}

struct prb_module module_http = {
	.flags = PRB_MODULE_IS_APP_LAYER,
	.name = "http",
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
};
