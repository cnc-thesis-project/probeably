#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define HTTP_BUFFER_SIZE (16*1024)

static int http_module_check(const char *response, int len)
{
	if (strncmp("HTTP/", response, 5))
		return -1;
	return 0;
}

static void http_module_init(struct probeably *p)
{

}

static void http_module_cleanup(struct probeably *p)
{

}

static int http_send_request(	struct probeably *p, struct prb_request *r, struct prb_socket *sock,
								const char *request, const char *type, int headers_only)
{
	char *ip = r->ip;
	int port = r->port;
	int timestamp = r->timestamp;

	if (prb_socket_connect(sock, ip, port) < 0) {
		return -1;
	}

	PRB_DEBUG("http", "Sending request '%s'", request);
	prb_socket_write(sock, request, strlen(request));

	char *http_buffer = calloc(1, HTTP_BUFFER_SIZE);

	size_t total = 0;
	size_t content_length = -1;
	size_t content_offset = -1;
	while (total < HTTP_BUFFER_SIZE - 1 && (content_offset == -1 || total - content_offset < content_length)) {
		int len = prb_socket_read(sock, http_buffer + total, HTTP_BUFFER_SIZE - 1 - total);
		if (len <= 0)
			break;

		total += len;

		if (content_length == -1) {
			// check for ontent-length header
			char *length_line = strstr(http_buffer, "Content-Length:");
			if (length_line && strstr(length_line, "\r\n")) {
				char *line_end = strstr(length_line, "\r\n");

				// set null character temporarily to make atoi stop at the end of line
				*line_end = 0;
				length_line += strlen("Content-Length:");
				content_length = atoi(length_line);
				// recover \r
				*line_end = '\r';

				PRB_DEBUG("http", "Content-Length: %zd", content_length);
			}
		}
		if (content_offset == -1) {
			// check where content begins
			char *content = strstr(http_buffer, "\r\n\r\n");
			if (content) {
				content += strlen("\r\n\r\n");
				content_offset = content - http_buffer;

				// break if we are only interested in headers
				if (headers_only)
					break;
			}
		}
	}

	int result = 0;
	if (http_module_check(http_buffer, total) == -1) {
		PRB_DEBUG("http", "Not a HTTP protocol\n");
		result = -1;
	}

	prb_write_data(p, r, "http", type, http_buffer, total,
			(result == 0 ? PRB_DB_SUCCESS : 0) | (total == HTTP_BUFFER_SIZE - 1 ? PRB_DB_CROPPED : 0));

	free(http_buffer);
	prb_socket_shutdown(sock);

	return result;
}

static int http_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *sock)
{
	PRB_DEBUG("http", "running module on %s:%d", r->ip, r->port);

	// get root, if it fails it's not a HTTP protocol
	if (http_send_request(p, r, sock, "GET / HTTP/1.1\r\nHost: www\r\n\r\n", "get_root", 0) == -1)
		return -1;

	// the rest of the requests don't return if it fails
	// because we already know that it worked for GET request

	// head root
	http_send_request(p, r, sock, "HEAD / HTTP/1.1\r\nHost: www\r\n\r\n", "head_root", 1);

	// get non existing file
	http_send_request(p, r, sock, "GET /this_should_not_exist_bd8a3 HTTP/1.1\r\nHost: www\r\n\r\n", "not_exist", 0);

	// get root with invalid http version
	http_send_request(p, r, sock, "GET / HTTP/1.999\r\nHost: www\r\n\r\n", "invalid_version", 0);

	// get root with invalid protocol
	http_send_request(p, r, sock, "GET / PTTH/1.1\r\nHost: www\r\n\r\n", "invalid_protocol", 0);

	// get very long path (1000 characters)
	char request_buffer[2048];
	char aaaaa[1001];
	memset(aaaaa, 'a', sizeof(aaaaa)-1);
	aaaaa[sizeof(aaaaa)-1] = 0;

	sprintf(request_buffer, "GET /%s HTTP/1.1\r\nHost: www\r\n\r\n", aaaaa);
	http_send_request(p, r, sock, request_buffer, "long_path", 0);

	// get favicon
	http_send_request(p, r, sock, "GET /favicon.ico HTTP/1.1\r\nHost: www\r\n\r\n", "get_favicon", 0);

	// get robots.txt
	http_send_request(p, r, sock, "GET /robots.txt HTTP/1.1\r\nHost: www\r\n\r\n", "get_robots", 0);

	// delete root
	http_send_request(p, r, sock, "DELETE / HTTP/1.1\r\nHost: www\r\n\r\n", "delete_root", 0);

	return 0;
}

struct prb_module module_http = {
	.flags = PRB_MODULE_IS_APP_LAYER,
	.name = "http",
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
	.check = http_module_check,
};
