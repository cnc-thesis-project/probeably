#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"
#include "util.h"

#define HTTP_BUFFER_SIZE (16*1024)

const char *user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0";

static int http_module_check(const char *response, int len)
{
	(void) len;
	if (strncmp("HTTP/", response, 5))
		return -1;
	return 0;
}

static void http_module_init(struct probeably *p)
{
	(void) p;
}

static void http_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int http_send_request(	struct probeably *p, struct prb_request *r, struct prb_socket *sock,
								const char *request, const char *type, int headers_only, int store_fail)
{
	char *ip = r->ip;
	int port = r->port;

	PRB_DEBUG("http", "Testing '%s'", type);

	if (prb_socket_connect(sock, ip, port) < 0) {
		return -1;
	}

	// right before sending request
	struct timespec request_start = start_timer();
	// time it took to get first packet
	float response_start = 0.0f;
	// time it took to get the whole response
	float response_end = 0.0f;

	prb_socket_write(sock, request, strlen(request));

	char *http_buffer = calloc(1, HTTP_BUFFER_SIZE);

	int total = 0;
	int content_length = -1;
	int content_offset = -1;
	while (total < HTTP_BUFFER_SIZE - 1 && (content_offset == -1 || total - content_offset < content_length)) {
		int len = prb_socket_read(sock, http_buffer + total, HTTP_BUFFER_SIZE - 1 - total);

		// measure time it took to get the first packet of response
		if (response_start == 0.0f)
			response_end = response_start = stop_timer(request_start);

		if (len <= 0)
			break;

		// this could actually be outside while loop but that will result the measurement
		// to be off in case the server doesn't close the socket,
		// thus to get reliable time stop_timer has to be called everytime it gets non-empty data.
		// also the time becomes incorrect if it the response exceeds the buffer size
		// since it will stop reading and proceed to next step
		response_end = stop_timer(request_start);

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

				PRB_DEBUG("http", "Content-Length: %d", content_length);
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

	if (store_fail || result >= 0) {
		prb_write_data(p, r, "http", type, http_buffer, total,
				(result == 0 ? PRB_DB_SUCCESS : 0) | (total == HTTP_BUFFER_SIZE - 1 ? PRB_DB_CROPPED : 0));

		char type_buf[128];
		char buf[128];
		snprintf(type_buf, sizeof(type_buf), "%s_time", type);
		snprintf(buf, sizeof(buf), "%f %f", response_start, response_end);

		prb_write_data(p, r, "http", type_buf, buf, strlen(buf),
				(result == 0 ? PRB_DB_SUCCESS : 0) | (total == HTTP_BUFFER_SIZE - 1 ? PRB_DB_CROPPED : 0));
	}

	free(http_buffer);
	prb_socket_shutdown(sock);

	return result;
}

static int http_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *sock)
{
	char request_header[2048];

	// get root, if it fails it's not a HTTP protocol
	snprintf(request_header, sizeof(request_header),
			"GET / HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	if (http_send_request(p, r, sock, request_header, "get_root", 0, 0) == -1)
		return -1;

	// the rest of the requests don't return if it fails
	// because we already know that it worked for GET request

	// head root
	snprintf(request_header, sizeof(request_header),
			"HEAD / HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "head_root", 1, 1);

	// very simple get
	http_send_request(p, r, sock, "GET / HTTP/1.1\r\n\r\n", "very_simple_get", 0, 1);

	// get non existing file
	snprintf(request_header, sizeof(request_header),
			"GET /this_should_not_exist_bd8a3 HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "not_exist", 0, 1);

	// get root with invalid http version
	snprintf(request_header, sizeof(request_header),
			"GET / HTTP/1.999\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "invalid_version", 0, 1);

	// get root with invalid protocol
	snprintf(request_header, sizeof(request_header),
			"GET / PTTH/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "invalid_protocol", 0, 1);

	// get very long path (1000 characters)
	char aaaaa[1001];
	memset(aaaaa, 'a', sizeof(aaaaa)-1);
	aaaaa[sizeof(aaaaa)-1] = 0;

	snprintf(request_header, sizeof(request_header),
			"GET /%s HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", aaaaa, user_agent);
	http_send_request(p, r, sock, request_header, "long_path", 0, 1);

	// get favicon
	snprintf(request_header, sizeof(request_header),
			"GET /favicon.ico HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "get_favicon", 0, 1);

	// get robots.txt
	snprintf(request_header, sizeof(request_header),
			"GET /robots.txt HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "get_robots", 0, 1);

	// delete root
	snprintf(request_header, sizeof(request_header),
			"DELETE / HTTP/1.1\r\nUser-Agent: %s\r\nHost: www\r\n\r\n", user_agent);
	http_send_request(p, r, sock, request_header, "delete_root", 0, 1);

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
