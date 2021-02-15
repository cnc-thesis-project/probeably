#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define HTTP_BUFFER_SIZE 512
static char http_buffer[HTTP_BUFFER_SIZE];

#define MAX_HEADERS 10

struct http_header {
	char *name;
	char *value;
};

struct http_status {
	char *version;
	int code;
	char *message;
};

// The parser is shit and needs to be checked for safety.
static struct http_header *read_headers(struct prb_socket *s)
{
	PRB_DEBUG("http", "Attempting to read headers\n");

	// Allocate one more header as a termination header to indicate end of header list.
	struct http_header *headers = malloc(sizeof(struct http_header) * (MAX_HEADERS + 1));
	int header_index = 0;

	while (header_index < MAX_HEADERS) {
		int i = 0;
		for (;;) {
			if (i >= HTTP_BUFFER_SIZE - 1) {
				break;
			}
			int err = prb_socket_read(s, &http_buffer[i], 1);
			if (err <= 0) {
				break;
			}
			char c = http_buffer[i];

			if (c == '\r') {
				continue;
			}
			else if (c == '\n') {
				break;
			}
			i++;
		}

		if (i == 0) {
			header_index++;
			break;
		}
		http_buffer[i] = '\0';
		PRB_DEBUG("http", "Read line '%s'\n", http_buffer);
		char *line = malloc(i + 1);
		memcpy(line, http_buffer, i + 1);
		struct http_header *header = &headers[header_index];
		header->name = strtok_r(line, ":", &line);
		header->value = strtok_r(NULL, "", &line);
		if (header->value[0] == ' ') {
			header->value = header->value + 1;
		}

		PRB_DEBUG("http", "Parsed header '%s' with value '%s'\n", headers[header_index].name, headers[header_index].value);

		header_index++;
	}

	// Set final termination header.
	headers[header_index - 1].name = 0;
	headers[header_index - 1].value = 0;

	for (int i = 0; i < header_index - 1; i++) {
		PRB_DEBUG("http", "Response header: %s=%s\n", headers[i].name, headers[i].value);
	}

	return headers;
}

static void free_headers(struct http_header* headers)
{
	PRB_DEBUG("http", "Freeing headers\n");
	for (int i = 0;; i++) {
		struct http_header *header = &headers[i];
		if (!header->name || !header->value) {
			break;
		}
		// We only have to free the name,
		// since the value is part of the same memory.
		free(header->name);
	}
	free(headers);
}

static void free_status(struct http_status *status)
{
	PRB_DEBUG("http", "Freeing status\n");
	free(status->version);
	free(status);
}

static struct http_status *read_status(struct prb_socket *s)
{
	PRB_DEBUG("http", "Attempting to read status line\n");
	unsigned int i;

	for (i = 0; i < HTTP_BUFFER_SIZE-1; i++) {
		int err = prb_socket_read(s, &http_buffer[i], 1);
		if (err <= 0) {
			return NULL;
		}
		else if (http_buffer[i] == '\r') {
			continue;
		}
		else if (http_buffer[i] == '\n') {
			break;
		}
	}
	http_buffer[i] = '\0';

	if (memcmp("HTTP", http_buffer, 4)) {
		return NULL;
	}

	char *status_line = (char *) malloc(sizeof(char)*i);
	snprintf(status_line, i, "%s", http_buffer);
	PRB_DEBUG("http", "Read status line '%s'\n", status_line);

	struct http_status *status = malloc(sizeof(struct http_status));
	status->version = strtok_r(status_line, " ", &status_line);
	status->code = atoi(strtok_r(NULL, " ", &status_line));
	status->message = strtok_r(NULL, "", &status_line);

	PRB_DEBUG("http", "Status: version=%s, code=%d, message=%s\n",
			status->version,
			status->code,
			status->message);

	return status;
}

static void http_module_init(struct probeably *p)
{

}

static void http_module_cleanup(struct probeably *p)
{

}

static int http_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *sock)
{
	int ret = 0;
	char *ip = r->ip;
	int port = r->port;
	int timestamp = r->timestamp;

	PRB_DEBUG("http", "running module on %s:%d\n", ip, port);

	if (prb_socket_connect(sock, ip, port) < 0) {
		return -1;
	}

	strcpy(http_buffer, "GET / HTTP/1.1\r\nHost: www\r\n\r\n");

	int count;
	PRB_DEBUG("http", "Sending request '%s'\n", http_buffer);
	count = prb_socket_write(sock, http_buffer, strlen(http_buffer));
	PRB_DEBUG("http", "Wrote %d bytes\n", count);

	struct http_status *status = read_status(sock);
	if (!status) {
		PRB_DEBUG("http", "Not a HTTP protocol\n");
		ret = -1;
		goto ret_shutdown;
	}
	struct http_header *headers = read_headers(sock);

	// Write status code to database
	char code_str[4];
	snprintf(code_str, 4, "%d", status->code);

	// Write headers to database
	for (int i = 0; headers[i].name && headers[i].value; i++) {
		char *name = headers[i].name;
		char *value = headers[i].value;
		int type_len = 16 + strlen(name);
		char *type = malloc(type_len + 1);
		snprintf(type, type_len + 1, "get_root_header_%s", name);
		free(type);
	}

	free_headers(headers);
	free_status(status);
ret_shutdown:
	prb_socket_shutdown(sock);
	return ret;
}

struct prb_module module_http = {
	.flags = PRB_MODULE_IS_APP_LAYER,
	.name = "http",
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
};
