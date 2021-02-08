#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sha.h>
#include "module.h"
#include "module-http.h"
#include "socket.h"
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
	headers[header_index].name = 0;
	headers[header_index].value = 0;

	for (int i = 0; i < header_index - 1; i++) {
		PRB_DEBUG("http", "Response header: %s=%s\n", headers[i].name, headers[i].value);
	}

	return headers;
}

static void free_headers(struct http_header* headers)
{
	// TODO: fix bug where sometimes it seg faults while freeing
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
	for (i = 0; i < HTTP_BUFFER_SIZE; i++) {
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
	http_buffer[i-1] = '\0';

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

	struct http_status *status = read_status(&sock);
	struct http_header *headers = read_headers(&sock);

	// TODO: do shit here

	prb_socket_shutdown(&sock);
	free_headers(headers);
	free_status(status);
}

struct module module_http = {
	.init = http_module_init,
	.cleanup = http_module_cleanup,
	.run = http_module_run,
};
