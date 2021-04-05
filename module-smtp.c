#include <stdio.h>
#include <string.h>
#include "module.h"
#include "module-smtp.h"
#include "socket.h"
#include "database.h"
#include "probeably.h"

#define BUFFER_SIZE (16*1024)
static char buffer[BUFFER_SIZE];

#define HELO "HELO test.com\r\n"

static int smtp_module_check(const char *response, int len)
{
	(void) response;
	(void) len;

	if (!strncmp(response, "220 ", 4)) {
		return 0;
	}

	return -1;
}

static int smtp_module_test(struct probeably *p, struct prb_request *r,
		struct prb_socket *s, char *response, size_t size)
{
	(void) p;
	(void) r;
	(void) s;
	(void) response;
	(void) size;

	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	int read_len = prb_socket_read(s, response, size);

	prb_socket_shutdown(s);

	return read_len;
}

static void smtp_module_init(struct probeably *p)
{
	p->ports_to_modules[25] = &module_smtp;
	p->ports_to_modules[465] = &module_smtp;
	p->ports_to_modules[587] = &module_smtp;
	p->ports_to_modules[2525] = &module_smtp;
}

static void smtp_module_cleanup(struct probeably *p)
{
	(void) p;
}

static int smtp_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	if (prb_socket_connect(s, r->ip, r->port) < 0) {
		return -1;
	}

	size_t read_len;
	size_t result;

	result = prb_socket_read(s, buffer, sizeof(buffer) - 1);
	if (result <= 0) {
		return -1;
	}
	read_len = result;


	prb_socket_write(s, HELO, strlen(HELO));
	result = prb_socket_read(s, &buffer[read_len], sizeof(buffer) - read_len - 1);
	if (result <= 0) {
		return -1;
	}
	read_len += result;
	buffer[read_len] = '\0';

	char *server_string = strtok(buffer, "\r\n");
	if (server_string == NULL) {
		return -1;
	}
	if (strncmp(server_string, "220 ", 4)) {
		return -1;
	}
	char *server_hello = strtok(NULL, "\r\n");
	if (server_hello == NULL) {
		return -1;
	}
	if (strncmp(server_hello, "250 ", 4)) {
		return -1;
	}

	PRB_DEBUG("smtp", "Server string: '%s'", server_string);
	PRB_DEBUG("smtp", "Server hello: '%s'", server_hello);


	prb_write_data(p, r, "smtp", "server_string", server_string, strlen(server_string), PRB_DB_SUCCESS);
	prb_write_data(p, r, "smtp", "server_hello", server_hello, strlen(server_hello), PRB_DB_SUCCESS);
	prb_socket_shutdown(s);

	return 0;
}

struct prb_module module_smtp = {
	.flags = PRB_MODULE_REQUIRES_RAW_SOCKET
		| PRB_MODULE_IS_APP_LAYER
		| PRB_MODULE_REQUIRES_TEST_RESPONSE,
	.name = "smtp",
	.init = smtp_module_init,
	.cleanup = smtp_module_cleanup,
	.run = smtp_module_run,
	.check = smtp_module_check,
	.test = smtp_module_test,
};
