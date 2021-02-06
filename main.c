#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <async.h>
#include <adapters/libev.h>



static void fakeProbing(const char *ip, int port)
{
	printf("fake probing go brrrrrrrrrrrrr (%s:%d)\n", ip, port);
}

static void monitorCallback(redisAsyncContext *c, void *r, void *privdata)
{
	redisReply *reply = r;

	if (!reply)
		return;

	// result from MONITOR itself isn't interesting
	if (!strcmp(reply->str, "OK"))
		return;

	//printf("REPLY: %s\n", reply->str);

	char *msg = strdup(index(reply->str, ']') + 2);
	char *cmd = strtok(msg, " ");

	// we are interested in SADD command
	if (cmd && !strcmp(cmd, "\"SADD\"")) {
		char *arg = strtok(0, " ");

		if (arg && strlen(arg) > 4 && !strncmp(arg + strlen(arg) - 4, "tcp", 3)) {
			// found a open port
			// arg is in format like "192.168.1.1:80/tcp" (including citation mark)

			char *ip = arg + 1;
			char *port_str = index(ip, ':') + 1;
			char *timestamp = strtok(0, " ") + 1;

			// remove delimiters
			port_str[-1] = 0;
			*index(port_str, '/') = 0;
			// remove '"' at the end
			*index(timestamp, '"') = 0;

			int port = atoi(port_str);

			printf("open port at: %s:%d (%s)\n", ip, port, timestamp);

			fakeProbing(ip, port);
		}
	}

	free(msg);
}

static void connectCallback(const redisAsyncContext *c, int status)
{
	if (status != REDIS_OK) {
		printf("error: %s\n", c->errstr);
		return;
	}

	printf("connected (^ 3^)\n");
}

static void disconnectCallback(const redisAsyncContext *c, int status)
{
	if (status != REDIS_OK) {
		printf("error: %s\n", c->errstr);
		return;
	}

	printf("disconnect ( ˘ω˘)\n");
}

int main(int argc, char **argv)
{
	redisAsyncContext *c;
	redisReply *reply;
	const char *hostname = (argc > 1) ? argv[1] : "127.0.0.1";

	int port = (argc > 2) ? atoi(argv[2]) : 6379;

	c = redisAsyncConnect(hostname, port);

	if (c->err) {
		printf("Connection error: %s\n", c->errstr);
		redisAsyncFree(c);

		exit(1);
	}

	redisLibevAttach(EV_DEFAULT_ c);
	redisAsyncSetConnectCallback(c, connectCallback);
	redisAsyncSetDisconnectCallback(c, disconnectCallback);
	redisAsyncCommand(c, monitorCallback, 0, "MONITOR");

	ev_loop(EV_DEFAULT_ 0);

	redisAsyncFree(c);

	return 0;
}
