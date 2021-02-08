#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <async.h>
#include <unistd.h>
#include <adapters/libev.h>



static void fake_probing(const char *ip, int port)
{
	printf("fake probing go brrrrrrrrrrrrr (%s:%d)\n", ip, port);
}

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	redisReply *reply = r;

	redisAsyncCommand(c, port_callback, 0, "BLPOP port 0");

	printf("port callback\n");
	sleep(1);

	if (!reply || reply->elements < 2)
		return;

	char *values = strdup(reply->element[1]->str);

	char *ip = strtok(reply->element[1]->str, ",");
	int port = atoi(strtok(0, ","));
	char *protocol = strtok(0, ",");
	int timestamp = atoi(strtok(0, ","));
	int status = atoi(strtok(0, ","));
	int reason = atoi(strtok(0, ","));
	int ttl = atoi(strtok(0, ","));

	if (!ip || port <= 0) {
		printf("error: got invalid format from redis:\n");
		printf("%s\n", values);

		free(values);
		return;
	}

	printf("probe: %s:%d (%d)\n", ip, port, timestamp);

	fake_probing(ip, port);

	free(values);
}

static void connect_callback(const redisAsyncContext *c, int status)
{
	if (status != REDIS_OK) {
		printf("error: %s\n", c->errstr);
		return;
	}

	printf("connected (^ 3^)\n");
}

static void disconnect_callback(const redisAsyncContext *c, int status)
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
	redisAsyncSetConnectCallback(c, connect_callback);
	redisAsyncSetDisconnectCallback(c, disconnect_callback);
	redisAsyncCommand(c, port_callback, 0, "BLPOP port 0");

	//fork();

	ev_loop(EV_DEFAULT_ 0);

	redisAsyncFree(c);

	return 0;
}
