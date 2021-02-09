#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <sqlite3.h>
#include <async.h>
#include <unistd.h>
#include <adapters/libev.h>
#include "probeably.h"
#include "module-http.h"
#include "module.h"
#include "socket.h"
#include "database.h"

pid_t *child = 0;
int child_len = 8;

static void fake_probing(const char *ip, int port)
{
	struct module *mod = &module_http;
	struct probeably p;

	//mod->init(&p);
	mod->run(&p, ip, port);
	//mod->cleanup(&p);

	PRB_DEBUG(__FILE__, "fake probing go brrrrrrrrrrrrr (%s:%d)\n", ip, port);
}

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	redisReply *reply = r;
	sqlite3 *db = privdata;

	redisAsyncCommand(c, port_callback, privdata, "BLPOP port 0");

	printf("port callback\n");

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
	prb_write_data(db, "test-module", "port-scan", ip, port, "hello", timestamp);

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

static void sigint_callback(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
	kill(0, SIGINT);
}

int main(int argc, char **argv)
{
	redisAsyncContext *c;
	redisReply *reply;
	const char *hostname = (argc > 1) ? argv[1] : "127.0.0.1";

	int port = (argc > 2) ? atoi(argv[2]) : 6379;

	prb_socket_init();

	ev_signal signal_watcher;
	ev_signal_init(&signal_watcher, sigint_callback, SIGINT);
	c = redisAsyncConnect(hostname, port);

	if (c->err) {
		printf("Connection error: %s\n", c->errstr);
		redisAsyncFree(c);

		exit(1);
	}

	child = malloc(sizeof(pid_t) * child_len);

	pid_t pid = 0;
	for (int i = 0; i < child_len; i++) {
		pid = fork();
		if (pid == 0)
			break;
		child[i] = pid;
	}

	// sqlite database has to be opened after fork or it may corrupt the file
	sqlite3 *db = prb_open_database("probeably.db");
	if (!db)
		return EXIT_FAILURE;

	if (pid != 0) {
		// parent path
		if (prb_init_database(db) == -1)
			return EXIT_FAILURE; // TODO: kill childrens

		ev_signal_start(EV_DEFAULT, &signal_watcher);
	} else {
		// child path

		// give parent time to create table to ensure it is available
		sleep(1);

		redisLibevAttach(EV_DEFAULT_ c);
		redisAsyncSetConnectCallback(c, connect_callback);
		redisAsyncSetDisconnectCallback(c, disconnect_callback);
		redisAsyncCommand(c, port_callback, db, "BLPOP port 0");
	}
	ev_loop(EV_DEFAULT_ 0);

	sqlite3_close(db);

	prb_socket_cleanup();
	redisAsyncFree(c);
	free(child);

	return 0;
}
