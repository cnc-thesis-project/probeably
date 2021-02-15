#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <sqlite3.h>
#include <async.h>
#include <unistd.h>
#include <adapters/libev.h>
#include <getopt.h>
#include "probeably.h"
#include "module.h"
#include "socket.h"
#include "database.h"

pid_t *child = 0;
int child_len = 8;

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	PRB_DEBUG("main", "Running port callback\n");

	redisReply *reply = r;
	sqlite3 *db = privdata;

	redisAsyncCommand(c, port_callback, privdata, "BLPOP port 0");


	if (!reply || reply->elements < 2)
		return;

	char *values = strdup(reply->element[1]->str);

	PRB_DEBUG("main", "Got from redis: %s\n", values);


	char *ip = strtok(reply->element[1]->str, ",");
	int port = atoi(strtok(0, ","));
	char *protocol = strtok(0, ",");
	int timestamp = atoi(strtok(0, ","));
	int status = atoi(strtok(0, ","));
	int reason = atoi(strtok(0, ","));
	int ttl = atoi(strtok(0, ","));

	if (!ip || port < 0) {
		printf("error: got invalid format from redis:\n");
		printf("%s\n", values);

		free(values);
		return;
	}

	PRB_DEBUG("main", "probing: %s:%d (%d)\n", ip, port, timestamp);

	struct prb_request req;
	req.ip = ip;
	req.port = port;
	req.timestamp = timestamp;

	if (port == 0) {
		// ip related analysis stuff, e.g. geoip
		run_ip_modules(&req);
		return;
	}

	// port related analysis stuff

	printf("probe: %s:%d (%d)\n", ip, port, timestamp);
	run_modules(&req);

	free(values);
}

static void connect_callback(const redisAsyncContext *c, int status)
{
	PRB_DEBUG("main", "Connecting (^ 3^)\n");
	if (status != REDIS_OK) {
		fprintf(stderr, "error: %s\n", c->errstr);
		return;
	}
}

static void disconnect_callback(const redisAsyncContext *c, int status)
{
	PRB_DEBUG("main", "Disconnecting ( ˘ω˘)\n");
	if (status != REDIS_OK) {
		fprintf(stderr, "error: %s\n", c->errstr);
		return;
	}
}

static void sigint_callback(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
	kill(0, SIGINT);
}

static void version()
{
	printf("probeably %s\n", PRB_VERSION);
}

static void usage()
{

	printf(
			"usage: probeably [options]\n"
			"  -h, --help        Print usage.\n"
			"  -v, --version     Print version string.\n"
			"  -H, --redis-host  Redis host.\n"
			"  -p, --redis-port  Redis port.\n"
		  );
}

int main(int argc, char **argv)
{
	const char *hostname = "127.0.0.1";
	int port = 6379;

	while (1) {
		static struct option long_opts[] = {
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'v'},
			{"redis-host", required_argument, 0, 'H'},
			{"redis-port", required_argument, 0, 'p'},
		};
		int opt_index = 0;
		int c = getopt_long(argc, argv, "hvH:p:", long_opts, &opt_index);

		if (c == -1) {
			break;
		}

		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
				break;
			case 'v':
				version();
				exit(EXIT_SUCCESS);
				break;
			case 'H':
				hostname = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;

			default:
				return EXIT_FAILURE;
		}
	}

	redisAsyncContext *c;
	redisReply *reply;

	prb_socket_init();
	init_modules();
	init_ip_modules();

	ev_signal signal_watcher;
	ev_signal_init(&signal_watcher, sigint_callback, SIGINT);
	c = redisAsyncConnect(hostname, port);

	if (c->err) {
		fprintf(stderr, "Connection error: %s\n", c->errstr);
		redisAsyncFree(c);

		exit(1);
	}

	PRB_DEBUG("main", "Starting workers...\n");

	child = malloc(sizeof(pid_t) * child_len);

	pid_t pid = 0;
	for (int i = 0; i < child_len; i++) {
		pid = fork();
		if (pid == 0)
			break;
		child[i] = pid;
	}

	// sqlite database has to be opened after fork or it may corrupt the file
	prb.db = prb_open_database("probeably.db");
	if (!prb.db)
		return EXIT_FAILURE;

	if (pid != 0) {
		// parent path
		if (prb_init_database(prb.db) == -1)
			return EXIT_FAILURE; // TODO: kill childrens

		ev_signal_start(EV_DEFAULT, &signal_watcher);
	} else {
		// child path

		// give parent time to create table to ensure it is available
		sleep(1);

		redisLibevAttach(EV_DEFAULT_ c);
		redisAsyncSetConnectCallback(c, connect_callback);
		redisAsyncSetDisconnectCallback(c, disconnect_callback);
		redisAsyncCommand(c, port_callback, prb.db, "BLPOP port 0");
	}
	ev_loop(EV_DEFAULT_ 0);

	cleanup_modules();
	cleanup_ip_modules();
	sqlite3_close(prb.db);
	prb_socket_cleanup();
	redisAsyncFree(c);
	free(child);

	return 0;
}
