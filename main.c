#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <async.h>
#include <unistd.h>
#include <adapters/libev.h>
#include <getopt.h>
#include "probeably.h"
#include "module-http.h"
#include "module.h"

pid_t *child = 0;
int child_len = 8;
struct probeably prb;

#define NUM_MODULES 1
struct prb_module *modules[NUM_MODULES] = {
	&module_http,
};

static void init_modules()
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->init(&prb);
	}
}

static void cleanup_modules()
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->cleanup(&prb);
	}
}

static void run_modules(const char *ip, int port)
{
	for (int i = 0; i < NUM_MODULES; i++) {
		modules[i]->run(&prb, ip, port);
	}

	PRB_DEBUG("main", "fake probing go brrrrrrrrrrrrr (%s:%d)\n", ip, port);
}

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	redisReply *reply = r;

	redisAsyncCommand(c, port_callback, 0, "BLPOP port 0");

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

	run_modules(ip, port);

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

static void version()
{
	printf("probeably %s\n", VERSION);
}

static void usage()
{
	printf(
			"usage: probeably [options]\n"
			"  --help, -h        Print usage.\n"
			"  --version, -v     Print version string.\n"
			"  --redis-host, -H  Redis host.\n"
			"  --redis-port, -p  Redis port.\n"
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
				fprintf(stderr, "Unrecognized option '%c'\n", c);
				return EXIT_FAILURE;
		}
	}

	redisAsyncContext *c;
	redisReply *reply;

	prb_socket_init();
	init_modules();

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

	if (pid != 0) {
		ev_signal_start(EV_DEFAULT, &signal_watcher);
	} else {
		redisLibevAttach(EV_DEFAULT_ c);
		redisAsyncSetConnectCallback(c, connect_callback);
		redisAsyncSetDisconnectCallback(c, disconnect_callback);
		redisAsyncCommand(c, port_callback, 0, "BLPOP port 0");
	}
	ev_loop(EV_DEFAULT_ 0);

	cleanup_modules();
	prb_socket_cleanup();
	redisAsyncFree(c);
	free(child);

	return 0;
}
