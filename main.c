#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <sqlite3.h>
#include <async.h>
#include <unistd.h>
#include <adapters/libev.h>
#include <sys/mman.h>
#include <getopt.h>
#include "config.h"
#include "probeably.h"
#include "module.h"
#include "socket.h"
#include "database.h"
#include "log.h"

int WORKER_ID = 0;
int *busy_workers = 0;
pthread_mutex_t *busy_workers_lock;

pid_t *child = 0;
ev_child cw;
int child_len = 32;

static void update_worker_state(int start_work)
{
	pthread_mutex_lock(busy_workers_lock);
	*busy_workers += (start_work ? 1 : -1);
	pthread_mutex_unlock(busy_workers_lock);
}

static struct timespec start_timer()
{
	struct timespec start;
	clock_gettime(CLOCK_REALTIME, &start);
	return start;
}

static float stop_timer(struct timespec start)
{
	struct timespec end = start_timer();
	return ((end.tv_sec - start.tv_sec) * (long)1e9 + (end.tv_nsec - start.tv_nsec)) / 1000000000.0f;
}

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	PRB_DEBUG("main", "Running port callback");

	redisReply *reply = r;
	sqlite3 *db = privdata;

	redisAsyncCommand(c, port_callback, privdata, "BLPOP port 0");

	if (!reply || reply->elements < 2)
		return;

	char *values = strdup(reply->element[1]->str);

	PRB_DEBUG("main", "Got from redis: %s", values);

	char *ip = strtok(reply->element[1]->str, ",");
	int port = atoi(strtok(0, ","));
	char *protocol = strtok(0, ",");
	int timestamp = atoi(strtok(0, ","));
	int status = atoi(strtok(0, ","));
	int reason = atoi(strtok(0, ","));
	int ttl = atoi(strtok(0, ","));

	if (!ip || port < 0) {
		PRB_ERROR("main", "error: got invalid format from redis: %s", values);

		free(values);
		return;
	}

	update_worker_state(1);

	PRB_DEBUG("main", "Start probing: %s:%d", ip, port);
	PRB_DEBUG("main", "Busy workers [%d/%d]", *busy_workers, child_len);

	struct prb_request req;
	req.ip = ip;
	req.port = port;
	req.timestamp = timestamp;

	if (port == 0) {
		// ip related analysis stuff, e.g. geoip
		struct timespec start = start_timer();
		run_ip_modules(&req);

		PRB_DEBUG("main", "Finished probing host %s (%fs)", req.ip, stop_timer(start));
		PRB_DEBUG("main", "Busy workers [%d/%d]", *busy_workers, child_len);
		(*busy_workers)--;
		return;
	}

	// port related analysis stuff

	struct timespec start = start_timer();
	run_modules(&req);

	update_worker_state(0);

	PRB_DEBUG("main", "Finished probing port %s:%d (%fs)", req.ip, req.port, stop_timer(start));
	PRB_DEBUG("main", "Busy workers [%d/%d]", *busy_workers, child_len);

	free(values);
}

static void connect_callback(const redisAsyncContext *c, int status)
{
	PRB_DEBUG("main", "Connecting ( ^ 3^)");
	if (status != REDIS_OK) {
		PRB_ERROR("main", "Failed to connect ( ╥ _╥): %s", c->errstr);
		exit(EXIT_FAILURE);
	}
	PRB_DEBUG("main", "Connected! ( ^ .^)");
}

static void disconnect_callback(const redisAsyncContext *c, int status)
{
	PRB_DEBUG("main", "Disconnecting ( ˘ ω˘)");
	if (status != REDIS_OK) {
		PRB_ERROR("main", "Redis disconnect error: %s", c->errstr);
		return;
	}
}

static void sigint_callback(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
	kill(0, SIGINT);
}

static void child_callback(EV_P_ ev_child *w, int revents)
{
	ev_child_stop (EV_A_ w);
	if (w->rstatus != 0) {
		PRB_ERROR("main", "Failure in worker. Exiting...");
		// TODO: clean up shit
		exit(EXIT_FAILURE);
	}
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
	char *config = "config.ini";

	WORKER_ID = getpid();

	while (1) {
		static struct option long_opts[] = {
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'v'},
			{"config", required_argument, 0, 'c'},
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
			case 'c':
				config = optarg;
				break;

			default:
				return EXIT_FAILURE;
		}
	}

	prb_load_config(config);
	child_len = prb_config.num_workers;

	redisAsyncContext *c;
	redisReply *reply;

	prb_socket_init();
	init_modules();
	init_ip_modules();

	ev_signal signal_watcher;
	ev_signal_init(&signal_watcher, sigint_callback, SIGINT);
	c = redisAsyncConnect(hostname, port);

	if (c->err) {
		PRB_ERROR("main", "Redis connection error: %s", c->errstr);
		redisAsyncFree(c);

		exit(EXIT_FAILURE);
	}

	// create shared memory
	// TODO: use struct for data in shared memory
	busy_workers = mmap(NULL, 4 + sizeof(pthread_mutex_lock), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!busy_workers) {
		PRB_ERROR("main", "Failed to create shared memroy");
		exit(EXIT_FAILURE);
	}

	// place mutex lock in shared memory and init mutex lock for shared memory
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);

	busy_workers_lock = (void *)&busy_workers[1];
	if (pthread_mutex_init(busy_workers_lock, &mutexattr))
	{
		PRB_ERROR("main", "Failed to initialize mutex ock");
		exit(EXIT_FAILURE);
	}

	PRB_DEBUG("main", "Starting workers...");

	child = malloc(sizeof(pid_t) * child_len);

	pid_t pid = 0;
	for (int i = 0; i < child_len; i++) {
		pid = fork();
		if (pid == 0)
			break;
		child[i] = pid;
	}

	WORKER_ID = getpid();

	// sqlite database has to be opened after fork or it may corrupt the file
	prb.db = prb_open_database("probeably.db");
	if (!prb.db)
		return EXIT_FAILURE;

	if (pid != 0) {
		// parent path
		if (prb_init_database(prb.db) == -1)
			return EXIT_FAILURE; // TODO: kill childrens

		ev_child_init(&cw, child_callback, pid, 0);
		ev_child_start(EV_DEFAULT_ &cw);
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
	pthread_mutex_destroy(busy_workers_lock);
	munmap(busy_workers, 4 + sizeof(pthread_mutex_lock));
	redisAsyncFree(c);
	free(child);

	return 0;
}
