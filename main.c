#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>
#include <sqlite3.h>
#include <hiredis/async.h>
#include <unistd.h>
#include <hiredis/adapters/libev.h>
#include <sys/mman.h>
#include <getopt.h>
#include "config.h"
#include "probeably.h"
#include "module.h"
#include "socket.h"
#include "database.h"
#include "log.h"
#include "util.h"

#define SHM_SIZE (sizeof(*shm) + sizeof(int) * worker_len)

int WORKER_ID = 0;
int WORKER_INDEX = 0;

ev_timer timer;
pid_t *child = 0;
ev_child cw;
int worker_len = 32;

struct shm_data *shm;

redisContext *monitor_con = 0;
static void monitor_callback(struct ev_loop *loop, ev_timer *timer, int revent)
{
	(void)loop;
	(void)timer;
	(void)revent;

	// maybe there is no need to lock the mutex?
	// it's just printing status and do not hurt if it occurs small error
	pthread_mutex_lock(&shm->busy_workers_lock);

	redisReply *reply = redisCommand(monitor_con, "LLEN port");
	size_t works_in_queue = reply->integer;
	freeReplyObject(reply);

	static size_t prev_works_in_queue = 0;
	static size_t prev_works_done = 0;
	printf("\nBusy workers [%d/%d]\n", shm->busy_workers, worker_len);
	printf("Works done in total: %zd (%+zd)\n", shm->works_done, shm->works_done - prev_works_done);
	printf("Works in queue: %zd (%+zd)\n", works_in_queue, works_in_queue - prev_works_in_queue);
	prev_works_done = shm->works_done;
	prev_works_in_queue = works_in_queue;

	// print status color explanation
	printf("Status color: ");
	for (int i = 0; i < WORKER_STATUS_LEN; i++) {
		printf("%s%s\x1b[0m ", worker_status_color[i], worker_status_name[i]);
	}
	printf("\n");

	// print worker status visually
	int width = 50;
	for (int y = 0; y < worker_len; y += width) {
		for (int x = 0; x < width && x + y < worker_len; x++) {
			int status = shm->worker_status[x + y];
			char working = (status != WORKER_STATUS_IDLE ? '#' : '.');
			printf("%s%c\x1b[0m", worker_status_color[status], working);
		}
		printf("\n");
	}

	pthread_mutex_unlock(&shm->busy_workers_lock);
}

static void update_worker_state(int start_work)
{
	shm->worker_status[WORKER_INDEX] = WORKER_STATUS_LOCK;
	pthread_mutex_lock(&shm->busy_workers_lock);

	if (start_work) {
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_BUSY;
		shm->busy_workers++;
	} else {
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_IDLE;
		shm->works_done++;
		shm->busy_workers--;
	}
	PRB_DEBUG("main", "Busy workers [%d/%d]", shm->busy_workers, worker_len);

	pthread_mutex_unlock(&shm->busy_workers_lock);
}

static void port_callback(redisAsyncContext *c, void *r, void *privdata)
{
	PRB_DEBUG("main", "Running port callback");

	redisReply *reply = r;
	redisAsyncCommand(c, port_callback, privdata, "BLPOP port 0");

	if (!reply || reply->elements < 2)
		return;

	char *values = strdup(reply->element[1]->str);

	PRB_DEBUG("main", "Got from redis: %s", values);

	char *ip = strtok(reply->element[1]->str, ",");
	int port = atoi(strtok(0, ","));

	// protocol
	strtok(0, ",");
	int timestamp = atoi(strtok(0, ","));

	/*
	// status
	strtok(0, ",");
	// reason
	strtok(0, ",");
	//ttl
	strtok(0, ",");
	*/

	if (!ip || port < 0) {
		PRB_ERROR("main", "error: got invalid format from redis: %s", values);

		free(values);
		return;
	}

	PRB_DEBUG("main", "Start probing: %s:%d", ip, port);
	update_worker_state(1);

	struct prb_request req;
	req.ip = ip;
	req.port = port;
	req.timestamp = timestamp;

	// run the module
	struct timespec start = start_timer();
	if (port == 0)
		run_ip_modules(&req); // ip related analysis stuff, e.g. geoip
	else
		run_modules(&req); // port related

	// done with the work
	if (port == 0)
		PRB_DEBUG("main", "Finished probing port %s:%d (%fs)", req.ip, req.port, stop_timer(start));
	else
		PRB_DEBUG("main", "Finished probing host %s (%fs)", req.ip, stop_timer(start));
	update_worker_state(0);

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
	(void) w;
	(void) revents;
	ev_break(loop, EVBREAK_ALL);
	PRB_DEBUG("main", "Killing workers...");
	kill(0, SIGINT);
	PRB_DEBUG("main", "Exiting...");
	exit(EXIT_SUCCESS);
}

static void child_callback(EV_P_ ev_child *w, int revents)
{
	(void) revents;
	ev_child_stop (EV_A_ w);
	if (w->rstatus != 0) {
		PRB_ERROR("main", "Failure in worker pid %d. Exitied with status %d. Exiting...", w->pid, w->rstatus);
		redisFree(monitor_con);
		kill(0, SIGINT);
		exit(EXIT_FAILURE);
	} else {
		PRB_ERROR("main", "Worker pid %d exited with 0", w->pid);
		redisFree(monitor_con);
		kill(0, SIGINT);
		exit(EXIT_SUCCESS);
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
			"  -h, --help		Print usage.\n"
			"  -v, --version	 Print version string.\n"
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
	prb_set_log(NULL);

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
	worker_len = prb_config.num_workers;
	FILE *log_fd = NULL;
	if (prb_config.log_file) {
		log_fd = fopen(prb_config.log_file, "w");
	}
	prb_set_log(log_fd);

	prb_socket_init();
	init_modules();
	init_ip_modules();

	ev_signal signal_watcher;
	ev_signal_init(&signal_watcher, sigint_callback, SIGINT);

	// create shared memory
	shm = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!shm) {
		PRB_ERROR("main", "Failed to create shared memroy");
		exit(EXIT_FAILURE);
	}
	memset(shm, 0, SHM_SIZE);

	// init mutex lock in shared memory
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);

	if (pthread_mutex_init(&shm->busy_workers_lock, &mutexattr))
	{
		PRB_ERROR("main", "Failed to initialize mutex lock");
		exit(EXIT_FAILURE);
	}

	// get current date/time
	time_t cur_time;
	struct tm *cur_tm;

	time(&cur_time);
	cur_tm = localtime(&cur_time);

	PRB_DEBUG("main", "Starting workers...");

	child = malloc(sizeof(pid_t) * worker_len);

	pid_t pid = 0;

	for (int i = 0; i < worker_len; i++) {
		WORKER_INDEX = i;
		pid = fork();
		if (pid == 0)
			break;
		child[i] = pid;
	}

	WORKER_ID = getpid();
	redisAsyncContext *c = 0;

	if (pid != 0) {
		struct timeval timeout = {1, 500000};
		monitor_con = redisConnectWithTimeout(hostname, port, timeout);

		if (monitor_con->err) {
			PRB_ERROR("main", "Redis connection error: %s", monitor_con->errstr);
			redisFree(monitor_con);

			exit(EXIT_FAILURE);
		}

		// parent path
		ev_child_init(&cw, child_callback, pid, 0);
		ev_child_start(EV_DEFAULT_ &cw);
		ev_signal_start(EV_DEFAULT, &signal_watcher);

		if (prb_config.monitor_rate) {
			if (prb_config.log_file) {
				// activate monitoring
				ev_timer_init(&timer, monitor_callback, 0, prb_config.monitor_rate);
				ev_timer_start(EV_DEFAULT, &timer);
			} else {
				PRB_ERROR("main", "'monitor_rate' must be used together with 'log_file'");
			}
		}
	} else {
		// child path

		// if single_db is not set, open worker unique sqlite database
		int id = WORKER_ID;
		if (prb_config.single_db) {
			id = 0;
		}

		// Make sure db folder exists
		mkdir("./db", 0770);

		// Create folder for the working db files
		char db_dir[128];
		snprintf(db_dir, sizeof(db_dir), "./db/%04d-%02d-%02d_%02d-%02d-%02d",
				1900 + cur_tm->tm_year, cur_tm->tm_mon + 1, cur_tm->tm_mday,
				cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
		mkdir(db_dir, 0770);

		// Create db file
		char db_name[128];
		snprintf(db_name, sizeof(db_name), "%s/%d.db", db_dir, id);

		prb.db = prb_open_database(db_name);
		if (!prb.db)
			return EXIT_FAILURE;

		if (prb_init_database(prb.db) == -1)
			return EXIT_FAILURE;

		c = redisAsyncConnect(hostname, port);

		if (c->err) {
			PRB_ERROR("main", "Redis connection error: %s", c->errstr);
			redisAsyncFree(c);

			exit(EXIT_FAILURE);
		}

		redisLibevAttach(EV_DEFAULT_ c);
		redisAsyncSetConnectCallback(c, connect_callback);
		redisAsyncSetDisconnectCallback(c, disconnect_callback);
		redisAsyncCommand(c, port_callback, 0, "BLPOP port 0");
	}
	ev_loop(EV_DEFAULT_ 0);

	cleanup_modules();
	cleanup_ip_modules();
	sqlite3_close(prb.db);
	prb_socket_cleanup();
	pthread_mutex_destroy(&shm->busy_workers_lock);
	munmap(shm, SHM_SIZE);
	if (c)
		redisAsyncFree(c);
	if (monitor_con)
		redisFree(monitor_con);
	prb_free_config();
	free(child);

	return 0;
}
