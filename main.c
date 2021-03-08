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
#include "ipc.h"
#include "util.h"

// size of shm struct + size of worker status array + size of currently processing ip array
#define SHM_SIZE (sizeof(*shm) + sizeof(int) * worker_len + sizeof(struct ip_con) * worker_len)

int WORKER_ID = 0;
int WORKER_INDEX = 0;

ev_timer timer;
pid_t *child = 0;
ev_child cw;
int worker_len = 32;

struct shm_data *shm;

redisContext *monitor_con = 0;

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

	pthread_mutex_unlock(&shm->busy_workers_lock);
}

static int update_ip_con(struct ip_con *ip_cons, int *size, char const *ip, int delta)
{
	// convert ip address to unsigned integer
	uint32_t addr = ip_to_int(ip);

	// perform binary search to find the corresponding geoip table for an IP address
	int l = 0;
	int r = *size - 1;
	int m = (r - l) / 2;
	while (l <= r) {
		if (ip_cons[m].addr == addr) {
			// found ip in ip_con table
			if ((ip_cons[m].count + delta <= prb_config.con_limit && ip_cons[m].count + delta >= 0)
					|| prb_config.con_limit <= 0) {
				ip_cons[m].count += delta;
				if (ip_cons[m].count == 0) {
					memmove(&ip_cons[m], &ip_cons[m+1], (*size - m - 1) * sizeof(struct ip_con));
					(*size)--;
				}
				return 0;
			} else {
				return -1;
			}
		}

		if (addr < ip_cons[m].addr)
			r = m - 1; // move to left half
		else
			l = m + 1; // move to right half

		m = l + (r - l) / 2;
	}

	if (delta < 0)
		return -1; // should never happen...

	// ip not found in table, add it
	// m has the index that the addr should have, so just insert there and it's sorted

	memmove(&ip_cons[m+1], &ip_cons[m], (*size - m) * sizeof(struct ip_con));
	ip_cons[m].count = delta;
	ip_cons[m].addr = addr;
	(*size)++;

	return 0;
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

	update_worker_state(1);

	// make sure that not too many works with the same ip address
	// but ip modules bypasses this since they don't talk with the server at all
	if (port > 0) {
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_CON_WAIT;
		for (;;) {
			pthread_mutex_lock(&shm->ip_cons_lock);
			if (update_ip_con(shm->ip_cons, &shm->ip_cons_count, ip, 1)) {
				// too many connections, wait and check again
				pthread_cond_wait(&shm->ip_cons_cv, &shm->ip_cons_lock);
				pthread_mutex_unlock(&shm->ip_cons_lock);
				continue;
			}

			// allowed to connect to the server
			pthread_mutex_unlock(&shm->ip_cons_lock);
			break;
		}
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_BUSY;
	}

	PRB_DEBUG("main", "Start probing: %s:%d", ip, port);

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
		PRB_DEBUG("main", "Finished probing host %s (%fs)", req.ip, stop_timer(start));
	else
		PRB_DEBUG("main", "Finished probing port %s:%d (%fs)", req.ip, req.port, stop_timer(start));

	if (port > 0) {
		// decrease the ip connection counter
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_LOCK;
		pthread_mutex_lock(&shm->ip_cons_lock);

		update_ip_con(shm->ip_cons, &shm->ip_cons_count, ip, -1);
		// wake up all workers that are waiting for their working ip to be available
		pthread_cond_broadcast(&shm->ip_cons_cv);

		pthread_mutex_unlock(&shm->ip_cons_lock);
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_BUSY;
	}

	update_worker_state(0);

	free(values);
}

static void connect_callback(const redisAsyncContext *c, int status)
{
	if (status != REDIS_OK) {
		PRB_ERROR("main", "Failed to connect ( ╥ _╥): %s", c->errstr);
		exit(EXIT_FAILURE);
	}
	PRB_DEBUG("main", "Connected! ( ^ 3^)");
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
		if (monitor_con) {
			redisFree(monitor_con);
		}
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

	PRB_INFO("main", "Starting probeably %s", PRB_VERSION);

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
	signal(SIGPIPE, SIG_IGN);

	// create shared memory
	shm = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!shm) {
		PRB_ERROR("main", "Failed to create shared memroy");
		exit(EXIT_FAILURE);
	}
	memset(shm, 0, SHM_SIZE);

	// point ip_cons to right place in the shared memory
	shm->ip_cons = (void *)((size_t)shm + offsetof(struct shm_data, worker_status) + sizeof(int) * worker_len);

	// init mutex lock in shared memory
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);

	if (pthread_mutex_init(&shm->busy_workers_lock, &mutexattr))
	{
		PRB_ERROR("main", "Failed to initialize mutex lock");
		exit(EXIT_FAILURE);
	}
	if (pthread_mutex_init(&shm->ip_cons_lock, &mutexattr))
	{
		PRB_ERROR("main", "Failed to initialize mutex lock");
		exit(EXIT_FAILURE);
	}

	// init condition variable in shared memory
	pthread_condattr_t cattr;
	pthread_condattr_init(&cattr);
	pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);

	if (pthread_cond_init(&shm->ip_cons_cv, &cattr))
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
		// Init IPC socket
		if (ipc_init() < 0) {
			PRB_ERROR("main", "IPC initialization failed. Exiting...");
			// TODO: clean
			exit(EXIT_FAILURE);
		}

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
		snprintf(db_dir, sizeof(db_dir), "./db/%04d-%02d-%02d_%02dh%02dm%02ds",
				1900 + cur_tm->tm_year, cur_tm->tm_mon + 1, cur_tm->tm_mday,
				cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
		mkdir(db_dir, 0770);

		// create symlink 'latest' pointing to the folder
		remove("./db/latest");
		symlink(strlen("./db/") + db_dir, "./db/latest");

		// Create db file
		char db_name[256];
		snprintf(db_name, sizeof(db_name), "%s/%d.db", db_dir, id);

		prb.db = prb_open_database(db_name);
		if (!prb.db)
			return EXIT_FAILURE;

		// for single db, only worker with index 0 initializes the db
		// for multi db, everyone initializes the db
		if ((!prb_config.single_db || WORKER_INDEX == 0) && prb_init_database(prb.db) == -1)
			return EXIT_FAILURE;
		else
			sleep(1); // give some time to initialize database table

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
	pthread_mutex_destroy(&shm->ip_cons_lock);
	pthread_cond_destroy(&shm->ip_cons_cv);
	munmap(shm, SHM_SIZE);
	if (c)
		redisAsyncFree(c);
	if (monitor_con)
		redisFree(monitor_con);
	prb_free_config();
	free(child);

	return 0;
}
