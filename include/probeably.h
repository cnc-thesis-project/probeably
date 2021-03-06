#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>
#include <pthread.h>
#include <stdint.h>
#include "log.h"

#ifndef PRB_VERSION
#define PRB_VERSION "no_version"
#endif

extern int WORKER_ID;		// pid based id
extern int WORKER_INDEX;	// index based id

struct ip_con
{
	uint32_t addr;
	int count;
};

// things to put in shared memory
struct shm_data
{
	size_t works_done;
	int busy_workers;
	pthread_mutex_t busy_workers_lock;
	struct ip_con *ip_cons;
	int ip_cons_count;
	pthread_mutex_t ip_cons_lock;
	int worker_status[];
};
extern struct shm_data *shm;

struct probeably {
	sqlite3 *db;
};

#endif
