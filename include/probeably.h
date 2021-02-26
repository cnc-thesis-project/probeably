#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>
#include <pthread.h>
#include "log.h"

#ifndef PRB_VERSION
#define PRB_VERSION "no_version"
#endif

extern int WORKER_ID;		// pid based id
extern int WORKER_INDEX;	// index based id

// things to put in shared memory
struct shm_data
{
	size_t works_done;
	int busy_workers;
	pthread_mutex_t busy_workers_lock;
	int worker_status[];
};
extern struct shm_data *shm;

struct probeably {
	sqlite3 *db;
};

#endif
