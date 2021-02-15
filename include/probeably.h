#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>

extern int WORKER_ID;

#define PRB_DEBUG(LABEL, ARGS...) printf("[%d-%s] ", WORKER_ID, LABEL); printf(ARGS);

struct probeably {
	sqlite3 *db;
};

#endif
