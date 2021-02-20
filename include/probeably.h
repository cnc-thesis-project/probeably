#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>
#include "log.h"

#ifndef PRB_VERSION
#define PRB_VERSION "no_version"
#endif

extern int WORKER_ID;

struct probeably {
	sqlite3 *db;
};

#endif
