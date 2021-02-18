#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>
#include "log.h"

extern int WORKER_ID;

struct probeably {
	sqlite3 *db;
};

#endif
