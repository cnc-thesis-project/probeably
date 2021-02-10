#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>
#include <sqlite3.h>

#define PRB_DEBUG(LABEL, ARGS...) printf("[%s] ", LABEL); printf(ARGS);

struct probeably {
	sqlite3 *db;
};

#endif
