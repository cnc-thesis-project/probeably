#ifndef _PROBEABLY_PROBEABLY_H
#define _PROBEABLY_PROBEABLY_H

#include <stdio.h>

#define PRB_DEBUG(LABEL, ARGS...) printf("[%s] ", LABEL); printf(ARGS);

struct probeably {
	FILE *fp;
};

#endif
