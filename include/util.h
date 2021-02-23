#ifndef _PROBEABLY_UTIL_H
#define _PROBEABLY_UTIL_H

#include <time.h>

struct timespec start_timer();
float stop_timer(struct timespec start);

#endif
