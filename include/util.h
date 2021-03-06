#ifndef _PROBEABLY_UTIL_H
#define _PROBEABLY_UTIL_H

#include <time.h>
#include <stdint.h>

struct timespec start_timer();
float stop_timer(struct timespec start);
uint32_t ip_to_int(const char *ip);

#endif
