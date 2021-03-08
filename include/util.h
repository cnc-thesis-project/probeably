#ifndef _PROBEABLY_UTIL_H
#define _PROBEABLY_UTIL_H

#include <time.h>
#include <stdint.h>

#define REV_4BYTE(b) ((b >> 24) | ((b >> 8) & 0xff00) | ((b << 8) & 0xff0000) | (b << 24));

struct timespec start_timer();
float stop_timer(struct timespec start);
uint32_t ip_to_int(const char *ip);

#endif
