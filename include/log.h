#ifndef _PROBEABLY_LOG_H
#define _PROBEABLY_LOG_H

#include <stdio.h>
#include "probeably.h"

#ifndef PRB_LOG_LEVEL
	#define PRB_LOG_LEVEL 0
#endif

// `do { ... } while (0)` is necessary to use multiple statement in macro,
// otherwise it can mess up stuff like single if-statement.

#if PRB_LOG_LEVEL < 1
	#define PRB_DEBUG(LABEL, ...) do { print_hash_color(WORKER_ID); printf("[%d-%s-debug]\033[0m ", WORKER_ID, LABEL); printf(__VA_ARGS__); printf("\n"); } while(0)
#else
	#define PRB_DEBUG
#endif

#if PRB_LOG_LEVEL < 2
	#define PRB_INFO(LABEL, ...) do { print_hash_color(WORKER_ID); printf("[%d-%s-info]\033[0m ", WORKER_ID, LABEL); printf(__VA_ARGS__); } while(0)
#else
	#define PRB_INFO
#endif

#if PRB_LOG_LEVEL < 3
	#define PRB_ERROR(LABEL, ...) do { print_hash_color(WORKER_ID); printf("[%d-%s-error]\033[0m \033[41m", WORKER_ID, LABEL); printf(__VA_ARGS__); printf("\033[0m\n"); } while (0)
#else
	#define PRB_ERROR
#endif

void print_hash_color(int num);
#endif
