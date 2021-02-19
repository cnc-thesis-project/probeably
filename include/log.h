#ifndef _PROBEABLY_LOG_H
#define _PROBEABLY_LOG_H

#include <stdio.h>
#include "probeably.h"

// `do { ... } while (0)` is necessary to use multiple statement in macro,
// otherwise it can mess up stuff like single if-statement.
#define PRB_DEBUG(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s-debug]\033[0m ", WORKER_ID, LABEL); printf(ARGS); printf("\n"); } while(0)
#define PRB_INFO(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s-info]\033[0m ", WORKER_ID, LABEL); printf(ARGS); } while(0)
#define PRB_ERROR(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s-error]\033[0m \033[41m", WORKER_ID, LABEL); printf(ARGS); printf("\033[0m\n"); } while (0)

void print_hash_color(int num);

#endif
