#ifndef _PROBEABLY_LOG_H
#define _PROBEABLY_LOG_H

#include <stdio.h>

#define print_hash_color(num) \
{ \
	int h = num * 2654435761; \
	int r = (((h & 0xFF0000) >> 16) & 0x7f) + 64; \
	int g = (((h & 0x00FF00) >> 8) & 0x7f) + 64; \
	int b = ((h & 0x0000FF) & 0x7f) + 64; \
	printf("\033[38;2;%d;%d;%dm", r, g, b); \
}

#define PRB_DEBUG(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s]\033[0m ", WORKER_ID, LABEL); printf(ARGS); printf("\n"); } while(0)
#define PRB_INFO(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s]\033[0m ", WORKER_ID, LABEL); printf(ARGS); } while(0)
#define PRB_ERROR(LABEL, ARGS...) do { print_hash_color(WORKER_ID); printf("[%d-%s]\033[0m \033[41m", WORKER_ID, LABEL); printf(ARGS); printf("\033[0m\n"); } while (0)

#endif
