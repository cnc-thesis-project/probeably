#include "log.h"

void print_hash_color(int num)
{
	num *= 2654435761;
	// limits r/g/b values to 64-191
	int r = (((num & 0xFF0000) >> 16) & 0x7f) + 64;
	int g = (((num & 0x00FF00) >> 8) & 0x7f) + 64;
	int b = ((num & 0x0000FF) & 0x7f) + 64;
	printf("\033[38;2;%d;%d;%dm", r, g, b);
}

struct timespec start_timer()
{
	struct timespec start;
	clock_gettime(CLOCK_REALTIME, &start);
	return start;
}

float stop_timer(struct timespec start)
{
	struct timespec end = start_timer();
	return ((end.tv_sec - start.tv_sec) * (long)1e9 + (end.tv_nsec - start.tv_nsec)) / 1000000000.0f;
}

