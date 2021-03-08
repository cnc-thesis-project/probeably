#include <arpa/inet.h>
#include "util.h"

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

uint32_t ip_to_int(const char *ip)
{
	// convert ip address to unsigned integer
	uint32_t addr = 0;
	inet_pton(AF_INET, ip, &addr);

	// return in reversed byte order
	return addr;
}

