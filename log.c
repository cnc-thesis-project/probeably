#include <stdio.h>
#include "log.h"

FILE *prb_log_fd;

void prb_set_log(FILE *log_fd)
{
	if (log_fd) {
		prb_log_fd = log_fd;
		setlinebuf(log_fd);
	} else {
		prb_log_fd = stdout;
	}
}

void print_hash_color(int num)
{
	num *= 2654435761;
	// limits r/g/b values to 64-191
	int r = (((num & 0xFF0000) >> 16) & 0x7f) + 64;
	int g = (((num & 0x00FF00) >> 8) & 0x7f) + 64;
	int b = ((num & 0x0000FF) & 0x7f) + 64;
	fprintf(prb_log_fd, "\033[38;2;%d;%d;%dm", r, g, b);
}
