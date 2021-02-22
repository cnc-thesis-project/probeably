#ifndef _PROBEABLY_CONFIG_H
#define _PROBEABLY_CONFIG_H

#include "ini.h"

struct _prb_config {
	int num_workers;
	int read_timeout;
	int write_timeout;
	int redownload_ip2asn;
};

extern struct _prb_config prb_config;

int prb_load_config(char *file);

#endif
