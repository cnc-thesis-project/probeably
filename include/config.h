#ifndef _PROBEABLY_CONFIG_H
#define _PROBEABLY_CONFIG_H

#include "ini.h"

struct _prb_config {
	int num_workers;
	int read_timeout;
	int write_timeout;
	int ip2asn_ttl;
	int single_db;
	char *log_file;
	float monitor_rate;
	int con_limit;
	char *ipc_socket;
	char *db_dir;
	char *geoip_path;
	char *redis_host;
	int redis_port;
	char *jarm_script;
	char *jarm_socket;
	int jarm_workers;
	int max_pending_requests;
};

extern struct _prb_config prb_config;

int prb_load_config(char *file);
void prb_free_config();

#endif
