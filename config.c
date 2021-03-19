#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "ini.h"
#include "log.h"

struct _prb_config prb_config = {0};

static int handler(void *user, const char *section, const char *name,
		const char *value)
{
	(void)user;
	PRB_DEBUG("config", "Getting key '%s' with value '%s' in section '%s'", name, value, section);

	if (!strcmp(section, "general")) {
		if (!strcmp(name, "num_workers")) {
			prb_config.num_workers = atoi(value);
		}
		else if (!strcmp(name, "read_timeout")) {
			prb_config.read_timeout = atoi(value);
		}
		else if (!strcmp(name, "write_timeout")) {
			prb_config.write_timeout = atoi(value);
		}
		else if (!strcmp(name, "ip2asn_ttl")) {
			prb_config.ip2asn_ttl = atoi(value);
		}
		else if (!strcmp(name, "single_db")) {
			prb_config.single_db = atoi(value);
		}
		else if (!strcmp(name, "log_file")) {
			prb_config.log_file = strdup(value);
		}
		else if (!strcmp(name, "monitor_rate")) {
			prb_config.monitor_rate = atof(value);
		}
		else if (!strcmp(name, "ipc_socket")) {
			prb_config.ipc_socket = strdup(value);
		}
		else if (!strcmp(name, "con_limit")) {
			prb_config.con_limit = atoi(value);
		}
		else if (!strcmp(name, "db_dir")) {
			prb_config.db_dir = strdup(value);
		}
		else if (!strcmp(name, "geoip_path")) {
			prb_config.geoip_path = strdup(value);
		}
		else if (!strcmp(name, "redis_host")) {
			prb_config.redis_host = strdup(value);
		}
		else if (!strcmp(name, "redis_port")) {
			prb_config.redis_port = atoi(value);
		}
		else if (!strcmp(name, "jarm_script")) {
			prb_config.jarm_script = strdup(value);
		}
		else if (!strcmp(name, "jarm_socket")) {
			prb_config.jarm_socket = strdup(value);
		}
		else if (!strcmp(name, "jarm_workers")) {
			prb_config.jarm_workers = atoi(value);
		}
	}
	return 0;
}

int prb_load_config(char *file)
{
	if (ini_parse(file, handler, NULL) < 0) {
		PRB_ERROR("config", "Failed to load config");
		return -1;
	}

	PRB_DEBUG("config", "Config %s loaded", file);
	return 0;
}

void prb_free_config()
{
	free(prb_config.log_file);
	free(prb_config.ipc_socket);
	free(prb_config.db_dir);
	free(prb_config.geoip_path);
	free(prb_config.redis_host);
	free(prb_config.jarm_script);
	free(prb_config.jarm_socket);
}
