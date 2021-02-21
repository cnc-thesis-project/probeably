#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "ini.h"
#include "log.h"

struct _prb_config prb_config;

static int handler(void *user, const char *section, const char *name,
		const char *value)
{
	(void)user;
	PRB_DEBUG("config", "Getting key '%s' with value '%s' in section '%s'", name, value, section);

	if (!strcmp(section, "general") && !strcmp(name, "num_workers")) {
		prb_config.num_workers = atoi(value);
	}
	else if (!strcmp(section, "general") && !strcmp(name, "read_timeout")) {
		prb_config.read_timeout = atoi(value);
	}
	else if (!strcmp(section, "general") && !strcmp(name, "read_timeout")) {
		prb_config.write_timeout = atoi(value);
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
