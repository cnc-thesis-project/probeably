#ifndef _PROBEABLY_DATABASE_H
#define _PROBEABLY_DATABASE_H

#include <sqlite3.h>

sqlite3 *prb_open_database(const char *path);
int prb_init_database(sqlite3 *db);
int prb_write_data(	struct probeably *prb, const char *name, const char *type, const char *ip, int port,
					const void *data, size_t data_size, int scan_time);

#endif
