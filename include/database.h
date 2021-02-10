#ifndef _PROBEABLY_DATABASE_H
#define _PROBEABLY_DATABASE_H

#include <sqlite3.h>

sqlite3 *prb_open_database(const char *path);
int prb_init_database(sqlite3 *db);
int prb_write_data(	sqlite3 *db, const char *name, const char *type, const char *ip, int port,
					const char *data, int scan_time);

#endif
