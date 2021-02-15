#ifndef _PROBEABLY_DATABASE_H
#define _PROBEABLY_DATABASE_H

#include <sqlite3.h>

// flags
#define PRB_DB_SUCCESS (1 << 0) // the data contains a response of a successful probing
#define PRB_DB_CROPPED (1 << 1) // whether the data was too large and has been cropped

sqlite3 *prb_open_database(const char *path);
int prb_init_database(sqlite3 *db);
int prb_write_data(	struct probeably *prb, struct prb_request *req, const char *name, const char *type,
					const void *data, size_t data_size, size_t flags);

#endif
