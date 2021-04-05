#include <sqlite3.h>
#include "probeably.h"
#include "module.h"
#include "time.h"

sqlite3 *prb_open_database(const char *path)
{
	sqlite3 *db = 0;
	int rc = sqlite3_open(path, &db);
	if (rc != SQLITE_OK) {
		PRB_ERROR("database", "Failed to open sqlite3 database file '%s': %s", path, sqlite3_errmsg(db));
		return 0;
	}

	// set one hour timeout
	// this is only relevant for single_db, which should only be used for debugging purpose
	sqlite3_busy_timeout(db, 3600 * 1000);

	return db;
}

int prb_init_database(sqlite3 *db)
{
	// name: the name of the module that probed
	// type: what the data contains, used to help pre-processor to determine the "phase"
	// ip: probed ip address
	// port: probed port
	// data: data (o.O)
	// scan_time: time the masscan got SYN-ACK from the port
	// probe_time: time the module stored this data into database
	// flags: each bits representing a flag (see database.h for details)
	// pid: the pid of worker that stored the data
	// uuid: uuid of masscan iteration

	char *query =	"CREATE TABLE IF NOT EXISTS Probe(name TEXT, type TEXT, ip TEXT, port INT"
					", data BLOB, scan_time INT, probe_time INT, flags INT, pid INT, uuid TEXT);";
	char *err_msg = 0;

	int rc = sqlite3_exec(db, query, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		PRB_ERROR("database", "Failed to create database table:\n%s", err_msg);
		return -1;
	}

	return 0;
}

int prb_write_data(	struct probeably *prb, struct prb_request *req, const char *name, const char *type,
					const void *data, size_t data_size, size_t flags)
{
	shm->worker_status[WORKER_INDEX] = WORKER_STATUS_DB_WRITE;
	PRB_DEBUG("database", "Writing %zd bytes to database", data_size);
	char *query = "INSERT INTO Probe VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
	sqlite3_stmt *res = 0;

	int rc = sqlite3_prepare_v2(prb->db, query, -1, &res, 0);
	if (rc != SQLITE_OK) {
		shm->worker_status[WORKER_INDEX] = WORKER_STATUS_BUSY;
		PRB_ERROR("database", "Failed to compile statement:\n%s", sqlite3_errmsg(prb->db));
		return -1;
	}

	sqlite3_bind_text(res, 1, name, -1, 0);
	sqlite3_bind_text(res, 2, type, -1, 0);
	sqlite3_bind_text(res, 3, req->ip, -1, 0);
	sqlite3_bind_int(res, 4, req->port);
	sqlite3_bind_blob(res, 5, data, data_size, 0);
	sqlite3_bind_int(res, 6, req->timestamp);
	sqlite3_bind_int(res, 7, time(0));
	sqlite3_bind_int(res, 8, flags);
	sqlite3_bind_int(res, 9, WORKER_ID);
	sqlite3_bind_text(res, 10, req->uuid, -1, 0);

	rc = sqlite3_step(res);
	shm->worker_status[WORKER_INDEX] = WORKER_STATUS_BUSY;

	if (rc != SQLITE_DONE) {
		PRB_ERROR("database", "Failed to execute statement:\n%s", sqlite3_errmsg(prb->db));
		return -1;
	}

	sqlite3_finalize(res);

	PRB_DEBUG("database", "Data written: name=%s, type=%s, ip=%s, port=%d, flags=%zx",
				name, type, req->ip, req->port, flags);

	return 0;

}
