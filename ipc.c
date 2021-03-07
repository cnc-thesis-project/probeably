#include <pthread.h>
#include <hiredis/hiredis.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ev.h>
#include "probeably.h"
#include "config.h"
#include "ipc.h"
#include "module.h"

#define IPC_BUFFER_SIZE 32
static char ipc_buffer[IPC_BUFFER_SIZE];
static struct ev_io w_accept;

static void ipc_command_monitor();

static char ipc_command_names[] = {
	"monitor",
};

static void(*ipc_commands[])(int) = {
	ipc_command_monitor,
};

static int ipc_run_command(char *name, int sd)
{
	for (size_t i = 0; i < sizeof(ipc_command_names); i++) {
		if (!strcmp(&ipc_command_names[i], name)) {
			ipc_commands[i](sd);
			return 0;
		}
	}

	return -1;
}

static void ipc_read_callback(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	ssize_t read_len;

	if (EV_ERROR & revents) {
		PRB_ERROR("ipc", "Invalid event");
		return;
	}

	PRB_DEBUG("ipc", "Reading from client...");
	read_len = recv(watcher->fd, ipc_buffer, IPC_BUFFER_SIZE, 0);

	if (read_len < 0) {
		PRB_ERROR("ipc", "Read error");
		return;
	}

	if (read_len == 0) {
		PRB_ERROR("ipc", "Peer is shutting down");
		goto ipc_read_callback_clean;
	}

	ipc_buffer[read_len - 1] = '\0';

	PRB_DEBUG("ipc", "IPC message received: '%s'", ipc_buffer);

	if (ipc_run_command(ipc_buffer, watcher->fd) < 0) {
		PRB_ERROR("ipc", "Failed running command '%s'", ipc_buffer);
	} else {
		PRB_INFO("ipc", "Command '%s' executed successfully", ipc_buffer);
	}

ipc_read_callback_clean:
	ev_io_stop(loop, watcher);
	shutdown(watcher->fd, SHUT_RDWR);
	close(watcher->fd);
	free(watcher);
}

static void ipc_accept_callback(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	PRB_DEBUG("ipc", "Accepting client...");
	int client_sd;
	struct sockaddr_un client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct ev_io *w_client = (struct ev_io*) malloc(sizeof(struct ev_io));

	if (EV_ERROR & revents) {
		PRB_ERROR("ipc", "Invalid event");
		return;
	}

	client_sd = accept(watcher->fd, (struct sockaddr *) &client_addr, &client_len);

	if (client_sd < 0) {
		PRB_ERROR("ipc", "Error accepting client");
		return;
	}

	ev_io_init(w_client, ipc_read_callback, client_sd, EV_READ);
	ev_io_start(loop, w_client);
}

static void ipc_command_monitor(int sd)
{
	PRB_DEBUG("ipc", "Running monitor command");
	// TODO: verify the proper size to alloc.
	int send_buffer_len = 4096 + worker_len*32;
	char *send_buffer = malloc(send_buffer_len);

	// maybe there is no need to lock the mutex?
	// it's just printing status and do not hurt if it occurs small error
	pthread_mutex_lock(&shm->busy_workers_lock);

	redisReply *reply = redisCommand(monitor_con, "LLEN port");
	size_t works_in_queue = reply->integer;
	freeReplyObject(reply);

	static size_t prev_works_in_queue = 0;
	static size_t prev_works_done = 0;
	snprintf(send_buffer, send_buffer_len, "Busy workers [%d/%d]\n", shm->busy_workers, worker_len);
	send(sd, send_buffer, strlen(send_buffer), 0);
	snprintf(send_buffer, send_buffer_len, "Works done in total: %zd (%+zd)\n", shm->works_done, shm->works_done - prev_works_done);
	send(sd, send_buffer, strlen(send_buffer), 0);
	snprintf(send_buffer, send_buffer_len, "Works in queue: %zd (%+zd)\n", works_in_queue, works_in_queue - prev_works_in_queue);
	send(sd, send_buffer, strlen(send_buffer), 0);
	prev_works_done = shm->works_done;
	prev_works_in_queue = works_in_queue;

	// print status color explanation
	snprintf(send_buffer, send_buffer_len, "Status color: ");
	send(sd, send_buffer, strlen(send_buffer), 0);
	for (int i = 0; i < WORKER_STATUS_LEN; i++) {
		snprintf(send_buffer, send_buffer_len, "%s%s\x1b[0m ", worker_status_color[i], worker_status_name[i]);
		send(sd, send_buffer, strlen(send_buffer), 0);
	}
	snprintf(send_buffer, send_buffer_len, "\n");
	send(sd, send_buffer, strlen(send_buffer), 0);

	// print worker status visually
	int width = 50;
	for (int y = 0; y < worker_len; y += width) {
		for (int x = 0; x < width && x + y < worker_len; x++) {
			int status = shm->worker_status[x + y];
			char working = (status != WORKER_STATUS_IDLE ? '#' : '.');
			snprintf(send_buffer, send_buffer_len, "%s%c\x1b[0m", worker_status_color[status], working);
			send(sd, send_buffer, strlen(send_buffer), 0);
		}
		snprintf(send_buffer, send_buffer_len, "\n");
		send(sd, send_buffer, strlen(send_buffer), 0);
	}

	pthread_mutex_unlock(&shm->busy_workers_lock);
	free(send_buffer);
}

int ipc_init()
{
	PRB_DEBUG("ipc", "Initializing IPC...");
	int sd;
	struct sockaddr_un addr;

	if ((sd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		PRB_ERROR("ipc", "Error creating socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), prb_config.ipc_socket);
	unlink(addr.sun_path);

	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		PRB_ERROR("ipc", "Failed binding to socket: %s", strerror(errno));
		return -1;
	}

	if (listen(sd, 2) < 0) {
		PRB_ERROR("ipc", "Failed listen.");
		return -1;
	}

	ev_io_init(&w_accept, ipc_accept_callback, sd, EV_READ);
	ev_io_start(EV_DEFAULT_ &w_accept);

	PRB_DEBUG("ipc", "IPC initialized");
	return 0;
}
