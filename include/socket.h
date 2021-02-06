#ifndef _PROBEABLY_SOCKET_H
#define _PROBEABLY_SOCKET_H

#define PRB_SOCKET_RAW (1 << 0)
#define PRB_SOCKET_SSL (1 << 1)

extern struct prb_socket;

ssize_t write(struct prb_socket, const void *buf, size_t count);

ssize_t read(struct prb_socket, void *buf, size_t count);

#endif
