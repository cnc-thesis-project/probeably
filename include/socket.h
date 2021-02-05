#ifndef _PROBEABLY_SOCKET_H
#define _PROBEABLY_SOCKET_H

#define SOCKET_RAW 1 << 0
#define SOCKET_SSL 1 << 1

extern struct socket;

write(struct socket, const void *buf, size_t count);

read(struct socket, void *buf, size_t count);
