PROGRAM := probeably
VERSION := $(shell git describe --always)

INCLUDE := -I./hiredis/ -I./include
CFLAGS := $(INCLUDE) -fsanitize=address -ggdb -D PRB_VERSION=\"$(VERSION)\"
LDFLAGS := -lasan -lwolfssl -lm -lev -lsqlite3
SOURCES := main.c socket.c database.c module-http.c module-ssh.c

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SOURCES) ./hiredis/libhiredis.a $(LDFLAGS)

clean:
	rm -f test $(PROGRAM)
