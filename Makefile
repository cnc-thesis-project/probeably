PROGRAM := probeably
VERSION := $(shell git describe --always)

INCLUDE := -I./hiredis/ -I./include
CFLAGS := $(INCLUDE) -fsanitize=address -ggdb -D VERSION=\"$(VERSION)\"
LDFLAGS := -lasan -lwolfssl -lm -lev
SOURCES := main.c module-http.c socket.c

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SOURCES) ./hiredis/libhiredis.a $(LDFLAGS)

clean:
	rm -f test $(PROGRAM)
