PROGRAM := probeably

INCLUDE := -I./hiredis/ -I./include
CFLAGS := $(INCLUDE) -fsanitize=address -ggdb
LDFLAGS := -lasan -lwolfssl -lm -lev -lsqlite3
SOURCES := main.c module-tls.c module-http.c socket.c database.c

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SOURCES) ./hiredis/libhiredis.a $(LDFLAGS)

clean:
	rm -f test $(PROGRAM)
