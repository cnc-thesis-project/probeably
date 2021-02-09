PROGRAM := probeably

INCLUDE := -I./hiredis/ -I./include
CFLAGS := $(INCLUDE) -fsanitize=address -ggdb
LDFLAGS := -lasan -lwolfssl -lm -lev
SOURCES := main.c module-http.c socket.c

all: $(PROGRAM)

$(PROGRAM): main.c $(SOURCES)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SOURCES) ./hiredis/libhiredis.a $(LDFLAGS)

clean:
	rm -f test $(PROGRAM)
