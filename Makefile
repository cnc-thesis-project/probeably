PROGRAM := probeably

INC_DIR := ./hiredis/
CFLAGS := -I$(INC_DIR) -fsanitize=address -ggdb
LDFLAGS := -lasan -lwolfssl -lm
TEST_SOURCES := test.c module-tls.c module-http.c socket.c

all: $(PROGRAM)

$(PROGRAM): main.c
	$(CC) -o $(PROGRAM) $(CFLAGS) main.c ./hiredis/libhiredis.a

test: $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o test -I./include $(TEST_SOURCES) $(LDFLAGS)

clean:
	rm -f test
