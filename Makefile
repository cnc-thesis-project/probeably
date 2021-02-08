PROGRAM := probeably

INC_DIR := ./hiredis/
CFLAGS := -I$(INC_DIR)
TEST_SOURCES := test.c module-tls.c module-http.c socket.c

all: $(PROGRAM)

$(PROGRAM): main.c
	$(CC) -o $(PROGRAM) $(CFLAGS) main.c ./hiredis/libhiredis.a

test: $(TEST_SOURCES)
	$(CC) -o test -I./include $(TEST_SOURCES) -lwolfssl -lm

clean:
	rm -f test
