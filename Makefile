PROGRAM := probeably

INC_DIR := ./hiredis/
CFLAGS := -I$(INC_DIR)
TEST_SOURCES := test.c module-tls.c module-http.c

all: $(PROGRAM)

$(PROGRAM): main.c
	$(CC) -o $(PROGRAM) $(CFLAGS) main.c ./hiredis/libhiredis.a

test: test.c module-tls.c
	$(CC) -o test -I./include -lwolfssl $(TEST_SOURCES)
