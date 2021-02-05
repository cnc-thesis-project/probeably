PROGRAM := probeably

INC_DIR := ./hiredis/
CFLAGS := -I$(INC_DIR)
LD := -lev

all: $(PROGRAM)

$(PROGRAM): main.c
	$(CC) -o $(PROGRAM) $(CFLAGS) main.c ./hiredis/libhiredis.a $(LD)
