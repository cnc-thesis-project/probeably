PROGRAM := probeably

VERSION := $(shell git describe --always)
LOG_LEVEL := 0

INCLUDE := -I./hiredis/ -I./include
CFLAGS := $(INCLUDE) \
	-fsanitize=address \
	-ggdb \
	-D PRB_VERSION=\"$(VERSION)\" \
	-D PRB_LOG_LEVEL=$(LOG_LEVEL) \
	-O3
LDFLAGS := -lasan -lwolfssl -lm -lev -lsqlite3 -lpthread
SOURCES := main.c \
	ini.c \
	config.c \
	module.c \
	socket.c \
	database.c \
	module-http.c \
	module-ssh.c \
	module-geoip.c \
	module-tls.c \
	log.c

all: $(PROGRAM)

$(PROGRAM): $(SOURCES)
	$(CC) -o $(PROGRAM) $(CFLAGS) $(SOURCES) ./hiredis/libhiredis.a $(LDFLAGS)

ip2asn:
	mkdir -p dataset
	curl -o dataset/ip2asn-v4-u32.tsv.gz https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz
	gunzip dataset/ip2asn-v4-u32.tsv.gz
	rm -f dataset/ip2asn-v4-u32.tsv.gz

clean:
	rm -f test $(PROGRAM)
