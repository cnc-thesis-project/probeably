#include <curl/curl.h>
#include <zlib.h>
#include "module.h"
#include "module-geoip.h"
#include "database.h"
#include "config.h"

static const char *database_url = "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz";
static const char *database_path = "./dataset/ip2asn-v4-u32.tsv.gz";

struct geoip_table
{
	uint32_t ip_start, ip_end;
	uint32_t asn;
	char *country;
	char *as_desc;
};

static struct geoip_table *geoip_map = 0;
static int geoip_len = 0;

static int url_download(const char *url, const char *path)
{
	FILE *f = fopen(path, "wb");
	if (!f) {
		PRB_ERROR("geoip", "Failed to create database file");
		return -1;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		PRB_ERROR("geoip", "Failed to initialize libcurl");
		fclose(f);
		return -1;
	}

	// set download url
	curl_easy_setopt(curl, CURLOPT_URL, url);
	// write to file
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);

	// send request
	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		PRB_ERROR("geoip", "Failed to download ip2asn database: %d", res);
		fclose(f);
		curl_easy_cleanup(curl);
		return -1;
	}

	fclose(f);
	curl_easy_cleanup(curl);
	return 0;
}

static char *inflate_database(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		PRB_ERROR("geoip", "Failed to open geoip dataset");
		return 0;
	}

	// get size
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	fseek(f, 0, SEEK_SET);

	// compressed data
	char *data_gz = malloc(size);
	fread(data_gz, 1, size, f);
	fclose(f);

	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	// input size
	strm.avail_in = size;
	// compressed data
	strm.next_in = (void *)data_gz;

	// needed to decompress gzip
	inflateInit2(&strm, 16+MAX_WBITS);

	// decompressed data, assuming it will be up to same size as compressed data
	char *data = 0;
	size_t data_offset = 0;

	// decompress
	do {
		size *= 2;
		data = realloc(data, size);
		// output size
		strm.avail_out = size - data_offset;
		// compressed data
		strm.next_out = (void *)(data + data_offset);

		int ret = inflate(&strm, Z_NO_FLUSH);
		switch (ret) {
			case Z_NEED_DICT:
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				PRB_ERROR("geoip", "Failed to decompress ip2asn database");
				goto fail_free;
		}

		data_offset += size - strm.avail_out;
	} while (strm.avail_out == 0);

	data = realloc(data, strm.total_out + 1);
	data[strm.total_out] = 0;

	inflateEnd(&strm);
	free(data_gz);

	return data;

fail_free:
	inflateEnd(&strm);
	free(data_gz);
	free(data);

	return 0;
}

static uint32_t ip_to_int(const char *ip)
{
	// convert ip address to unsigned integer
	uint32_t addr = 0;
	inet_pton(AF_INET, ip, &addr);

	// return in reversed byte order
	return (addr >> 24) | ((addr >> 8) & 0xff00) | ((addr << 8) & 0xff0000) | (addr << 24);
}

static struct geoip_table *find_geoip(const char *ip)
{
	// convert ip address to unsigned integer
	uint32_t addr = ip_to_int(ip);

	// perform binary search to find the corresponding geoip table for an IP address
	int l = 0;
	int r = geoip_len - 1;
	int m = (r - l) / 2;
	while (l <= r) {
		if (geoip_map[m].ip_start <= addr && addr <= geoip_map[m].ip_end)
		return &geoip_map[m];

		if (addr < geoip_map[m].ip_start)
			r = m - 1; // move to left half
		else
			l = m + 1; // move to right half

		m = l + (r - l) / 2;
	}

	return 0;
}

static void geoip_module_init(struct probeably *p)
{
	(void) p;

	// download ip2asn database file if not found locally,
	// or update if the last download time exceeds configured ttl

	int download = 0;

	if (access(database_path, F_OK) != 0) {
		download = 1;
	} else {
		struct stat attrib;
		stat(database_path, &attrib);

		if (prb_config.ip2asn_ttl >= 0 && time(0) - attrib.st_mtime >= prb_config.ip2asn_ttl)
			download = 1;
	}

	if (download) {
		PRB_DEBUG("geoip", "Downloading ip2asn database from %s", database_url);
		if (url_download(database_url, database_path) == -1)
			return; // TODO: return -1
	} else {
		PRB_DEBUG("geoip", "Using cached ip2asn database");
	}

	char *database = inflate_database(database_path);
	if (!database)
		return; // TODO: return -1

	// the "buffer" size, it's temporary and will be shrinked when the whole tsv has been parsed
	geoip_len = 512*1024;
	geoip_map = malloc(sizeof(struct geoip_table) * geoip_len);

	char *save = database;
	char *line = strtok_r(database, "\n", &save);
	int lines = 0;

	do {
		if (lines == geoip_len) {
			geoip_len *= 2;
			geoip_map = realloc(geoip_map, sizeof(struct geoip_table) * geoip_len);
		}

		struct geoip_table *g = &geoip_map[lines];

		char *line_tmp = strdup(line);
		g->ip_start = atoi(strtok(line_tmp, "\t"));
		g->ip_end = atoi(strtok(0, "\t"));
		g->asn = atoi(strtok(0, "\t"));
		// not interested in ip range that is not routed
		if (g->asn == 0) {
			free(line_tmp);
			continue;
		}
		g->country = strdup(strtok(0, "\t"));
		g->as_desc = strdup(strtok(0, "\n"));

		free(line_tmp);

		lines++;
	} while ((line = strtok_r(0, "\n", &save)));

	// shrink to minimum size
	geoip_len = lines;
	geoip_map = realloc(geoip_map, sizeof(struct geoip_table) * geoip_len);

	PRB_DEBUG("geoip", "loaded %d lines of geoip routes", geoip_len);

	free(database);
}

static void geoip_module_cleanup(struct probeably *p)
{
	(void) p;
	for (int i = 0; i < geoip_len; i++) {
		free(geoip_map[i].country);
		free(geoip_map[i].as_desc);
	}

	free(geoip_map);
	geoip_map = 0;
	geoip_len = 0;
}

static int geoip_module_run(struct probeably *p, struct prb_request *r, struct prb_socket *s)
{
	(void) s;
	struct geoip_table *g = find_geoip(r->ip);

	if (!g) {
		PRB_DEBUG("geoip", "No geoip info found for address %s", r->ip);
		return 0;
	}

	char line[256];
	sprintf(line, "%s\t%u\t%s", g->country, g->asn, g->as_desc);

	PRB_DEBUG("geoip", "%s, Country: %s, AS: %u (%s)", r->ip, g->country, g->asn, g->as_desc);
	prb_write_data(p, r, "geoip", "info", line, strlen(line), PRB_DB_SUCCESS);

	return 0;
}

struct prb_module module_geoip = {
	.name = "geoip",
	.init = geoip_module_init,
	.cleanup = geoip_module_cleanup,
	.run = geoip_module_run,
};
