#include "module.h"
#include "module-geoip.h"
#include "database.h"

static const char *geoip_file = "./dataset/ip2asn-v4-u32.tsv";

struct geoip_table
{
	uint32_t ip_start, ip_end;
	uint32_t asn;
	char *country;
	char *as_desc;
};

static struct geoip_table *geoip_map = 0;
static int geoip_len = 0;

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
	FILE *f = fopen(geoip_file, "r");
	if (!f) {
		PRB_ERROR("geoip", "Failed to open geoip dataset");
		return;
	}

	// the "buffer" size, it's temporary and will be shrinked when the whole tsv has been parsed
	geoip_len = 512*1024;
	geoip_map = malloc(sizeof(struct geoip_table) * geoip_len);

	char line[256];
	int lines = 0;

	while (fgets(line, sizeof(line), f)) {
		if (lines == geoip_len) {
			geoip_len *= 2;
			geoip_map = realloc(geoip_map, sizeof(struct geoip_table) * geoip_len);
		}

		struct geoip_table *g = &geoip_map[lines];

		g->ip_start = atoi(strtok(line, "\t"));
		g->ip_end = atoi(strtok(0, "\t"));
		g->asn = atoi(strtok(0, "\t"));
		// not interested in ip range that is not routed
		if (g->asn == 0)
			continue;
		g->country = strdup(strtok(0, "\t"));
		g->as_desc = strdup(strtok(0, "\n"));


		lines++;
	}

	// shrink to minimum size
	geoip_len = lines;
	geoip_map = realloc(geoip_map, sizeof(struct geoip_table) * geoip_len);

	PRB_DEBUG("geoip", "loaded %d lines of geoip routes", geoip_len);

	fclose(f);
}

static void geoip_module_cleanup(struct probeably *p)
{
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
	PRB_DEBUG("geoip", "Running geoip module");

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
