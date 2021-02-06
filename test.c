#include <stdio.h>
#include "probeably.h"
#include "module.h"
#include "module-tls.h"
#include "module-http.h"

int main(int argc, char *argv[])
{
	struct module *mod = &module_http;
	struct probeable p;

	mod->init(&p);
	mod->run(&p);
	mod->cleanup(&p);
}
