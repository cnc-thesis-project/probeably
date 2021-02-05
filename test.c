#include <stdio.h>
#include "probeable.h"
#include "module.h"
#include "module-tls.h"

int main(int argc, char *argv[])
{
	struct module *mod = &module_tls;
	struct probeable p;

	mod->init(&p);
	mod->run(&p);
	mod->cleanup(&p);
}
