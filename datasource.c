#include "xfc.h"

struct datasource **ds;
int nrdatasource;

struct datasource *datasource_register (struct datasource *nds) {
	struct datasource **ptr = realloc(ds, (nrdatasource+1)*sizeof(*ds));
	if (!ptr) {
		return NULL;
	}
	ds = ptr;
	ds[nrdatasource] = nds;
	nrdatasource++;

	return nds;
}

struct datasource *datasource_find (const char *driver) {
	int i;

	if (!driver)
		return NULL;

	for (i = 0; i < nrdatasource; i++) {
		if (!strcmp(ds[i]->driver, driver)) {
			struct datasource *ret = malloc(sizeof *ret);
			memcpy(ret, ds[i], sizeof *ret);
			return ret;
		}
	}

	return NULL;
}

void datasource_init(void) {
	datasource_register (&datasource_mysql);
	datasource_register (&datasource_axfr);
	datasource_register (&datasource_ldap);
}
