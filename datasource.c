#include <pthread.h>

#include "xfc.h"

struct datasource **ds;
int nrdatasource;

pthread_mutex_t ds_mutex;
pthread_mutexattr_t ds_mutex_attr;


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

int datasource_prepare(struct datasource *ds, void *arg) {
	int st = 1;
    pthread_mutex_lock(&ds_mutex);
	if (ds->prepare) {
		st = ds->prepare(ds, arg);
	}

	return st;
}

int datasource_finish(struct datasource *ds, void *arg) {
	int st = 1;
	if (ds->finish) {
		st = ds->finish(ds, arg);
	}
    pthread_mutex_unlock(&ds_mutex);

	return st;
}

void datasource_init(void) {
	pthread_mutexattr_init(&ds_mutex_attr);
	pthread_mutex_init(&ds_mutex, &ds_mutex_attr);
	datasource_register (&datasource_mysql);
	datasource_register (&datasource_axfr);
	datasource_register (&datasource_ldap);
}
