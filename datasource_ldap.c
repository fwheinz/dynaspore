#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <ldap.h>

#include <pthread.h>

#include "xfc.h"

int datasource_ldap_fetch_zones(struct datasource *ds, const char *name, void *arg) {
	LDAP *ldap = ds->priv;

	if (!ldap)
		return 0;

	if (name && !is_valid_dnsname(name))
		return 0;

	LDAPMessage *search_result, *entry;
	int paged = 1;
	struct berval *cookie = NULL;

	int nr = 0;
	LDAPControl *paging = NULL, **serverControls;
	do {
		ldap_create_page_control(ldap, 1000, cookie, 0, &paging);
		LDAPControl *serverControlsArray[2] = {paging, NULL};
	       	serverControls = serverControlsArray;

		int result = ldap_search_ext_s(
				ldap,
				"ou=hosts,dc=noc",
				LDAP_SCOPE_SUBTREE,
				"(objectClass=dNSDomain)",
				NULL,
				0,
				serverControls,
				NULL,
				NULL,
				0,
				&search_result
				);

		if (result != LDAP_SUCCESS) {
			fprintf(stderr, "ldap_search_ext_s failed: %s\n", ldap_err2string(result));
			ldap_control_free(paging);
			return 0;
		}

		char *attribute, **domains, **values;
		for (entry = ldap_first_entry(ldap, search_result); entry != NULL;
				entry = ldap_next_entry(ldap, entry)) {
			nr++;
			BerElement *ber;
			domains = NULL;
			for (attribute = ldap_first_attribute(ldap, entry, &ber);
					attribute != NULL;
					attribute = ldap_next_attribute(ldap, entry, ber)) {
				if (strcmp(attribute, "associatedDomain") == 0) {
					domains = ldap_get_values(ldap, entry, attribute);
					ldap_memfree(attribute);
					break;
				}
				ldap_memfree(attribute);
			}
			if (ber != NULL) ber_free(ber, 0);
			if (domains) {
				for (attribute = ldap_first_attribute(ldap, entry, &ber);
						attribute != NULL;
						attribute = ldap_next_attribute(ldap, entry, ber)) {
					char *type = NULL;
					if (strcmp(attribute, "sOARecord") == 0) {
						type = "SOA";
					} else if (strcmp(attribute, "aRecord") == 0) {
						type = "A";
					} else if (strcmp(attribute, "aAAARecord") == 0) {
						type = "AAAA";
					} else if (strcmp(attribute, "mXRecord") == 0) {
						type = "MX";
					} else if (strcmp(attribute, "nSRecord") == 0) {
						type = "NS";
					} else if (strcmp(attribute, "tXTRecord") == 0) {
						type = "TXT";
					} else if (strcmp(attribute, "cNAMERecord") == 0) {
						type = "CNAME";
					} else if (strcmp(attribute, "pTRRecord") == 0) {
						type = "PTR";
					} else if (strcmp(attribute, "sRVRecord") == 0) {
						type = "SRV";
					}

					if (type) {
						values = ldap_get_values(ldap, entry, attribute);
						if (values != NULL) {
							for (int i = 0; domains[i] != NULL; i++) {
								for (int j = 0; values[j] != NULL; j++) {
									if (strcmp(type, "SOA") == 0)
										fetch_zone(domains[i], 1);
									create_record(domains[i], type, values[j], NULL, NULL);
								}
							}
						}
						ldap_value_free(values);
					}
					ldap_memfree(attribute);
				}
				if (ber != NULL) ber_free(ber, 0);
				free(domains);
				domains = NULL;
			}

		}
		ldap_control_free(paging);

		LDAPControl **returnedControls = NULL;
		result = ldap_parse_result(ldap, search_result, NULL, NULL, NULL, NULL, &returnedControls, 0);
		ldap_parse_page_control(ldap, returnedControls, NULL, &cookie);
		if (cookie != NULL && cookie->bv_len == 0) {
			paged = 0;
		}

		ldap_msgfree(search_result);
	} while (paged);

    /*
    time_t now = time(NULL);
    MYSQL_ROW row;
    struct zone *z = NULL;
    printf("Nr allocs before: %d (%lu bytes)\n", nralloc, bytesalloc);
    int count = 0;
    while ((row = mysql_fetch_row(res))) {
	if (!row[5]) continue;
	count++;
	if (count%100000 == 0) DEBUG(1, "%d records loaded...\n", count);
        if (!z || strcmp(z->name, row[5])) {
            z = fetch_zone(row[5], 1);
            if (!z) {
                DEBUG(3, "Failed to create invalid zone %s\n", row[5]);
                continue;
            }
            if (z->last_reload != now) {
                zone_remove_records(z, -1);
                int i;
                for (i = z->nrkeys - 1; i >= 0; i--) {
                    struct dnskey *dnskey = z->keys[i];
                    int st = zone_del_key(z, dnskey);
                    if (st) {
                        xl_unref_ud(arg, dnskey->ud);
                    }
                }
                z->last_reload = now;
                const char *dsname = xl_getstring(arg, "dsname");
                    if (dsname)
                        strcpy(z->datasource, dsname);
                    else
                        strcpy(z->datasource, "unknown");
            }
        }
        char *prio = row[4];
        if (!prio)
            prio = "10";
        create_record(row[0], row[1], row[2], row[3], prio);
        nr++;
    }
    mysql_free_result(res);
    printf("Nr allocs after: %d (%lu bytes)\n", nralloc, bytesalloc);
    */

	printf("Ingested %d records\n", nr);
    return nr;
}

int datasource_ldap_prepare(struct datasource *ds, void *arg) {
    const char *host = xl_getstring(arg, "hostname");
    const char *username = xl_getstring(arg, "username");
    const char *password = xl_getstring(arg, "password");
//    const char *dbname = xl_getstring(arg, "dbname");

    LDAP *ldap;
    int result = ldap_initialize(&ldap, host);
    if (result != LDAP_SUCCESS) {
	    fprintf(stderr, "ldap_initialize failed: %s\n", ldap_err2string(result));
	    return 0;
    }

    int ldap_version = LDAP_VERSION3;
    result = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (result != LDAP_OPT_SUCCESS) {
        fprintf(stderr, "ldap_set_option (LDAP_OPT_PROTOCOL_VERSION) failed: %s\n", ldap_err2string(result));
        ldap_unbind_ext_s(ldap, NULL, NULL);
        return 0;
    }

    result = ldap_simple_bind_s(ldap, username, password);
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_simple_bind_s failed: %s\n", ldap_err2string(result));
        ldap_unbind_ext_s(ldap, NULL, NULL);
        return 0;
    }


    ds->priv = ldap;

    return 1;
}

int datasource_ldap_finish(struct datasource *ds, void *arg) {
    LDAP *ldap = ds->priv;
    if (ldap) {
        ldap_unbind_ext_s(ldap, NULL, NULL);
        ds->priv = NULL;
    }
    free(ds);

    return 1;
}

struct datasource datasource_ldap = {
    .driver = "ldap",
    .prepare = datasource_ldap_prepare,
    .zoneload = datasource_ldap_fetch_zones,
    .zonesave = NULL,
    .keyload = NULL,
    .keysave = NULL,
    .finish = datasource_ldap_finish
};

