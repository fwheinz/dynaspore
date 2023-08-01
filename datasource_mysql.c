#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mysql.h>

#include <pthread.h>

#include "xfc.h"

int datasource_mysql_fetch_zones(struct datasource *ds, const char *name, void *arg) {
    int nr = 0;
    MYSQL *con = ds->priv;

    if (!con)
        return 0;

    if (name && !is_valid_dnsname(name))
        return 0;

    char query[1024] = "SELECT DISTINCT records.name,records.type,records.content,records.ttl,records.prio,domains.name,domains.id FROM records LEFT JOIN domains ON domains.id=records.domain_id WHERE domains.id IS NOT NULL";
    if (name && *name) {
        sprintf(query + strlen(query), " AND domains.name = '%s'", name);
    }
    sprintf(query+strlen(query), " ORDER BY records.domain_id,records.name,records.type");
    mysql_query(con, query);
    MYSQL_RES *res = mysql_use_result(con);
    if (!res) {
        DEBUG(1, "%s: Error querying zones: %s\n", ds->driver, mysql_error(con));
        return 0;
    }
    time_t now = time(NULL);
    MYSQL_ROW row;
    struct zone *z = NULL;
    printf("Nr allocs before: %d (%lu bytes)\n", nralloc, bytesalloc);
    while ((row = mysql_fetch_row(res))) {
        if (!z || strcmp(z->name, row[5])) {
            z = fetch_zone(row[5], 1);
            if (!z) {
                DEBUG(1, "Failed to create invalid zone %s\n", row[5]);
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

    return nr;
}

static long mysql_get_zone_id(MYSQL *con, struct zone *z) {
    int l = strlen(z->name);
    char query[l * 2 + 100];

    int pos = snprintf(query, sizeof (query), "SELECT id FROM domains WHERE name='");
    pos += mysql_real_escape_string(con, query + pos, z->name, strlen(z->name));
    query[pos] = '\'';
    query[pos + 1] = '\0';
    int st = mysql_query(con, query);
    if (st != 0) {
        DEBUG(1, "mysql_get_zone_id: %s\n", mysql_error(con));
        return -1;
    }

    MYSQL_RES *res = mysql_use_result(con);
    if (st != 0) {
        DEBUG(1, "mysql_get_zone_id: %s\n", mysql_error(con));
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    long result;
    if (!row) {
        mysql_free_result(res);
        pos = snprintf(query, sizeof (query), "INSERT INTO domains (name) VALUES('");
        pos += mysql_real_escape_string(con, query + pos, z->name, strlen(z->name));
        query[pos] = '\'';
        query[pos + 1] = ')';
        query[pos + 2] = '\0';
        st = mysql_query(con, query);
        if (st != 0) {
            DEBUG(1, "mysql_get_zone_id: INSERT failed: %s", mysql_error(con));
            return -1;
        }
        st = mysql_query(con, "SELECT LAST_INSERT_ID()");
        if (st != 0) {
            DEBUG(1, "mysql_get_zone_id: LAST_INSERT_ID() failed: %s", mysql_error(con));
            return -1;
        }
        res = mysql_use_result(con);
        row = mysql_fetch_row(res);
        if (!row) {
            mysql_free_result(res);
            return -1;
        }
    }

    result = atol(row[0]);
    mysql_free_result(res);

    return result;
}

static int mysql_remove_zone_entries(MYSQL *con, long id) {
    char query[128];
    snprintf(query, sizeof (query), "DELETE FROM records WHERE domain_id=%ld", id);
    int st = mysql_query(con, query);
    if (st != 0) {
        DEBUG(1, "Error removing zone entries for ID %ld: %s\n", id, mysql_error(con));
        return -1;
    }
    return 0;
}

static void mysql_insert_record(MYSQL *con, long domain_id, char *name,
        char *type, char *content, unsigned long ttl, int prio) {
    MYSQL_BIND fields[6];
    memset(fields, 0, sizeof (fields));

    MYSQL_STMT *stmt = mysql_stmt_init(con);
    char *query = "INSERT INTO records (domain_id, name, type, content, ttl, prio) VALUES(?,?,?,?,?,?)";
    mysql_stmt_prepare(stmt, query, strlen(query));

    fields[0].buffer_type = MYSQL_TYPE_LONG;
    fields[0].buffer = &domain_id;
    fields[0].buffer_length = sizeof (domain_id);

    unsigned long namelen = strlen(name);
    fields[1].buffer_type = MYSQL_TYPE_STRING;
    fields[1].buffer = name;
    fields[1].buffer_length = namelen;
    fields[1].length = &namelen;

    unsigned long typelen = strlen(type);
    fields[2].buffer_type = MYSQL_TYPE_STRING;
    fields[2].buffer = type;
    fields[2].buffer_length = typelen;
    fields[2].length = &typelen;

    unsigned long contentlen = strlen(content);
    fields[3].buffer_type = MYSQL_TYPE_STRING;
    fields[3].buffer = content;
    fields[3].buffer_length = contentlen;
    fields[3].length = &contentlen;

    fields[4].buffer_type = MYSQL_TYPE_LONG;
    fields[4].buffer = &ttl;
    fields[4].buffer_length = sizeof (ttl);

    bool isnull = prio < 0;
    fields[5].buffer_type = MYSQL_TYPE_LONG;
    fields[5].buffer = &prio;
    fields[5].buffer_length = sizeof (prio);
    fields[5].is_null = &isnull;

    mysql_stmt_bind_param(stmt, fields);
    int st = mysql_stmt_execute(stmt);
    if (st != 0) {
        DEBUG(1, "Error inserting record: %s\n", mysql_error(con));
    } else {
    }
    mysql_stmt_close(stmt);
}

struct msze {
    struct datasource *ds;
    long id;
};

static void mysql_save_zone_entry(diptr_t di, diptr_t parent, int subtree, void* args) {
    struct msze *m = args;
    char buf[65536];
    int i = di->nrrecords;
    if (di->type == T_NSEC || di->type == T_DNSKEY || di->type == T_RRSIG) {
        return;
    }

    unsigned char *ptr = di->record;
    while (i--) {
        ptr = retrieve_record_data_dots(ptr, buf, sizeof (buf), 0);
        if (!ptr)
            break;
        char *saveptr;

        char *name = strtok_r(buf, " ", &saveptr);
        if (!name) continue;

        char *ttlstr = strtok_r(NULL, " ", &saveptr);
        if (!ttlstr) continue;
        unsigned long ttl = strtoul(ttlstr, NULL, 10);

        char *class = strtok_r(NULL, " ", &saveptr);
        if (!class) continue;

        char *type = strtok_r(NULL, " ", &saveptr);
        if (!type) continue;

        int prio = -1;
        if (typecmp(type, "MX") || typecmp(type, "SRV")) {
            char *priostr = strtok_r(NULL, " ", &saveptr);
            if (!priostr) continue;
            prio = atoi(priostr);
        }

        char *content = strtok_r(NULL, "", &saveptr);
        if (!content || !strcmp(content, "NOTPARSED")) continue;

        mysql_insert_record(m->ds->priv, m->id, name, type, content, ttl, prio);
    }
}

int datasource_mysql_save_zones(struct datasource *ds, struct zone *z, void *arg) {
    MYSQL *con = ds->priv;
    if (!con)
        return 0;

    long id = mysql_get_zone_id(ds->priv, z);
    if (id < 0)
        return 0;
    mysql_remove_zone_entries(ds->priv, id);

    struct msze m = {.ds = ds, .id = id};

    walk_zone(z->node, mysql_save_zone_entry, &m, 0);

    return 1;
}

int datasource_mysql_fetch_keys(struct datasource *ds, const char *name, void *arg, void (*cb)(void *arg, struct dnskey *k, char *z)) {
    char query[768], where[512];
    int ret = 0;

    MYSQL *con = ds->priv;
    if (!con)
        return 0;

    if (name && !is_valid_dnsname(name))
        return 0;

    if (name)
        sprintf(where, " WHERE name='%s' ", name); // Need no escape since we checked with is_valid_dnsname
    else
        where[0] = 0;

    snprintf(query, sizeof (query), "SELECT name,flags,content,active FROM cryptokeys left join domains on cryptokeys.domain_id=domains.id %s ORDER BY flags", where);
    mysql_query(con, query);
    MYSQL_RES *res = mysql_use_result(con);
    if (!res) {
        DEBUG(1, "%s: Error querying keys: %s\n", ds->driver, mysql_error(con));
        return 0;
    }
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        if (!is_valid_dnsname(row[0]))
            continue;
        int kf = row[1] ? atoi(row[1]) : 256;
        DEBUG(2, "Loading %s-key for zone %s\n", (kf == 256) ? "ZSK" : "KSK", row[0]);
        struct dnskey k;
        int st = parse_dnssec_key(kf, row[2], &k);
        if (st != 0) {
            k.active = row[3][0] == '1';
            cb(arg, &k, row[0]);
            ret++;
        }
    }
    mysql_free_result(res);

    return ret;
}

static void mysql_insert_key(MYSQL *con, long domain_id, int flags,
        int active, char *content) {
    MYSQL_BIND fields[6];
    memset(fields, 0, sizeof (fields));

    MYSQL_STMT *stmt = mysql_stmt_init(con);
    char *query = "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES(?,?,?,?)";
    mysql_stmt_prepare(stmt, query, strlen(query));

    fields[0].buffer_type = MYSQL_TYPE_LONG;
    fields[0].buffer = &domain_id;
    fields[0].buffer_length = sizeof (domain_id);

    fields[1].buffer_type = MYSQL_TYPE_LONG;
    fields[1].buffer = &flags;
    fields[1].buffer_length = sizeof (flags);

    fields[2].buffer_type = MYSQL_TYPE_TINY;
    fields[2].buffer = &active;
    fields[2].buffer_length = sizeof (active);

    unsigned long contentlen = strlen(content);
    fields[3].buffer_type = MYSQL_TYPE_STRING;
    fields[3].buffer = content;
    fields[3].buffer_length = contentlen;
    fields[3].length = &contentlen;

    mysql_stmt_bind_param(stmt, fields);
    int st = mysql_stmt_execute(stmt);
    if (st != 0) {
        DEBUG(1, "Error inserting key: %s\n", mysql_error(con));
    }
    mysql_stmt_close(stmt);
}

static int mysql_remove_key_entries(MYSQL *con, long id) {
    char query[128];
    snprintf(query, sizeof (query), "DELETE FROM cryptokeys WHERE domain_id=%ld", id);
    int st = mysql_query(con, query);
    if (st != 0) {
        DEBUG(1, "Error removing key entries for ID %ld: %s\n", id, mysql_error(con));
        return -1;
    }
    return 0;
}

int datasource_mysql_save_keys(struct datasource *ds, struct zone *z, void *arg) {
    MYSQL *con = ds->priv;
    if (!con)
        return 0;

    long id = mysql_get_zone_id(ds->priv, z);
    if (id < 0)
        return 0;
    mysql_remove_key_entries(ds->priv, id);

    char str[8192];
    for (int i = 0; i < z->nrkeys; i++) {
        struct dnskey *dnskey = z->keys[i];
        export_rsa_key(dnskey, str, sizeof (str));
        mysql_insert_key(con, id, dnskey->keyflags, dnskey->active, str);
    }

    return 1;
}

int datasource_mysql_prepare(struct datasource *ds, void *arg) {
    MYSQL *con = mysql_init(NULL);
    const char *host = xl_getstring(arg, "hostname");
    const char *username = xl_getstring(arg, "username");
    const char *password = xl_getstring(arg, "password");
    const char *dbname = xl_getstring(arg, "dbname");
    if (mysql_real_connect(con, host, username, password, dbname, 0, NULL, 0) == NULL) {
        DEBUG(1, "%s: Error connecting: %s\n", ds->driver, mysql_error(con));
        mysql_close(con);
        return 0;
    }

    ds->priv = con;

    return 1;
}

int datasource_mysql_finish(struct datasource *ds, void *arg) {
    MYSQL *conn = ds->priv;
    if (conn) {
        mysql_close(conn);
        ds->priv = NULL;
    }
    free(ds);

    return 1;
}

struct datasource datasource_mysql = {
    .driver = "pdns_mysql",
    .prepare = datasource_mysql_prepare,
    .zoneload = datasource_mysql_fetch_zones,
    .zonesave = datasource_mysql_save_zones,
    .keyload = datasource_mysql_fetch_keys,
    .keysave = datasource_mysql_save_keys,
    .finish = datasource_mysql_finish
};

