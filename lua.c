#include <assert.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <openssl/pem.h>
#include <pthread.h>

#define SCRIPTPATH "/opt/dynaspore/lua/internal/"

#define LUA_FUNCTION(FNAME) int luafunc_ ## FNAME(lua_State *L)
#define LUA_ADD_FUNCTION(FNAME) lua_pushcfunction(L, luafunc_ ## FNAME); \
    lua_setglobal(L, #FNAME)

#include "xfc.h"

static lua_State *L;
void xl_register_functions(lua_State *L);
static void lua_setint(lua_State *L, char *key, long val);
static void lua_setstring(lua_State *L, char *key, char *val);


/**********************/
/*  Helper functions  */
/**********************/

pthread_mutex_t lua_mutex;
pthread_mutexattr_t lua_mutex_attr;

void _lua_lock(void) {
    pthread_mutex_lock(&lua_mutex);
}

int _lua_trylock(void) {
    return pthread_mutex_trylock(&lua_mutex);
}

void _lua_unlock(void) {
    pthread_mutex_unlock(&lua_mutex);
}

const char *xl_getstring(void *context, char *key) {
    lua_State *L = context;
    const char *ret = NULL;

    lua_lock();

    if (lua_gettop(L) >= 1 && lua_istable(L, 1)) {
        lua_pushstring(L, key);
        lua_rawget(L, 1);
        ret = lua_tostring(L, -1);
        lua_pop(L, 1);
    }

    lua_unlock();

    return ret;
}

int xl_getnumber(void *context, char *key, int *valid) {
    lua_State *L = context;
    int ret = 0;

    if (valid) *valid = 0;

    lua_lock();

    if (lua_gettop(L) >= 1 && lua_istable(L, 1)) {
        lua_pushstring(L, key);
        lua_rawget(L, 1);
        if (lua_isnumber(L, -1)) {
            if (valid) *valid = 1;
            ret = lua_tonumber(L, -1);
        }
        lua_pop(L, 1);
    }

    lua_unlock();

    return ret;
}

void xl_tablefunction(lua_State *L, const char *name, void *function) {
    lua_pushstring(L, name);
    lua_pushcfunction(L, function);
    lua_settable(L, -3);
}


/***********************/
/* Datasource handling */
/***********************/

int datasource_zoneload(lua_State *L) {
    int ret = 0;

    if ((lua_gettop(L) != 2) || !lua_istable(L, 1))
        return 0;

    lua_pushstring(L, "driver");
    lua_rawget(L, 1);
    const char *driver = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_pushstring(L, "dsname");
    lua_rawget(L, 1);
    const char *dsname = lua_tostring(L, -1);
    lua_pop(L, 1);

    struct datasource *ds = datasource_find(driver);
    if (!ds || !ds->zoneload)
        return 0;

    if (lua_isstring(L, 2) || lua_isnil(L, 2)) {
        const char *z = lua_tostring(L, 2);
        if (!ds)
            return 0;
        lua_unlock();
        if (ds->prepare)
            ds->prepare(ds, L);
        ret += ds->zoneload(ds, z, L);
        lua_lock();
        if (z) {
            struct zone *zone = fetch_zone(z, 0);
            reprocess_zone(zone);
        } else {
            reprocess_zone_datasource(dsname);
        }
        lua_unlock();
        if (ds->finish)
            ds->finish(ds, L);
        lua_lock();
    } else if (lua_type(L, 2) == LUA_TTABLE) {
        int i = 1;
        lua_unlock();
        if (ds->prepare)
            ds->prepare(ds, L);
        lua_lock();
        do {
            lua_rawgeti(L, 2, i++);
            if (lua_type(L, -1) != LUA_TSTRING)
                break;
            const char *z = lua_tostring(L, -1);
            lua_pop(L, 1);
            lua_unlock();
            ret += ds->zoneload(ds, z, L);
            lua_lock();
            struct zone *zone = fetch_zone(z, 0);
            reprocess_zone(zone);
        } while (1);
        lua_unlock();
        if (ds->finish)
            ds->finish(ds, L);
        lua_lock();
    } else {
        return 0;
    }

    lua_pushnumber(L, ret);
    return 1;
}

int datasource_zonesave(lua_State *L) {
    int ret = 0;

    if ((lua_gettop(L) != 2) || !lua_istable(L, 1))
        return 0;

    lua_pushstring(L, "driver");
    lua_rawget(L, 1);
    const char *driver = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_pushstring(L, "dsname");
    lua_rawget(L, 1);
    const char *dsname = lua_tostring(L, -1);
    lua_pop(L, 1);

    struct datasource *ds = datasource_find(driver);
    if (!ds || !ds->zonesave)
        return 0;

    const char *zonename = lua_tostring(L, 2);
    struct zone *z;
    if (zonename && (z = fetch_zone(zonename, 0))) {
        if (ds->prepare)
            ds->prepare(ds, L);
        int st = ds->zonesave(ds, z, L);
        if (st > 0) {
            snprintf(z->datasource, sizeof (z->datasource), "%s", dsname);
        }
        if (ds->finish)
            ds->finish(ds, L);
        lua_pushnumber(L, 1);
        return 1;
    }

    return 0;
}

static void addkey(void *arg, struct dnskey *k, char *z) {
    lua_State *L = arg;
    lua_pushstring(L, z);
    lua_gettable(L, -2);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushstring(L, z);
        lua_pushvalue(L, -2);
        lua_settable(L, -4);
    }
    int index = lua_rawlen(L, -1) + 1;
    struct xl_dnskey *dnskey = xl_malloc(L, XL_DNSKEY, sizeof (struct xl_dnskey));
    if (!dnskey) {
        lua_pop(L, 1);
        return;
    }
    luaL_getmetatable(L, "dnskey");
    lua_setmetatable(L, -2);
    memcpy(&dnskey->key, k, sizeof (struct dnskey));
    dnskey->key.ud = lua_touserdata(L, -1);
    lua_rawseti(L, -2, index);
    lua_pop(L, 1);
}

int datasource_keyload(lua_State *L) {
    int ret = 0;

    if ((lua_gettop(L) != 2) || !lua_istable(L, 1))
        return 0;


    lua_pushstring(L, "driver");
    lua_rawget(L, 1);
    const char *driver = lua_tostring(L, -1);
    lua_pop(L, 1);

    struct datasource *ds = datasource_find(driver);
    if (!ds || !ds->keyload)
        return 0;

    lua_newtable(L);
    if (lua_isstring(L, 2) || lua_isnil(L, 2)) {
        const char *z = lua_tostring(L, 2);
        DEBUG(1, "Loading keys for zone %s with driver %s\n", z, driver);
        if (!ds)
            return 0;
        if (ds->prepare)
            ds->prepare(ds, L);
        lua_unlock();
        ret += ds->keyload(ds, z, L, addkey);
        lua_lock();
        if (ds->finish)
            ds->finish(ds, L);
    } else if (lua_type(L, 2) == LUA_TTABLE) {
        int i = 1;
        ds->prepare(ds, L);
        do {
            lua_rawgeti(L, 2, i++);
            if (lua_type(L, -1) != LUA_TSTRING)
                break;
            const char *z = lua_tostring(L, -1);
            lua_pop(L, 1);
            lua_unlock();
            ret += ds->keyload(ds, z, L, addkey);
            lua_lock();
        } while (1);
        ds->finish(ds, L);
    } else {
        return 0;
    }

    return 1;
}

int datasource_keysave(lua_State *L) {
    int ret = 0;

    if ((lua_gettop(L) != 2) || !lua_istable(L, 1))
        return 0;

    lua_pushstring(L, "driver");
    lua_rawget(L, 1);
    const char *driver = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_pushstring(L, "dsname");
    lua_rawget(L, 1);
    const char *dsname = lua_tostring(L, -1);
    lua_pop(L, 1);

    struct datasource *ds = datasource_find(driver);
    if (!ds || !ds->keysave)
        return 0;

    const char *zonename = lua_tostring(L, 2);
    struct zone *z;
    if (zonename && (z = fetch_zone(zonename, 0))) {
        if (ds->prepare)
            ds->prepare(ds, L);
        int st = ds->keysave(ds, z, L);
        if (st > 0) {
            snprintf(z->datasource, sizeof (z->datasource), "%s", dsname);
        }
        if (ds->finish)
            ds->finish(ds, L);
        lua_pushnumber(L, 1);
        return 1;
    }

    return 0;
}

int datasource_ops(lua_State *L) {
    int ret = 0;

    if ((lua_gettop(L) != 1) || !lua_istable(L, 1))
        return 0;

    lua_pushstring(L, "driver");
    lua_rawget(L, 1);
    const char *driver = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_pushstring(L, "dsname");
    lua_rawget(L, 1);
    const char *dsname = lua_tostring(L, -1);
    lua_pop(L, 1);

    struct datasource *ds = datasource_find(driver);
    lua_newtable(L);
    if (ds) {
        lua_pushstring(L, "zoneload");
        lua_pushnumber(L, ds->zoneload != NULL);
        lua_rawset(L, -3);
        lua_pushstring(L, "zonesave");
        lua_pushnumber(L, ds->zonesave != NULL);
        lua_rawset(L, -3);
        lua_pushstring(L, "keyload");
        lua_pushnumber(L, ds->keyload != NULL);
        lua_rawset(L, -3);
        lua_pushstring(L, "keysave");
        lua_pushnumber(L, ds->keysave != NULL);
        lua_rawset(L, -3);
    }

    return 1;
}

int datasource_index(lua_State *L) {
    const char *key = luaL_checkstring(L, 2);

    lua_newtable(L);
    xl_tablefunction(L, "zoneload", datasource_zoneload);
    xl_tablefunction(L, "keyload", datasource_keyload);
    xl_tablefunction(L, "zonesave", datasource_zonesave);
    xl_tablefunction(L, "keysave", datasource_keysave);
    xl_tablefunction(L, "ops", datasource_ops);

    lua_pushstring(L, "dsname");
    lua_pushvalue(L, 2);
    lua_settable(L, -3);

    lua_pushvalue(L, 2);
    lua_pushvalue(L, -2);
    lua_settable(L, 1);

    return 1;
}

void xl_init_datasource(lua_State *L) {
    lua_newtable(L);
    luaL_newmetatable(L, "datasource");

    lua_pushstring(L, "__index");
    lua_pushcfunction(L, datasource_index);
    lua_settable(L, -3);

    lua_setmetatable(L, -2);
    lua_setglobal(L, "datasource");
}



/***********************/
/* DNS Record handling */

/***********************/

int record_index(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    if (!name)
        return 0;

    struct xl_data *d = lua_touserdata(L, 1);
    struct xl_record *r = (void*) d->data;
    diptr_t di = maketree(root, r->name, -1, 0);
    if (!di)
        return 0;

    if (r->type == 0) { // Need the record type first
        if (strcasecmp(name, "types") == 0) {
            lua_newtable(L);
            int i, j = 1;
            for (i = T_FIRST; i < T_LAST; i++) {
                if (HASTYPE(di, i)) {
                    lua_pushstring(L, inttype2typestr(i));
                    lua_rawseti(L, -2, j++);
                }
            }
        } else {
            int typenr = typestr2type(name);
            if (typenr <= 0)
                return 0;
            struct xl_record *nr = xl_dup(L, d);
            luaL_getmetatable(L, "record");
            lua_setmetatable(L, -2);
            nr->type = typenr;
        }
        return 1;
    } else if (r->index == 0) {
        int index;
        if (!strcmp(name, "new")) {
            index = -1;
        } else if (!strcmp(name, "count")) {
            diptr_t di = maketree(root, r->name, type2id(r->type), 0);
            int ret = 0;
            if (di)
                ret = di->nrrecords;
            lua_pushnumber(L, ret);
            return 1;
#ifdef RECORDSTATS
        } else if (!strcmp(name, "requests")) {
            diptr_t di = maketree(root, r->name, type2id(r->type), 0);
            int ret = 0;
            if (di)
                ret = di->nrreq;
            lua_pushnumber(L, ret);
            return 1;
#endif
        } else {
            index = atoi(name);
            if (index <= 0)
                return 0;
        }
        diptr_t di = maketree(root, r->name, type2id(r->type), index < 0 ? 1 : 0);
        if (!di || di->nrrecords < index)
            return 0;
        if (index < 0 && di->zone == NULL) {
            struct answerdata ad;
            diptr_t zz = walktree(r->name, strlen(r->name), T_SOA, &ad);
            if (zz)
                di->zone = zz->zone;
        }
        struct xl_record *nr = xl_dup(L, d);
        luaL_getmetatable(L, "record");
        lua_setmetatable(L, -2);
        nr->index = index;
        return 1;
    } else {
        diptr_t di = maketree(root, r->name, type2id(r->type), 0);
        if (!di || di->nrrecords < r->index)
            return 0;
        unsigned char *ptr = skip_records(di->record, r->index - 1);
        if (!strcmp(name, "content") || !strcmp(name, "record")) {
            char rec[100000];
            retrieve_record_data(ptr, rec, sizeof (rec));
            if (*name == 'c') { // We want content, not record
                ptr = skip_word(rec); // Skip over name
                ptr = skip_word(ptr); // Skip over ttl
                ptr = skip_word(ptr); // Skip over class
                ptr = skip_word(ptr); // Skip over type
            } else {
                ptr = rec;
            }
            if (ptr) {
                lua_pushstring(L, ptr);
                return 1;
            } else {
                return 0;
            }
        } else if (!strcmp(name, "ttl")) {
            get_string(&ptr);
            ptr += 4;
            unsigned int ttl = get_uint(&ptr);
            lua_pushnumber(L, ttl);
            return 1;
        } else {
            return 0;
        }
    }
}

int record_newindex(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    const char *value = lua_tostring(L, 3);
    struct xl_data *d = lua_touserdata(L, 1);
    struct xl_record *r = (void*) d->data;

    if (!r->type && !r->index && lua_isnil(L, 3)) {
        int typenr = typestr2type(name);
        if (typenr <= 0)
            return 0;

        diptr_t di = maketree(root, r->name, type2id(typenr), 0);
        if (di) {
            clear_record(di);
            reprocess_zone(di->zone);
        }
        return 0;
    }
    if (!r->index)
        return 0;

    int typeid = type2id(r->type);
    diptr_t di = maketree(root, r->name, typeid, 0);
    if (!di)
        return 0;
    if (strcmp(name, "content") == 0) {
        if (r->index < 0) {
            create_record_raw(r->name, r->type, value, 86400, -1);
        } else {
            unsigned char *record = di->record;
            unsigned char *srecord = di->shortrecord;
            unsigned char *newrec = NULL;
            int newreclen = 0;
            unsigned char *newsrec = NULL;
            int newsreclen = 0;
            int i, nrrecords = 0;
            for (i = 0; i < di->nrrecords; i++) {
                if (r->index - 1 == i) {
                    if (di->up)
                        di->up->nrrecords--;
                    ss.nrrecords--;
                    record = skip_records(record, 1);
                    srecord = skip_records(srecord, 1);
                    if (!value)
                        continue;
                    char content[4096];
                    int contentlen = create_record_content(content, r->type, value, -1);
                    if (contentlen <= 0)
                        continue;
                    int nl = strlen(r->name) + 2;

                    newrec = x_realloc(newrec, newreclen + nl + 10 + contentlen);
                    unsigned char *ptr = newrec + newreclen;
                    unsigned char *nptr = name2lbl(ptr, r->name);
                    nl = nptr - ptr;
                    ptr = nptr;
                    PUTSHORT(ptr) = htons(r->type);
                    ptr += 2;
                    PUTSHORT(ptr) = htons(0x0001);
                    ptr += 2;
                    PUTINT(ptr) = htonl(86400);
                    ptr += 4;
                    PUTSHORT(ptr) = htons(contentlen);
                    ptr += 2;
                    memcpy(ptr, content, contentlen);
                    newreclen += nl + 10 + contentlen;

                    newsrec = x_realloc(newsrec, newsreclen + 12 + contentlen);
                    ptr = newsrec + newsreclen;
                    PUTSHORT(ptr) = htons(0xc00c);
                    ptr += 2;
                    PUTSHORT(ptr) = htons(r->type);
                    ptr += 2;
                    PUTSHORT(ptr) = htons(0x0001);
                    ptr += 2;
                    PUTINT(ptr) = htonl(86400);
                    ptr += 4;
                    PUTSHORT(ptr) = htons(contentlen);
                    ptr += 2;
                    memcpy(ptr, content, contentlen);
                    newsreclen += 12 + contentlen;
                    if (di->up)
                        di->up->nrrecords++;
                    nrrecords++;
                    ss.nrrecords++;
                } else {
                    int nl = strlen(record) + 1;
                    unsigned char *ptr = record + nl;
                    unsigned short rdlength = ptr[8]*256 + ptr[9];
                    int ll = rdlength + nl + 10;
                    newrec = x_realloc(newrec, newreclen + ll);
                    memcpy(newrec + newreclen, record, ll);
                    newreclen += ll;
                    record += ll;

                    ptr = srecord;
                    rdlength = ptr[10]*256 + ptr[11];
                    ll = rdlength + 12;
                    newsrec = x_realloc(newsrec, newsreclen + ll);
                    memcpy(newsrec + newsreclen, srecord, ll);
                    newsreclen += ll;
                    srecord += ll;
                    nrrecords++;
                }
            }
            x_free(di->record);
            x_free(di->shortrecord);
            di->record = newrec;
            di->recordlen = newreclen;
            di->shortrecord = newsrec;
            di->shortrecordlen = newsreclen;
            di->nrrecords = nrrecords;
            fix_parent(di);
        }
        reprocess_zone(di->zone);
    } else if (!strcmp(name, "ttl")) {
        if (r->index < 1 || r->index > di->nrrecords) {
            return 0;
        }
        unsigned int ttl = strtoul(value, NULL, 10);
        char *rec = skip_records(di->record, r->index - 1);
        char *srec = skip_records(di->shortrecord, r->index - 1);
        rec += strlen(rec) + 5;
        PUTINT(rec) = htonl(ttl);
        srec += 6;
        PUTINT(srec) = htonl(ttl);
        reprocess_zone(di->zone);
    }

    return 0;
}

int records_index(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    if (!is_valid_dnsname(name))
        return 0;
    diptr_t di = maketree(root, name, -1, 0);
    if (!di) {
        return 0;
    }
    struct xl_record *r = xl_malloc(L, XL_RECORD, sizeof (struct xl_record));
    if (!r)
        return 0;
    strcpy(r->name, di->name);
    luaL_getmetatable(L, "record");
    lua_setmetatable(L, -2);

    return 1;
}

int records_newindex(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    if (!is_valid_dnsname(name))
        return 0;
    struct xl_record *r = xl_malloc(L, XL_RECORD, sizeof (struct xl_record));
    if (!r)
        return 0;
    strcpy(r->name, name);
    diptr_t di = maketree(root, name, -1, 1);
    if (!di)
        return 0;
    luaL_getmetatable(L, "record");
    lua_setmetatable(L, -2);

    return 1;
}

void xl_init_records(lua_State *L) {
    /* Create records table and records metatable */
    lua_newtable(L);
    luaL_newmetatable(L, "records");
    xl_tablefunction(L, "__index", records_index);
    xl_tablefunction(L, "__newindex", records_newindex);
    lua_setmetatable(L, -2);
    lua_setglobal(L, "records");

    /* Create record metatable */
    luaL_newmetatable(L, "record");
    xl_tablefunction(L, "__index", record_index);
    xl_tablefunction(L, "__newindex", record_newindex);
    lua_pop(L, 1);
}


/***********************/
/* DNSSec Key handling */

/***********************/

static int dnskey_export(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    if (!dnskey)
        return 0;
    int format = lua_tointeger(L, 2);

    struct dnskey *key = &dnskey->key;
    char str[8192];
    str[0] = '\0';

    switch (format) {
        case 0: // Private-key-format v1.2
            export_rsa_key(key, str, sizeof (str));
            lua_pushstring(L, str);
            break;
        case 1: // PEM format
            ;
            BIO *mem = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPrivateKey(mem, key->rsa, NULL, NULL, 0, NULL, NULL);
            char *str;
            int size = BIO_get_mem_data(mem, &str);
            lua_pushlstring(L, str, size);
            BIO_free(mem);
            break;
        default:
            lua_pushnil(L);
    }

    return 1;
}

LUA_FUNCTION(genkey) {
    if (lua_gettop(L) < 1 || !lua_isnumber(L, 1)) {
        return 0;
    }
    int bits = lua_tointeger(L, 1);
    int flags = lua_isnumber(L, 2) ? lua_tonumber(L, 2) : 256;
    struct xl_dnskey *k = xl_malloc(L, XL_DNSKEY, sizeof (struct xl_dnskey));
    int st = gen_rsa_key(flags, bits, &k->key);
    if (!st)
        return 0;
    luaL_getmetatable(L, "dnskey");
    lua_setmetatable(L, -2);
    k->key.ud = lua_touserdata(L, -1);

    return 1;
}

LUA_FUNCTION(importkey) {
    int keyflags = 256;
    const char *keydata = lua_tostring(L, 1);
    if (!keydata)
        return 0;
    if (lua_isnumber(L, 2)) {
        keyflags = lua_tonumber(L, 2);
    }
    struct xl_dnskey *k = xl_malloc(L, XL_DNSKEY, sizeof (struct xl_dnskey));
    luaL_getmetatable(L, "dnskey");
    lua_setmetatable(L, -2);
    int st = 0;
    if (strstr(keydata, "-----BEGIN RSA PRIVATE KEY-----") == keydata)
        st = parse_pem_key(keyflags, keydata, &k->key);
    else if (strstr(keydata, "Private-key-format: v1.2") == keydata)
        st = parse_rsa_key(keyflags, keydata, &k->key);
    else
        DEBUG(1, "Invalid key: %.20s\n", keydata);
    if (!st) {
        lua_pop(L, 1);
        return 0;
    }
    k->key.ud = lua_touserdata(L, -1);

    return 1;
}

static int dnskey_show(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    if (!dnskey)
        return 0;

    lua_newtable(L);
    lua_setint(L, "active", dnskey->key.active);
    lua_setint(L, "algo", dnskey->key.algo);
    lua_setint(L, "flags", dnskey->key.keyflags);
    lua_setint(L, "tag", dnskey->key.keytag);

    return 1;
}

static int dnskeyrr(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    if (!dnskey)
        return 0;

    char content[8192];
    int len = dnssec_get_dnskeyrr(&dnskey->key, content, sizeof (content));
    if (len <= 0)
        return 0;

    char string[8192];
    len = retrieve_record_content(content, typestr2type("DNSKEY"), len, string, sizeof (string), NULL, 0, 0);
    if (len <= 0)
        return 0;

    lua_pushstring(L, string);

    return 1;
}

static int dsrr(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    if (!dnskey)
        return 0;
    const char *name = lua_tostring(L, 2);
    if (!name)
        return 0;

    char content[8192];
    int len = dnssec_get_dsrr_from_dnskey(name, &dnskey->key, content, sizeof (content));
    if (len <= 0)
        return 0;

    char string[8192];
    len = retrieve_record_content(content, typestr2type("DS"), len, string, sizeof (string), NULL, 0, 0);
    if (len <= 0)
        return 0;

    lua_pushstring(L, string);

    return 1;
}

static int dnskey_gc(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    DEBUG(1, "Garbage collecting dnskey %p\n", dnskey)
        if (dnskey)
            RSA_free(dnskey->key.rsa);

    return 0;
}

static int dnskey_index(lua_State *L) {
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    const char *name = lua_tostring(L, 2);
    if (!dnskey || !name)
        return 0;

    if (!strcmp(name, "export")) {
        lua_pushcfunction(L, dnskey_export);
        return 1;
    } else if (!strcmp(name, "show")) {
        lua_pushcfunction(L, dnskey_show);
        return 1;
    } else if (!strcmp(name, "dnskeyrr")) {
        lua_pushcfunction(L, dnskeyrr);
        return 1;
    } else if (!strcmp(name, "dsrr")) {
        lua_pushcfunction(L, dsrr);
        return 1;
    } else if (!strcmp(name, "flags")) {
        lua_pushnumber(L, dnskey->key.keyflags);
        return 1;
    } else if (!strcmp(name, "algo")) {
        lua_pushnumber(L, dnskey->key.algo);
        return 1;
    } else if (!strcmp(name, "active")) {
        lua_pushnumber(L, dnskey->key.active);
        return 1;
    } else if (!strcmp(name, "tag")) {
        lua_pushnumber(L, dnskey->key.keytag);
        return 1;
    }

    return 0;
}

static int dnskey_newindex(lua_State *L) {
    if (lua_gettop(L) != 3)
        return 0;
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 1);
    const char *name = lua_tostring(L, 2);
    if (!dnskey || !name)
        return 0;

    if (!strcmp(name, "flags")) {
        dnskey->key.keyflags = lua_tonumber(L, 3);
        dnssec_fix_key(&dnskey->key);
    } else if (!strcmp(name, "active")) {
        dnskey->key.active = lua_tonumber(L, 3);
    } else if (!strcmp(name, "algo")) {
        // TODO check valid algos
        dnskey->key.algo = lua_tonumber(L, 3);
        dnssec_fix_key(&dnskey->key);
    }

    return 0;
}

static void xl_init_dnssec(lua_State *L) {
    /* create zones table and zones metatable */
    luaL_newmetatable(L, "dnskey");
    xl_tablefunction(L, "__gc", dnskey_gc);
    xl_tablefunction(L, "__index", dnskey_index);
    xl_tablefunction(L, "__newindex", dnskey_newindex);
    lua_pop(L, 1);
}

/***********************/
/*    Zone handling    */

/***********************/

struct zones_list_param {
    const char *dsname;
    lua_State *L;
    int lastindex;
    int first, last, current;
};

int _xl_zones_list(struct zone *z, void *arg) {
    struct zones_list_param *zp = arg;

    if (zp->dsname && strcmp(zp->dsname, z->datasource)) {
        return 0;
    }

    zp->current++;

    if ((zp->first >= 0 && zp->current - 1 < zp->first) ||
            (zp->last >= 0 && zp->current - 1 >= zp->last)) {
        return 0;
    }

    int index = ++zp->lastindex;

    lua_pushstring(zp->L, z->name);
    lua_rawseti(zp->L, -2, index);

    return 1;
}

static int zones_list(lua_State *L) {
    struct zones_list_param zp = {
        .L = L,
        .dsname = NULL,
        .lastindex = 0,
        .first = -1,
        .last = -1,
        .current = 0
    };
    const char *prefix = NULL;

    if (lua_gettop(L) > 0 && lua_istable(L, 1)) {
        zp.dsname = xl_getstring(L, "dsname");
        prefix = xl_getstring(L, "prefix");
        int valid;
        zp.first = xl_getnumber(L, "first", &valid);
        if (!valid) zp.first = -1;
        zp.last = xl_getnumber(L, "last", &valid);
        if (!valid) zp.last = -1;
    }

    zp.L = L;
    zp.lastindex = 0;
    lua_newtable(L);
    if (prefix)
        walk_zones_prefix(_xl_zones_list, &zp, prefix);
    else
        walk_zones(_xl_zones_list, &zp);

    lua_pushstring(L, "__total");
    lua_pushnumber(L, zp.current);
    lua_settable(L, -3);
    lua_pushstring(L, "__count");
    lua_pushnumber(L, zp.lastindex);
    lua_settable(L, -3);

    return 1;
}

struct zonegetparams {
    lua_State *L;
    int lastindex;
};

static void _xl_zoneget(diptr_t di, diptr_t parent, int subtree, void *args) {
    struct zonegetparams *zgp = args;

    int index = ++zgp->lastindex;
    lua_newtable(zgp->L);
    lua_pushstring(zgp->L, di->name);
    lua_rawseti(zgp->L, -2, 1);
    lua_pushstring(zgp->L, inttype2typestr(subtree));
    lua_rawseti(zgp->L, -2, 2);

    lua_rawseti(zgp->L, -2, index);
}

static int zone_getkeys(lua_State *L) {
    int i;
    struct xl_zone *zone = xl_touserdata(L, XL_ZONE, 1);

    if (!zone)
        return 0;

    lua_newtable(L);
    struct zone *z = zone->z;
    for (i = 0; i < z->nrkeys; i++) {
        xl_pushref(L, z->keys[i]->ud);
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

static int zone_addkey(lua_State *L) {
    struct xl_zone *zone = xl_touserdata(L, XL_ZONE, 1);
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 2);
    if (!zone || !dnskey)
        return 0;
    int st = zone_add_key(zone->z, &dnskey->key);
    if (st) {
        xl_ref(L, 2);
        lua_pushnumber(L, 1);
        return 1;
    }

    return 0;
}

static int zone_delkey(lua_State *L) {
    struct xl_zone *zone = xl_touserdata(L, XL_ZONE, 1);
    struct xl_dnskey *dnskey = xl_touserdata(L, XL_DNSKEY, 2);

    if (!zone || !dnskey)
        return 0;

    int st = zone_del_key(zone->z, &dnskey->key);
    if (st) {
        xl_unref(L, 2);
        lua_pushnumber(L, 1);
        return 1;
    }

    return 0;
}

static int _zone_delkeys(lua_State *L, struct zone *z) {
    int i, ret = 0;
    for (i = z->nrkeys - 1; i >= 0; i--) {
        struct dnskey *dnskey = z->keys[i];
        int st = zone_del_key(z, dnskey);
        if (st) {
            xl_unref_ud(L, dnskey->ud);
            ret++;
        }
    }
    return ret;
}

static int zone_delkeys(lua_State *L) {
    struct xl_zone *zone = xl_touserdata(L, XL_ZONE, 1);
    if (!zone)
        return 0;
    lua_pushnumber(L, _zone_delkeys(L, zone->z));
    return 1;
}

static int zone_show(lua_State *L) {
    struct xl_zone *xz = xl_touserdata(L, XL_ZONE, 1);
    if (!xz)
        return 0;
    struct zone *z = xz->z;

    lua_newtable(L);
    lua_setstring(L, "name", z->name);
    lua_setint(L, "zoneid", z->zoneid);
    lua_setint(L, "last_reload", z->last_reload);
    lua_setint(L, "flags", z->flags);
    lua_setstring(L, "datasource", z->datasource);
    lua_setint(L, "dnskeys", z->nrkeys);
    lua_pushstring(L, "recordnames");

    struct zonegetparams zgp;
    zgp.L = L;
    zgp.lastindex = 0;
    lua_newtable(L);
    walk_zone(z->node, _xl_zoneget, &zgp, 0);
    lua_settable(L, -3);

    return 1;
}

static int zone_clear(lua_State *L) {
    struct xl_zone *xz = xl_touserdata(L, XL_ZONE, 1);
    if (!xz)
        return 0;
    const char *typestr = lua_tostring(L, 2);

    struct zone *z = xz->z;

    int type = -1;
    if (typestr) {
        type = typestr2type(typestr);
        if (type < 0)
            return 0;
        type = type2id(type);
        if (!type)
            return 0;
    }

    zone_remove_records(z, type);
    reprocess_zone(z);

    lua_pushnumber(L, 1);
    return 1;
}

static int zone_bulkedit(lua_State *L) {
    struct xl_zone *xz = xl_touserdata(L, XL_ZONE, 1);
    if (!xz)
        return 0;
    struct zone *z = xz->z;

    if (lua_gettop(L) > 1) {
        int bulkedit = lua_tointeger(L, 2);

        int do_reprocess = !bulkedit && (z->flags & ZONE_BULKEDIT);
        if (!bulkedit)
            z->flags &= ~ZONE_BULKEDIT;
        else
            z->flags |= ZONE_BULKEDIT;
        if (do_reprocess)
            reprocess_zone(z);
    }

    lua_pushnumber(L, !!(z->flags & ZONE_BULKEDIT));
    return 1;
}

static int zone_process(lua_State *L) {
    struct xl_zone *xz = xl_touserdata(L, XL_ZONE, 1);
    if (!xz)
        return 0;
    struct zone *z = xz->z;

    reprocess_zone_forced(z);

    return 0;
}

static int zone_index(lua_State *L) {
    struct xl_zone *xz = xl_touserdata(L, XL_ZONE, 1);
    const char *name = lua_tostring(L, 2);
    if (!xz || !name)
        return 0;

    if (!strcmp(name, "getkeys")) {
        lua_pushcfunction(L, zone_getkeys);
        return 1;
    } else if (!strcmp(name, "addkey")) {
        lua_pushcfunction(L, zone_addkey);
        return 1;
    } else if (!strcmp(name, "delkey")) {
        lua_pushcfunction(L, zone_delkey);
        return 1;
    } else if (!strcmp(name, "delkeys")) {
        lua_pushcfunction(L, zone_delkeys);
        return 1;
    } else if (!strcmp(name, "clear")) {
        lua_pushcfunction(L, zone_clear);
        return 1;
    } else if (!strcmp(name, "show")) {
        lua_pushcfunction(L, zone_show);
        return 1;
    } else if (!strcmp(name, "bulkedit")) {
        lua_pushcfunction(L, zone_bulkedit);
        return 1;
    } else if (!strcmp(name, "process")) {
        lua_pushcfunction(L, zone_process);
        return 1;
    }

    return 0;
}

static int zones_index(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    if (!name || !is_valid_dnsname(name))
        return 0;
    struct zone *z = fetch_zone(name, 0);
    if (!z)
        return 0;
    struct xl_zone *xz = xl_malloc(L, XL_ZONE, sizeof (struct xl_zone));
    if (!xz)
        return 0;
    xz->z = z;
    luaL_getmetatable(L, "zone");
    lua_setmetatable(L, -2);


    return 1;
}

static int zones_newindex(lua_State *L) {
    const char *name = lua_tostring(L, 2);
    int nr = lua_tonumber(L, 3);

    if (!nr) {
        // Delete a zone if nil is assigned
        struct zone *z = fetch_zone(name, 0);
        if (z) {
            _zone_delkeys(L, z);
            dnstree_remove_zone(z);
        }
    } else {
        if (!is_valid_dnsname(name))
            return 0;
        fetch_zone(name, 1); // Zone is created here
    }

    return 0;
}

static void xl_init_zones(lua_State *L) {
    /* create zones table and zones metatable */
    lua_newtable(L);
    xl_tablefunction(L, "list", zones_list);
    luaL_newmetatable(L, "zones");
    xl_tablefunction(L, "__index", zones_index);
    xl_tablefunction(L, "__newindex", zones_newindex);
    lua_setmetatable(L, -2);
    lua_setglobal(L, "zones");

    /* Create zone metatable */
    luaL_newmetatable(L, "zone");
    xl_tablefunction(L, "__index", zone_index);
    lua_pop(L, 1);

}

/***********************/
/*  Lua Script engine  */

/***********************/

int xl_reload(FILE *sock) {
    if (!L)
        return 0;

    lua_lock();
    int st = luaL_loadfile(L, SCRIPTPATH "xfc.lua");
    if (st) {
        DEBUG(1, "Error parsing LUA master script: %s\n", lua_tostring(L, -1));
        if (sock) {
            reply(sock, 500, NULL);
            fprintf(sock, "Error parsing LUA master script:\n%s\n", lua_tostring(L, -1));
        }
        lua_unlock();
        return 0;
    }

    st = lua_pcall(L, 0, 0, 0);
    if (st) {
        DEBUG(1, "Error executing LUA master script: %s\n", lua_tostring(L, -1));
        if (sock) {
            reply(sock, 500, NULL);
            fprintf(sock, "Error executing LUA master script:\n%s\n", lua_tostring(L, -1));
        }
    }
    lua_unlock();

    return st ? 0 : 1;
}

int xl_init(FILE *sock) {
    lua_State *oldL = L;

    pthread_mutexattr_init(&lua_mutex_attr);
    pthread_mutexattr_settype(&lua_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lua_mutex, &lua_mutex_attr);

    lua_lock();
    L = luaL_newstate();
    luaL_openlibs(L);
    xl_init_datasource(L);
    xl_init_zones(L);
    xl_init_records(L);
    xl_init_dnssec(L);
    xl_register_functions(L);

    int ret = xl_reload(sock);
    if (!ret) {
        if (oldL) {
            lua_close(L);
            L = oldL;
        }
    } else if (oldL) {
        lua_close(oldL);
    }
    lua_unlock();

    return ret;
}

static void sendescapedstring(FILE *sock, const char *string) {
    fputc('\"', sock);

    const char *ptr = string;
    while (*ptr) {
        switch (*ptr) {
            case '\n':
                fputc('\\', sock);
                fputc('n', sock);
                break;
            case '\r':
                fputc('\\', sock);
                fputc('r', sock);
                break;
            case '\f':
                fputc('\\', sock);
                fputc('f', sock);
                break;
            case '\t':
                fputc('\\', sock);
                fputc('t', sock);
                break;
            case '\b':
                fputc('\\', sock);
                fputc('b', sock);
                break;
            case '\\':
                fputc('\\', sock);
                fputc('\\', sock);
                break;
            case '"':
                fputc('\\', sock);
                fputc('"', sock);
                break;
            case '/':
                fputc('\\', sock);
                fputc('/', sock);
                break;
            default:
                fputc(*ptr, sock);
        }
        ptr++;
    }

    fputc('\"', sock);
}

void _lua_result_to_json(FILE *sock, lua_State *L, int depth) {
    if (depth > 100) {
        fprintf(sock, "0\n");
        return;
    }
    struct xl_data *xd;
    switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
            fprintf(sock, "%lld", lua_tointeger(L, -1));
            lua_pop(L, 1);
            break;
        case LUA_TBOOLEAN:
            fprintf(sock, "%s", lua_toboolean(L, -1) ? "true" : "false");
            lua_pop(L, 1);
            break;
        case LUA_TSTRING:
            sendescapedstring(sock, lua_tostring(L, -1));
            lua_pop(L, 1);
            break;
        case LUA_TUSERDATA:
            xd = lua_touserdata(L, -1);
            if (!xd)
                fprintf(sock, "\"<UD#NULL>\"");
            else
                fprintf(sock, "\"<UD#%d>\"", xd->type);
            lua_pop(L, 1);
            break;
        case LUA_TTABLE:
            // Check for an array
            lua_rawgeti(L, -1, 1);
            if (lua_type(L, -1) != LUA_TNIL) {
                lua_pop(L, 1);
                int len = lua_rawlen(L, -1);
                fprintf(sock, "[\n");
                int i;
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(L, -1, i);
                    _lua_result_to_json(sock, L, depth + 1);
                    if (i < len) {
                        fprintf(sock, ",\n");
                    } else {
                        fprintf(sock, "\n");
                    }
                }
                lua_pop(L, 1);
                fprintf(sock, "]\n");
                break;
            }
            lua_pop(L, 1);

            // It is not an array, so it is a table
            fprintf(sock, "{\n");
            lua_pushnil(L);
            int st = lua_next(L, -2);
            do {
                if (!st)
                    break;
                if (lua_type(L, -2) == LUA_TNUMBER) {
                    fprintf(sock, " \"%lld\": ", lua_tointeger(L, -2));
                } else if (lua_type(L, -2) == LUA_TSTRING) {
                    fputc(' ', sock);
                    sendescapedstring(sock, lua_tostring(L, -2));
                    fputc(':', sock);
                    fputc(' ', sock);
                } else {
                    lua_pop(L, 1);
                    st = lua_next(L, -2);
                    continue;
                }
                _lua_result_to_json(sock, L, depth + 1);
                fflush(sock);
                st = lua_next(L, -2);
                if (st)
                    fprintf(sock, ",\n");
                else
                    fprintf(sock, "\n");
            } while (st);
            lua_pop(L, 1);
            fprintf(sock, "}\n");
            break;
        default:
            fprintf(sock, "0");
            lua_pop(L, 1);
            break;
    }
}

void lua_result_to_json(FILE *sock, lua_State *L) {
    _lua_result_to_json(sock, L, 0);
}

static void push_postdata(lua_State *L, char *post) {
    if (post)
        lua_pushstring(L, post);
    else
        lua_pushnil(L);
}

void lua_handle_webexec(FILE *sock, char *param, char *post) {
    if (!L && !xl_init(sock))
        return;

    lua_lock();
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    lua_getglobal(T, "webexec");
    lua_pushstring(T, param);
    push_postdata(T, post);
    int st = lua_pcall(T, 2, 1, 0);
    if (st) {
        DEBUG(1, "Error handling webexec: %s\n", lua_tostring(T, -1));
        if (sock) {
            reply(sock, 500, NULL);
            fprintf(sock, "Error handling webexec:\n%s\n", lua_tostring(L, -1));
        }
        lua_pop(T, 1);
    } else {
        reply(sock, 200, NULL);
        lua_result_to_json(sock, T);
    }

    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();
}

int lua_getconfig(lua_State *L, char *string) {
    char *ptr = string, *ptr2;

    lua_getglobal(L, "global");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 0;
    }

    do {
        ptr2 = strchr(ptr, '/');
        if (ptr2)
            *ptr2 = '\0';
        lua_pushstring(L, ptr);
        lua_rawget(L, -2);
        lua_remove(L, -2);
        if (!lua_istable(L, -1) && ptr2) {
            lua_pop(L, 1);
            return 0;
        }
        ptr = ptr2 + 1;
    } while (ptr2);

    return 1;
}

int lua_ipv4_address_configured(unsigned int ip) {
    int ret = 0;

    lua_lock();
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    char config[] = "config/network/bindipv4";
    int st = lua_getconfig(T, config);

    if (st == 0) {
        DEBUG(1, "Failed to get bindipv4\n");
        lua_unlock();
        return 0;
    }

    int i = 1;
    do {
        lua_rawgeti(T, -1, i++);
        if (lua_isnil(T, -1))
            break;
        if (lua_isstring(T, -1)) {
            unsigned int cip = inet_addr(lua_tostring(T, -1));
            if (cip == ip)
                ret = 1;
        }
        lua_pop(T, 1);
    } while (!ret);
    lua_pop(T, 1);

    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();

    return ret;
}

int lua_ipv4_address_transfer(unsigned int *ip, int maxaddrs) {

    if (lua_trylock() != 0)
	    return 0;
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    char config[] = "config/network/bindipv4";
    int st = lua_getconfig(T, config);

    if (st == 0) {
        DEBUG(1, "Failed to get bindipv4\n");
        lua_unlock();
        return 0;
    }

    int j = 0;
    int i = 1;
    do {
        lua_rawgeti(T, -1, i++);
        if (lua_isnil(T, -1))
            break;
        if (lua_isstring(T, -1)) {
            unsigned int cip = inet_addr(lua_tostring(T, -1));
	    if (j < maxaddrs)
		    ip[j++] = cip;
        }
        lua_pop(T, 1);
    } while (1);
    lua_pop(T, 1);

    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();

    while (j < maxaddrs)
	    ip[j++] = 0;

    return 1;
}

int lua_ipv6_address_transfer(char ip[][16], int maxaddrs) {

    if (lua_trylock() != 0)
	    return 0;
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    char config[] = "config/network/bindipv6";
    int st = lua_getconfig(T, config);

    if (st == 0) {
        DEBUG(1, "Failed to get bindipv6\n");
        lua_unlock();
        return 0;
    }

    int j = 0;
    int i = 1;
    do {
        lua_rawgeti(T, -1, i++);
        if (lua_isnil(T, -1))
            break;

        if (lua_isstring(T, -1)) {
	    struct in6_addr in6;
            const char *ipv6 = lua_tostring(T, -1);
            int st = inet_pton(AF_INET6, ipv6, &in6);
            if (st == 1) {
		memcpy(ip[j++], in6.s6_addr, 16);
            }
        }
        lua_pop(T, 1);
    } while (1);
    lua_pop(T, 1);

    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();

    while (j < maxaddrs)
	    memset(ip[j++], 0, 16);

    return 1;
}


int lua_ipv6_address_configured(void *ip) {
    struct in6_addr in6;

    int ret = 0;
    lua_lock();
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    char config[] = "config/network/bindipv6";
    int st = lua_getconfig(T, config);

    if (st == 0) {
        DEBUG(1, "Failed to get bindipv6\n");
        lua_unlock();
        return 0;
    }

    int i = 1;
    do {
        lua_rawgeti(T, -1, i++);
        if (lua_isnil(T, -1))
            break;
        if (lua_isstring(T, -1)) {
            const char *ipv6 = lua_tostring(T, -1);
            int st = inet_pton(AF_INET6, ipv6, &in6);
            if (st == 1) {
                if (!memcmp(&in6, ip, sizeof (in6))) {
                    ret = 1;
                }
            }
        }
        lua_pop(T, 1);
    } while (!ret);
    lua_pop(T, 1);

    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();

    return ret;
}

void lua_handle_webrequest(FILE *sock, char *subsys, char *cmd, char *param, char *post) {
    if (!L && !xl_init(sock))
        return;

    lua_lock();
    lua_State *T = lua_newthread(L);
    int r = luaL_ref(L, LUA_REGISTRYINDEX);

    lua_getglobal(T, "webrequest");
    lua_pushstring(T, subsys);
    lua_pushstring(T, cmd);
    lua_pushstring(T, param);
    push_postdata(T, post);
    int st = lua_pcall(T, 4, 1, 0);
    if (st) {
        DEBUG(1, "Error handling webrequest: %s\n", lua_tostring(T, -1));
        lua_pop(T, 1);
        if (sock) {
            reply(sock, 500, NULL);
            fprintf(sock, "Error handling webrequest:\n%s\n", lua_tostring(L, -1));
        }
    } else {
        reply(sock, 200, NULL);
        lua_result_to_json(sock, T);
    }
    luaL_unref(L, LUA_REGISTRYINDEX, r);
    lua_unlock();
}



/*********************/
/*  LUA C-Functions  */

/*********************/

static void lua_setint(lua_State *L, char *key, long val) {
    lua_pushstring(L, key);
    lua_pushnumber(L, val);
    lua_settable(L, -3);
}

static void lua_setstring(lua_State *L, char *key, char *val) {
    lua_pushstring(L, key);
    lua_pushstring(L, val);
    lua_settable(L, -3);
}

void *xl_malloc(void *state, int type, int len) {
    struct xl_data *data = lua_newuserdata(state, sizeof (struct xl_data) +len);
    memset(data, 0, sizeof (struct xl_data) +len);
    data->type = type;
    data->len = len;
    return data->data;
}

int xl_ref(void *state, int index) {
    struct xl_data *data = lua_touserdata(state, index);
    if (!data)
        return -1;
    if (data->ref == 0) {
        DEBUG(1, "Registering key %p\n", data);
        lua_pushvalue(state, index);
        data->regid = luaL_ref(state, LUA_REGISTRYINDEX);
    }

    return ++data->ref;
}

int xl_unref_ud(void *state, struct xl_data *data) {
    if (!data)
        return -1;
    if (data->ref == 1) {
        DEBUG(1, "Unregistering key %p\n", data);
        luaL_unref(state, LUA_REGISTRYINDEX, data->regid);
        data->regid = -1;
    }

    return --data->ref;
}

int xl_unref(void *state, int index) {
    struct xl_data *data = lua_touserdata(state, index);
    return xl_unref_ud(state, data);
}

int xl_pushref(void *state, struct xl_data *data) {
    lua_State *L = state;
    if (data->regid) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, data->regid);
        return 1;
    } else {
        lua_pushnil(L);
        return 0;
    }
}

void *xl_dup(void *state, struct xl_data *orig) {
    struct xl_data *data = lua_newuserdata(state, orig->len + sizeof (struct xl_data));
    data->type = orig->type;
    data->len = orig->len;
    memcpy(data->data, orig->data, orig->len);
    return data->data;
}

void *xl_touserdata(void *state, int type, int index) {
    lua_State *L = state;
    if (index > 0 && (lua_gettop(L) < index))
        return NULL;
    if (!lua_isuserdata(L, index))
        return NULL;
    struct xl_data *data = lua_touserdata(L, index);
    if (data->type != type)
        return NULL;

    return data->data;
}

LUA_FUNCTION(getstats) {
    lua_newtable(L);
    lua_setint(L, "nrcores", ss.nrcores);
    lua_setint(L, "start", ss.start);
    lua_setint(L, "nrzones", ss.nrzones);
    lua_setint(L, "nrrecords", ss.nrrecords);
    lua_setint(L, "maxtreedepth", ss.maxtreedepth);
    lua_setint(L, "timestamp", getmstimestamp());
    lua_setint(L, "lastreset", ss.lastreset);

    return 1;
}

LUA_FUNCTION(resetstats) {
    resetstats();

    return 1;
}

LUA_FUNCTION(getcorestats) {
    if (lua_gettop(L) != 1 || !lua_isnumber(L, 1))
        return 0;
    int nr = lua_tointeger(L, 1);
    if (nr > ss.nrcores)
        return 0;
    struct corestats *cs = ss.corestats + nr;
    lua_newtable(L);
    lua_setint(L, "rxpkt", cs->rxpkt);
    lua_setint(L, "txpkt", cs->txpkt);
    lua_setint(L, "rxbytes", cs->rxbytes);
    lua_setint(L, "txbytes", cs->txbytes);
    unsigned long tsdiff = getmstimestamp() - ss.lastreset;
    if (tsdiff) {
        lua_setint(L, "rxpps", cs->rxpkt * 1000 / tsdiff);
        lua_setint(L, "txpps", cs->txpkt * 1000 / tsdiff);
        lua_setint(L, "rxbps", cs->rxbytes * 8000 / tsdiff);
        lua_setint(L, "txbps", cs->txbytes * 8000 / tsdiff);
    }

    return 1;
}

LUA_FUNCTION(treewalk) {
    if (lua_gettop(L) != 1 || !lua_istable(L, 1))
        return 0;
    int i = 1;
    diptr_t pos = root;
    do {
        lua_rawgeti(L, 1, i++);
        if (lua_type(L, -1) != LUA_TNUMBER) {
            lua_pop(L, 1);
            break;
        }
        int j = lua_tointeger(L, -1);
        pos = DICH(pos->ch[j]);
        lua_pop(L, 1);
        if (!pos)
            return 0;
    } while (1);

    lua_newtable(L);
    lua_setint(L, "nrrecords", pos->nrrecords);
    lua_setint(L, "depth", pos->depth);
    if (pos->zone) {
        lua_setstring(L, "zone", pos->zone->name);
        lua_setint(L, "zoneid", pos->zone->zoneid);
    }
    lua_setstring(L, "name", pos->name);
    lua_pushstring(L, "sub");
    lua_newtable(L);
    for (i = 0; i < NRNODES; i++) {
        if (DICH(pos->ch[i])) {
            if (i >= T_FIRST && !HASTYPE(pos, i))
                continue;
            char nr[32];
            sprintf(nr, "%d", i);
            lua_pushstring(L, nr);
            lua_newtable(L);
            char buf[16];
            if (i < T_A) {
                buf[0] = id2char(i);
                buf[1] = 0;
            } else {
                strcpy(buf, inttype2typestr(i));
            }
            lua_setstring(L, "ch", buf);
            lua_setstring(L, "name", DICH(pos->ch[i])->name);
            lua_settable(L, -3);
        }
    }
    lua_settable(L, -3);
    if (pos->record && pos->nrrecords) {
        lua_pushstring(L, "records");
        lua_newtable(L);
        i = 1;
        int nr = pos->nrrecords;
        char *record = pos->record;
        while (nr--) {
            char rd[2048];
            record = retrieve_record_data(record, rd, sizeof (rd));
            lua_pushnumber(L, i++);
            lua_pushstring(L, rd);
            lua_settable(L, -3);
        }
        lua_settable(L, -3);
    }

    return 1;
}

static void _zoneprint(diptr_t di, diptr_t parent, int subtree, void* args) {
    assert(di->up == parent);
    DEBUG(1, "%40s (%d) ZONE %s\n", di->name, di->type, di->zone->name);
}

LUA_FUNCTION(zoneprint) {
    walk_dnstree(root, _zoneprint, NULL, 0);
    return 0;
}

struct branchinfo {
    int id;
    int nr; 
};
static void _getbranchinfo (diptr_t di, diptr_t parent, int subtree, void *args) {
    struct branchinfo *info = args;

    for (int i = 0; i < 40; i++) {
        if (di->ch[i])
            info[i].nr++;
    }
}

static int sort_branchinfo(const void *a, const void *b) {
    const struct branchinfo *aa = a, *bb = b;

    return bb->nr-aa->nr;
}

LUA_FUNCTION(getbranchinfo) {
    struct branchinfo info[40];

    for (int i = 0; i < 40; i++) {
        info[i].id = i;
        info[i].nr = 0;
    }
    walk_dnstree(root, _getbranchinfo, info, 1);
    info[char2id('*')].nr = -1;
    qsort(info, sizeof(info)/sizeof(info[0]), sizeof(info[0]), sort_branchinfo);
    char str[41];
    for (int i = 0; i < 40; i++) {
        str[i] = id2char(info[i].id);
    }
    str[40] = '\0';

    lua_pushstring(L, str);

    return 1;
}

#ifdef RECORDSTATS

static void _resetrecordstats(diptr_t di, diptr_t parent, int subtree, void *args) {
    di->nrreq = 0;
}

LUA_FUNCTION(resetrecordstats) {
    walk_dnstree(root, _resetrecordstats, NULL, 0);
    return 0;
}

struct recordstats {
    int nr;
    diptr_t slots[1];
};

static void _getrecordstats(diptr_t di, diptr_t parent, int subtree, void *args) {
    struct recordstats *rs = args;

    int i;
    for (i = rs->nr - 1; i >= 0; i--) {
        if (rs->slots[i] && rs->slots[i]->nrreq > di->nrreq)
            break;
    }
    i++;
    if (i >= rs->nr)
        return;
    int j;
    for (j = rs->nr - 1; j > i; j--) {
        rs->slots[j] = rs->slots[j - 1];
    }
    rs->slots[i] = di;
}

LUA_FUNCTION(getrecordstats) {
    int nr = lua_tointeger(L, 1);
    if (!nr)
        return 0;

    struct recordstats *rs = alloca(sizeof (struct recordstats) + sizeof (diptr_t) * nr);
    memset(rs, 0, sizeof (struct recordstats) + sizeof (diptr_t) * nr);
    rs->nr = nr;

    walk_dnstree(root, _getrecordstats, rs, 0);
    int i;
    lua_newtable(L);
    for (i = 0; i < nr; i++) {
        if (rs->slots[i]) {
            lua_newtable(L);
            lua_pushstring(L, "name");
            lua_pushstring(L, rs->slots[i]->name);
            lua_rawset(L, -3);
            lua_pushstring(L, "type");
            lua_pushstring(L, inttype2typestr(rs->slots[i]->type));
            lua_rawset(L, -3);
            lua_pushstring(L, "requests");
            lua_pushnumber(L, rs->slots[i]->nrreq);
            lua_rawset(L, -3);
            lua_rawseti(L, -2, i+1);
        }
    }

    return 1;
}

#endif

LUA_FUNCTION(getsid) {
    lua_pushstring(L, sid);

    return 1;
}

void xl_register_functions(lua_State *L) {
    LUA_ADD_FUNCTION(getstats);
    LUA_ADD_FUNCTION(genkey);
    LUA_ADD_FUNCTION(importkey);
    LUA_ADD_FUNCTION(zoneprint);
    LUA_ADD_FUNCTION(resetstats);
    LUA_ADD_FUNCTION(getcorestats);
    LUA_ADD_FUNCTION(getsid);
    LUA_ADD_FUNCTION(treewalk);
    LUA_ADD_FUNCTION(getbranchinfo);
#ifdef RECORDSTATS
    LUA_ADD_FUNCTION(resetrecordstats);
    LUA_ADD_FUNCTION(getrecordstats);
#endif
}

