#ifndef _XFC_H
#define _XFC_H

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>

#define DEBUGLEVEL 2

#define RECORDSTATS 1

typedef struct di * diptr_t;
typedef struct di * dich_t;
#define DICH(x) (x)
#define DICHA(x) (x)
#define DICHAR(x) (x)
#define DI_GET(x) (x)
#define DICHNULL(x) (x)

#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

typedef unsigned char u8;

void *x_realloc(void *ptr, size_t size);
void *x_malloc(size_t size);
void *x_calloc(size_t num, size_t size);
void x_free(void *ptr);

extern int nralloc;
extern long bytesalloc;




#define LOGFP stderr
#define DEBUG(x,y ...) do { if (DEBUGLEVEL >= x) { fprintf(LOGFP, y); } } while (0);

enum {
    T_FIRST = 40,
    T_A = T_FIRST,
    T_AAAA,
    T_NS,
    T_SOA,
    T_MX,
    T_SRV,
    T_TXT,
    T_CNAME,
    T_PTR,
    T_TLSA,
    T_DNSKEY,
    T_RRSIG,
    T_NSEC3,
    T_NSEC,
    T_DS,
    T_LAST // Must be last!
};

struct di {
    unsigned char depth;
    unsigned char type;
    unsigned char nrrecords;
    unsigned char has_soa : 1, has_ns : 1, has_wc : 1, has_cname : 1, padding:4;
    dich_t ch[40 + (T_LAST - T_FIRST)];
    unsigned char *record, *shortrecord;
    int recordlen, shortrecordlen;
    unsigned int nrreq;
    struct zone *zone;
    diptr_t cname;
    diptr_t *additional;
    diptr_t up;
    char name[0]; // MUST BE LAST!
} __attribute__ ((packed));
extern diptr_t root;
#define NRNODES (sizeof(root->ch)/sizeof(root->ch[0]))

struct nsec_tree {
    struct nsec_tree *left;
    struct nsec_tree *right;
    struct nsec_tree *next;
    diptr_t parent;
    diptr_t record;
    char name[1];
};

struct answerdata {
    diptr_t answer;
    diptr_t soa;
    diptr_t wc;

    int rtype;
};


void open_socket(char *ip);
void *packet_loop(void *);
void printdi(struct di *);
struct di *walktree(char *name, int nl, int typeid, struct answerdata *ad);
int answer_packet(unsigned char *buf, int len, int maxlen);
diptr_t maketree(diptr_t pos, const char *name, int typeid, int store);
struct zone *zonestartswith(char *name);
int walk_zones(int (*cb)(struct zone *z, void *arg), void *arg);
int walk_zones_prefix(int (*cb)(struct zone *z, void *arg), void *arg, const char *prefix);
void walk_zone(diptr_t node, void (*cb)(diptr_t di, diptr_t parent, int subtree, void* args), void* args, int callnodes);
void walk_dnstree(diptr_t node, void (*cb)(diptr_t di, diptr_t parent, int subtree, void* args), void* args, int callnodes);
diptr_t find_nsec_record(struct zone *z, char *name);

void zone_set(diptr_t di, struct zone *z);
void zone_delete(struct zone *z);
void zone_remove_records(struct zone *z, int type);
void nsec_tree_free(struct zone *z);
void dnstree_remove_zone(struct zone *z);
void clear_record(diptr_t);
int remove_records_by_type(diptr_t di, unsigned long type);

#define HASTYPE(di,type) (DICHNULL((di)->ch[type]) && DICH((di)->ch[type])->nrrecords)




#define ISLABELSEP(x) ((x) == LABELSEP)

#define RTYPE_NORMAL   0
#define RTYPE_SUBDEL   1
#define RTYPE_NODATA   2
#define RTYPE_NXDOMAIN 3
#define RTYPE_WILDCARD 4

char id2char(int id);

#include "char2id.h"
static inline int char2id (unsigned char ch) {
	return ((signed char *) CHAR2IDTABLE)[ch];
}

static inline int char2id2(unsigned char c) {
    c |= 0x20;
    if (likely(c >= 'a' && c <= 'z')) {
        return c - 'a';
    } else if (c >= '0' && c <= '9') {
        return c - '0' + 0x1A;
    } else if (c == '-') {
        return 0x24;
    } else if (c == 0x7f) {
        return 0x25;
    } else if (c == '.') {
        return LABELSEP;
    } else if (c == '*') {
        return WILDCARD;
    } else {
        return -1;
    }
}

static inline int type2id(unsigned int type) {
    return ((const unsigned char*)
            "\x00\x28\x2a\x00\x00\x2f\x2b\x00\x00\x00"
            "\x00\x00\x30\x00\x00\x2c\x2e\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00"
            "\x00\x00\x00\x2d\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x36\x00\x00\x33\x35\x32\x00"
            "\x34\x00\x31\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x28")[type & 0x7f];
}

static inline void fix_parent(diptr_t di) {
    if (!di->up)
	    return;
    if (di->type == T_SOA) {
        di->up->has_soa = di->nrrecords > 0;
    } else if (di->type == T_NS) {
        di->up->has_ns = di->nrrecords > 0;
    } else if (di->up->type == WILDCARD) {
        di->up->up->has_wc = di->up->nrrecords > 0;
    } else if (di->type == T_CNAME) {
        di->up->has_cname = di->nrrecords > 0;
    }
}

int typestr2type(const char *type);
const char *inttype2typestr(int type);
const char *type2typestr(int type);
int lbl2name(unsigned char *lbl, char *name, int maxlen);
int lbl2name_fast(unsigned char *lbl, char *name, int maxlen);
int lbl2name_compressed(unsigned char **lbl, char *name, unsigned char *pkt, int pktlen);
int lbl2name2(unsigned char *lbl, char *name, int maxlen);
unsigned char *name2lbl(unsigned char *target, const char *domain);
int nrlbls(unsigned char *lbl);

extern char *aux_buf;
extern int aux_buflen;

typedef struct {
    unsigned char data[1024];
    int len;
} db_t;

struct dnskey {
    int keyflags;
    int algo;
    int keytag;
    int active;

    db_t modulus;
    db_t publicexponent;
    db_t privateexponent;
    db_t prime1;
    db_t prime2;
    db_t exponent1;
    db_t exponent2;
    db_t coefficient;

    RSA *rsa; // Type struct rsa

    void *ud;
};

struct corestats {
    unsigned long rxpkt;
    unsigned long txpkt;

    unsigned long rxbytes;
    unsigned long txbytes;
};

struct serverstats {
    int nrcores;
    time_t start;
    int nrzones;
    int nrrecords;
    int maxtreedepth;
    unsigned long lastreset;

    struct corestats *corestats;
};

extern struct serverstats ss;

void create_record_data(diptr_t di, const char *name, int type, unsigned int ttl, unsigned char *data, int datalen);
diptr_t create_record_from_line(const char *line);
int create_rrsig_record_content(unsigned char *rbuf, const char *content);
int create_dnskey_record_content(unsigned char *rbuf, const char *content);
int create_record_content(unsigned char *rbuf, int type, const char *content, int prio);
unsigned char *skip_records(unsigned char *ptr, int nr);
void reprocess_zone(struct zone *z);
void reprocess_zone_forced(struct zone *z);
void reprocess_zone_datasource(const char *dsname);
char *skip_word(char *ptr);
diptr_t create_record_raw(const char *name, int type, const char *content, unsigned int ttl, int prio);
diptr_t create_record(char *name, const char *type, char *content, const char *ttl, char *prio);
diptr_t diallocname(diptr_t parent, const char *name, int type);
void difree(diptr_t);
void walk_records(diptr_t dip, void (*cb)(diptr_t di, diptr_t parent, int subtree, void *arg), void *arg);
unsigned long getmstimestamp(void);
int remove_zone(struct zone *zone);
struct datasource *datasource_add_mysql(char *host, char *dbname, char *username, char *password);
int is_valid_dnsname(const char *name);
void lua_handle_webexec(FILE *sock, char *url, char *post);
void lua_handle_webrequest(FILE *sock, char *subsys, char *cmd, char *param, char *post);
int lua_ipv4_address_transfer(unsigned int *ip, int maxaddrs);
int lua_ipv4_address_configured(unsigned int ip);
int lua_ipv6_address_transfer(char ip[][16], int maxaddrs);
int lua_ipv6_address_configured(void *ip);
void _lua_lock();
int _lua_trylock();
void _lua_unlock();
void resetstats(void);
int deploy_keys(struct zone *z);
void free_key(struct dnskey *key);

void reply(FILE *sock, int code, char *msg);
int xl_init(FILE *sock);
int xl_reload(FILE *sock);


void *start_control(void*);

extern __thread char sid[256];


#define XL_UNDEF    0
#define XL_TREEITEM 1
#define XL_DNSKEY   2
#define XL_RECORD   3
#define XL_ZONE     4

struct xl_data {
    int type;
    int len;
    int regid;
    int ref;
    char data[1];
};

struct xl_record {
    char name[256];
    int type;
    int index;
};

struct xl_zone {
    struct zone *z;
};

struct xl_dnskey {
    struct dnskey key;
};

int getpubkey(struct dnskey *k, unsigned char *buf, int len);
int gen_rsa_key(int flags, int bits, struct dnskey *dnskey);
int parse_rsa_key(int keyflags, const char *key, struct dnskey *dnskey);
int parse_dnssec_key(int keyflags, const char *key, struct dnskey *dnskey);
int parse_pem_key(int keyflags, const char *key, struct dnskey *dnskey);
int export_rsa_key(struct dnskey *key, char *buf, int len);

void sign_zone(struct zone *z);
int Base64encode_len(int len);
int Base64encode(char * coded_dst, const unsigned char *plain_src, int len_plain_src);
int Base64decode_len(const char * coded_src);
int Base64decode(unsigned char * plain_dst, const char *coded_src);


void *xl_malloc(void *state, int type, int len);
void *xl_dup(void *state, struct xl_data *data);
int xl_ref(void *state, int index);
int xl_pushref(void *state, struct xl_data *data);
int xl_unref_ud(void *state, struct xl_data *data);
int xl_unref(void *state, int index);
void *xl_touserdata(void *state, int type, int index);


extern unsigned long steps;

void *mymalloc(size_t size);
void *mycalloc(size_t nmemb, size_t size);
char *mystrdup(char *str);

#define PUTCHAR(x) *((unsigned char *)x)
#define PUTSHORT(x) *((unsigned short *)x)
#define PUTINT(x) *((unsigned int *)x)
#define GETCHAR(x) *((unsigned char *)x)
#define GETSHORT(x) *((unsigned short *)x)
#define GETINT(x) *((unsigned int *)x)

static inline unsigned int get_uint(unsigned char **pptr) {
    unsigned char *ptr = *pptr;
    unsigned int ret = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
    *pptr += 4;
    return ret;
}

static inline void put_uint(unsigned char **pptr, unsigned int v) {
    unsigned char *ptr = *pptr;
    ptr[0] = v >> 24;
    ptr[1] = v >> 16;
    ptr[2] = v >> 8;
    ptr[3] = v;
    *pptr += 4;
}

static inline unsigned short get_ushort(void *arg) {
    unsigned char **pptr = arg;
    unsigned char *ptr = *pptr;
    unsigned short ret = ptr[0] << 8 | ptr[1];
    *pptr += 2;
    return ret;
}

static inline void put_ushort(unsigned char **pptr, unsigned short v) {
    unsigned char *ptr = *pptr;
    ptr[0] = v >> 8;
    ptr[1] = v;
    *pptr += 2;
}

static inline unsigned char get_uchar(unsigned char **pptr) {
    unsigned char *ptr = *pptr;
    unsigned short ret = ptr[0];
    *pptr += 1;
    return ret;
}

static inline void put_uchar(unsigned char **pptr, unsigned char v) {
    unsigned char *ptr = *pptr;
    ptr[0] = v;
    *pptr += 1;
}

static inline char *get_string(unsigned char **pptr) {
    char *ptr = (char*)*pptr;
    *pptr += strlen(ptr) + 1;

    return ptr;
}

static inline void put_string(unsigned char **pptr, char *string) {
    strcpy((char*)*pptr, string);
    *pptr += strlen(string) + 1;
}

#define ZONE_BULKEDIT 1

struct zone {
    char name[257];
    time_t last_reload;
    char datasource[64];
    unsigned int flags;
    int zoneid;
    struct zone *left, *right, *parent;
    int ldepth, rdepth;
    diptr_t node;
    int active;
    struct nsec_tree *nsec, *nsec_last;
    struct dnskey **keys;
    int nrkeys;
};

struct record {
    char name[257];
    unsigned int ttl;
    int cls;
    int type;
    char rdata[65536];
    int rdlength;
};

struct rtype {
    char name[10];
    int (*create) (char *rbuf, int rlen, char *content);
    int (*retrieve)(char *rbuf, int rlen, char *content);
    int (*pktparse)(char *pkt, int pktlen, char *ptr, struct record *r);
};

int parse_record_from_packet(u8 *pkt, int pktlen, u8 *ptr, struct record *r);

struct datasource {
    char *driver;
    int (*prepare)(struct datasource *ds, void *arg);
    int (*reload)(struct datasource *ds, struct zone *zone, void *arg);
    int (*zoneload)(struct datasource *ds, const char *name, void *arg);
    int (*zonesave)(struct datasource *ds, struct zone *z, void *arg);
    int (*keyload)(struct datasource *ds, const char *name, void *arg, void (*cb)(void *arg, struct dnskey *k, char *z));
    int (*keysave)(struct datasource *ds, struct zone *z, void *arg);
    int (*finish)(struct datasource *ds, void *arg);

    void *priv;
    pthread_mutex_t mutex;
};
struct datasource *datasource_register(struct datasource *nds);
struct datasource *datasource_find(const char *name);
void datasource_init(void);
extern struct datasource datasource_mysql, datasource_axfr;
const char *xl_getstring(void *context, char *key);
int xl_getnumber(void *context, char *key, int *valid);
void xl_error(void *context, char *error);

unsigned char *retrieve_record_data(unsigned char *ptr, char *buf, int len);
unsigned char *retrieve_record_data_dots(unsigned char *ptr, char *buf, int len, int dots);
unsigned char *retrieve_record_data_axfr(unsigned char *ptr, char *buf, int len, unsigned char *pkt, int pktlen, struct record *r);
int retrieve_record_content(unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots);

struct zone *fetch_zone(const char *name, int create);
int zone_add_key(struct zone *z, struct dnskey *key);
int zone_del_key(struct zone *z, struct dnskey *key);
int deploy_nsec(struct zone *z);
int typecmp(const char *str, const char *type);

void dnstree_inaugurate_zone(struct zone *z);

void dnssec_fix_key(struct dnskey *);
int dnssec_get_dsrr_from_dnskey(const char *name, struct dnskey *dnskey, unsigned char *rbuf, int rbuflen);
int dnssec_get_dnskeyrr(struct dnskey *key, unsigned char *rbuf, int rbuflen);

void do_benchmark (void);

// #define lua_lock() do { DEBUG(1, "lua_lock in %s()@%s:%d\n", __FUNCTION__, __FILE__, __LINE__); _lua_lock(); } while (0)
// #define lua_unlock() do { DEBUG(1, "lua_unlock in %s()@%s:%d\n", __FUNCTION__, __FILE__, __LINE__); _lua_unlock(); } while (0)
#define lua_lock _lua_lock
#define lua_unlock _lua_unlock
#define lua_trylock _lua_trylock

#endif
