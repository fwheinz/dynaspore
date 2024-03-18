#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <mysql/mysql.h>

#include "xfc.h"

static const char *findopt(const char *key, const char *name) {
    const char *ptr = strstr(key, name);
    if (!ptr)
        return NULL;
    ptr += strlen(name);
    while (*ptr && *ptr == ' ')
        ptr++;

    return ptr;
}

static int parsebase64(const char *data, db_t *dst) {
    int decodelen = Base64decode_len(data);
    if (decodelen > 1024)
        return 0;
    dst->len = Base64decode(dst->data, data);

    return dst->len;
}

static int optbase64(const char *key, const char *name, db_t *dst) {
    const char *ptr = findopt(key, name);
    if (!ptr)
        return 0;
    return parsebase64(ptr, dst);
}

#define PARSEB64(name, addr) do { if (optbase64(key, name ":", addr) == 0) { DEBUG(1, "Error parsing " name "\n"); x_free(ret); return 0; } } while (0);

int parse_rsa_key(int keyflags, const char *key, struct dnskey *ret) {
    PARSEB64("Modulus", &ret->modulus);
    PARSEB64("PublicExponent", &ret->publicexponent);
    PARSEB64("PrivateExponent", &ret->privateexponent);
    PARSEB64("Prime1", &ret->prime1);
    PARSEB64("Prime2", &ret->prime2);
    PARSEB64("Exponent1", &ret->exponent1);
    PARSEB64("Exponent2", &ret->exponent2);
    PARSEB64("Coefficient", &ret->coefficient);

    const char *ptr = findopt(key, "Algorithm:");
    if (!ptr) {
        DEBUG(1, "Error parsing algorithm\n");
        x_free(ret);
        return 0;
    }
    ret->active = 1;

    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(ret->modulus.data, ret->modulus.len, NULL);
    BIGNUM *e = BN_bin2bn(ret->publicexponent.data, ret->publicexponent.len, NULL);
    BIGNUM *d = BN_bin2bn(ret->privateexponent.data, ret->privateexponent.len, NULL);
    BIGNUM *p = BN_bin2bn(ret->prime1.data, ret->prime1.len, NULL);
    BIGNUM *q = BN_bin2bn(ret->prime2.data, ret->prime2.len, NULL);
    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    ret->rsa = rsa;
    dnssec_fix_key(ret);

    return 1;
}

int parse_pem_key(int keyflags, const char *key, struct dnskey *ret) {
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, key, strlen(key));
    RSA *rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
    if (!rsa)
        return 0;
    ret->rsa = rsa;
    ret->algo = 8;
    ret->keyflags = keyflags;
    ret->active = 1;
    dnssec_fix_key(ret);

    return 1;
}

static int storebignumb64(const BIGNUM *a, char *buf, int len) {
    int l = Base64encode_len(BN_num_bytes(a));
    if (l > len)
        return -1;
    unsigned char tmp[BN_num_bytes(a)];
    l = BN_bn2bin(a, tmp);
    l = Base64encode(buf, tmp, l);

    return l - 1;
}

static char *algostr(int algo) {
    switch (algo) {
        case 8:
            return "RSASHA256";
            break;
        default:
            return "UNKNOWN";
            break;
    }
}

int export_rsa_key(struct dnskey *key, char *buf, int len) {
    char *ptr = buf;

    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(key->rsa, &n, &e, &d);
    RSA_get0_factors(key->rsa, &p, &q);
    RSA_get0_crt_params(key->rsa, &dmp1, &dmq1, &iqmp);

    int l = snprintf(ptr, len, "Private-key-format: v1.2\nAlgorithm: %d (%s)\nModulus: ", key->algo, algostr(key->algo));
    len -= l;
    ptr += l;
    l = storebignumb64(n, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nPublicExponent: ");
    len -= l;
    ptr += l;
    l = storebignumb64(e, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nPrivateExponent: ");
    len -= l;
    ptr += l;
    l = storebignumb64(d, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nPrime1: ");
    len -= l;
    ptr += l;
    l = storebignumb64(p, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nPrime2: ");
    len -= l;
    ptr += l;
    l = storebignumb64(q, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nExponent1: ");
    len -= l;
    ptr += l;
    l = storebignumb64(dmp1, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nExponent2: ");
    len -= l;
    ptr += l;
    l = storebignumb64(dmq1, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\nCoefficient: ");
    len -= l;
    ptr += l;
    l = storebignumb64(iqmp, ptr, len);
    len -= l;
    ptr += l;

    l = snprintf(ptr, len, "\n");

    return ptr - buf;
}

int gen_rsa_key(int flags, int bits, struct dnskey *key) {
    static BIGNUM *e = NULL;
    if (!e) {
        e = BN_new();
        BN_set_word(e, RSA_F4); // Exponent is 0x10001
    }
    key->keyflags = flags;
    key->algo = 8;

    RSA *rsa = RSA_new();

    lua_unlock();
    int st = RSA_generate_key_ex(rsa, bits, e, NULL);
    if (st == 1) {
        const BIGNUM *n, *e, *d, *p, *q;
        RSA_get0_key(rsa, &n, &e, &d);
        RSA_get0_factors(rsa, &p, &q);
        key->rsa = rsa;
        if (BN_num_bytes(n) <= sizeof (key->modulus.data))
            key->modulus.len = BN_bn2bin(n, key->modulus.data);
        if (BN_num_bytes(e) <= sizeof (key->publicexponent.data))
            key->publicexponent.len = BN_bn2bin(e, key->publicexponent.data);
        if (BN_num_bytes(d) <= sizeof (key->privateexponent.data))
            key->privateexponent.len = BN_bn2bin(d, key->privateexponent.data);
        if (BN_num_bytes(p) <= sizeof (key->prime1.data))
            key->prime1.len = BN_bn2bin(p, key->prime1.data);
        if (BN_num_bytes(q) <= sizeof (key->prime2.data))
            key->prime2.len = BN_bn2bin(q, key->prime2.data);
        key->active = 1;
        dnssec_fix_key(key);
    }
    lua_lock();

    return st;
}

int getpubkey(struct dnskey *k, unsigned char *buf, int len) {
    int lfl = 1;
    unsigned char *ptr = buf;

    if (k->publicexponent.len >= 256)
        lfl = 3;

    if (len < (lfl + k->publicexponent.len + k->modulus.len))
        return 0;

    if (lfl == 3) {
        *ptr++ = 0;
        *ptr++ = k->publicexponent.len >> 8;
        *ptr++ = k->publicexponent.len;
    } else {
        *ptr++ = k->publicexponent.len;
    }
    memcpy(ptr, k->publicexponent.data, k->publicexponent.len);
    ptr += k->publicexponent.len;
    memcpy(ptr, k->modulus.data, k->modulus.len);
    ptr += k->modulus.len;

    return ptr - buf;
}

int recordless(unsigned char *r1, unsigned char *r2) {
    unsigned char *ptr1 = r1;
    unsigned char *ptr2 = r2;
    ptr1 += strlen((char*)ptr1) + 1; // Skip over owner
    ptr2 += strlen((char*)ptr2) + 1; // Skip over owner
    int l1 = ptr1[8]*256 + ptr1[9];
    int l2 = ptr2[8]*256 + ptr2[9];
    int i, l = l1;
    if (l > l2)
        l = l2;
    ptr1 += 10;
    ptr2 += 10;


    for (i = 0; i < l; i++) {
        if (ptr1[i] < ptr2[i]) {
            return 1;
        } else if (ptr1[i] > ptr2[i]) {
            return 0;
        }
    }
    if (l1 < l2)
        return 1;

    return 0;
}

void sign_record(diptr_t rec, struct dnskey *key) {
    int i, j, nrrec = DI_GET(rec)->nrrecords;
    unsigned char *rrset = alloca(rec->recordlen);
    unsigned char **records = alloca((nrrec) * sizeof (unsigned char *));
    unsigned char **recordssorted = alloca((nrrec) * sizeof (unsigned char *));
    unsigned int origttl = 4000000000;
    unsigned short type = 0;
    char *name = DI_GET(rec)->name;
    char *zonename = rec->zone->name;

    memcpy(rrset, DI_GET(rec)->record, DI_GET(rec)->recordlen);

    // Parse the rrset into individual records
    unsigned char *ptr = rrset;
    for (i = 0; i < nrrec; i++) {
        records[i] = ptr;
        ptr = ptr + strlen((char*)ptr) + 1; // Skip over NAME
        unsigned int ttl = ptr[4] << 24 | ptr[5] << 16 | ptr[6] << 8 | ptr[7];
        if (ttl < origttl)
            origttl = ttl;
        unsigned short rdlength = ptr[8]*256 + ptr[9];
        type = ptr[0]*256 + ptr[1];
        ptr += 10 + rdlength; // Skip over TYPE, CLASS, TTL, RDLENGTH, RDATA
    }

    // set the ttl value of the pseudorecords
    for (i = 0; i < nrrec; i++) {
        ptr = records[i];
        ptr = ptr + strlen((char*)ptr) + 5; // Skip over NAME, TYPE, CLASS
        PUTINT(ptr) = htonl(origttl);
    }

    // Now sort the records
    for (i = 0; i < nrrec; i++) {
        int winner = -1;
        for (j = 0; j < nrrec; j++) {
            if (!records[j]) {
                continue;
            } else if (winner < 0) {
                winner = j;
            } else if (recordless(records[j], records[winner])) {
                winner = j;
            }
        }
        recordssorted[i] = records[winner];
        records[winner] = NULL;
    }

    unsigned char algo = key->algo;
    unsigned char lbls = nrlbls(rrset);
    if (rrset[1] == '*')
        lbls--;
    unsigned int sigexp = time(NULL) + 86400 * 30;
    unsigned int siginc = time(NULL);
    unsigned short keytag = key->keytag;

    int sslen = 20 + strlen(zonename) + DI_GET(rec)->recordlen;
    unsigned char *ss = alloca(sslen);
    ptr = ss;
    PUTSHORT(ptr) = htons(type);
    ptr += 2;
    PUTCHAR(ptr) = algo;
    ptr += 1;
    PUTCHAR(ptr) = lbls;
    ptr += 1;
    PUTINT(ptr) = htonl(origttl);
    ptr += 4;
    PUTINT(ptr) = htonl(sigexp);
    ptr += 4;
    PUTINT(ptr) = htonl(siginc);
    ptr += 4;
    PUTSHORT(ptr) = htons(keytag);
    ptr += 2;
    ptr = name2lbl(ptr, zonename);
    for (i = 0; i < nrrec; i++) {
        unsigned char *rr = recordssorted[i];
        unsigned char *tmp = rr + strlen((char*)rr) + 9;
        int rdlength = tmp[0]*256 + tmp[1];
        tmp += rdlength + 2;
        memcpy(ptr, rr, (tmp - rr));
        ptr += (tmp - rr);
    }

    SHA256_CTX md;
    SHA256_Init(&md);
    SHA256_Update(&md, ss, sslen);
    unsigned char digest[SHA256_DIGEST_LENGTH];

    unsigned char signature[1000];
    unsigned int siglen = sizeof (signature);
    SHA256_Final(digest, &md);
    RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &siglen, key->rsa);
    char b64[1000];
    Base64encode(b64, signature, siglen);

    char str[4096];
    unsigned char data[4096];
    snprintf(str, sizeof (str), "%s %u %u %u %u %u %u %s. %s", type2typestr(type),
            algo, lbls, origttl, sigexp, siginc, keytag, zonename, b64);

    int len = create_rrsig_record_content(data, str);
    if (len < 0) {
        DEBUG(1, "Parse error for RRSIG: %s\n", str);
        return;
    }
    if (!DICH(rec->ch[T_RRSIG])) {
        DICHA(rec->ch[T_RRSIG]) = diallocname(0, name, T_RRSIG);
    }
    if (*name == '.')
        name++;
    create_record_data(DICH(rec->ch[T_RRSIG]), name, 46, origttl, data, len);
    DEBUG(4, "Created signature for %s: %s (%d)\n", name, str, len);
}

void sign_subtree(diptr_t di, struct dnskey *key, int depth) {
    int i;
    struct di *node = di;
    if (depth > 0 && DICH(node->ch[T_SOA]))
        return;
    for (i = 0; i < sizeof (node->ch) / sizeof (node->ch[0]); i++) {
        if (DICH(node->ch[i])) {
            if (i < T_A) {
                if (depth > 0 || i == LABELSEP)
                    sign_subtree(DICH(node->ch[i]), key, depth + 1);
            } else {
                if ((i == T_DNSKEY && key->keyflags == 257) ||
                        (i != T_DNSKEY && key->keyflags == 256))
                    sign_record(DICH(node->ch[i]), key);
            }
        }
    }
}

void sign_zone(struct zone *z) {
    zone_remove_records(z, T_RRSIG);
    deploy_keys(z);

    int active = 0;
    int i;
    for (i = 0; i < z->nrkeys; i++) {
        struct dnskey *key = z->keys[i];
        active += key->active;
    }
    if (!active)
        return;
    deploy_nsec(z);

    for (i = 0; i < z->nrkeys; i++) {
        struct dnskey *key = z->keys[i];
        if (key->active) {
            DEBUG(2, "Found key %d for zone %s\n", key->keytag, z->name);
            sign_subtree(z->node, key, 0);
        }
    }
}

static int deploy_key(struct zone *z, struct dnskey *key) {
    unsigned char rbuf[4096];

    int len = getpubkey(key, rbuf, sizeof (rbuf));
    if (len == 0) {
        DEBUG(2, "deploy_key: Key for %s invalid\n", z->name);
        return 0;
    }
    char b64key[Base64encode_len(len)];
    len = Base64encode(b64key, rbuf, len);

    char content[100 + len];
    snprintf(content, sizeof (content), "%d %d %d %s", key->keyflags, 3, key->algo, b64key);

    DEBUG(3, "Deployed: %s IN DNSKEY %s\n", z->name, content);
    create_record((char *) z->name, "DNSKEY", content, "3600", NULL);

    return 1;
}

int deploy_keys(struct zone *z) {
    int ret = 0, i;

    if (HASTYPE(z->node, T_DNSKEY))
        clear_record(DICH(z->node->ch[T_DNSKEY]));

    for (i = 0; i < z->nrkeys; i++) {
        struct dnskey *key = z->keys[i];
        deploy_key(z, key);
        ret++;
    }

    return ret;
}

void create_nsec_record(diptr_t ln, const char *name, struct zone *z) {
    char content[1024], *ptr = content;
    int len = sizeof (content);
    int i;

    int l = snprintf(ptr, len, "%s. NSEC RRSIG ", name);
    ptr += l;
    len -= l;
    for (i = T_FIRST; i < T_LAST; i++) {
        diptr_t di = DICH(ln->ch[i]);
        if (di && di->nrrecords) {
            l = snprintf(ptr, len, "%s ", inttype2typestr(i));
            ptr += l;
            len -= l;
        }
    }
    create_record_raw(ln->name, 47, content, 3600, -1);
}

static struct nsec_tree *nsec_set_next_name(struct nsec_tree *root, struct nsec_tree *prev, struct zone *z) {

    if (root) {
        prev = nsec_set_next_name(root->left, prev, z);
        if (prev) {
            create_nsec_record(prev->parent, root->parent->name, z);
            prev->next = root;
        }
        prev = nsec_set_next_name(root->right, root, z);
    }

    return prev;
}

void _create_nsec_tree(struct nsec_tree **ptr, diptr_t di) {
    if (!*ptr) {
        *ptr = x_calloc(sizeof (struct nsec_tree)+strlen(di->name) + 1, 1);
        strcpy((*ptr)->name, di->name);
        (*ptr)->parent = di;
    } else {
        int st = strcmp((*ptr)->name, di->name);
        if (st > 0)
            _create_nsec_tree(&(*ptr)->left, di);
        else if (st < 0)
            _create_nsec_tree(&(*ptr)->right, di);
    }
}

void create_nsec_tree(diptr_t di, diptr_t parent, int subtree, void *args) {
    struct nsec_tree **tree = args;
    _create_nsec_tree(tree, parent);
}

diptr_t find_nsec_record(struct zone *z, char *name) {
    if (!z)
        return NULL;
    struct nsec_tree *tree = z->nsec, *last = NULL;
    while (tree) {
        int st = strcasecmp(tree->name, name);
        if (st > 0) {
            tree = tree->left;
        } else if (st < 0) {
            last = tree;
            tree = tree->right;
        } else {
            return DICH(tree->parent->ch[T_NSEC]);
        }
    }
    if (!last)
        last = z->nsec_last;
    if (!last || !last->parent)
        return 0;
    return DICH(last->parent->ch[T_NSEC]);
}

static void _nsec_tree_free(struct nsec_tree *tree) {
    if (!tree)
        return;
    _nsec_tree_free(tree->left);
    _nsec_tree_free(tree->right);
    x_free(tree);
}

void nsec_tree_free(struct zone *z) {
    _nsec_tree_free(z->nsec);
    z->nsec = NULL;
}

int deploy_nsec(struct zone *z) {
    // Remove old entries
    zone_remove_records(z, T_NSEC);
    nsec_tree_free(z);
    struct nsec_tree **tree = &z->nsec;
    walk_zone(z->node, create_nsec_tree, tree, 0);
    struct nsec_tree *last = nsec_set_next_name(*tree, NULL, z);
    struct nsec_tree *first = *tree;
    while (first && first->left)
        first = first->left;
    last->next = first;
    create_nsec_record(last->parent, first->parent->name, z);
    z->nsec_last = last;

    return 0;
}

void free_key(struct dnskey *key) {
    RSA_free(key->rsa);
    x_free(key);
}

static unsigned int keytag(unsigned char key[], unsigned int keysize) {
    unsigned long ac; /* assumed to be 32 bits or larger */
    int i; /* loop index */

    for (ac = 0, i = 0; i < keysize; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

int dnssec_get_dnskeyrr(struct dnskey *key, unsigned char *rbuf, int rbuflen) {
    int len = getpubkey(key, rbuf, rbuflen);
    if (len <= 0) {
        DEBUG(2, "dnssec_calc_keytag: Key invalid\n");
        return -1;
    }
    char b64key[Base64encode_len(len)];
    len = Base64encode(b64key, rbuf, len);

    char content[len + 100];
    snprintf(content, sizeof (content), "%d %d %d %s", key->keyflags, 3, key->algo, b64key);

    int rdlength = create_dnskey_record_content(rbuf, content);

    return rdlength;
}

static int dnssec_get_dsrr_from_dnskeyrr(const char *name, unsigned char *dnskeyrr, int rrlen, unsigned char *rbuf, int rbuflen) {
    if (!is_valid_dnsname(name))
        return -1;

    if (rbuflen < 4 + SHA256_DIGEST_LENGTH)
        return -1;

    unsigned char lbl[257];
    unsigned char *ptr = name2lbl(lbl, name);

    SHA256_CTX md;
    SHA256_Init(&md);
    SHA256_Update(&md, lbl, ptr - lbl);
    SHA256_Update(&md, dnskeyrr, rrlen);

    unsigned short kt = keytag(dnskeyrr, rrlen);
    get_ushort(&dnskeyrr); // flags
    get_uchar(&dnskeyrr); // protocol
    unsigned char algorithm = get_uchar(&dnskeyrr); // algorithm

    put_ushort(&rbuf, kt);
    put_uchar(&rbuf, algorithm);
    put_uchar(&rbuf, 2); // 2 is SHA256
    SHA256_Final(rbuf, &md);

    return 4 + SHA256_DIGEST_LENGTH;
}

int dnssec_get_dsrr_from_dnskey(const char *name, struct dnskey *dnskey, unsigned char *rbuf, int rbuflen) {
    unsigned char content[8192];

    int len = dnssec_get_dnskeyrr(dnskey, content, sizeof (content));
    if (len < 0)
        return -1;

    return dnssec_get_dsrr_from_dnskeyrr(name, content, len, rbuf, rbuflen);
}

static int dnssec_calc_keytag(struct dnskey *key) {
    unsigned char rbuf[4096];

    int rdlength = dnssec_get_dnskeyrr(key, rbuf, sizeof (rbuf));
    key->keytag = keytag(rbuf, rdlength);

    return 1;
}

static int RSA_augment_key(RSA *rsa) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp = BN_new();

    const BIGNUM *n, *e, *d, *p, *q;
    BIGNUM *dmp1, *dmq1, *iqmp;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);

    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();

    if (!BN_sub(tmp, p, BN_value_one())) goto fail;
    if (!BN_mod(dmp1, d, tmp, ctx)) goto fail;
    if (!BN_sub(tmp, q, BN_value_one())) goto fail;
    if (!BN_mod(dmq1, d, tmp, ctx)) goto fail;
    if (!BN_mod_inverse(iqmp, q, p, ctx)) goto fail;
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

    goto cleanup;

fail:
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);

cleanup:
    BN_free(tmp);
    BN_CTX_free(ctx);

    return 1;
}

void dnssec_fix_key(struct dnskey *k) {
    RSA_augment_key(k->rsa);
    dnssec_calc_keytag(k);
}

int parse_dnssec_key(int keyflags, const char *key, struct dnskey *ret) {
    const char *ptr = findopt(key, "Algorithm:");
    if (!ptr) {
        DEBUG(1, "Error parsing algorithm\n");
        x_free(ret);
        return 0;
    }
    ret->keyflags = keyflags;
    ret->algo = atoi(ptr);
    if (ret->algo == 8) {
        // RSA
        return parse_rsa_key(keyflags, key, ret);
    } else {
        DEBUG(1, "Unsupported algorithm: %d\n", ret->algo);
        x_free(ret);
        return 0;
    }
}


