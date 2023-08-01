#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#ifndef TEST
#include <rte_memcpy.h>
#else
#warning "Compiling in test mode"

int rte_memcpy(void *dst, void *src, int len) {
    return memcpy(dst, src, len);
}
#endif

#include "xfc.h"

const char *type2typestr(int type) {

    switch (type) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 12:
            return "PTR";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 28:
            return "AAAA";
        case 33:
            return "SRV";
        case 43:
            return "DS";
        case 46:
            return "RRSIG";
        case 47:
            return "NSEC";
        case 48:
            return "DNSKEY";
        case 50:
            return "NSEC3";
        case 51:
            return "NSEC3PARAM";
        case 52:
            return "TLSA";
        case 99:
            return "SPF";
    }
    return "UNK";
}

int typecmp(const char *str, const char *type) {
    while (*type && *str && (toupper(*str++) == toupper(*type++)))
        ;

    if (!*type && (!*str || *str == ' '))
        return 1;

    return 0;
}

int typestr2type(const char *type) {
    if (typecmp(type, "A")) {
        return 1;
    }
    if (typecmp(type, "AAAA")) {
        return 28;
    }
    if (typecmp(type, "NS")) {
        return 2;
    }
    if (typecmp(type, "SOA")) {
        return 6;
    }
    if (typecmp(type, "PTR")) {
        return 12;
    }
    if (typecmp(type, "MX")) {
        return 15;
    }
    if (typecmp(type, "SRV")) {
        return 33;
    }
    if (typecmp(type, "TXT")) {
        return 16;
    }
    if (typecmp(type, "CNAME")) {
        return 5;
    }
    if (typecmp(type, "SPF")) {
        return 99;
    }
    if (typecmp(type, "TLSA")) {
        return 52;
    }
    if (typecmp(type, "DNSKEY")) {
        return 48;
    }
    if (typecmp(type, "RRSIG")) {
        return 46;
    }
    if (typecmp(type, "NSEC")) {
        return 47;
    }
    if (typecmp(type, "NSEC3")) {
        return 50;
    }
    if (typecmp(type, "NSEC3PARAM")) {
        return 51;
    }
    if (typecmp(type, "DS")) {
        return 43;
    }

    return -1;
}

const char *inttype2typestr(int type) {
    switch (type) {
        case T_A:
            return "A";
        case T_AAAA:
            return "AAAA";
        case T_NS:
            return "NS";
        case T_SOA:
            return "SOA";
        case T_MX:
            return "MX";
        case T_SRV:
            return "SRV";
        case T_TXT:
            return "TXT";
        case T_CNAME:
            return "CNAME";
        case T_PTR:
            return "PTR";
        case T_TLSA:
            return "TLSA";
        case T_DNSKEY:
            return "DNSKEY";
        case T_RRSIG:
            return "RRSIG";
        case T_NSEC3:
            return "NSEC3";
        case T_NSEC:
            return "NSEC";
        case T_DS:
            return "DS";
    }
    return "UNK";
}

unsigned char *name2lbl(unsigned char *target, const char *domain) {
    assert(is_valid_dnsname(domain));
    
    if (!strlen(domain)) {
        target[0] = '\0';
        return target;
    }
    strcpy((char *) target + 1, domain);
    if (target[strlen((char*)target + 1)] == '.')
        target[strlen((char*)target + 1)] = '\0';
    unsigned char *ptr = target;
    do {
        unsigned char *lptr = ptr++;
        *lptr = 0;
        while (*ptr && *ptr != '.') {
            (*lptr)++;
            ptr++;
            if (*lptr > 63)
                return NULL;
        }
    } while (*ptr);

    return ptr + 1;
}

int lbl2name(unsigned char *lbl, char *name, int maxlen) {
    int len = 0;

    if (!*lbl)
        return 1;
    if (maxlen > 256)
        maxlen = 256;
    rte_memcpy(name, lbl, maxlen);
    do {
        int l = *name + 1;
        len += l;
        if (len > maxlen)
            return -2;
        if (l > 1)
            *name = '.';
        else
            break;
        name += l;
    } while (1);

    return len;
}

int lbl2name_compressed(unsigned char **_lbl, char *dst, unsigned char *pkt, int pktlen) {
    unsigned char *lbl = *_lbl;
    unsigned char *ptr = lbl;
    unsigned char *pktend = pkt + pktlen;
    int crec = 0, lbllen = 0;

    if (!pkt)
        pktend = lbl + 255;

    while ((ptr >= pkt) && (ptr < pktend) && (crec < 10)) {
        int l = *ptr;
        if ((l & 0xc0) == 0xc0) {
            if (!pkt)
                return -1;
            if (crec == 0)
                *_lbl = ptr + 2;
            ptr = pkt + ptr[1] + (ptr[0]&0x3f)*256;
            crec++;
            continue;
        } else if (l > 0x7f) {
            // invalid
            DEBUG(1, "l2nc labellen invalid: %d\n", l);
            return -1;
        } else if (l == 0) {
            dst[lbllen] = '\0';
            if (crec == 0)
                *_lbl = ptr + 1;
            return lbllen;
        }
        ptr++;
        if (lbllen > 0) {
            dst[lbllen] = '.';
            lbllen++;
        }
        if ((ptr + l) > pktend) {
            //invalid
            DEBUG(1, "l2nc labellen too long: %d\n", l);
            return -1;
        }
        if ((lbllen + l) > 255) {
            DEBUG(1, "l2nc label too long: %d\n", lbllen + l);
            //invalid
            return -1;
        }
        memcpy(dst + lbllen, ptr, l);
        ptr += l;
        lbllen += l;
    }

    DEBUG(1, "l2nc failed: crec %d, lbllen %d\n", crec, lbllen);


    // invalid
    return -1;
}

char noop(unsigned char ch) {
    return ch;
}

int lbl2name2(unsigned char *lbl, char *name, int maxlen) {
    int len = 0;

    if (!*lbl)
        return 1;
    if (maxlen > 256)
        maxlen = 256;
    rte_memcpy(name, lbl, maxlen);
    unsigned char ch = 0;
    do {
        int l = *name + 1;
        if (l <= 0)
            return 0;
        *name = 0x80 | ch;
        len += l;
        if (len > maxlen)
            return -2;
        ch = 0;
        for (int i = 1; i <= l; i++) {
            ch += name[i]&0xf;
        }
        if (l <= 1)
            break;
        name += l;
    } while (1);
    name[1] = '\0';

    return len + 1;
}

int name2name2(char *name, char *target, int maxlen) {
    unsigned char *tmp = alloca(strlen(name) + 2);
    name2lbl(tmp, name);
    return lbl2name2(tmp, target, maxlen);
}

int nrlbls(unsigned char *lbl) {
    int len = strlen((char*)lbl);
    int ret = 0;

    while (*lbl) {
        ret++;
        len -= *lbl - 1;
        if (len < 0)
            break;
        lbl += *lbl + 1;
    }

    return ret;
}

char id2char (int id) {
    for (int i = 0; i < 256; i++) {
        if (CHAR2IDTABLE[i] == id)
            return i;
    }
    return -1;
}

char id2char2(int id) {
    if (id < 26)
        return 'a' + id;
    if (id < 36)
        return '0' + (id - 26);
    if (id == 36)
        return '-';
    if (id == 37)
        return '_';
    if (id == 38)
        return '.';
    if (id == 39)
        return '*';
    return -1;
}

void printdi(struct di *di) {
    int i;

    if (!di) {
        printf("NULLRECORD\n");
        return;
    }

    printf("%02d: %50s ", di->depth, di->name);
    for (i = 0; i < sizeof (di->ch) / sizeof (di->ch[0]); i++) {
        if (DICH(di->ch[i])) {
            if (i < 40)
                printf("%c", id2char(i));
            else if (i < T_LAST)
                printf(" %s", inttype2typestr(i));
        } else
            printf(" ");
    }
    printf("\n");
}

int is_valid_dnsname(const char *name) {
    int i, ll;

    if (!name || strlen(name) > 255)
        return 0;

    ll = 0;
    int nl = strlen(name);
    for (i = 0; i < nl; i++) {
        char c = name[i];
        if (!(
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                (c == '.') ||
                (c == '*') ||
                (c == '-') ||
                (c == '_')
                ))
            return 0;
        if (c == '.') {
            if (ll == 0)
                return 0;
            ll = 0;
        } else {
            ll++;
            if (ll >= 64)
                return 0;
        }
    }

    return 1;
}

unsigned long getmstimestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

char *skip_word(char *ptr) {
    if (!ptr)
        return NULL;
    ptr = strchr(ptr, ' ');
    if (!ptr)
        return NULL;
    while (*ptr && *ptr == ' ')
        ptr++;
    return ptr;
}

