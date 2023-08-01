#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#include <rte_malloc.h>

#include "xfc.h"

#define MAXLENENCODED (x) ((x*4)+3)
#define SKIP_WHITESPACE(x) do { while ((x) && *(x) && *(x) == ' ') (x)++; } while(0);

struct rtype rtypes[260];

static int put_character_string (const unsigned char *data, int datalen, char *dst, int dstlen) {
	int i, pos = 0;

	if (dstlen < 3) {
		return -1;
	}
	dstlen -= 3;
	dst[pos++] = '\"';
	for (i = 0; i < datalen; i++) {
		if (data[i] == '\\') {
			if (dstlen < 2)
				return -1;
			dst[pos++] = '\\';
			dst[pos++] = '\\';
			dstlen -= 2;
		} else if (isprint(data[i])) {
			if (dstlen < 1)
				return -1;
			dst[pos++] = data[i];
			dstlen--;
		} else {
			if (dstlen < 4)
				return -1;
			unsigned char ch = data[i];
			dst[pos++] = '\\';
			dst[pos++] = '0' + ch/100;
			dst[pos++] = '0' + (ch/10)%10;
			dst[pos++] = '0' + ch%10;
			
			dstlen -= 4;
		}
	}

	dst[pos++] = '\"';
	dst[pos] = '\0';

	return pos;
}

static int get_character_string (const char *str, int strlen, char *dst, int dstlen) {
	int restlen = strlen;
	int pos = 0;
	int i = 0;

	if (str[i] == '"') {
		if (str[strlen-1] != '"')
			return -1;
		i++;
		strlen--;
	}

	for (; i < strlen; i++) {
		if (!str[i])
			break;
		if (pos >= (dstlen-1))
			return -1;
		if (str[i] == '\\') {
			if (restlen < 2)
				return -1;
			if (isdigit(str[i+1])) {
				if ((restlen < 4) || !isdigit(str[i+2]) || !isdigit(str[i+3]))
					return -1;
				dst[pos++] = (str[i+1]-'0')*100+(str[i+2]-'0')*10+(str[i+3]-'0');
				restlen -= 4;
				i += 3;
			} else {
				dst[pos++] = str[i+1];
				i++;
				restlen -= 2;
			}
		} else {
			dst[pos++] = str[i];
			restlen--;
		}
	}
	dst[pos] = '\0';

	return pos;
}

int create_a_record_content (unsigned char *rbuf, const char *content) {
	if (inet_pton(AF_INET, content, rbuf))
		return 4;
	return -1;
}

int create_aaaa_record_content (unsigned char *rbuf, const char *content) {
	if (inet_pton(AF_INET6, content, rbuf))
		return 16;
	return -1;
}

int create_ns_record_content (unsigned char *rbuf, const char *content) {
        if (!is_valid_dnsname(content))
            return -1;
	unsigned char *ptr = name2lbl(rbuf, content);

	return ptr - rbuf;
}

int create_cname_record_content (unsigned char *rbuf, const char *content) {
        if (!is_valid_dnsname(content))
            return -1;
	unsigned char *ptr = name2lbl(rbuf, content);

	return ptr - rbuf;
}

int create_ptr_record_content (unsigned char *rbuf, const char *content) {
        if (!is_valid_dnsname(content))
            return -1;
	unsigned char *ptr = name2lbl(rbuf, content);

	return ptr - rbuf;
}


int create_mx_record_content (unsigned char *rbuf, const char *content, int prio) {
	const char *ptr = content;
	if (prio < 0) { // This means, expect prio at start of content
		while (*ptr && *ptr == ' ') ptr++;
		prio = atoi(content);
		ptr = strchr(ptr, ' ');
	}

	PUTSHORT(rbuf) = htons(prio);
	if (!ptr)
		return -1;
	while (*ptr == ' ')
		ptr++;
        if (!is_valid_dnsname(ptr))
            return -1;
	unsigned char *ptr2 = name2lbl(rbuf+2, ptr);

	return ptr2 - rbuf;
}

int create_txt_record_content (unsigned char *rbuf, const char *content) {
	unsigned char *dst = rbuf;

	char *decoded = alloca(strlen(content)+2);
	int l = get_character_string(content, strlen(content), decoded, strlen(content)+2);
	if (l < 0)
		return -1;


	while (l) {
		if (l > 255) {
			*dst = 255;
			l -= 255;
		} else {
			*dst = l;
			l = 0;
		}
		memcpy(dst+1, decoded, *dst);
		decoded += *dst;
		dst += *dst + 1;
		if ((dst - rbuf) > 2048)
			break;
	}

	return dst - rbuf;
}

int create_soa_record_content (unsigned char *rbuf, const char *content) {
	char *ptr = (char *)content;

	while (*ptr && *ptr == ' ') ptr++;
	char *mname = ptr;

	ptr = strchr(ptr, ' ');
	if (!ptr)
		return -1;
	*ptr++ = '\0';
	while (*ptr && *ptr == ' ') ptr++;
	char *rname = ptr;

	ptr = strchr(ptr, ' ');
	if (!ptr)
		return -1;
	*ptr++ = '\0';
	while (*ptr && *ptr == ' ') ptr++;
	unsigned long serial = strtoul(ptr, NULL, 10);
	
	ptr = strchr(rname, '@');
	if (ptr)
		*ptr = '.';

	unsigned char *rptr = rbuf;
        if (!is_valid_dnsname(mname) || !is_valid_dnsname(rname))
            return -1;
	rptr = name2lbl(rptr, mname);
	rptr = name2lbl(rptr, rname);
	PUTINT(rptr) = htonl(serial); rptr += 4;   // SERIAL
	PUTINT(rptr) = htonl(10800);  rptr += 4;   // REFRESH
	PUTINT(rptr) = htonl(3600);   rptr += 4;   // RETRY
	PUTINT(rptr) = htonl(604800); rptr += 4;   // EXPIRE
	PUTINT(rptr) = htonl(3600);   rptr += 4;   // MINIMUM

	return rptr - rbuf;
}

int create_srv_record_content (unsigned char *rbuf, const char *content, int prio) {
	char *ptr = (char *)content;

	if (prio < 0) { // This means, expect prio at start of content
		SKIP_WHITESPACE(ptr);
		prio = atoi(content);
		ptr = strchr(ptr, ' ');
	}
	if (!ptr)
		return -1;

	SKIP_WHITESPACE(ptr);
	char *weight = ptr;

	ptr = strchr(ptr, ' ');
	if (!ptr)
		return -1;
	*ptr++ = '\0';
	SKIP_WHITESPACE(ptr);
	char *port = ptr;

	ptr = strchr(ptr, ' ');
	if (!ptr)
		return -1;
	*ptr++ = '\0';
	SKIP_WHITESPACE(ptr);
	char *target = ptr;
	
	unsigned char *rptr = rbuf;
	PUTSHORT(rptr) = htons(prio);         rptr += 2;
	PUTSHORT(rptr) = htons(atoi(weight)); rptr += 2;
	PUTSHORT(rptr) = htons(atoi(port));   rptr += 2;
        if (!is_valid_dnsname(target))
            return -1;
	rptr = name2lbl(rptr, target);

	return rptr - rbuf;
}

int create_ds_record_content (unsigned char *rbuf, const char *content) {
	const char *ptr = content, *b64;

	SKIP_WHITESPACE(ptr);
	unsigned short keytag = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char algorithm = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char digest = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	b64 = ptr;

	unsigned char *rptr = rbuf;
	PUTSHORT(rptr) = htons(keytag); rptr += 2;
	PUTCHAR (rptr) = algorithm;     rptr += 1;
	PUTCHAR (rptr) = digest;        rptr += 1;
	int dl = Base64decode(rptr, b64); rptr += dl;

	return rptr - rbuf;
}

int create_dnskey_record_content (unsigned char *rbuf, const char *content) {
	const char *ptr = content, *b64;

	SKIP_WHITESPACE(ptr);
	unsigned short keyflags = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char protocol = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char algorithm = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	b64 = ptr;

	unsigned char *ptr2 = rbuf;
	PUTSHORT(ptr2) = htons(keyflags); ptr2 += 2;
	PUTCHAR (ptr2) = protocol;        ptr2 += 1;
	PUTCHAR (ptr2) = algorithm;       ptr2 += 1;
	int dl = Base64decode(ptr2, b64); ptr2 += dl;

	return ptr2 - rbuf;
}

int create_nsec_record_content (unsigned char *rbuf, const char *content) {
	char *ptr = (char*)content;
	unsigned char *start = rbuf;

	ptr = strchr(ptr, ' '); if (!ptr) return -1;
	*ptr = '\0';
        if (!is_valid_dnsname(content))
            return -1;
	rbuf = name2lbl(rbuf, content);
	*ptr = ' ';
	memset(rbuf, 0, 34);
	int maxtypeblock = 0;
	SKIP_WHITESPACE(ptr);
	do {
		int type = typestr2type(ptr);

		if (type > 0 && type < 256) {
			int typeblock = type >> 3;
			if (typeblock > maxtypeblock)
				maxtypeblock = typeblock;
			rbuf[typeblock+2] |= (0x80 >> (type&0x7));
		}
		ptr = strchr(ptr, ' ');
		SKIP_WHITESPACE(ptr);
	} while (ptr && *ptr);
	rbuf[1] = maxtypeblock+1;
	rbuf += 2 + maxtypeblock + 1;

	return rbuf - start;
}

int create_rrsig_record_content (unsigned char *rbuf, const char *content) {
	char *ptr = (char *)content, *name, *b64;

	SKIP_WHITESPACE(ptr);
	int type = typestr2type(ptr);
	if (type < 0)
		return -1;

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char algorithm = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned char lbls = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned int origttl = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned int sigexp = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned int siginc = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	unsigned short keytag = atoi(ptr);

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	name = strdupa(ptr);
	char *tmp = strchr(name, ' '); if (!tmp) return -1;
	*tmp = '\0';

	ptr = strchr(ptr, ' '); if (!ptr) return -1; SKIP_WHITESPACE(ptr);
	b64 = ptr;

	unsigned char *rptr = rbuf;
	PUTSHORT(rptr) = htons(type); rptr += 2;
	PUTCHAR (rptr) = algorithm  ; rptr += 1;
	PUTCHAR (rptr) = lbls       ; rptr += 1;
	PUTINT  (rptr) = htonl(origttl)    ; rptr += 4;
	PUTINT  (rptr) = htonl(sigexp)     ; rptr += 4;
	PUTINT  (rptr) = htonl(siginc)     ; rptr += 4;
	PUTSHORT(rptr) = htons(keytag)     ; rptr += 2;
        if (!is_valid_dnsname(name))
            return -1;
	rptr = name2lbl(rptr, name);
	int dl = Base64decode(rptr, b64); rptr += dl;

	return rptr - rbuf;
}

int create_record_content (unsigned char *rbuf, int type, const char *content, int prio) {
	switch (type) {
		case  1: // A
			return create_a_record_content(rbuf, content);
		case  2: // NS
			return create_ns_record_content(rbuf, content);
		case  5: // CNAME
			return create_cname_record_content(rbuf, content);
		case  6: // SOA
			return create_soa_record_content(rbuf, content);
		case 12: // PTR
			return create_ptr_record_content(rbuf, content);
		case 15: // MX
			return create_mx_record_content(rbuf, content, prio);
		case 16: // TXT
			return create_txt_record_content(rbuf, content);
		case 28: // AAAA
			return create_aaaa_record_content(rbuf, content);
		case 33: // SRV
			return create_srv_record_content(rbuf, content, prio);
		case 43: // DS
			return create_ds_record_content(rbuf, content);
		case 46: // RRSIG
			return create_rrsig_record_content(rbuf, content);
		case 47: // NSEC
			return create_nsec_record_content(rbuf, content);
		case 48: // DNSKEY
			return create_dnskey_record_content(rbuf, content);
		default:
			return -1;
	}
}

void create_record_data (diptr_t di, const char *name, int type, unsigned int ttl, unsigned char *data, int datalen) {
	unsigned char *ptr;

	int sz = datalen+12+strlen(name);
	DI_GET(di)->record = x_realloc(DI_GET(di)->record, DI_GET(di)->recordlen+datalen+12+strlen(name));
	ptr = DI_GET(di)->record + DI_GET(di)->recordlen;
	unsigned char *origptr = ptr;
	ptr = name2lbl(ptr, name);
	int namelen = ptr - origptr;
	PUTSHORT(ptr) = htons(type);         ptr+=2; // TYPE
	PUTSHORT(ptr) = htons(0x0001);       ptr+=2; // CLASS IN
	PUTINT  (ptr) = htonl(ttl);          ptr+=4; // TTL
	PUTSHORT(ptr) = htons(datalen);      ptr+=2; // RDLENGTH
	memcpy(ptr, data, datalen);
	ptr += datalen;
	DI_GET(di)->recordlen += datalen + 10 + namelen;
	if (ptr-origptr != sz) {
		printf("Error: %lu != %d\n", ptr-origptr, sz);
		printf("Name: %s, namelen: %d, strlen: %lu\n", name, namelen, strlen(name));
		assert(ptr-origptr == sz);
	}

	DI_GET(di)->shortrecord = x_realloc(DI_GET(di)->shortrecord, DI_GET(di)->shortrecordlen+datalen+20);
	ptr = DI_GET(di)->shortrecord + DI_GET(di)->shortrecordlen;
	PUTSHORT(ptr) = htons(0xc00c);             ptr+=2; // COMPRESSED LABEL
	PUTSHORT(ptr) = htons(type);               ptr+=2; // TYPE
	PUTSHORT(ptr) = htons(0x0001);             ptr+=2; // CLASS IN
	PUTINT  (ptr) = htonl(ttl);                ptr+=4; // TTL
	PUTSHORT(ptr) = htons(datalen);            ptr+=2; // RDLENGTH
	memcpy(ptr, data, datalen);
	DI_GET(di)->shortrecordlen += datalen + 10 + 2;

	DI_GET(di)->nrrecords++;
	if (di->up && type != T_RRSIG)
		di->up->nrrecords++;
        fix_parent(di);
}

diptr_t create_record_raw (const char *name, int type, const char *content, unsigned int ttl, int prio) {
	unsigned char rbuf[4096];
        
        if (!is_valid_dnsname(name)) {
            return NULL;
        }

	// Create the record content in our buffer
	int rdlength = create_record_content(rbuf, type, content, prio);
	if (rdlength < 0) {
		return 0;
	}

	diptr_t di = maketree(root, name, type2id(type), 1);

	di->depth = strlen(name)+1;
	create_record_data(di, name, type, ttl, rbuf, rdlength);
	ss.nrrecords++;

	return di;
}

diptr_t create_record (char *name, const char *type, char *content, const char *ttl, char *prio) {
	if (!name || !type || !content)
		return 0;

	if (strlen(name) > 0 && name[strlen(name)-1] == '.') {
		name[strlen(name)-1] = '\0';
	}

	int typenr = typestr2type(type);
	int typeid = type2id(typenr);
	if (typeid < 0)
		return 0;
	int p = -1;
	if (prio)
		p = atoi(prio);

	unsigned long ttlnr = 300; // Default TTL
	if (ttl)
		ttlnr = strtoul(ttl, NULL, 10);

	return create_record_raw(name, typenr, content, ttlnr, p);
}

diptr_t create_record_from_line (const char *_line) {
    char *line = strdup(_line);
    char *name = NULL, *ttl = NULL, *class = NULL, *type = NULL, *content = NULL;

	name = line;

	ttl = strchr(name, ' ');
	if (!ttl)
		goto out;
	*ttl++ = '\0';
	SKIP_WHITESPACE(ttl);

	class = strchr(ttl, ' ');
	if (!class)
		goto out;
	*class++ = '\0';
	SKIP_WHITESPACE(class);

	type = strchr(class, ' ');
	if (!type)
		goto out;
	*type++ = '\0';
	SKIP_WHITESPACE(type);

	content = strchr(type, ' ');
	if (!content)
		goto out;
	*content++ = '\0';
	SKIP_WHITESPACE(content);

	if (strcasecmp(class, "IN"))
		goto out;


	diptr_t ret = create_record(name, type, content, ttl, NULL);
	free(line);

	return ret;
out:
	DEBUG(1, "XXX: %s %s %s %s %s\n", name, ttl, class, type, content);
	free(line);
	return NULL;
}

#define DOTS (dots?".":"")

int retrieve_a_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len) {
	*bp = '\0';
	inet_ntop(AF_INET, ptr, bp, len);
	return strlen(bp);
}

int retrieve_mx_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	unsigned short priority = get_ushort(&ptr);
	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return 0;
	snprintf(bp, len, "%d %s%s", priority, name, DOTS);

	return strlen(bp);
}

int retrieve_srv_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	unsigned short priority = get_ushort(&ptr);
	unsigned short weight = get_ushort(&ptr);
	unsigned short port = get_ushort(&ptr);
	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return 0;
	snprintf(bp, len, "%d %d %d %s%s", priority, weight, port, name, DOTS);

	return strlen(bp);

}

int retrieve_cname_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return 0;
	snprintf(bp, len, "%s%s", name, DOTS);

	return strlen(bp);
}

int retrieve_ptr_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return 0;
	snprintf(bp, len, "%s%s", name, DOTS);

	return strlen(bp);
}

int retrieve_ns_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return 0;
	snprintf(bp, len, "%s%s", name, DOTS);

	return strlen(bp);
}

int retrieve_aaaa_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len) {
	*bp = '\0';
	inet_ntop(AF_INET6, ptr, bp, len);
	return strlen(bp);
}

int retrieve_txt_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len) {
	char *start = bp;

	while (rdlength > 0) {
		int l = *ptr;
		if (l > rdlength-1) {
			return -1;
		}
		ptr++;
		int st = put_character_string(ptr, l, bp, len);
		if (st < 0) {
			return -1;
		}
		ptr += l;
		bp += st;
		len -= st;
		rdlength -= (l+1);
	}

	return (bp - start);
}

int retrieve_dnskey_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len) {
	char *start = bp;

	unsigned short flags = get_ushort(&ptr);
	unsigned char protocol = get_uchar(&ptr);
	unsigned char algorithm = get_uchar(&ptr);

	int l = snprintf(bp, len, "%hu %hhu %hhu ", flags, protocol, algorithm);
	bp += l;
	len -= l;
	Base64encode(bp, ptr, rdlength-4);

	return (bp - start);
}

int retrieve_ds_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len) {
	char *start = bp;

	unsigned short keytag = get_ushort(&ptr);
	unsigned char algorithm = get_uchar(&ptr);
	unsigned char digest = get_uchar(&ptr);

	int l = snprintf(bp, len, "%hu %hhu %hhu ", keytag, algorithm, digest);
	bp += l;
	len -= l;
        int i;
        for (i = 0; i < rdlength-4; i++) {
            sprintf(bp, "%02X", ptr[i]);
            bp += 2;
        }

	return (bp - start);
}

int retrieve_nsec_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
    unsigned char *sptr = ptr;
    char *start = bp;
    char name[257];
    int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
    if (ll < 0)
        return 0;
    
    rdlength -= (ptr - sptr);
    
    int l = snprintf(bp, len, "%s%s ", name, DOTS);
    bp += l;
    len -= l;
    
    while (len > 0 && rdlength > 2) {
        int window = *ptr++;
        int bitmaplen = *ptr++;
        rdlength -= 2;
        if (rdlength < bitmaplen)
            break;
        int i, j;
        for (i = 0; i < bitmaplen; i++) {
            for (j = 0; j < 8; j++) {
                if (ptr[i] & (0x80 >> j)) {
                    int type = (window<<8)+i*8+j;
                    const char *typestr = type2typestr(type);
                    if (!strcmp(typestr, "UNK")) {
                        l = snprintf(bp, len, "TYPE%d ", type);
                    } else {
                        l = snprintf(bp, len, "%s ", typestr);
                    }
                    bp += l;
                    len -= l;
                }
            }
        }
    }
    
    return (bp - start);
}

int retrieve_soa_record_content (unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	*bp = '\0';
	char mname[257], rname[257];
	int ll = lbl2name_compressed(&ptr, mname, pkt, pktlen);
	if (ll < 0)
		return 0;
	ll = lbl2name_compressed(&ptr, rname, pkt, pktlen);
	if (ll < 0)
		return 0;
	unsigned int serial = get_uint(&ptr);
	unsigned int refresh = get_uint(&ptr);
	unsigned int retry = get_uint(&ptr);
	unsigned int expire = get_uint(&ptr);
	unsigned int minimum = get_uint(&ptr);

	snprintf(bp, len, "%s%s %s%s %u %u %u %u %u", mname, DOTS, rname, DOTS, serial, refresh, retry, expire, minimum);

	return strlen(bp);
}

int retrieve_record_content(unsigned char *ptr, int type, int rdlength, char *bp, int len, unsigned char *pkt, int pktlen, int dots) {
	switch (type) {
		case 1: // A
			return retrieve_a_record_content (ptr, type, rdlength, bp, len);
			break;
		case 2: // NS
			return retrieve_ns_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 5: // CNAME
			return retrieve_cname_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 6: // SOA
			return retrieve_soa_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 12: // PTR
			return retrieve_ptr_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 15: // MX
			return retrieve_mx_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 16: // TXT
			return retrieve_txt_record_content (ptr, type, rdlength, bp, len);
			break;
		case 28: // AAAA
			return retrieve_aaaa_record_content (ptr, type, rdlength, bp, len);
			break;
		case 33: // SRV
			return retrieve_srv_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
			break;
		case 43: // DS
			return retrieve_ds_record_content (ptr, type, rdlength, bp, len);
			break;
		case 47: // NSEC
			return retrieve_nsec_record_content (ptr, type, rdlength, bp, len, pkt, pktlen, dots);
                        break;
		case 48: // DNSKEY
			return retrieve_dnskey_record_content (ptr, type, rdlength, bp, len);
			break;
		default:
			return snprintf(bp, len, "NOTPARSED");
			break;
	}
}

unsigned char *retrieve_record_data_dots (unsigned char *ptr, char *buf, int len, int dots) {
	char *bp = buf;
	*bp = '\0'; len--;

	char name[257];
	int ll = lbl2name((unsigned char *)get_string(&ptr), name, len);
	if (ll < 0)
		return NULL;
	unsigned short type = get_ushort(&ptr);
	unsigned short class = get_ushort(&ptr);
	unsigned int ttl = get_uint(&ptr);
	unsigned short rdlength = get_ushort(&ptr);
	ll = snprintf(bp, len, "%s%s %d %s %s ", name+1, dots?".":"", ttl, (class==1)?"IN":"UNK", type2typestr(type));
	bp += ll;
	len -= ll;
	ll = retrieve_record_content(ptr, type, rdlength, bp, len, NULL, 0, dots);
	bp += ll;
	len -= ll;
	ptr += rdlength;

	return ptr;
}

unsigned char *retrieve_record_data (unsigned char *ptr, char *buf, int len) {
    return retrieve_record_data_dots (ptr, buf, len, 1);
}

unsigned char *retrieve_record_data_axfr (unsigned char *ptr, char *buf, int len, unsigned char *pkt, int pktlen, struct record *r) {
	char *bp = buf;
	*bp = '\0'; len--;
	unsigned char *pktend = pkt + pktlen;

	char name[257];
	int ll = lbl2name_compressed(&ptr, name, pkt, pktlen);
	if (ll < 0)
		return NULL;
	if (ptr + 10 >= pktend)
		return NULL;
	unsigned short type = get_ushort(&ptr);
	unsigned short class = get_ushort(&ptr);
	unsigned int ttl = get_uint(&ptr);
	unsigned short rdlength = get_ushort(&ptr);
	ll = snprintf(bp, len, "%s. %d %s %s ", name, ttl, (class==1)?"IN":"UNK", type2typestr(type));
	bp += ll;
	len -= ll;
	ll = retrieve_record_content(ptr, type, rdlength, bp, len, pkt, pktlen, 1);
	bp += ll;
	len -= ll;

	ptr += rdlength;

	if (r) {
		snprintf(r->name, sizeof(r->name), "%s", name);
		r->type = type;
		r->cls = class;
		r->ttl = ttl;
		r->rdlength = rdlength;
	}

	return ptr;
}


unsigned char *skip_records (unsigned char *ptr, int nr) {
	while (nr--) {
		if (ptr[0] == 0xc0 && ptr[1] == 0x0c) {
			ptr += 2;
		} else {
			get_string(&ptr);
		}
		ptr += 8;
		unsigned short rdlength = get_ushort(&ptr);
		ptr += rdlength;
	}

	return ptr;
}

