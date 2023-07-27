#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#include <assert.h>

#define MAXFILESIZE 1048576

#include "xfc.h"

static char *zonefile_fetch (const char *url, const char *name) {
    char *ret = NULL;
    int retlen = 0, retsize = 0;
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s", url, name);
    
    FILE *f = fopen(filename, "r");
    if (f == NULL)
        return NULL;
    
    int st = 0;
    do {
        if (retsize - retlen < 1024) {
            retsize += 1024;
            char *newbuf = realloc(ret, retsize);
            if (!newbuf) {
                st = -1;
                break;
            }
            ret = newbuf;
        }
        st = fread(ret+retlen, 1, retsize - retlen - 1, f);
        if (st <= 0)
            break;
        retlen += st;
    } while (retlen < MAXFILESIZE);
    fclose(f);
    
    if (st < 0) {
        free(ret);
        ret = NULL;
    } else {
        ret[retlen] = '\0';
    }
    
    return ret;
}

static inline void skip_chars (char **_ptr, char *chars) {
    char *ptr = *_ptr;
    
    while (ptr && *ptr && strchr(chars, *ptr)) {
        ptr++;
    }
    *_ptr = ptr;
}
static inline void skip_until_chars (char **_ptr, char *chars) {
    char *ptr = *_ptr;
    
    while (ptr && *ptr && !strchr(chars, *ptr)) {
        ptr++;
    }
    *_ptr = ptr;
}

static inline int iseof (char *ptr) {
    if (!ptr || !*ptr)
        return 1;
    return 0;
}

static inline int iseol (char *ptr) {
    if (iseof(ptr) || *ptr == '\r' || *ptr == '\n')
        return 1;
    return 0;
}

static inline void skipnl (char **_ptr) {
    return skip_chars(_ptr, "\r\n");
}

#define NEWLINES "\r\n"
#define WHITESPACE " \t"

static inline char *nextword (char *ptr, int multiline) {
    do {
        if (multiline) {
            skip_chars(&ptr, WHITESPACE NEWLINES);
        } else {
            skip_chars(&ptr, WHITESPACE);
        }
        if (*ptr == ';') {
            skip_until_chars(&ptr, NEWLINES);
            continue;
        }
        break;
    } while (1);
    
    return ptr;
}

static char *_skip_word(char *ptr) {
    int in_string = 0, esc = 0;
    
    if (*ptr == '\"') {
        in_string = 1;
        ptr++;
    }
    
    while (*ptr) {
        if (in_string) {
            if (*ptr == '\r' || *ptr == '\n')
                assert(0);
            if (esc) {
                esc = 0;
            } else {
                if (*ptr == '\\')
                    esc = 1;
                else if (*ptr == '\"') {
                    ptr++;
                    return ptr;
                }
            }
            ptr++;
        } else {
            if (*ptr == ';' || *ptr == '\r' || *ptr == '\n' || *ptr == '\"' ||
                    *ptr == ' ' || *ptr == '\t' || *ptr == '(' || *ptr == ')')
                return ptr;
            ptr++;
        }
    }
    
    return ptr;
}

static char **fetch_nextline (char **_zf) {
    char **parts = NULL;
    char *zf = *_zf;
    int multiline = 0;
    int nrparts = 0;

    char *word = nextword(zf, 1);
    do {
        if (!word)
            break;
        if (*word == '(') {
            word++;
            multiline++;
            word = nextword(word, multiline);
        } else if (*word == ')') {
            word++;
            multiline--;
            word = nextword(word, multiline);
        }
        if (*word == '\r' || *word == '\n' || !*word)
            break;
        char *wordend = _skip_word(word);
        int wordlen = wordend - word;
        parts = realloc(parts, (nrparts+2) * sizeof(char *));
        parts[nrparts] = malloc(wordlen+1);
        memcpy(parts[nrparts], word, wordlen);
        parts[nrparts][wordlen] = '\0';
        nrparts++;
        zf = wordend;
        word = nextword(zf, multiline);
    } while (1);
    zf = word;
    
    if (parts)
        parts[nrparts] = NULL;
    
    *_zf = zf;
    
    return parts;
}

static void freeparts(char **parts) {
    int i = 0;
    while (parts[i]) {
        free(parts[i]);
        i++;
    }
    free(parts);
}

static void parse_zonefile (const char *zone, char *zf) {
    char **parts;
    
    while ((parts = fetch_nextline (&zf))) {
        int i = 0;
        while (parts[i]) {
            i++;
        }
        freeparts(parts);
        printf("\n");
    }
}

#if 0
static int datasource_zonefile_fetch_zones (struct datasource *ds, const char *name, void *arg) {
	int nr = 0;

	if (!name || !is_valid_dnsname(name))
		return 0;

        
	const char *url = xl_getstring(arg, "url");
        const char *dsname = xl_getstring(arg, "dsname");

	struct zone *z = fetch_zone(name, 1);
	zone_remove_records(z, -1);
	if (dsname)
		strcpy(z->datasource, dsname);
	else
		strcpy(z->datasource, "unknown");
	z->last_reload = time(NULL);
        
        char *zf = zonefile_fetch(url, name);

	return nr;
}

struct datasource datasource_zonefile = {
	.driver = "zonefile",
	.fetch_zones = datasource_zonefile_fetch_zones,
};
#else
void dztest (char *name) {
    char *zf = zonefile_fetch(".", name);
    assert(zf);
    parse_zonefile(NULL, zf);
}
#endif

