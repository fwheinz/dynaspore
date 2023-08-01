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

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#include <mysql.h>

#include <rte_malloc.h>

#include "xfc.h"

// The root of the DNS tree
diptr_t root;

// Track memory usage
int nralloc = 0;
long bytesalloc = 0;

// Alignment of data buffers
#define ALIGN 1

// Use RTE malloc, otherwise system malloc is used
#define RTEMALLOC 1

// Buffer headroom
#define HR 128

#ifdef RTEMALLOC
void *x_realloc(void *ptr, size_t size) {
    size = (size + HR)/HR*HR;
    if (!ptr) {
        nralloc++;
        bytesalloc += size;
    }
    return rte_realloc(ptr, size, ALIGN);
}

void *x_malloc(size_t size) {
    size = (size + HR)/HR*HR;
    nralloc++;
    bytesalloc += size;
    char *ret = rte_zmalloc(NULL, size, ALIGN);

    return ret;
}

void *x_calloc(size_t num, size_t size) {
    nralloc++;
    bytesalloc += size*num;
    char *ret = rte_calloc(NULL, num, size, ALIGN);

    return ret;
}

void x_free(void *ptr) {
    nralloc--;
    rte_free(ptr);
}
#else

void *x_realloc(void *ptr, size_t size) {
    if (!ptr) {
        nralloc++;
        bytesalloc += size;
    }
    return realloc(ptr, size);
}

void *x_malloc(size_t size) {
    nralloc++;
    bytesalloc += size;
    char *ret = malloc(size);
    memset(ret, '\0', size);

    return ret;
}

void *x_calloc(size_t num, size_t size) {
    nralloc++;
    bytesalloc += size*num;
    char *ret = calloc(num, size);

    return ret;
}

void x_free(void *ptr) {
    nralloc--;
    free(ptr);
}
#endif


/**
   Allocate a new DNS tree entry.

   parent: The parent node of the new node
   name: The DNS name (part) of the new node
   type: Type of the new node (i.e. the next character or the DNS record type)

   returns: Pointer to the new node
*/
diptr_t diallocname(diptr_t parent, const char *name, int type) {
    int size = sizeof (struct di) + strlen(name) + 1;
    diptr_t di = x_malloc(size);
    if (di == NULL) {
        DEBUG(1, "Out of memory! (%d chunks with %ld bytes)\n", nralloc, bytesalloc);
        exit(EXIT_FAILURE);
    }
    strcpy(di->name, name);
    di->up = parent;
    di->type = type;

    return di;
}

/**
   Free the passed tree node. The caller has to make sure that it is no
   longer referenced.

   di: The tree node to free
*/
void difree(diptr_t di) {
    x_free(di);
}

/**
   Calculate the common depth of the two names (i.e. the length of the
   largest common suffix).

   n1, n2: The involved DNS names
   returns: Length of largest common suffix
*/

int common_depth(const char *n1, const char *n2) {
    int l1 = strlen(n1);
    int l2 = strlen(n2);
    int l = (l1 > l2) ? l2 : l1;
    int i;

    for (i = 0; i < l; i++) {
        if (char2id(n1[l1 - i]) != char2id(n2[l2 - i]))
            break;
    }
    if (char2id(n1[l1 - i]) == char2id(n2[l2 - i]))
        return i;
    else
        return i - 1;
}

/**
   Create a new tree node for the given name in passed subtree.

   pos: the subtree in which the node should be created
   _name: The DNS name of the new node
   typeid: The node DNS record type (-1 for none)
   store: Create new leaves in the tree (otherwise only overwrite existing)
*/
diptr_t maketree(diptr_t pos, const char *_name, int typeid, int store) {
    char *name = strdupa(_name);
    int nl = strlen(name);
    int wildcard = 0;
    int treedepth = 1;
    struct zone *curzone = NULL;

    if (*name == '*') { // Wildcard entry?
        wildcard = 1;
        name++; // Skip the asterisk
        nl--;
        if (nl < 0)
            return 0;
    }

    // Trim a trailing dot
    if ((nl > 0) && (name[nl - 1] == '.')) {
        nl--;
        name[nl] = '\0';
    }

    if (store)
        DEBUG(4, "\nInserting  name %40s (%d)\n", name, store);

    // Find the correct place in the tree
    while (pos->depth < nl) {
	// Find the character that corresponds to the current position in the tree
	// to index the correct subtree
        int ch = char2id(name[nl - pos->depth - 1]);
        if (ch == -1) {
            return 0; // We hit an invalid character
        }
        if (pos->zone && ISLABELSEP(ch)) {
            curzone = pos->zone; // Track the most specific zone that we have seen
        }
        if (!DICHNULL(pos->ch[ch])) { // The subtree is empty
            if (store != 1) // Bail out if we may not create new tree nodes
                return 0;
	    // Create the new node as a subnode of the current tree node
            DEBUG(4, "Allocating name %40s (Depth %d)\n", name, nl);
            diptr_t new = diallocname(pos, name, ch);
            new->depth = nl;
            DICHA(pos->ch[ch]) = DICHAR(new);
            treedepth++;
        } else {
            // Dive into the correct subtree
            struct di *tmp = DICH(pos->ch[ch]);
            // Find out the length of the longest common suffix
            int cd = common_depth(tmp->name, name);
            if (store)
                DEBUG(4, "Found      name %40s (CD %d, Depth %d)\n", tmp->name, cd, tmp->depth);
            if (cd < tmp->depth) {
                // The length of the longest common suffix is smaller than the
                // current tree depth, so we have to insert a new node in the middle
                if (store != 1)
                    return 0; // Bail out if we may not create new nodes
                // Create the new node here
                diptr_t new = diallocname(pos, name + nl - cd, ch);

                // Insert it between the current and the child node
                new->depth = cd;
                int ch2 = char2id(tmp->name[strlen(tmp->name) - cd - 1]);
                DICHA(new->ch[ch2]) = DICHAR(tmp);
                DICHA(pos->ch[ch]) = DICHAR(new);
                tmp->up = new;
                treedepth++;

                if (nl == cd) {
                    // The name is consumed fully by the previous node name
                    // E.g.: current name was: abcdef, new name is abcd. Split into
                    // abcd
                    //   |
                    //  ef
                    // This was already performed above, so we are done already.
                    DEBUG(4, "Need to split: %c\n", tmp->name[strlen(tmp->name) - cd - 1]);
                    pos = new;
                    break;
                } else {
                    // The name is not consumed fully by the previous node name, so we have
                    // to fork the tree here into two directions
                    // E.g.: current name was: abcdef, new name is: abcdxy
                    // Fork into: abcd
                    //           /    \ .
                    //          ef    xy
                    DEBUG(4, "Need to fork: %c / %c\n", tmp->name[strlen(tmp->name) - cd - 1], name[nl - cd - 1]);
                    ch2 = char2id(name[nl - cd - 1]);
                    // Another node has to be allocated and inserted at the correct location
                    DICHA(new->ch[ch2]) = DICHAR(diallocname(new, name, ch2));
                    DICH(new->ch[ch2])->depth = nl;
                    pos = DICH(new->ch[ch2]);
                    treedepth++;
                    break;
                }
            }
        }

        treedepth++;
        pos = DICH(pos->ch[ch]);
    }

    if (wildcard) {
        // If a wildcard record should be created, allocate it here if it does not
        // exist yet.
        if (!DICHNULL(pos->ch[WILDCARD])) {
            DICHA(pos->ch[WILDCARD]) = DICHAR(diallocname(pos, name - 1, WILDCARD));
            DICH(pos->ch[WILDCARD])->depth = pos->depth + 1;
        }
        pos = DICH(pos->ch[WILDCARD]);
    }
    if (typeid < 0)
        return pos; // If no type was requested, just return the inner node
    if (pos->zone)
        curzone = pos->zone;
    if (!DICHNULL(pos->ch[typeid])) { 
        // A node for a DNS record should be created
        if (store != 1)
            return 0; // Bail out if creation is not allowed
        // Create the new node here
        DICHA(pos->ch[typeid]) = DICHAR(diallocname(pos, name, typeid));
    }
    pos = DICH(pos->ch[typeid]);
    treedepth++;
    // Track the maximum tree depth here
    if (ss.maxtreedepth < treedepth)
        ss.maxtreedepth = treedepth;
    // Set the DNS zone pointer of the current node
    pos->zone = curzone;

    return pos; // Return the new or found node
}

/**
  Create space for additional records (in the sense of RFC1034/1035) in the pointer list
  dptr: The pointer list for all additional records

  returns: The address of the new entry in the pointer list
*/
diptr_t *create_additional(diptr_t **dptr) {
    int i = 0;

    if (!*dptr)
        *dptr = x_calloc(1, sizeof (void*)*3);
    while ((*dptr)[i])
        i++;
    if (i > 1) {
        *dptr = x_realloc(*dptr, sizeof (void*)*(i + 2));
    }
    (*dptr)[i + 1] = 0;
    return (*dptr)+i;
}

/**
   Add a link to a DNS tree entry as additional record to another entry.
   Example: Add the A record for the domain names in an NS record, if available

   off: Offset in bytes of the target DNS name in the record content
   type: DNS record type to look for in the tree
   di: The entry in the DNS tree to add the additional record to
*/
static void process_additional_name(int off, int type, struct di *di) {
    unsigned char *record = (unsigned char *) di->record;
    int i;

    for (i = 0; i < di->nrrecords; i++) {
        // Extract the target DNS name from the current record
        char tname[256];
        // Find out the record DNS name
        int len = lbl2name(record, tname, di->recordlen-(record-(unsigned char*)di->record));
        if (!len)
            return;
        // Skip the record DNS name here, add an offset to the actual name (record type dependent)
        record += len + 10 + off;
        // Decode the actual DNS name here
        len = lbl2name(record, tname, di->recordlen-(record-(unsigned char*)di->record));
        if (len <= 0)
            return;
        record += len;
        // Find the name in the current DNS tree
        diptr_t ad = maketree(root, tname + 1, type, 0);
        if (ad) {
            // If the name was found, add a link to the current entry
            diptr_t *adp = create_additional(&di->additional);
            *adp = ad;
        }
    }
}

/**
   Add a pointer to the actual records for a CNAME record, if the
   actual records are also present in the DNS tree.
   di: the tree node to add cname-links to
*/
void process_additional_cname(struct di *di) {
    unsigned char *record = (unsigned char *) di->record;
    int i;

    for (i = 0; i < di->nrrecords; i++) {
        char tname[256];
        // Skip DNS record name
        int len = lbl2name(record, tname, sizeof (tname));
        if (!len)
            return;
        record += len + 10;
        // Extract CNAME target
        len = lbl2name(record, tname, sizeof (tname));
        if (len <= 0)
            return;
        record += len;
        // Look up CNAME target in tree
        diptr_t ad = maketree(root, tname + 1, -1, 0);
        di->cname = ad;
    }
}

/**
   Process additional records for a tree node.
   dip: the tree node to process
   parent: the parent node (unused)
   type: the record type 
   arg: arguments (unused)
*/
void process_additional(diptr_t dip, diptr_t parent, int type, void *arg) {
    struct di *di = DI_GET(dip);
    // Remove any existing additional record links
    if (di->additional) {
        x_free(di->additional);
        di->additional = NULL;
    }
    di->cname = 0;
    // Process additional records depending on record type
    switch (type) {
        case T_NS:
            process_additional_name(0, T_A, di);
            break;
        case T_MX:
            process_additional_name(2, T_A, di);
            break;
        case T_SRV:
            process_additional_name(6, T_A, di);
            break;
        case T_CNAME:
            process_additional_cname(di);
            break;
    }
}

/**
   Reprocess all additional records on a zone.
   z: The zone to reprocess
   forced: Do not process on bulk edit, unless forced
*/
static void _reprocess_zone(struct zone *z, int forced) {
    if (!z || z->active == 0 || ((z->flags & ZONE_BULKEDIT) && !forced))
        return;
    walk_zone(z->node, process_additional, NULL, 0);
    sign_zone(z);
}

/**
   Reprocess a single zone.
   z: The zone to reprocess
*/
void reprocess_zone(struct zone *z) {
    _reprocess_zone(z, 0);
}

/**
   Reprocess a single zone forced. This means, also reprocess
   if the zone is in bulk edit mode
   z: The zone to reprocess
*/
void reprocess_zone_forced(struct zone *z) {
    _reprocess_zone(z, 1);
}

/**
   Reprocess a zone only if it is from a specific data source.
   z: The zone to reprocess
   arg: Pointer to the data source name
*/
int _reprocess_zone_datasource_cb(struct zone *z, void *arg) {
    char *dsname = arg;
    if (!strcmp(dsname, z->name)) {
        reprocess_zone(z);
        return 1;
    }

    return 0;
}

/**
   Reprocess all zones of a specific data source.
   arg: Pointer to the data source name
*/
void reprocess_zone_datasource(const char *datasource) {
    walk_zones(_reprocess_zone_datasource_cb, (void *) datasource);
}

/**
   Optimize the DNS tree. If there is only a single subnode, merge it with the current node
   n: The node tree to optimize
*/
diptr_t optimize_tree(diptr_t n) {
    diptr_t last = NULL;
    unsigned int i, found = 0;
    struct di *node = DI_GET(n);

    for (i = 0; i < sizeof (node->ch) / sizeof (node->ch[0]); i++) {
        // Iterate over all subtrees
        if (DICHNULL(node->ch[i])) {
            // Optimize subtree first
            diptr_t ptr = optimize_tree(DICH(node->ch[i]));
            if (ptr != DICH(node->ch[i])) {
                difree(DICH(node->ch[i]));
                DICHA(node->ch[i]) = DICHAR(ptr);
            }
            last = DICH(node->ch[i]);
            // Count number of non-empty subtrees
            found++;
            if (i >= T_A || i == LABELSEP || i == WILDCARD) // We do not optimize records
                found++;
        }
    }
    if (found == 1) {
        return last;
    } else {
        return n;
    }
}

/**
  Free up all ressources of a record.
  dip: The node with the record
*/
void clear_record(diptr_t dip) {
    if (dip->up && dip->type != T_RRSIG) {
        dip->up->nrrecords -= dip->nrrecords;
        ss.nrrecords -= dip->nrrecords;
    }
    fix_parent(dip);
    
    dip->recordlen = dip->shortrecordlen = dip->nrrecords = 0;
    x_free(dip->record); dip->record = NULL;
    x_free(dip->shortrecord); dip->shortrecord = NULL;
}

