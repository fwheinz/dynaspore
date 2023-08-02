#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <assert.h>
#include <mysql.h>

#include "xfc.h"

static struct zone *zones;
int nextzoneid = 1000;

static struct zone *_fetch_zone(struct zone **z, const char *name, int create, struct zone *parent, int *created) {
    struct zone *ret;

    if (!*z) {
        if (!create)
            return NULL;
        *z = x_calloc(sizeof (struct zone), 1);
        char *dst = (*z)->name;
        int dstlen = sizeof ((*z)->name);
        strncpy(dst, name, dstlen-1);
        dst[dstlen - 1] = '\0';
        (*z)->active = 1;
        (*z)->zoneid = nextzoneid++;
        (*z)->parent = parent;
        (*z)->node = maketree(root, dst, -1, 1);
        assert((*z)->node);
        ss.nrzones++;
        if (created)
            *created = 1;
        ret = *z;
    } else {
        struct zone *zo = *z;
        int cmp = strcasecmp(zo->name, name);
        if (cmp == 0) {
            if (zo->active) {
                ret = zo;
            } else if (create) {
                if (created)
                    *created = 1;
                zo->active = 1;
                ss.nrzones++;
                zo->node = maketree(root, zo->name, -1, 1);
                ret = zo;
            } else {
                ret = NULL;
            }
        } else if (cmp > 0) {
            ret = _fetch_zone(&zo->left, name, create, zo, created);
        } else {
            ret = _fetch_zone(&zo->right, name, create, zo, created);
        }
    }

#define BALANCE_ZONETREE 0
#if BALANCE_ZONETREE    
    struct zone *zo = *z;
    if (zo->left) {
        int max = zo->left->ldepth;
        if (zo->left->rdepth > max)
            max = zo->left->rdepth;
        zo->ldepth = max+1;
    } else {
        zo->ldepth = 0;
    }
    if (zo->right) {
        int max = zo->right->ldepth;
        if (zo->right->rdepth > max)
            max = zo->right->rdepth;
        zo->rdepth = max+1;
    }
    int balance = zo->ldepth - zo->rdepth;
    if (balance < -1 || balance > 1) {
        struct zone *parent = zo->parent;
        struct zone **pptr;
        if (!parent) {
            pptr = &zones;
        } else if (zo == parent->left) {
            pptr = &parent->left;
        } else if (zo == parent->right) {
            pptr = &parent->right;
        } else {
            assert(0);
        }
        
        if (balance < -1) {
            // zo->right becomes new root
            struct zone *newroot = zo->right;
            
            *pptr = newroot;
            newroot->parent = parent;
            
            zo->right = newroot->left;
            if (zo->right)
                zo->right->parent = zo;
            
            newroot->left = zo;
            zo->parent = newroot;
            
            int newrdepth = newroot->rdepth;
            int max = zo->ldepth > zo->rdepth ? zo->ldepth : zo->rdepth;
            newroot->ldepth = max+1;
            zo->rdepth = newrdepth;
        }
        if (balance > 1) {
            struct zone *newroot = zo->left;
            
            *pptr = newroot;
            newroot->parent = parent;
            
            zo->left = newroot->right;
            if (zo->left)
                zo->left->parent = zo;
            
            newroot->right = zo;
            zo->parent = newroot;
            
            int newldepth = newroot->ldepth;
            int max = zo->ldepth > zo->rdepth ? zo->ldepth : zo->rdepth;
            newroot->rdepth = max+1;
            zo->ldepth = newldepth;
        }
    }
#endif
    
    return ret;
}

struct zone *fetch_zone(const char *name, int create) {
    if (!is_valid_dnsname(name))
        return NULL;

    int created = 0;
    struct zone *ret = _fetch_zone(&zones, name, create, NULL, &created);
    if (created) {
        dnstree_inaugurate_zone(ret);
    }

    return ret;
}

/*
 * Walking the zonetree
 */

static int _walk_zones(struct zone *z, int (*cb)(struct zone *z, void *arg), void *arg, int depth, const char *prefix) {
    int ret = 0;
    int st = 0;
    if (prefix)
        st = strncmp(z->name, prefix, strlen(prefix));
    if (z) {
        if (st >= 0)
            ret += _walk_zones(z->left, cb, arg, depth + 1, prefix);
        if (z->active && st == 0)
            ret += cb(z, arg);
        if (st <= 0)
            ret += _walk_zones(z->right, cb, arg, depth + 1, prefix);
    }

    return ret;
}

int walk_zones(int (*cb)(struct zone *z, void *arg), void *arg) {
    return _walk_zones(zones, cb, arg, 0, NULL);
}

int walk_zones_prefix(int (*cb)(struct zone *z, void *arg), void *arg, const char *prefix) {
    return _walk_zones(zones, cb, arg, 0, prefix);
}

static void _walk_zone(diptr_t node, void (*cb)(diptr_t di, diptr_t parent, int subtree, void* args),
        void* args, int depth, int callnodes, int allzones) {
    int i, newzonestart = 0;

    if (!allzones && depth && node->zone) // A new zone starts here
        newzonestart = 1;
    int nrrecords = 0;
    for (i = 0; i < sizeof (node->ch) / sizeof (node->ch[0]); i++) {
        if (newzonestart && ISLABELSEP(i))
            continue;
        if (DICHNULL(node->ch[i])) {
            if (i < T_A) {
                if ((depth == 0) && !ISLABELSEP(i) && !allzones)
                    continue;
                if (callnodes)
                    cb(DICH(node->ch[i]), node, i, args);
                _walk_zone(DICH(node->ch[i]), cb, args, depth + 1, callnodes, allzones);
            } else if (HASTYPE(node, i)) {
                cb(DICH(node->ch[i]), node, i, args);
                nrrecords += DICH(node->ch[i])->nrrecords;
            }
        }
    }
    node->nrrecords = nrrecords;
}

/*
 * Walking one zone in the dnstree
 */

void walk_zone(diptr_t node, void (*cb)(diptr_t di, diptr_t parent, int subtree, void* args),
        void* args, int callnodes) {
    _walk_zone(node, cb, args, 0, callnodes, 0);
}

/*
 * Walking the whole dnstree
 */

void walk_dnstree(diptr_t node, void (*cb)(diptr_t di, diptr_t parent, int subtree, void* args),
        void* args, int callnodes) {
    _walk_zone(node, cb, args, 0, callnodes, 1);
}

void _zone_set(diptr_t node, diptr_t parent, int subtree, void *zone) {
    node->zone = zone;
}

void zone_set(diptr_t di, struct zone *z) {
    walk_zone(di, _zone_set, z, 0);
}

void _zone_remove_records(diptr_t di, diptr_t parent, int subtree, void *args) {
    int type = *((int *) args);

    if (((type < 0) || (type == T_RRSIG)) && DICHNULL(di->ch[T_RRSIG])) {
        clear_record(DICH(di->ch[T_RRSIG]));
    }
    if ((type < 0) || (type == di->type))
        clear_record(di);
}

void zone_remove_records(struct zone *z, int type) {
    walk_zone(z->node, _zone_remove_records, &type, 0);
}

void zone_delete(struct zone *z) {
    z->active = 0;

    z->last_reload = 0;
    z->node = 0;

    nsec_tree_free(z);

    ss.nrzones--;
}

int zone_add_key(struct zone *z, struct dnskey *key) {
    int i;
    for (i = 0; i < z->nrkeys; i++) {
        if (z->keys[i] == key)
            return 0;
    }

    struct dnskey **keys = realloc(z->keys, sizeof (struct xl_dnskey *)*(z->nrkeys + 1));
    if (!keys)
        return 0;
    keys[z->nrkeys++] = key;
    z->keys = keys;
    reprocess_zone(z);

    return 1;
}

int zone_del_key(struct zone *z, struct dnskey *key) {
    int found = 0;
    int i;

    for (i = 0; i < z->nrkeys; i++) {
        if (!found && (z->keys[i] == key)) {
            found = 1;
        } else if (found) {
            z->keys[i - 1] = z->keys[i];
        }
    }
    if (found) {
        z->nrkeys--;
        reprocess_zone(z);
    }
    return found;
}

struct zone *find_parent_zone(struct zone *z) {
    diptr_t di = z->node;

    while (di->up) {
        if (ISLABELSEP(di->type) && di->up->zone) {
            return di->up->zone;
        }
        di = di->up;
    }

    return NULL;
}

void dnstree_inaugurate_zone(struct zone *z) {
    struct zone *parent = find_parent_zone(z);
    diptr_t di = z->node;
    di->zone = z;
    zone_set(di, z);
    reprocess_zone(z);
    if (parent)
        reprocess_zone(parent);
}

void dnstree_remove_zone(struct zone *z) {
    struct zone *parent = find_parent_zone(z);
    diptr_t di = z->node;
    di->zone = NULL;
    zone_set(di, parent);
    zone_delete(z);
    if (parent)
        reprocess_zone(parent);
}
