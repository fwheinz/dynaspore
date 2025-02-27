#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <rte_memcpy.h>

#include "xfc.h"

#define RTYPE_NORMAL 0
#define RTYPE_SUBDEL 1

unsigned long steps = 0;

/* Answer a single DNS request. The DNS packet is located in buf with length len.
 * _maxlen_ bufferspace is available in buf.
 */
int answer_packet(unsigned char *buf, int len, int maxlen) {
    char _name[256], *name = _name + 1;
    int edns = 0, udpsize = 512, DO = 0, tc = 0;
    struct answerdata ad = {0, 0, 0, 0};

    if (len < 12) // Minimum length for a DNS packet
        return -1;

    // Check header: QR 0, Opcode 0, AA 0, TC 0, RD 0
    // Check header: RA 0, Z 0, RCODE 0
    // Check header: QC 1
    if ((buf[2]&0xfe) != 0 || buf[4] != 0 || buf[5] != 1) {
        DEBUG(3, "Invalid header\n");
        return -1;
    }
    // Decode the question label name
    int lbllen = lbl2name(buf + 12, _name, len - 16);
    if (lbllen == -2) {
        DEBUG(3, "Invalid label\n");
        return -1;
    }
    // Check length and minimal length of packet, to avoid buffer overruns
    if (len - 12 - lbllen - 4 < 0) {
        DEBUG(3, "Labellen %d != %d\n", lbllen, len);
        return -1;
    }
    // Check query class
    if (buf[lbllen + 14] != 0 || buf[lbllen + 15] != 1) {
        DEBUG(3, "Wrong class (not IN): %d %d %d\n", lbllen, buf[lbllen+14], buf[lbllen+15]);
        return -1; // We only answer for class IN
    }
    int type = type2id(buf[lbllen + 12]*256 + buf[lbllen + 13]);
    len = 12 + lbllen + 4;

    // Find the correct entry in the DNS tree for the given type and name
    struct di *di = walktree(name, lbllen - 2, type, &ad);

    // Set QR flag to tag answer as response
    buf[2] |= 0x80;
    maxlen -= len;
    unsigned char *bp = buf + len;

    if (buf[11] == 1) { // We have an additional record, probably EDNS0
        if ((bp[0] == 0) // Root Domain
                && (bp[1] == 0) && (bp[2] == 41) // Type OPT
                ) {
            edns = 1;
            udpsize = bp[3]*256 + bp[4];
            DO = bp[7]&0x80;
            DEBUG(3, "Got EDNS record (UDPsize: %d, DNSSEC: %s)\n", udpsize, DO ? "yes" : "no");
            if (maxlen > udpsize)
                maxlen = udpsize;
            maxlen -= 11; // Reserve space for EDNS reply
        }
    }

    // Now construct the reply packet
    buf[3] = buf[6] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    //  rtype = RTYPE_NXDOMAIN; di = NULL;
    do {
        // Handle NXDOMAIN and NODATA
        if (ad.rtype == RTYPE_NXDOMAIN || ad.rtype == RTYPE_NODATA) {
            if (di) { // We have an SOA-record, so we are authoritative
                // Add AA flag
                buf[2] |= 0x04;
                // Set number of answer records
                buf[9] = di->nrrecords;
                if (di->recordlen > maxlen) {
                    // Truncated answer due to lack of buffer space
                    tc = 1;
                    break;
                }
                // Copy record data into buffer
                rte_memcpy(bp, di->record, di->recordlen);
                // Advance buffer pointer and adjust remaining length
                bp += di->recordlen;
                maxlen -= di->recordlen;

                // DNSSEC requested?
                if (DO && DICHNULL(di->ch[T_RRSIG])) {
                    // Look for RRSIG record
                    struct di *rrsig = DICH(di->ch[T_RRSIG]);
                    if (rrsig->recordlen > maxlen) {
                        tc = 1;
                        break;
                    }
                    // Copy RRSIG record into answer buffer
                    rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                    bp += rrsig->recordlen;
                    maxlen -= rrsig->recordlen;
                    buf[9] += rrsig->nrrecords;

                    // Find and copy NSEC records for NXDOMAIN
                    diptr_t nsec = find_nsec_record(di->zone, name);
                    if (nsec) {
                        if (nsec->recordlen > maxlen) {
                            tc = 1;
                            break;
                        }
                        rte_memcpy(bp, nsec->record, nsec->recordlen);
                        bp += nsec->recordlen;
                        maxlen -= nsec->recordlen;
                        buf[9] += nsec->nrrecords;
                        if (DICHNULL(nsec->ch[T_RRSIG])) {
                            struct di *rrsig = DICH(nsec->ch[T_RRSIG]);
                            if (rrsig->recordlen > maxlen) {
                                tc = 1;
                                break;
                            }
                            rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                            bp += rrsig->recordlen;
                            maxlen -= rrsig->recordlen;
                            buf[9] += rrsig->nrrecords;
                        }
                    }
                }
            }
            if (ad.rtype == RTYPE_NXDOMAIN) // Name does not exist
                buf[3] = di ? 0x03 : 0x05; // Set NXDOMAIN or REFUSED
        } else {

            // Handle normal replies
            if ((ad.rtype == RTYPE_NORMAL) || (ad.rtype == RTYPE_WILDCARD)) {
                // Set AA flag
                buf[2] |= 0x04;
                // Check if short record fits
                if (di->shortrecordlen > maxlen) {
                    tc = 1;  // No, truncated
                    break;
                }
                // Copy record data into answer buffer
                rte_memcpy(bp, di->shortrecord, di->shortrecordlen);
                bp += di->shortrecordlen;
                maxlen -= di->shortrecordlen;
                // Adjust ancount
                buf[7] = di->nrrecords;

                // Handle RRSIG records for DNSSEC
                if (DO && DICHNULL(di->ch[T_RRSIG])) {
                    struct di *rrsig = DICH(di->ch[T_RRSIG]);
                    // Check remaining length
                    if (rrsig->shortrecordlen > maxlen) {
                        tc = 1; // Not enough, truncated
                        break;
                    }
                    // Copy rrsig record into answer buffer
                    rte_memcpy(bp, rrsig->shortrecord, rrsig->shortrecordlen);
                    bp += rrsig->shortrecordlen;
                    maxlen -= rrsig->shortrecordlen;
                    buf[7] += rrsig->nrrecords;
                }

                // Handle cname chains. Optimization: transitive hull
                int maxcnamechain = 10;
                while (di->cname && maxcnamechain--) {
                    if (DICHNULL(di->cname->ch[T_CNAME])) // Another cname has precedence
                        di = DICH(di->cname->ch[T_CNAME]);
                    else
                        di = DICH(di->cname->ch[type]); // Otherwise, find record by type
                    if (!di)
                        break; // Record not found
                    if (di->recordlen > maxlen) {
                        tc = 1;
                        break; // Record too long
                    }
                    // Adjust number of answers (ancount)
                    buf[7] += di->nrrecords;
                    // Copy record into answer buffer
                    rte_memcpy(bp, di->record, di->recordlen);
                    bp += di->recordlen;
                    maxlen -= di->recordlen;

                    // Find RRSIG record for CNAME
                    if (DO && DICHNULL(di->ch[T_RRSIG])) {
                        struct di *rrsig = DICH(di->ch[T_RRSIG]);
                        if (rrsig->recordlen > maxlen) {
                            tc = 1;
                            break; // Truncated
                        }
                        // Copy rrsig record into answer buffer
                        rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                        bp += rrsig->recordlen;
                        maxlen -= rrsig->recordlen;
                        // Adjust ancount
                        buf[7] += rrsig->nrrecords;
                    }
                }
                
                if (di && DO && ad.rtype == RTYPE_WILDCARD) {
                    // Wildcard record found, we have to prove, that
                    // there is no real record by providing the
                    // corresponding nsec record
                    diptr_t nsec = find_nsec_record(di->zone, name);
                    if (nsec) {
                        // Found the nsec
                        if (nsec->recordlen > maxlen) {
                            tc = 1;
                            break; // but too long, truncated
                        }
                        // Copy the nsec record
                        rte_memcpy(bp, nsec->record, nsec->recordlen);
                        bp += nsec->recordlen;
                        maxlen -= nsec->recordlen;
                        buf[9] += nsec->nrrecords;
                        // Copy the rrsig record for the nsec record
                        if (DICHNULL(nsec->ch[T_RRSIG])) {
                            struct di *rrsig = DICH(nsec->ch[T_RRSIG]);
                            if (rrsig->recordlen > maxlen) {
                                tc = 1; // Truncated, exit
                                break;
                            }
                            // Copy the rrsig record
                            rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                            bp += rrsig->recordlen;
                            maxlen -= rrsig->recordlen;
                            buf[9] += rrsig->nrrecords;
                        }
                    }
                }
            } else if (ad.rtype == RTYPE_SUBDEL) {
                // No answer found, but a subdelegation
                if (di->recordlen > maxlen) {
                    tc = 1;
                    break;
                }
                // Copy packet into answer buffer
                rte_memcpy(bp, di->record, di->recordlen);
                bp += di->recordlen;
                maxlen -= di->recordlen;
                // Adjust NS count
                buf[9] = di->nrrecords;

                // Check, if we have to add DNSSEC records
                if (DO && DICHNULL(di->ch[T_RRSIG])) {
                    struct di *rrsig = DICH(di->ch[T_RRSIG]);
                    if (rrsig->recordlen > maxlen) {
                        tc = 1;
                        break; // Truncated, leave
                    }
                    // Copy rrsig record into answer buffer
                    rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                    bp += rrsig->recordlen;
                    maxlen -= rrsig->recordlen;
                    // Adjust NS count
                    buf[9] += rrsig->nrrecords;
                }
            }
        }
        if (di && di->additional) {
            // We have additional records to add
            int i = 0;
            while (di->additional[i]) {
                // Process all additional records
                struct di *add = di->additional[i];
                if (add->recordlen > maxlen) {
                    tc = 1;
                    break; // Truncated, exit loop
                }
                // Copy additional records into answer buffer
                rte_memcpy(bp, add->record, add->recordlen);
                bp += add->recordlen;
                maxlen -= add->recordlen;
                // Increase adcount
                buf[11] += add->nrrecords;

                if (DO && DICHNULL(add->ch[T_RRSIG])) {
                    // Also add RRSIG records for additional records
                    struct di *rrsig = DICH(add->ch[T_RRSIG]);
                    if (rrsig->recordlen > maxlen) {
                        tc = 1;
                        break;
                    }
                    // copy rrsig record into answer buffer
                    rte_memcpy(bp, rrsig->record, rrsig->recordlen);
                    bp += rrsig->recordlen;
                    maxlen -= rrsig->recordlen;
                    // Increase adcount
                    buf[11] += rrsig->nrrecords;
                }
                i++;
            }
        }
    } while (0);

    // Add EDNS data at the end
    if (edns) {
        memcpy(bp, "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00", 11);
        bp[7] |= DO;
        bp += 11;
        buf[11]++;
    }

    if (tc) {
        // Answer is truncated, so set truncated flag
        buf[2] |= 0x02;
    }
    
    return bp - buf;
}

/**
   Find entry for name and type in tree
   name: DNS name to look for
   nl: Length of name
   typeid: Record type
   ad: supplemental answer characteristics
*/
static inline diptr_t _walktree(char *name, int nl, int typeid, struct answerdata *ad) {
    diptr_t pos = root;  // Current tree level
    int lastdepth = 0;   // Last depth level
    ad->rtype = RTYPE_NORMAL; // Response type (assume normal response here)

    DEBUG(3, "Starting lookup for %s\n", name);

    int depth = pos->depth;
    while (depth < nl) {
#if (DEBUGLEVEL >= 3)
        printdi(pos);
#endif

        // Next character to look for
        int ch = char2id(name[nl - depth - 1]);
        // Record if we are at a label separator
        int nxtislblsep = name[nl - depth] == '.';
        if (unlikely(ch < 0)) {
            // We hit an invalid character, bail out
            ad->rtype = RTYPE_NXDOMAIN;
            return NULL;
        }

        DEBUG(3, "Looking for %d\n", ch);
        if (nxtislblsep && pos->has_wc) {
            // We found a candidate wildcard record, memorize it
            DEBUG(3, "Recording wildcard: %s\n", DICH(pos->ch[WILDCARD])->name);
            ad->wc = DICH(pos->ch[WILDCARD]);
        }
        if (ch == LABELSEP) { // Look for SOA / delegations
            if (pos->has_soa && pos->zone) {
                // We found a candidate SOA record, memorize it
                DEBUG(3, "Recording SOA: %s\n", DICH(pos->ch[T_SOA])->name);
                ad->soa = DICH(pos->ch[T_SOA]);
            } else if (pos->has_ns) {
                // We found a candidate subdelegation, memorize it
                ad->rtype = RTYPE_SUBDEL;
                DEBUG(3, "Found delegation: %s\n", DICH(pos->ch[T_NS])->name);
                ad->answer = DICH(pos->ch[T_NS]);
                return DICH(pos->ch[T_NS]);
            }
        }
        pos = DICH(pos->ch[ch]); // Step down in the tree
        if (!pos)
            break; // Subtree is empty, no record found
        depth = pos->depth; // Current depth
        int deltadepth = depth - lastdepth - 1; // Depth change to previous depth
        DEBUG(3, "Comparing %s with %s (dd %d)\n", pos->name, name + nl - depth, deltadepth);
        // Check, if the new name part matches the name in the tree
        if (unlikely((depth > nl)
               || (deltadepth && strncasecmp(pos->name, name + nl - depth, deltadepth))
        )
                ) {
            pos = NULL; // Mismatch, no record found
            break;
        }
        lastdepth = depth;
    }

    if (pos && pos->has_soa && pos->zone) {
        // We are at a SOA record
        ad->soa = DICH(pos->ch[T_SOA]);
    } else if (pos && pos->has_ns) {
        // We are at a subdelegation here
        DEBUG(3, "Found Delegation: %s\n", DICH(pos->ch[T_NS])->name);
        ad->rtype = RTYPE_SUBDEL;
        ad->answer = DICH(pos->ch[T_NS]);
        return DICH(pos->ch[T_NS]);
    }

    if ((!pos || !pos->nrrecords) && ad->wc) {
        // No record found, but we have a candidate wildcard record to use
        pos = ad->wc;
        ad->rtype = RTYPE_WILDCARD;
        DEBUG(3, "Going with wildcard: \n");
    } else {
        DEBUG(3, "Going with record: \n");
    }
    
#if (DEBUGLEVEL >= 3)
    printdi(pos);
#endif

    if (pos && pos->nrrecords) { // We have entries for the requested name
        if (HASTYPE(pos, T_CNAME)) {       // Check if there is a CNAME entry
            pos = DICH(pos->ch[T_CNAME]);
        } else if (typeid > 0 && HASTYPE(pos, typeid)) { // Check for the requested type
            pos = DICH(pos->ch[typeid]);
        } else {                           // Otherwise return NODATA
            ad->rtype = RTYPE_NODATA;
            return ad->soa;
        }
    } else {                    // No entries for the name => NXDOMAIN
        ad->rtype = RTYPE_NXDOMAIN;
        return ad->soa;
    }
    ad->answer = pos;
    ad->rtype = RTYPE_NORMAL; // Response type (assume normal response here)

    return pos;
}

/**
   Find entry for name and type in tree and update statistics, if activated
   name: DNS name to look for
   nl: Length of name
   typeid: Record type
   ad: supplemental answer characteristics
*/
diptr_t walktree(char *name, int nl, int typeid, struct answerdata *ad) {
    diptr_t res = _walktree(name, nl, typeid, ad);
#ifdef RECORDSTATS
    if (res)
        res->nrreq++;
#endif
    return res;
}
