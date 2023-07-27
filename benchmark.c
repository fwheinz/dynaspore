#include <stdio.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <pthread.h>


#include "xfc.h"

#define NRREQS 7000000
int nrreqs;
#define PKTSIZE 512

int pid = 1000;
int make_dns_packet(struct rte_ipv4_hdr *ip);
int make_dns_packet(struct rte_ipv4_hdr *ip) {
        ip->version_ihl = 0x45;
        ip->type_of_service = 0x00;
        ip->packet_id = pid++;
        ip->fragment_offset = 0x00;
        ip->time_to_live = 0x40;
        ip->next_proto_id = 17;
        ip->hdr_checksum = 0;
        ip->src_addr = inet_addr("195.191.92.17");
        ip->dst_addr = inet_addr("195.191.92.20");
        struct rte_udp_hdr *udp = (void*)((char *)ip + sizeof(struct rte_ipv4_hdr));
        udp->src_port = pid;
        udp->dst_port = 0x3500;
        udp->dgram_cksum = 0x00;
        unsigned char *payload = (unsigned char *)udp + sizeof(struct rte_udp_hdr);

        char line[1024];
        char *ptr = fgets(line, sizeof(line), stdin);
        if (!ptr) {
            printf("EOF\n");
            return 0;
        }
        ptr[strlen(ptr)-1] = '\0';
        ptr = strchr(line, '\t');
        if (!ptr) {
            printf("No tab found\n");
            return -1;
        }
        *ptr++ = 0;
        if (!is_valid_dnsname(line)) {
            return -1;
        }
        int type = typestr2type(ptr);
        if (type < 0) {
            printf("Invalid type: '%s'\n", ptr);
            return -1;
        }
        int paylen = 16;
        memcpy(payload,
                        "\x31\x37"
                        "\x00\x00"
                        "\x00\x01"
                        "\x00\x00"
                        "\x00\x00"
                        "\x00\x01"
                        , 12);
        char line2[1024];
        strcpy(line2, line);
        ptr = name2lbl(payload+12, line);
        memcpy(ptr, "\x00\x01\x00\x01", 4);
        ptr[1] = type;
        ptr += 4;
        memcpy(ptr, "\x00\x00\x29\x10\x00\x80\x00\x00\x00\x00\x00", 11);
        ptr += 11;

        int udplen = (char*)ptr - (char*)udp;
        udp->dgram_len = htons(udplen); // TODO
        ip->total_length = htons(udplen+sizeof(struct rte_ipv4_hdr)); // TODO
        ip->hdr_checksum = 0;


        return udplen+sizeof(struct rte_ipv4_hdr);
}

unsigned char **prepare_pkts (void) {
        unsigned char **ret;

        ret = malloc(NRREQS*sizeof(unsigned char*));

        int i;
        for (i = 0; i < NRREQS; i++) {
                unsigned char *buf = malloc(PKTSIZE);

                struct rte_ether_hdr *e = (void*)buf;
                rte_eth_macaddr_get(0, &e->s_addr);
                memcpy(e->d_addr.addr_bytes, "\x00\x1b\x21\x81\x54\xb8", 6);
//              memcpy(e->d_addr.addr_bytes, "\x00\x60\xdd\x46\x76\xf2", 6); // ns1
                e->ether_type = 0x0008;

                struct rte_ipv4_hdr *ip = (void*)((char *)e+sizeof(struct rte_ether_hdr));
                int len = make_dns_packet(ip);
                if (!len)
                        break;
                if (len < 0) {
                    i--;
                    free(buf);
                } else {
                    ret[i] = buf;
                }
        }
        nrreqs = i;

        return ret;
}

static inline int timems (void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec*1000+tv.tv_usec/1000;
}

struct lcore_params {
    unsigned worker_id;
    struct rte_mempool *mem_pool;
};

unsigned char **pkts;
unsigned lcore_id, worker_id = 0;
static int do_benchmark_single (struct lcore_params *parms) {
    long i;
    int id = parms->worker_id;
    int start = timems();
    for (i = 0; i < nrreqs; i++) {
//        unsigned char *p = pkts[(i+id*1000000)%nrreqs];
        unsigned char *p = pkts[(i*8+id)%nrreqs];
        int len = p[38]*256+p[39];
        answer_packet(p+42, len, PKTSIZE);
    }
    int end = timems();
    printf("%d: %ld requests per second (%d %d)\n", id, (i*1000)/(end-start), end, start);

    return 0;
}

void do_benchmark (void) {
    printf("Preparing pkts for benchmark...\n");
    pkts = prepare_pkts();
    printf("Done.\n");

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        struct lcore_params *p = malloc(sizeof(*p));
        if (!p)
            rte_panic("malloc failure\n");
        *p = (struct lcore_params){worker_id, NULL};

        printf("Starting lcore %d\n", lcore_id);
        rte_eal_remote_launch((lcore_function_t *)do_benchmark_single, p, lcore_id);
        worker_id++;
    }
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return;
    }

}

