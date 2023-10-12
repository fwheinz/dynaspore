#define MTU 1472

#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>

#include <rte_eal.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_hexdump.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_distributor.h>
#include <rte_dev_info.h>


#include "xfc.h"

#define RX_RING_SIZE 256
#define TX_RING_SIZE 512
#define NUM_MBUFS ((64*1024)-1)
#define MBUF_SIZE 65535
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

/* uncommnet below line to enable debug logs */
/* #define DEBUG */
//#define DEBUG

#ifdef DEBUG
#define LOG_LEVEL RTE_LOG_DEBUG
#define LOG_DEBUG(log_type, fmt, args...) do {  \
    RTE_LOG(DEBUG, log_type, fmt, ##args);      \
} while (0)
#else
#define LOG_LEVEL RTE_LOG_WARNING
#define LOG_DEBUG(log_type, fmt, args...) do {} while (0)
#endif

#define RTE_LOGTYPE_DISTRAPP RTE_LOGTYPE_USER1

/* mask of enabled ports */
static uint32_t enabled_port_mask;
volatile uint8_t quit_signal;
int rings;
struct rte_mempool *mbuf_pool;
struct rte_mempool *tcp_pool;

struct serverstats ss;

static volatile struct app_stats {
    struct {
        uint64_t rx_pkts;
        uint64_t returned_pkts;
        uint64_t enqueued_pkts;
    } rx __rte_cache_aligned;

    struct {
        uint64_t dequeue_pkts;
        uint64_t tx_pkts;
    } tx __rte_cache_aligned;
} app_stats;

#ifndef ETH_MQ_RX_RSS
#define ETH_MQ_RX_RSS RTE_ETH_MQ_RX_RSS
#define DEV_RX_OFFLOAD_IPV4_CKSUM RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#define ETH_MQ_TX_NONE RTE_ETH_MQ_TX_NONE
#endif

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .offloads = DEV_RX_OFFLOAD_IPV4_CKSUM
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = DEV_RX_OFFLOAD_IPV4_CKSUM
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_hf = 0x38d34,
        }
    },
};

struct output_buffer {
    unsigned count;
    struct rte_mbuf *mbufs[BURST_SIZE];
};

struct metadata {
    struct rte_ipv4_hdr *ip;
    struct rte_udp_hdr *udp;
    unsigned char *payload;
    int paylen;
};
#define USER(x) ((struct metadata *)x->shinfo)

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rxRings = rings, txRings = rings;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count_avail())
        return -1;

    retval = rte_eth_dev_configure(port, rxRings, txRings, &port_conf);
    if (retval != 0)
        return retval;

    for (q = 0; q < rxRings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                        rte_eth_dev_socket_id(port),
                        NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    static struct rte_eth_txconf tx_conf = {
        .tx_thresh = {
            .pthresh = 32,
            .hthresh = 0,
            .wthresh = 0,
        },
        .tx_free_thresh = 32,
        .tx_rs_thresh = 32,
    };



    for (q = 0; q < txRings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                        rte_eth_dev_socket_id(port),
                        &tx_conf);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    struct rte_eth_link link;
    rte_eth_link_get_nowait(port, &link);
    if (!link.link_status) {
        sleep(1);
        rte_eth_link_get_nowait(port, &link);
    }

    if (!link.link_status) {
        printf("Link down on port %"PRIu8"\n", port);
        return 0;
    }

    rte_eth_allmulticast_enable(port);

    return 0;
}

struct lcore_params {
    unsigned worker_id;
    struct rte_mempool *mem_pool;
};

static void
print_stats(void)
{
    struct rte_eth_stats eth_stats;
    unsigned i;

    printf("\nRX thread stats:\n");
    printf(" - Received:    %"PRIu64"\n", app_stats.rx.rx_pkts);
    printf(" - Processed:   %"PRIu64"\n", app_stats.rx.returned_pkts);
    printf(" - Enqueued:    %"PRIu64"\n", app_stats.rx.enqueued_pkts);

    printf("\nTX thread stats:\n");
    printf(" - Dequeued:    %"PRIu64"\n", app_stats.tx.dequeue_pkts);
    printf(" - Transmitted: %"PRIu64"\n", app_stats.tx.tx_pkts);

    for (i = 0; i < rte_eth_dev_count_avail(); i++) {
        rte_eth_stats_get(i, &eth_stats);
        printf("\nPort %u stats:\n", i);
        printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
        printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
        printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
        printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
        printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
    }
}

#define MAXADDRS 20

unsigned int ipv4_addresses[MAXADDRS];
char ipv6_addresses[MAXADDRS][16];


// Check, if the given IPv4 address is configured
static int ipv4_address_configured (unsigned int ip) {
    lua_ipv4_address_transfer(ipv4_addresses, MAXADDRS);

    for (int i = 0; i < MAXADDRS; i++) {
        if (ipv4_addresses[i] == ip)
            return 1;
    }
    return 0;
}

// Check, if the given IPv6 address is configured
static int ipv6_address_configured (char *ip) {
    lua_ipv6_address_transfer(ipv6_addresses, MAXADDRS);

    for (int i = 0; i < MAXADDRS; i++) {
        if (memcpy(ipv6_addresses[i], ip, 16) == 0)
            return 1;
    }
    return 0;
}

// Handle a TCP packet (IPv6)
static void handle_tcp (struct rte_mbuf *buf, struct rte_tcp_hdr *tcp, void *payload, int paylen) {
    if (tcp->dst_port == htons(53)) {
        // Prepare L4-Header
        tcp->dst_port = tcp->src_port;
        tcp->src_port = htons(53);
        tcp->data_off = 0x50;

        if (tcp->tcp_flags == 0x02) {
            // We got a SYN packet, respond with SYN-ACK
            tcp->recv_ack = ntohl(htonl(tcp->sent_seq)+1);
            tcp->tcp_flags |= 0x10;
            paylen = 0;
            buf->pkt_len = buf->data_len = 20;
        } else if (tcp->tcp_flags & 0x10) {
            // We got a data packet, answer a query
            int datalen = paylen;
            if (datalen) {
                paylen -= 2;
                payload += 2;
                paylen = answer_packet(payload, paylen, rte_pktmbuf_data_room_size(mbuf_pool)-RTE_PKTMBUF_HEADROOM-56);
                if (paylen < 0)
                    paylen = 0;
                else {
                    *((unsigned short *)payload-1) = htons(paylen);
                    paylen += 2;
                }
                buf->pkt_len = buf->data_len = paylen + 20;
                tcp->tcp_flags |= 0x01;
            } else if (tcp->tcp_flags & 0x01) {
                tcp->tcp_flags = 0x10;
                buf->pkt_len = buf->data_len = 20;
                datalen = 1;
            } else { // No data and no fin
                return;
            }
            unsigned int ack = tcp->recv_ack;
            tcp->recv_ack = ntohl(htonl(tcp->sent_seq)+datalen);
            tcp->sent_seq = ack;

        } else {
            return;
        }

        buf->hash.usr = 0x01;
        buf->l4_len = sizeof(struct rte_tcp_hdr);
        buf->tso_segsz = 1350;
        tcp->cksum = 0;
    }
}

static inline void handle_pkt (struct rte_mbuf *buf, int id) {
    buf->hash.usr = 0x00;
    struct rte_ether_hdr *e = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);

    if (e->ether_type == 0x0608) {
        // Handle ARP Packets
        if (buf->pkt_len < sizeof(struct rte_ether_hdr)+sizeof(struct rte_arp_hdr))
            return;
        struct rte_arp_hdr *a = (void*)((char*)e+sizeof(struct rte_ether_hdr));
        struct in_addr in;
        in.s_addr = a->arp_data.arp_tip;
        if ((a->arp_opcode == ntohs(RTE_ARP_OP_REQUEST)) && ipv4_address_configured(a->arp_data.arp_tip)) { 
            a->arp_data.arp_tip = a->arp_data.arp_sip;
            a->arp_data.arp_sip = in.s_addr;
            a->arp_opcode = htons(RTE_ARP_OP_REPLY);
            memcpy(&a->arp_data.arp_tha, &a->arp_data.arp_sha, sizeof(a->arp_data.arp_tha));
            rte_eth_macaddr_get(buf->port, &a->arp_data.arp_sha);
            rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
            rte_eth_macaddr_get(buf->port, &e->src_addr);
            buf->hash.usr = 0x01;
        }
    } else if (e->ether_type == 0xDD86) {
        // Handle IPv6 packets
        if (buf->pkt_len < sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))
            return;
        struct rte_ipv6_hdr *ip = (void*)((char*)e+sizeof(struct rte_ether_hdr));
        if (ip->proto == 58) {
            struct rte_icmp_hdr *icmp = (void*)((char*)ip+sizeof(struct rte_ipv6_hdr));
            if (icmp->icmp_type == 135 && icmp->icmp_code == 0) {
                // We got a neighbor solicitation
                char *payload = (void*)((char*)icmp+sizeof(struct rte_icmp_hdr));
                if (ipv6_address_configured(payload)) {
                    rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
                    rte_eth_macaddr_get(buf->port, &e->src_addr);
                    
                    memcpy(ip->dst_addr, ip->src_addr, sizeof(ip->dst_addr));
                    memcpy(ip->src_addr, payload, sizeof(ip->src_addr));
                    ip->hop_limits = 255;
                    ip->payload_len = htons(sizeof(icmp)+24);
                    
                    icmp->icmp_type = 136;
                    icmp->icmp_cksum = 0;
                    icmp->icmp_ident = 0x60;

                    payload[16] = 2;
                    payload[17] = 1;
                    rte_eth_macaddr_get(buf->port, (void*)payload+18);

                    icmp->icmp_cksum = rte_ipv6_udptcp_cksum(ip, icmp);
                    buf->hash.usr = 0x01;
                }
            }
        } else if (ip->proto == IPPROTO_UDP) {
            // IPv6 UDP packet
            if (buf->pkt_len < sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr)+sizeof(struct rte_udp_hdr)+17)
                return;
            struct rte_udp_hdr *udp = (void*)((unsigned char *)ip+sizeof(*ip));
            if (udp->dst_port == htons(53)) {
                rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
                rte_eth_macaddr_get(buf->port, &e->src_addr);
                udp->dst_port = udp->src_port;
                udp->src_port = htons(53);
                char tmp[16];
                memcpy(tmp, ip->src_addr, sizeof(tmp));
                memcpy(ip->src_addr, ip->dst_addr, sizeof(ip->src_addr));
                memcpy(ip->dst_addr, tmp, sizeof(ip->dst_addr));
                buf->ol_flags = RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
                buf->l2_len = sizeof(struct rte_ether_hdr);
                buf->l3_len = sizeof(struct rte_ipv6_hdr);
                buf->l4_len = sizeof(struct rte_udp_hdr);
                buf->hash.usr = 0x00;
            }
        } else if (ip->proto == IPPROTO_TCP) {
            // IPv6 TCP packet
            struct rte_tcp_hdr *tcp = (void*)((unsigned char *)ip+sizeof(*ip));
            if (tcp->dst_port == htons(53)) {
                // Prepare L2-Header
                rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
                rte_eth_macaddr_get(buf->port, &e->src_addr);

                // Prepare L3-Header
                char tmp[16];
                memcpy(tmp, ip->src_addr, sizeof(tmp));
                memcpy(ip->src_addr, ip->dst_addr, sizeof(ip->src_addr));
                memcpy(ip->dst_addr, tmp, sizeof(ip->dst_addr));
                ip->hop_limits = 0xff;

                buf->l2_len = sizeof(struct rte_ether_hdr);
                buf->l3_len = sizeof(struct rte_ipv6_hdr);
                buf->l4_len = sizeof(struct rte_tcp_hdr);
                int paylen = htons(ip->payload_len) - (tcp->data_off >> 2);
                void *payload = (char*) tcp + (tcp->data_off >> 2);
                handle_tcp(buf, tcp, payload, paylen);
                ip->payload_len = htons(buf->pkt_len);
                buf->pkt_len += sizeof(*ip)+sizeof(struct rte_ether_hdr);
                buf->data_len += sizeof(*ip)+sizeof(struct rte_ether_hdr);
                buf->ol_flags = RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM;
                tcp->cksum = 0;
                tcp->cksum = rte_ipv6_phdr_cksum(ip, buf->ol_flags);
            }
        }

    } else if (e->ether_type == 0x0008) {
        // IPv4 Packet
        if (buf->pkt_len < sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr))
            return;
        struct rte_ipv4_hdr *ip = (void*)((char*)e+sizeof(struct rte_ether_hdr));
        if (ip->next_proto_id == IPPROTO_UDP) {
            // IPv4 UDP Packet
            int ihl = (ip->version_ihl&RTE_IPV4_HDR_IHL_MASK)*RTE_IPV4_IHL_MULTIPLIER;
            if (buf->pkt_len < sizeof(struct rte_ether_hdr)+ihl+sizeof(struct rte_udp_hdr)+17)
                return;
            struct rte_udp_hdr *udp = (void*)((unsigned char *)ip+ihl);
            if (udp->dst_port == htons(53)) {
                USER(buf)->udp = udp;
                USER(buf)->ip = ip;
                rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
                rte_eth_macaddr_get(buf->port, &e->src_addr);
                udp->dst_port = udp->src_port;
                udp->src_port = htons(53);
                unsigned int tmp = ip->src_addr;
                ip->src_addr = ip->dst_addr;
                ip->dst_addr = tmp;
                ip->time_to_live = 0x40;
                buf->hash.usr = 0x01;
                buf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
                buf->l2_len = sizeof(struct rte_ether_hdr);
                buf->l3_len = sizeof(struct rte_ipv4_hdr);
                buf->l4_len = sizeof(struct rte_udp_hdr);
                void *payload = (void*)((unsigned char*)udp+sizeof(struct rte_udp_hdr));
                USER(buf)->payload = payload;
                int paylen = htons(ip->total_length) - ((char*)payload - (char*)ip);
                USER(buf)->paylen = paylen;
                paylen = answer_packet(payload, paylen, rte_pktmbuf_data_room_size(mbuf_pool)-RTE_PKTMBUF_HEADROOM-42);
                buf->pkt_len = buf->data_len = ((char*)payload - (char*)ip)+paylen+14;
                udp->dgram_len = htons(paylen+sizeof(struct rte_udp_hdr));
                ip->total_length = htons(buf->pkt_len-14);
                ip->hdr_checksum = 0;
                udp->dgram_cksum = 0;
                                
                if (paylen > MTU) {
                    struct rte_mbuf *out[45];
                    rte_pktmbuf_adj(buf, (uint16_t)sizeof(struct rte_ether_hdr));
                    int nrpkt = rte_ipv4_fragment_packet(buf, out, sizeof(out)/sizeof(*out), 1300,
                            mbuf_pool, mbuf_pool);
                    if (nrpkt > 0) {
                        int i;
                        for (i = 0; i < nrpkt; i++) {
                            void *ptr = rte_pktmbuf_prepend(out[i], (uint16_t)sizeof(struct rte_ether_hdr));
                            out[i]->l2_len = sizeof(struct rte_ether_hdr);
                            rte_memcpy(ptr, e, sizeof(struct rte_ether_hdr));
                        }
                        rte_eth_tx_burst(buf->port, id, out, nrpkt);
                    }
                    buf->hash.usr = 0x00;
                }
            }
        } else if (ip->next_proto_id == IPPROTO_TCP) {
            // IPv4 TCP Packet
            int ihl = (ip->version_ihl&RTE_IPV4_HDR_IHL_MASK)*RTE_IPV4_IHL_MULTIPLIER;
            struct rte_tcp_hdr *tcp = (void*)((unsigned char *)ip+ihl);
            if (tcp->dst_port == htons(53)) {

                // Prepare L2-Header
                rte_ether_addr_copy(&e->src_addr, &e->dst_addr);
                rte_eth_macaddr_get(buf->port, &e->src_addr);

                // Prepare L3-Header
                unsigned int tmp = ip->src_addr;
                ip->src_addr = ip->dst_addr;
                ip->dst_addr = tmp;
                ip->time_to_live = 0x40;

                // Prepare L4-Header
                tcp->dst_port = tcp->src_port;
                tcp->src_port = htons(53);
                tcp->data_off = 0x50;


                void *payload = (void*)((unsigned char*)tcp+(tcp->data_off>>2)+2);
                int paylen = htons(ip->total_length) - ((char*)payload - (char*)ip);
                if (tcp->tcp_flags == 0x02) {
                    tcp->recv_ack = ntohl(htonl(tcp->sent_seq)+1);
                    tcp->tcp_flags |= 0x10;
                    paylen = 0;
                    buf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
                    buf->pkt_len = buf->data_len = 54;
                } else if (tcp->tcp_flags & 0x10) {
                    int datalen = ntohs(ip->total_length)-ihl-(tcp->data_off>>2);
                    if (datalen) {
                        paylen = answer_packet(payload, paylen, rte_pktmbuf_data_room_size(mbuf_pool)-RTE_PKTMBUF_HEADROOM-54);
                        *((unsigned short *)payload-1) = htons(paylen);
                        buf->pkt_len = buf->data_len = paylen + 54 + 2;
                        tcp->tcp_flags |= 0x01;
                    } else if (tcp->tcp_flags & 0x01) {
                        tcp->tcp_flags = 0x10;
                        buf->pkt_len = buf->data_len = 54;
                        datalen = 1;
                    } else { // No data and no fin
                        return;
                    }
                    unsigned int ack = tcp->recv_ack;
                    tcp->recv_ack = ntohl(htonl(tcp->sent_seq)+datalen);
                    tcp->sent_seq = ack;
                    if (buf->data_len != 54)
                        buf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM;
                    else
                        buf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
                } else {
                    return;
                }

                buf->hash.usr = 0x01;
                buf->l2_len = sizeof(struct rte_ether_hdr);
                buf->l3_len = sizeof(struct rte_ipv4_hdr);
                buf->l4_len = sizeof(struct rte_tcp_hdr);
                buf->tso_segsz = 1350;
                ip->total_length = htons(buf->pkt_len-14);
                ip->hdr_checksum = 0;
                tcp->cksum = 0;
                tcp->cksum = rte_ipv4_phdr_cksum(ip, buf->ol_flags);
            }

        }
    }
}

int activeport = -1;
static int lcore_worker(struct lcore_params *p) {
    const unsigned id = p->worker_id;
    struct corestats *cs = &ss.corestats[id];

    printf("Worker %d waiting for packets...\n", id);
    while (!quit_signal) {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(activeport, id, bufs, BURST_SIZE);
        if (!nb_rx)
            continue;
        cs->rxpkt += nb_rx;
        int i;
        struct metadata md[nb_rx];
        for (i = 0; i < nb_rx; i++) {
            cs->rxbytes += bufs[i]->pkt_len+24;
            bufs[i]->shinfo = (void*) &md[i];
            bufs[i]->hash.usr = 0;
            handle_pkt(bufs[i], id);
            if (!bufs[i]->hash.usr) {
                bufs[i]->pkt_len = bufs[i]->data_len = 0;
            }
        }
        const uint16_t nb_tx = rte_eth_tx_burst(activeport, id, bufs, nb_rx);
        for (i = 0; i < nb_rx; i++) {
            if (i >= nb_tx) {
                rte_pktmbuf_free(bufs[i]);
            } else {
                int len = bufs[i]->pkt_len;
                if (len > 0) {
                    cs->txpkt++;
                    if (len < 60)
                        cs->txbytes += 84;
                    else
                        cs->txbytes += len + 24;
                }
            }
        }

    }
    return 0;
}

/* display usage */
    static void
print_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK\n"
            "  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
            prgname);
}

    static int
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

/* Parse the argument given in the command line of the application */
    static int
parse_args(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:",
            lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind <= 1) {
        print_usage(prgname);
        return -1;
    }

    argv[optind-1] = prgname;

    optind = 0; /* reset getopt lib */
    return 0;
}

/* Main function, does initialization and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
    unsigned lcore_id, worker_id = 0;
    unsigned nb_ports;
    uint8_t portid;
    uint8_t nb_ports_available;
    pthread_t control;

    /* init EAL */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;

    rings = rte_lcore_count();
    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid distributor parameters\n");

    if (rte_lcore_count() < 1)
        rte_exit(EXIT_FAILURE, "Error, This application needs at "
                "least one logical core to run!\n");

        
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                MBUF_SIZE,
//      RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    nb_ports_available = nb_ports;

    root = diallocname(NULL, "", 0);
    ss.nrcores = rte_lcore_count();
    ss.corestats = calloc(sizeof(struct corestats), ss.nrcores);
    ss.start = time(NULL);
    ss.lastreset = getmstimestamp();

    datasource_init();
    xl_init(stderr);

#ifdef BENCHMARK
    do_benchmark();
    exit(1);
#endif

    pthread_create(&control, NULL, start_control, NULL);

    /* initialize all ports */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            nb_ports_available--;
            continue;
        }
        if (activeport >= 0) {
            printf("More than one port enabled, this is not supported yet. Exiting...\n\n");
            exit(EXIT_FAILURE);
        }
        /* init port */
        struct rte_ether_addr mac;
        rte_eth_macaddr_get(portid, &mac);
        printf("Initializing port %u (%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx) ... ", (unsigned) portid,
                mac.addr_bytes[0],
                mac.addr_bytes[1],
                mac.addr_bytes[2],
                mac.addr_bytes[3],
                mac.addr_bytes[4],
                mac.addr_bytes[5]
              );

        activeport = portid;
        fflush(stdout);

        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot initialize port %"PRIu8"\n",
                    portid);
        printf("done.\n");

    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
                "All available ports are disabled. Please set portmask.\n");
    }

    struct rte_eth_link link;
    printf("Waiting for link...\n");
    do {
        rte_eth_link_get(activeport, &link);
    } while (!link.link_status);

    printf("Link is up (%d)! Starting workers...\n", link.link_status);


    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
        if (!p)
            rte_panic("malloc failure\n");
        *p = (struct lcore_params){worker_id, mbuf_pool};

        rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, lcore_id);
        worker_id++;
    }


    struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p) 
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){worker_id, mbuf_pool};
    lcore_worker(p);

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    print_stats();
    return 0;
}
