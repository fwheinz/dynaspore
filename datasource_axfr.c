#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>

#include "xfc.h"

static int axfr_parse(const char *name, char *buf, int len, int *nrrec) {
    if (len < 12) {
        DEBUG(1, "AXFR: Invalid length %d\n", len);
        return -1;
    }
    unsigned char *ptr = buf;
    ptr += 2;
    unsigned short flags = ntohs(GETSHORT(ptr));
    ptr += 2;
    if (flags != 0x8400) {
        DEBUG(1, "AXFR: Invalid status: 0x%04hX\n", flags);
        return -1;
    }
    int qdcount = ntohs(GETSHORT(ptr));
    ptr += 2;
    int ancount = ntohs(GETSHORT(ptr));
    ptr += 2;
    int nscount = ntohs(GETSHORT(ptr));
    ptr += 2;
    int arcount = ntohs(GETSHORT(ptr));
    ptr += 2;

    char *pkt = buf;

    if (qdcount > 1)
        return -1;
    else if (qdcount) {
        char qname[257];

        int ll = lbl2name_compressed(&ptr, qname, pkt, len);
        if (ll < 0) {
            DEBUG(1, "AXFR query lbl corrupted\n");
            return -1;
        }

        int qtype = get_ushort(&ptr);
        int qclass = get_ushort(&ptr);
    }

    char record[100000];
    while (ancount--) {
        struct record rec;
        ptr = retrieve_record_data_axfr(ptr, record, sizeof (record), pkt, len, &rec);
        if (!ptr)
            return -1;

        if (*nrrec == 0) {
            if (rec.type != 6) // SOA must be the first record
                return -1;
            if (strcasecmp(rec.name, name))
                return -1;
        } else if (rec.type == 6) { // SOA must be the last record
            return 1;
        }
        (*nrrec)++;
        diptr_t x = create_record_from_line(record);
    }

    return 0;
}

static int axfr_connect(const char *hostname, const char *port) {
    struct addrinfo hints, *result;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    int st = getaddrinfo(hostname, port, &hints, &result);

    if (st) {
        DEBUG(2, "Error looking up %s/%s: %s\n", hostname, port, gai_strerror(st));
        return -1;
    }

    for (; result; result = result->ai_next) {
        int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (fd < 0) {
            DEBUG(2, "Error creating socket: %s\n", strerror(errno));
            continue;
        }
        fcntl(fd, F_SETFL, O_NONBLOCK);
        st = connect(fd, result->ai_addr, result->ai_addrlen);
        if (st < 0 && (errno != EINPROGRESS)) {
            DEBUG(2, "Error connecting to %s/%s: %s\n", hostname, port, strerror(errno));
            close(fd);
            continue;
        }

        fd_set fdset;
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        st = select(fd + 1, NULL, &fdset, NULL, &tv);
        if (st < 0) {
            DEBUG(2, "Select failed: %s\n", strerror(errno));
            close(fd);
            continue;
        } else if (st == 0) {
            DEBUG(2, "Connect to %s/%s timed out\n", hostname, port);
            close(fd);
            continue;
        }
        int err, errlen = sizeof (err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err) {
            DEBUG(2, "Connect to %s/%s failed: %s\n", hostname, port, strerror(errno));
            close(fd);
            continue;
        } else {
            fcntl(fd, F_SETFL, 0);
            return fd;
        }
    }

    return -1;
}

static void send_axfr_request(int fd, const char *name) {
    char buf[1024], *ptr = buf;

    /* Send the AXFR Request */

    unsigned short id = time(NULL) + getpid();
    ptr += 2; // Leave space for the length field
    PUTSHORT(ptr) = htons(id);
    ptr += 2; // ID
    PUTSHORT(ptr) = 0x00;
    ptr += 2; // Flags
    PUTSHORT(ptr) = htons(0x0001);
    ptr += 2; // QDCOUNT
    PUTSHORT(ptr) = 0x00;
    ptr += 2; // ANCOUNT
    PUTSHORT(ptr) = 0x00;
    ptr += 2; // NSCOUNT
    PUTSHORT(ptr) = htons(0x0001);
    ptr += 2; // ARCOUNT
    ptr = name2lbl(ptr, name);
    PUTSHORT(ptr) = htons(0xFC);
    ptr += 2; // QTYPE  (AXFR)
    PUTSHORT(ptr) = htons(0x0001);
    ptr += 2; // QCLASS (IN)
    /* EDNS0 */
    PUTCHAR(ptr) = 0x00;
    ptr += 1; // root domain
    PUTSHORT(ptr) = htons(0x29);
    ptr += 2; // Type OPT
    PUTSHORT(ptr) = htons(0xffff);
    ptr += 2; // Class (payload size)
    PUTINT(ptr) = htonl(0x0);
    ptr += 4; // ttl (extrcode&flags)
    PUTSHORT(ptr) = htons(0x00);
    ptr += 2; // RDLENGTH

    int len = ptr - buf;
    ptr = buf;
    PUTSHORT(ptr) = htons(len - 2);
    int sent = 0;
    do {
        int st = write(fd, buf + sent, len - sent);
        if (st < 0) {
            perror("AXFR write");
            return;
        }
        sent += st;
    } while (sent < len);
}

static int parse_axfr_msg(int fd, const char *name, int *nrrec) {
    /* Receive and parse the AXFR Reply */

    unsigned short rlen = 0;
    int st = read(fd, &rlen, 2);
    if (st < 0) {
        perror("AXFR Error reading reply length");
        return -1;
    } else if (st != 2) {
        DEBUG(1, "AXFR Wrong reply length length: %d\n", st);
        return -1;
    }
    rlen = ntohs(rlen);


    char *reply = alloca(rlen);
    int received = 0;
    do {
        st = read(fd, reply + received, rlen - received);
        if (st < 0) {
            perror("AXFR read");
            return -1;
        } else if (st == 0) {
            perror("AXFR read EOF (premature)");
            return -1;
        }
        received += st;
    } while (received < rlen);


//    char fname[1024];
//    sprintf(fname, "/tmp/%s.axfr", name);
//    int tfd = open(fname, O_RDWR | O_CREAT | O_APPEND, 0600);
//    if (tfd < 0) {
//        perror("open testfile");
//    } else {
//        write(tfd, reply, rlen);
//        close(tfd);
//    }

    return axfr_parse(name, reply, rlen, nrrec);
}

int datasource_axfr_fetch_zones(struct datasource *ds, const char *name, void *arg) {
    int nr = 0;

    if (!is_valid_dnsname(name))
        return 0;

    const char *hostname = xl_getstring(arg, "hostname");
    const char *port = xl_getstring(arg, "port");
    const char *dsname = xl_getstring(arg, "dsname");
    if (!port)
        port = "53";
    int fd = axfr_connect(hostname, port);
    if (fd < 0) {
        return 0;
    }

    send_axfr_request(fd, name);
    int newzone = 0;
    struct zone *z = fetch_zone(name, 0);
    if (!z) {
        z = fetch_zone(name, 1);
        newzone++;
    } else {
        zone_remove_records(z, -1);
    }
    if (dsname)
        strcpy(z->datasource, dsname);
    else
        strcpy(z->datasource, "unknown");
    z->last_reload = time(NULL);
    int nrrec = 0;
    do {
    } while (parse_axfr_msg(fd, name, &nrrec) == 0);

    close(fd);
    
    if (nrrec == 0 && newzone) {
        dnstree_remove_zone(z);
    }

    return nrrec > 0 ? 1 : 0;
}

int datasource_axfr_finish (struct datasource *ds, void *arg) {
	free(ds);

	return 1;
}

struct datasource datasource_axfr = {
    .driver = "axfr",
    .zoneload = datasource_axfr_fetch_zones,
    .finish = datasource_axfr_finish
};

