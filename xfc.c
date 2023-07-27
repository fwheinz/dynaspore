#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>

#include <mysql.h>

#include "xfc.h"

void usage (void) {
	fprintf(stderr, "Usage: xfc [-t <NR>] [-i <IP>]\n"
			"        -i <IP>    Listen on this IP (mandatory, multiple)\n"
			"        -t <NR>    Number of threads (optional, default: 4)\n"
			"        -H <DBHOST>    Database host\n"
			"        -U <DBUSER>    Database user\n"
			"        -P <DBPASSWD>  Database password\n"
			"        -D <DBNAME>    Database name\n"
			"        -b             Benchmark mode\n"
			"\n"
	       );
	exit(EXIT_FAILURE);
}

char *getname (void) {
	return "g.h.i.j.k.l.m.n.o.subdel3.ichwillne.info";
	return "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.subdel3.ichwillne.info";
}

void benchmarkmode (void) {
	unsigned char pkt[4096], *ptr;
	unsigned long long send = 0, recv = 0;
	int count = 40000001, i;
	struct timeval s, e;


	gettimeofday(&s, NULL);
	ptr = name2lbl(pkt+12, getname());
	for (i = 0; i < count; i++) {
		memcpy(pkt, 
				"\x12\x34" // ID
				"\x00\x00" // Flags
				"\x00\x01" // QDCOUNT
				"\x00\x00" // ANCOUNT
				"\x00\x00" // NSCOUNT
				"\x00\x00" // ARCOUNT
				, 12
		      );
		memcpy(ptr,
				"\x00\x01" // TYPE  A
				"\x00\x01" // CLASS IN
				, 4
		      );
		int len = ptr-pkt+4;
		send += len;
		recv += answer_packet(pkt, len, sizeof(pkt), NULL, NULL);
	}
	gettimeofday(&e, NULL);

	int sec = e.tv_sec - s.tv_sec;
	int usec = e.tv_usec - s.tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	int msec = sec*1000+usec/1000;

	printf("Elapsed: %d msec, Sent: %llu, Recv: %llu\n", msec, send, recv);
	printf("TX: %llu MBit/s   RX: %llu MBit/s\n", send/msec/125, recv/msec/125);

	exit(EXIT_FAILURE);
}

int main (int argc, char **argv) {
	int opt, i;
	int threads = 4, bench = 0;
	char *host = "localhost", *user = "root", *password = "", *dbname = "dns";

	while ((opt = getopt(argc, argv, "bH:U:P:D:i:t:h")) > 0) {
		switch (opt) {
			case 'b':
				bench++;
				break;
			case 'i':
//				open_socket(optarg);
				printf("Listening on %s\n", optarg);
				break;
			case 't':
				threads = atoi(optarg);
				break;
			case 'H':
				host = optarg;
				break;
			case 'U':
				user = optarg;
				break;
			case 'P':
				password = optarg;
				break;
			case 'D':
				dbname = optarg;
				break;
			case 'h':
				usage();
				break;
		}
	}

	printf("Configuring records...\n");
	configure_records(host, user, password, dbname);
	configure_dnssec(host, user, password, dbname);
	exit(1);
	if (bench)
		benchmarkmode();
	printf("Starting threads: "); fflush(stdout);
	for (i = 0; i < threads-1; i++) {
		pthread_t p;
//		pthread_create(&p, NULL, packet_loop, NULL);
		printf("%d ", i); fflush(stdout);
		fflush(stdout);
	}
	printf("\n");
	printf("Waiting for packets...\n");
	sleep(100);
	
	exit(EXIT_SUCCESS);
}

