CC=gcc

LIBS=mysqlclient libdpdk lua5.3 libcrypto libssl ldap

WARN=-Wall -Wno-address-of-packed-member -Wno-deprecated-declarations
CFLAGS = $$(pkg-config --cflags $(LIBS)) $(WARN) -O4 -falign-loops=4 -march=native -mtune=native -ggdb -DLDAP_DEPRECATED
LDFLAGS = -lpthread $$(pkg-config --libs $(LIBS))

OBJS := main.o util.o buildtree.o process.o base64.o dnssec.o control.o zones.o lua.o datasource.o datasource_mysql.o datasource_zonefile.o datasource_ldap.o datasource_axfr.o records.o benchmark.o

all: dynaspore

dynaspore: char2id.h $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(OBJS): char2id.h

char2id.h: gentable
	./gentable $(BO) > char2id.h

gentable: gentable.o
	$(CC) $(LDFLAGS) gentable.o -o gentable

clean:
	rm -f $(OBJS) gentable gentable.o char2id.h dynaspore

run: dynaspore
	./dynaspore -c6db -n4 -- -p1

debug: dynaspore
	gdb -ex run --args ./dynaspore -c6db -n4 -- -p1
