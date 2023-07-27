CC=gcc

LIBS=mysqlclient libdpdk lua5.3 libcrypto libssl

WARN=-Wall -Wno-address-of-packed-member -Wno-pointer-sign -Wno-sign-compare -Wno-unused-variable
CFLAGS += $$(pkg-config --cflags $(LIBS)) $(WARN) -O3 -march=native -mtune=native -fno-strict-aliasing -fomit-frame-pointer -flto -falign-loops=8 -ggdb
LDFLAGS += -lpthread $$(pkg-config --libs $(LIBS))

OBJS := main.o util.o buildtree.o process.o base64.o dnssec.o control.o zones.o lua.o datasource.o datasource_mysql.o datasource_zonefile.o datasource_axfr.o records.o benchmark.o

all: dynaspore

dynaspore: char2id.h $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

char2id.h: gentable
	./gentable $(BO) > char2id.h

gentable: gentable.o
	$(CC) gentable.o -o gentable

clean:
	rm -f $(OBJS) gentable.o char2id.h dynaspore

run: dynaspore
	./dynaspore -c6db -n4 -- -p1

debug: dynaspore
	gdb -ex run --args ./dynaspore -c6db -n4 -- -p1
