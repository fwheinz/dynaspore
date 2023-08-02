# Dynaspore

Experimental DNS server based on DPDK

**Important files:**

- process.c - Look up query results in the DNS database tree
- buildtree.c - Build the in-memory DNS database tree

**Requirements:**

Libraries:
- lua5.3
- libmysqlclient
- dpdk (>=21)
- openssl (libcrypto, libssl)

Packages for Debian Bookworm:

apt install libdpdk-dev liblua5.3-dev libssl-dev libcrypto-dev libmariadb-dev-compat

System:
- DPDK enabled 10G network device
- 20 x 1GB hugepages
- iommu deactivated (kernel-commandline: iommu=off)

Tested with: Debian 12 Bookworm, Ubuntu 22.04

Compile and start with: *make run*




