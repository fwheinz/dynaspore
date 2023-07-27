# Dynaspore

Experimental DNS server based on DPDK

**Important files:**

- process.c - Look up query results in the DNS database tree
- buildtree.c - Build the in-memory DNS database tree

**Requirements:**

Libraries:
- lua5.3
- libmysqlclient
- dpdk
- openssl (libcrypto, libssl)

System:
- DPDK enabled 10G network device
- 20 x 1GB hugepages
- iommu deactivated (kernel-commandline)

Tested with: Debian 11.7 Bullseye

Compile and start with: *make run*




