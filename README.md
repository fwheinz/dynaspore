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

apt install dpdk dpdk-kmods-dkms libdpdk-dev liblua5.3-dev lua-filesystem lua-cgi libssl-dev libmariadb-dev-compat php-curl php-ldap

For lua-cgi, symlinks have to be created:
ln -s /usr/share/lua/5.1/cgilua /usr/share/lua/5.3/cgilua
ln -s /usr/share/lua/5.1/cgilua.lua /usr/share/lua/5.3/cgilua.lua

System:
- DPDK enabled 10G network device
- 20 x 1GB hugepages 
- iommu deactivated (kernel-commandline: iommu=off)

Add kernel command line options (e.g. in /etc/default/grub): "hugepagesz=1G hugepages=20 iommu=off"
Create directory /hugepages-1G
Add to /etc/fstab: "none /hugepages-1G hugetlbfs pagesize=1G 0 0"
Add to /etc/modules: "igb_uio" for compatible intel cards

Check interfaces: "dpdk-devbind.py -s"
Bind interface at PCI address $ADDR to igb_uio module: "dpdk-devbind.py -b igb_uio $ADDR"
For example: dpdk-devbind.py -b igb_uio 09:00.0



Tested with: Debian 12 Bookworm, Ubuntu 22.04

Compile and start with: *make run*




