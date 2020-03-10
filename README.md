# Kreon

## Build Dependencies
To build Kreon, the following libraries have to be installed on your system:
* `libnuma` - 
* `libibverbs` - Infiniband verbs
* `librdmacm` - RDMA Connection Manager 
* `libzookeeper_mt` Zookeeper client bindings for C

Additionally, Kreon uses cmake for its build system and the gcc and g++
compilers for its compilation.

### Installing Dependencies on Ubuntu 18.04 LTS
Run the following command with superuser privileges:
```
# apt install libnuma-dev libibverbs-dev librdmacm-dev libzookeeper-mt-dev
```

For the build tools and compiler:
```
# apt install cmake build-essential
```

## Building Kreon
From the project's root folder, run the following commands:
```
cmake .
make
```

## Running Kreon
Kreon uses RDMA for all network communication, which requires support from the
network interface to run. A software implementation (soft-RoCE) exists and can
run on all network interfaces.

### Enabling soft-RoCE
soft-RoCE is part of the mainline Linux kernel versions since version 4.9
through the `rdma_rxe` kernel module. To enable it for a network adapter the
following steps are required:

#### 1. Install dependencies
The `ibverbs-utils` and `rdma-core` packages are required to enable soft-RoCE.
These packages should be in most distirbutions' repositories

##### Installing Dependencies on Ubuntu 18.04 LTS
Run the following command form a terminal with root access (or use sudo):
```
# apt install ibverbs-utils rdma-core perftest
```

##### Enable soft-RoCE
To enable soft-RoCE on a network command run the following commands with
superuser privileges:
```
rxe_cfg start
rxe_cfg add eth_interface
```
where `eth_interface` is the name of an ethernet network adapter interface. To
view available network adapters run `ip a`.

The command `rxe_cfg start` has to be run at every boot to use RDMA features.

##### Verify soft-RoCE is working
To verify that soft-RoCE is working, we can run a simple RDMA Write throuhgput
benchmark.

First, open two shells, one to act as the server and one to act as the client.
Then run the following commands:
* On the server: `ib_write_bw`
* On the client: `ib_write_bw eth_interface_ip`, where `eth_interface_ip` is
the IP address of a soft-RoCE enabled ethernet interface.

Example output:
* Server process:
```
************************************
* Waiting for client to connect... *
************************************
---------------------------------------------------------------------------------------
                    RDMA_Write BW Test
 Dual-port       : OFF		Device         : rxe0
 Number of qps   : 1		Transport type : IB
 Connection type : RC		Using SRQ      : OFF
 CQ Moderation   : 100
 Mtu             : 1024[B]
 Link type       : Ethernet
 GID index       : 1
 Max inline data : 0[B]
 rdma_cm QPs	 : OFF
 Data ex. method : Ethernet
---------------------------------------------------------------------------------------
 local address: LID 0000 QPN 0x0011 PSN 0x3341fd RKey 0x000204 VAddr 0x007f7e1b8fa000
 GID: 00:00:00:00:00:00:00:00:00:00:255:255:192:168:122:205
 remote address: LID 0000 QPN 0x0012 PSN 0xbfbac5 RKey 0x000308 VAddr 0x007f70f5843000
 GID: 00:00:00:00:00:00:00:00:00:00:255:255:192:168:122:205
---------------------------------------------------------------------------------------
 #bytes     #iterations    BW peak[MB/sec]    BW average[MB/sec]   MsgRate[Mpps]
 65536      5000             847.44             827.84 		   0.013245
---------------------------------------------------------------------------------------
```

* Client process:
```
---------------------------------------------------------------------------------------
                    RDMA_Write BW Test
 Dual-port       : OFF		Device         : rxe0
 Number of qps   : 1		Transport type : IB
 Connection type : RC		Using SRQ      : OFF
 TX depth        : 128
 CQ Moderation   : 100
 Mtu             : 1024[B]
 Link type       : Ethernet
 GID index       : 1
 Max inline data : 0[B]
 rdma_cm QPs	 : OFF
 Data ex. method : Ethernet
---------------------------------------------------------------------------------------
 local address: LID 0000 QPN 0x0012 PSN 0xbfbac5 RKey 0x000308 VAddr 0x007f70f5843000
 GID: 00:00:00:00:00:00:00:00:00:00:255:255:192:168:122:205
 remote address: LID 0000 QPN 0x0011 PSN 0x3341fd RKey 0x000204 VAddr 0x007f7e1b8fa000
 GID: 00:00:00:00:00:00:00:00:00:00:255:255:192:168:122:205
---------------------------------------------------------------------------------------
 #bytes     #iterations    BW peak[MB/sec]    BW average[MB/sec]   MsgRate[Mpps]
 65536      5000             847.44             827.84 		   0.013245
---------------------------------------------------------------------------------------
```
