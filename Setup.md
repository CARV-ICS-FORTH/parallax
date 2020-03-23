# Kreon

This document focuses on setting up a development environment for the
distributed of Kreon on a local machine.

## Set up Development Environment

Kreon uses RDMA for all network communication, which requires support from the
network interface to run. A software implementation (soft-RoCE) exists and can
run on all network interfaces.

### Enabling soft-RoCE
soft-RoCE is part of the mainline Linux kernel versions since version 4.9
through the `rdma_rxe` kernel module. To enable it for a network adapter the
following steps are required:

#### Install dependencies
The `ibverbs-utils` and `rdma-core` packages are required to enable soft-RoCE.
These packages should be in most distirbutions' repositories

##### Installing Dependencies on Ubuntu 18.04 LTS
Run the following command with superuser privileges:
```
apt install ibverbs-utils rdma-core perftest
```

#### Enable soft-RoCE
To enable soft-RoCE on a network command run the following commands with
superuser privileges:
```
rxe_cfg start
rxe_cfg add eth_interface
```
where `eth_interface` is the name of an ethernet network adapter interface. To
view available network adapters run `ip a`.

*Warning: The command `rxe_cfg start` has to be run at every boot to use RDMA.*

#### Verify soft-RoCE is working
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

## Running Kreon

### Start a Zookeeper Server

1. Download and untar Zookeeper 3.6.0 using the following command
    ````
    wget https://downloads.apache.org/zookeeper/zookeeper-3.6.0/apache-zookeeper-3.6.0-bin.tar.gz
    tar xf apache-zookeeper-3.6.0-bin.tar.gz
    ````
2. `cd apache-zookeeper-3.6.0-bin`

3. Use the sample configuration by running the following commands through
    Zookeeper's root directory
    ````
    cp conf/zoo_sample.cfg conf/zoo.cfg
    ````

4. Start the Zookeeper Server
    ````
    ./bin/zkServer.sh start
    ````

### Start a Kreon Server
<!-- FIXME Mention kreon_server/conf.h:RDMA_IP_FILTER and zookeeper_host_port -->

Follow these steps, while in project's root directory:

1. Set the define RDMA_IP_FILTER in kreon_server/conf.h to the prefix of your
   RDMA device (eg. "192.168.122." for the device 192.168.122.105). Recompile
   for the change to take effect.

2. Initialize a file device
    ````
    fallocate --length 4G /tmp/kreon-disk.dat
    ./scripts/mkfs.eutropia.single.sh /tmp/kreon-disk.dat 1 1
    ````

3. Start the server
    ````
    ./build/kreon_server/kreon_server 6060 /tmp/kreon-disk.dat 4 0 1
    ````

4. Create a Kreon region (will include all possible keys)
    ````
    ./scripts/create_region.sh
    ````

### Test Functionality Using YCSB

````
cd build/YCSB-CXX
cp -r ../../ansible/ycsb_execution_plans .
./ycsb-kreon -threads 1 -e ycsb_execution_plans/execution_plan_la.txt
````