# Building Kreon

## Build Dependencies

To build Kreon, the following libraries have to be installed on your system:
* `libnuma` - Allocations with NUMA policy
* `libibverbs` - Infiniband verbs
* `librdmacm` - RDMA Connection Manager
* `libzookeeper_mt` - Zookeeper client bindings for C

For Mellanox cards, the Infiniband and RDMA libraries are included in the software package provided by the vendor.
Additionally, Kreon uses cmake for its build system and the gcc and g++ compilers for its compilation.

### Installing Dependencies on Ubuntu 18.04 LTS

Kreon requires CMake version >= 3.11.0. On Ubuntu, you need to add the
following repository to get the latest stable version of CMake:

	wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | sudo apt-key add -
	sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
	sudo apt update

Run the following command with superuser privileges:

	sudo apt install libnuma-dev libibverbs-dev librdmacm-dev libzookeeper-mt-dev

For the build tools and compiler:

	sudo apt install cmake build-essential

### Installing Depedencies on Centos/RHEL 7

Kreon requires CMake version >= 3.11.0. On Centos/RHEL this is supplied from the
EPEL repository and can be installed with:

	sudo yum install cmake3 kernel-devel gcc-c++


#### Dependencies for Single Node Kreon

	sudo yum install numactl-devel boost-devel

#### Additional Dependencies for Distributed Kreon

For RDMA:

	sudo yum install libibverbs-devel librdmacm-devel

You also need to install ZooKeeper. Ready-made packages are available from
Cloudera.
1. Add Cloudera's Centos 7 repository as described
[here](https://docs.cloudera.com/documentation/enterprise/5-14-x/topics/cdh_ig_cdh5_install.html)
2. Install the Zookeeper C binding for clients:

	    yum install zookeeper-native

## Build Configuration

Compilation is done using the clang compiler, provided by the clang package in
most Linux distributions. To configure Kreon's build systems and build it run
the commands:

	mkdir build
	cd build
	cmake ..
	make

On Centos/RHEL 7, replace the `cmake` command with the `cmake3` command supplied
from the EPEL package of the same name.

## Build Configuration Parameters

The CMake scripts provided support two build configurations; "Release" and
"Debug". The Debug configuration enables the "-g" option during compilation to
allow debugging. The build configuration can be defined as a parameter to the
cmake call as follows:

	cmake3 .. -DCMAKE_BUILD_TYPE="Debug|Release" .

The default build configuration is "Debug".

The "Release" build disables warnings and enables optimizations.

## Build Targets

* build/kreon/libkreon.a - Kreon library (standalone version)
* build/kreon/libkreonr.a - Kreon library with replication enabled
	(distributed version)
* build/TuRDMA/turdma.a - RDMA library used for applications and servers in the
	distributed version
* build/TucanaServer/libtuclient.a - Client library for applications talking to
	a tucanaserver
* build/TucanaServer/tucanaserver - Server
* build/YCSB-CXX/ycsb-edb - Standalone kreon ycsb benchmark
* build/YCSB-CXX/ycsb-kreon - Distributed kreon ycsb benchmark

## Build Package

You can install Kreon in your standard path using cmake.

To enable packaging and installation support you need to define `KREON_BUILD_CPACK` when invoking cmake.

Run `make package` inside the `build` folder to create an RPM file.

Run `make install` inside the `build` folder to install the RPM file.

Run `make uninstall` inside the `build` folder to remove files installed by `make install`. (Directories are not deleted)

In case you want to link statically without using cmake check `scripts/pack-staticlib.py` to create a single binary called `libkreon2.a` and link with it.


# Static Analyzer

Install the clang static analyzer with the command:

	sudo pip install scan-build

Before running the analyzer, make sure to delete any object files and
executables from previous build by running in the root of the repository:

	rm -r build

Then generate a report using:

	scan-build --intercept-first make

The last line of the above command's output will mention the folder where the
newly created report resides in. For example:

	"scan-build: Run 'scan-view /tmp/scan-build-2018-09-05-16-21-31-978968-9HK0UO'
	to examine bug reports."

To view the report you can run the above command, assuming you have a graphical
environment or just copy the folder mentioned to a computer that does and open
the index.html file in that folder.

# Development in cluster

For development in the cluster source the script to get the latest tools:

	source kreon/scripts/devel-tools/env-vars.sh

# Install shfmt

To install shfmt run the command below in your shell:

	GO111MODULE=on go get mvdan.cc/sh/v3/cmd/shfmt


# Generating compile_commands.json for Single Node Kreon

Install compdb for header awareness in compile_commands.json:

	pip install --user git+https://github.com/Sarcasm/compdb.git#egg=compdb

After running cmake .. in the build directory run:

	cd ..
	compdb -p build/ list > compile_commands.json
	mv compile_commands.json build
	cd kreon
	ln -sf ../build/compile_commands.json

# Pre commit hooks using pre-commit

To install pre-commit:

	pip install pre-commit --user
	pre-commit --version
	2.2.0

If the above command does not print 2.2.0 you need to update python using:

	sudo yum update python3

Then try upgrading pre-commit:

	pip install -U pre-commit --user

To install pre-commit hooks:

	cd kreon
	pre-commit install
    pre-commit install --hook-type commit-msg

If everything worked as it should then the following message should be printed:
	pre-commit installed at .git/hooks/pre-commit

If you want to run a specific hook with a specific file run:

	pre-commit run hook-id --files filename
	pre-commit run cmake-format --files CMakeLists.txt

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

Git commit message template
--------------------------------------------------------------------------------

	git config commit.template .git-commit-template
