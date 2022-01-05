# Parallax
Parallax is an LSM-based persistent key-value store designed for flash storage devices (SSDs, NVMe). Parallax reduces I/O amplification and increases CPU efficiency using the following mechanism. It categorizes key-value (KV) pairs into three size-based categories: Small, Medium, and Large. Then it applies a different policy for each category. It stores Small KV pairs inside the LSM levels (as RocksDB). It always performs key-value separation for KV pairs (as BlobDB), writing them in a value log, and it uses a garbage collection (GC) mechanism for the value log. For medium KV pairs, it uses a hybrid policy: It performs KV separation up to the semi-last levels and then stores them in place to bulk-free space without using GC.

![Parallax](https://i.imgur.com/7XYSGwW.jpg)

You can find more details in the paper:

Giorgos Xanthakis, Giorgos Saloustros, Nikos Batsaras, Anastasios Papagiannis, and Angelos Bilas. 2021. Parallax: Hybrid Key-Value Placement in LSM-based Key-Value Stores. In Proceedings of the ACM Symposium on Cloud Computing (SoCC '21). Association for Computing Machinery, New York, NY, USA, 305–318. DOI:https://doi.org/10.1145/3472883.3487012

# Building Parallax


### Installing Dependencies on Ubuntu 18.04 LTS

Parallax requires CMake version >= 3.11.0. On Ubuntu, you need to add the
following repository to get the latest stable version of CMake:

	wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | sudo apt-key add -
	sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
	sudo apt update

Run the following command with superuser privileges:

	sudo apt install libnuma-dev

For the build tools and compiler:

	sudo apt install cmake build-essential

### Installing Depedencies on Centos/RHEL 7

Parallax requires CMake version >= 3.11.0. On Centos/RHEL this is supplied from the
EPEL repository and can be installed with:

	sudo yum install cmake3 kernel-devel gcc-c++ numactl-devel boost-devel

## Build Configuration

Compilation is done using the gcc/clang compilers, provided by the gcc/clang packages in
most Linux distributions. To configure Parallax's build systems and build it run
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

* build/lib/libparallax.a/so - Parallax library
* build/YCSB-CXX/ycsb-edb - Standalone Parallax YCSB benchmark
* build/tests/ - Tests for Parallax
## Build Package

You can install Parallax in your standard path using cmake.

Run `cpack -G "RPM"` inside the `build` folder to create an RPM file.

Run `cpack -G "DEB"` inside the `build` folder to create a DEB file.

Run `sudo rpm -Uvh parallax.rpm` using the rpm file produced from the `cpack` command.

Run `sudo dpkg -i parallax.deb` using the deb filed produced from the `cpack` command.

Run `make install` inside the `build` folder to install Parallax without producing an RPM or DEB file.

Run `make uninstall` inside the `build` folder to remove files installed by `make install`. (Directories are not deleted)

In case you want to link statically without using cmake check `scripts/pack-staticlib.py` to create a single binary called `libparallax2.a` and link with it.
