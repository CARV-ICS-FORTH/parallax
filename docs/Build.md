# Building Parallax


### Installing Dependencies on Ubuntu 22.04 LTS


Run the following command with superuser privileges:

	sudo apt install cmake build-essential libnuma-dev libboost-all-dev

### Installing Depedencies on Centos/RHEL 7

Parallax requires CMake version >= 3.11.0. On Centos/RHEL this is supplied from the
EPEL repository and can be installed with:

	sudo yum install cmake3 kernel-devel gcc-c++ numactl-devel boost-devel

## Build Configuration

Compilation is done using the gcc/clang compilers, provided by the gcc/clang packages in
most Linux distributions. To configure Parallax's build systems and build it run
the commands:

	cmake --workflow --preset debug
or 

	cmake --workflow --preset release

The "Release" build disables warnings and enables optimizations.
On Centos/RHEL 7, replace the `cmake` command with the `cmake3` command supplied
from the EPEL package of the same name.


## Build Targets

* build/{debug,release}/lib/libparallax.a/so - Parallax library
* build/{debug,release}/YCSB-CXX/ycsb-edb - Standalone Parallax YCSB benchmark
* build/{debug,release}/tests/ - Tests for Parallax

## Build Package

You can install Parallax in your standard path using make.

Run `make install` inside the `build/release` folder to install Parallax without producing an RPM or DEB file.

Run `make uninstall` inside the `build` folder to remove files installed by `make install`. (Directories are not deleted)

Also, you can create an RPM or DEB file using CPack.

Run `cpack -G "RPM"` inside the `build` folder to create an RPM file.

Run `cpack -G "DEB"` inside the `build` folder to create a DEB file.

Run `sudo rpm -Uvh parallax.rpm` using the rpm file produced from the `cpack` command.

Run `sudo dpkg -i parallax.deb` using the deb filed produced from the `cpack` command.



In case you want to link statically without using cmake check `scripts/pack-staticlib.py` to create a single binary called `libparallax2.a` and link with it.
