Build Configuration
--------------------------------------------------------------------------------
CMake version 3.0.2 or greater is required to build this project.
On CentOS 7, you can install it from the epel repository with the command:

	sudo yum -y install cmake3

It can then be invoked with the cmake3 command.

Compilation is done using the clang compiler, provided by the clang package in
most Linux distributions.
To configure the build and compile on Centos 7 use :

	mkdir build
	cd build
	cmake3 ..
	make

Build Configuration Parameters
--------------------------------------------------------------------------------
The CMake scripts provided support two build configurations; "Release" and
"Debug". The Debug configuration enables the "-g" option during compilation to
allow debugging. The build configuration can be defined as a parameter to the
cmake call as follows:

	cmake3 .. -DCMAKE_BUILD_TYPE="Debug|Release" .

The default build configuration is "Debug".

The "Release" build disables warnings and enables optimizations.

Build Targets
--------------------------------------------------------------------------------
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

Static Analyzer
--------------------------------------------------------------------------------
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

Clang Format
--------------------------------------------------------------------------------
Install the clang-format for Centos with the commands below:

Install CentOS SCLo RH repository:

	yum install centos-release-scl-rh

Install llvm-toolset-7-git-clang-format rpm package:

	yum install llvm-toolset-7-git-clang-format

After successfully running the commands above clang-format should be installed at:

	/opt/rh/llvm-toolset-7/root/usr/bin

To format your code run in the build directory:

	make format

Generating compile_commands.json for Single Node Kreon
--------------------------------------------------------------------------------
Install compdb for header awareness in compile_commands.json:

	pip install --user git+https://github.com/Sarcasm/compdb.git#egg=compdb

After running cmake .. in the build directory run:

	cd ..
	compdb -p build/ list > compile_commands.json
	mv compile_commands.json build
	cd kreon
	ln -sf ../build/compile_commands.json

Pre commit hooks using pre-commit
--------------------------------------------------------------------------------
To install pre-commit:

	pip install pre-commit --user
	pre-commit --version
	2.2.0

If the above command does not print 2.2.0 you need to update python using:

	sudo yum update python3

Then try upgrading pre-commit:

	pip install -U pre-commit --user

To install pre-commit hooks:

	cd HEutropia
	pre-commit install

If everything worked as it should then the following message should be printed:
	pre-commit installed at .git/hooks/pre-commit

If you want to run a specific hook with a specific file run:

	pre-commit run hook-id --files filename
	pre-commit run cmake-format --files CMakeLists.txt
