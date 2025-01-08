# Parallax Portals Server Overview

Multiple clients can access Parallax through the Parallax server. The current
implementation uses Portals4 API from BullSequana (Portails4).

## Configuring the Server-Client NID,IP
To run portals_parallax_server and the tests you need to
export the ip (of the NIC) and nids (last NIC ip number) that
will be used by the server and the clients in each terminal.

To specify the `NID,IP`, use the following command in your terminal e.g:

```bash
export SERVER_NID=120 CLIENT_NID=121 NET_IP=192.168.4.121
``````

## How to run Server
Parallax portals server starts with the following command:

```bash
./portals_parallax_server -t <num of server threads> \
-p <port to listen for new connections> \
-f <file to save Parallax data> \
-L0 <L0 size in MB> \
-GF <growth factor between LSM levels> \
-pf <optional: erase all data on startup>
``````
## Parallax Portals Container
Parallax Portals includes a dockerfile with the all the libraries needed in the image to be used for tests.
Located under ```parallax/portals_container/```.

Change the run_build.sh script variables:
```
IMAGE_NAME="bull_portals"
DOCKERFILE="DockerFile"
HOST_DIR="/tmp/par.dat" <This file will be mounted from host to the container and used for the db>
CONTAINER_DIR="/app/par.dat"
PARALLAX_DIR="../../parallax"
```

and run :

```./run_build.sh```

The container will have a copy of parallax simply go in the parallax folder and build parallax with portals. Inside the container
there is file located at **/app/useful_commands** where there are commands for building parallax and running tests.

## Statistics scripts
There are various scripts that can be used to calculate statistics for the server-client.
The scripts can be used with and without the container.
### server scripts

**parallax/build/lib/profile_flamegraph.sh** is used to profile the performance of portals_parallax_server using the perf tool and generate a Flamegraph to visualize the stack traces during its execution. It also logs CPU utilization data during the profiling.

Change these script variables accordingly:

```
SERVER_ARGS=(-t 1 -f /app/par.dat -L0 4 -GF 4 -pf) <server arguments>
OUTPUT_DIR="./profile_results" <output dir>
```

**parallax/build/lib/run_portals_srv.sh** is used to monitor the performance and system metrics during the execution of the portals_parallax_server. It records network, disk, and CPU statistics, calculates network throughput, and organizes the results in a directory.

Change these script variables accordingly:

```
NETWORK_INTERFACE="ens10d1.905" <NIC to gather stats from>
NUM_THREAD=32 <server number of threads>
```

**Run the scripts and when the tests are finished kill with ctrl+C**

### client scripts
**parallax/build/YCSB-CXX/run-ycsb-portals.sh** is used to monitor and profile the performance of ycsb-net that benchmarks database operations across multiple processes. It logs network, disk, and CPU statistics, and calculates network throughput after the execution.

Change these script variables accordingly:

```
NETWORK_INTERFACE="ens10d1.905" <NIC to gather stats from>
NUM_PROCESSES=32 <number of client processes>
```

**parallax/build/YCSB-CXX/calculate_throughput.sh** is used after the ycsb tests are completed to compute the total operations per second of the database of all clients. It extracts throughput values from ops.txt files and sums them up to calculate a final total throughput.

## Folder stucture

server folder contains all the server related code whereas par_net contain all
the client related code. The implementation the Parallax network library that
uses par_net classes is at <PARALLAX_HOME_FOLDER>/lib/api/parallax_client_lib.c

## Running YCSB Against Parallax portals Server

To run YCSB against the portals Parallax server, use the ycsb-net executable.
This executable is specifically designed for interfacing with the Parallax
server over TCP/IP or Portals, ensuring optimal performance and compatibility.

If parallax was built with TCP/IP Set in <PARALLAX_HOME_FOLDER>options.yml the property
parallax_server: <server_hostname>:<server_port>, where Parallax server runs.

## For Developers

You can consult the [Parallax_Portals](docs/parallax_portals.md) file, which explains how the Portals server is structured.

# Parallax Server Overview

Multiple clients can access Parallax through the Parallax server. The current
implementation uses TCP/IP sockets with a custom wire protocol. Parallax server
starts with the following command:


```bash
./parallax_server -t <num of server threads> \
-b <IP address to bind to> \
-p <port to listen for new connections> \
-f <file to save Parallax data> \
-L0 <L0 size in MB> \
-GF <growth factor between LSM levels> \
-pf <optional: erase all data on startup>
``````

To use this feature, applications must use the public API of Parallax, with the
key difference being that they should link against parallax_client_lib
instead of parallax.

## Folder stucture

server folder contains all the server related code whereas par_net contain all
the client related code. The implementation the Parallax network library that
uses par_net classes is at <PARALLAX_HOME_FOLDER>/lib/api/parallax_client_lib.c


## Running YCSB Against Parallax TCP/IP Server

To run YCSB against the TCP/IP Parallax server, use the ycsb_tcp executable.
This executable is specifically designed for interfacing with the Parallax
server over TCP/IP, ensuring optimal performance and compatibility.

Set in <PARALLAX_HOME_FOLDER>options.yml the property
parallax_server: <server_hostname>:<server_port>, where Parallax server runs.
