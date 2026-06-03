# InfiniBand Parallax Server

An InfiniBand-based network server implementation for the Parallax Key-Value Store.

## Server Side Architecture

At startup, the server initializes all required InfiniBand RDMA resources, including protection domains (PD), completion queues (CQ), queue pairs (QP), and memory regions (MR).  
Unlike TCP/IP or Portals (existing Parallax server implementations), InfiniBand requires explicit connection establishment (a handshake) between the server and client before any messages can be exchanged. To handle this, the server utilizes a dedicated Communication Manager thread responsible for listening, accepting, and establishing incoming client connections.  
Once connections are established, the server maintains a pool of worker threads. Every worker has its own shared receive queue (SRQ) and wakes up via hardware interrupts when receiving a request.

### Server Handle Worker Threads

Worker threads are spawned during server startup. Each worker is responsible for:

1. Polling its completion queue (CQ) for new network requests.
2. Executing the requested operation.
3. Sending a reply header back to the client.

**Note:** `SCAN` operations, `par_sync`, `par_delete`, and `par_exists` are **NOT** implemented.

---

## Client Side Architecture

The client interacts with the server exclusively through the standard Parallax API. The RDMA networking details are entirely abstracted away, allowing the client to safely call familiar operations (open, close, put, get, write_blob, read_blob).  
Before issuing data requests, the client library (`parallax_client_lib.c`) sets up the InfiniBand connection during the open call.

For each request, the client prepares a network header (par_net_header) containing:

- Virtual address of the data (if not sent inline).
- Size of the payload.
- Remote key (rkey) for RDMA access.
- Request ID (to match responses).
- Opcode of the requested operation.
- An inline_flag indicating whether the data fits in the message header.

### Sending Requests

To avoid the overhead of repeatedly registering memory regions, the client maintains a set of pre-registered buffers:

- Receive Pool: Allocated and registered via `ibv_reg_mr` to asynchronously catch server responses.
- Send Pool: Allocated and registered so the server can securely access client data.

Depending on the size of the payload, the client will route the request via two paths:

1. Small Payload (Inline): Data is sent directly inline within the request header. No virtual addresses, sizes, or rkeys are needed.
2. Large Payload (RDMA Read): The client provides the data's virtual address, size, and rkey. The memory region containing the data is registered, allowing the server to asynchronously pull the payload using a zero-copy RDMA Read operation.

---

## Large KV Blob Storage

To support exceptionally large Key-Value pairs without stalling Parallax's B-Tree compactions, we introduced a native Blob Storage feature.

Large payloads bypass the standard B-Tree index and are routed directly to the server's local file system via two new dedicated APIs: `write_blob` and `read_blob`.

Configuration:
You can specify the directory where these large blobs are stored on the server using the `-bd` (or `--blob_dir`) CLI flag. If omitted, the server will safely default to writing blobs to `/tmp`. Furthermore, if the format flag (`-pf`) is provided on startup, the server will automatically wipe out old blobs from the configured directory to prevent ghost data from filling the disk.

---

## Build Instructions

To build the project with the InfiniBand server enabled, you must pass specific flags to CMake.

Required CMake Flags:

- `-DNET=INFINIBAND` (Enables the IB Server/Client)
- `-DBUILD_SHARED_LIBS=ON` (Builds shared libraries so the client program can use the installed library)
- `-DKV_MAX_SIZE=ON` and `-DSEGMENT_SIZE=4194304`

```bash

cmake .. \
  -DCMAKE_BUILD_TYPE="Release" \
  -DCMAKE_C_FLAGS="-Wno-main" \
  -DNET=INFINIBAND \
  -DCMAKE_INSTALL_PREFIX=/usr/local/ \
  -DBUILD_SHARED_LIBS=ON \
  -DKV_MAX_SIZE=ON \
  -DSEGMENT_SIZE=4194304

make -j10
make install

```

### Client Polling vs Event Mode

By default, the client polls (spins) the CPU while waiting for a reply from the server. This yields the lowest possible latency and highest throughput.

Alternatively, you can compile the client in Event Mode by passing `-DUSE_IBV_CQ_EVENT=ON` to CMake. In this mode, the client thread sleeps and is only woken up via hardware interrupts when a response arrives.

---

## Run Instructions

Start the server with:

```bash
./infiniband_parallax_server \
  -t <thread-num> \
  -b <if-address> \
  -p <port> \
  -f <path-to-db> \
  -L0 <size-in-MB> \
  -GF <growth-factor> \
  -bd <blob-directory-path>

```

### Multiple Servers

The project supports running and addressing multiple servers in parallel. You can specify one or more `address:port` entries in your client-side `options.yml` configuration file:

- **Single server:**
  `parallax_server: 192.168.5.120:7471`
- **Multiple servers:**
  `parallax_server: 192.168.5.120:7471 192.168.5.120:7472 192.168.5.121:7471`

The client library will automatically establish connections to all listed servers and distribute requests seamlessly across the cluster.

**Note:** Ensure `if-address` and `port` bindings align with your specific cluster's subnet configuration before running.
