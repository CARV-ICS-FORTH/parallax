# InfiniBand Parallax Server

This project provides an InfiniBand-based network server implementation for Parallax.

## Server Side

At startup, the server initializes all required InfiniBand RDMA resources (protection domain, completion queues, queue pairs, memory regions, etc.).
Unlike TCP/IP or Portals (existing Parallax server implementations), InfiniBand requires an explicit connection establishment (handshake) between server and client before any messages can be exchanged. To handle this, the server introduces a dedicated Communication Manager thread responsible for accepting and establishing client connections (this thread runs separately from the workers). 

Once connections are established, the server relies on a pool of network worker threads (adapted from the Portals implementation). These workers continuously poll for incoming client requests, dequeue them from a [custom queue](https://github.com/Thodorhs/sim-universal-construction), and execute them. Requests are inserted into this queue by the server after receiving and parsing the client’s request.

### Worker Threads
Worker threads are spawned during server startup. Each worker:
- Polls the completion queue for new requests.
- Dequeues requests from the custom queue.
- Executes the requested operation.
- Sends a reply header to the client.

(Note: workers are reused from the Portals implementation. For more details, see [parallax_portals.md](https://carvgit.ics.forth.gr/storage/parallax/-/blob/parallax_infiniband/docs/parallax_portals.md?ref_type=heads#worker-thread))
<br />
<br /> 

**IMPORTANT**: Sync, Delete, and Scan operations are NOT implemented.

## Client Side

The client interacts with the server through the Parallax API. The RDMA details are abstracted away, so the client only calls the familiar operations (open, close, put, get).
Before issuing requests, the client library (parallax_client_lib.c) sets up the InfiniBand connection during the open call. For each request, it prepares a network header (par_net_header) containing:
- Virtual address of the data (if not inline / large send buffer).
- Size of the data.
- Remote key (rkey) for RDMA access.
- Request ID (to match responses).
- Opcode of the requested operation.
- A flag indicating whether the data is inline or not.
This header gives the server all necessary information to execute the request.

### Sending Requests

- A receive buffer is allocated and registered with ibv_reg_mr so the client can receive responses.
- A send buffer is allocated and registered with ibv_reg_mr so the server can access it.
- Depending on the send buffer size:
    1. Small send buffer: Data is sent inline; no virtual address, size, or rkey is needed.
    2. Large send buffer: The client provides flags, the data’s virtual address, size, and rkey. The memory region containing the data (e.g., for put) is also registered, so the server can later perform an RDMA read.

## Server-Side Request Execution

When the server receives a request:
- Small send buffer: The client indicates the data is inline. The server reads the data directly from the request.
- Large send buffer: The client indicates the data is not inline and provides the virtual address and rkey. The server then performs an RDMA read to fetch the data directly from the client’s memory.

For large put operations, the server uses a pool of pre-registered RDMA buffers to avoid repeatedly registering memory regions (which is expensive). A mechanism ensures buffers are reused efficiently, and if all buffers are occupied, workers will wait until one becomes available.

## Build Instructions

To enable the InfiniBand server, set:
`-DUSE_INFINIBAND=ON`

The server also requires the custom queue (build instructions [here](https://carvgit.ics.forth.gr/storage/parallax/-/blob/parallax_infiniband/docs/Build.md?ref_type=heads#2-build-sim-universal-construction)) to be pre-built.
Pass the following flags to CMake:
```
-DQUEUE_LIB=/path/to/lib
-DQUEUE_INCLUDE_DIR=/path/to/includes
```

Enable shared libraries with `-DBUILD_SHARED_LIBS=ON`
so that the client program can use the library installed via make install.

Finally, set the segment size flag (required for large KVs):
`-DSEGMENT_SIZE=134217728`

## Run Instructions

Start the server with:

```
./infiniband_parallax_server \
  -t <thread-num> \
  -b <if-address> \
  -p <port> \
  -f <path> \
  -L0 <size-in-MB> \
  -GF <growth-factor>
```

**Note**: if-address and port depend on each machine’s configuration. Adjust accordingly before running.
