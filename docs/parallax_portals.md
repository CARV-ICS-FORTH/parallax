# Parallax KV Store over Portals
This document explains how the Parallax Key-Value Store works over the Portals network protocol. First, it covers the basic background on Portals needed to understand the system. Then, it explains how the Portals Parallax server handles client requests and sends responses.

# Portals Background

- Portal Table
- Events and Event Queues
- Memory Descriptors
- Match Lists and Match List Entries

## Portal Table


- Portal index refers to a portal table entry.
- Each entry has three data structures
attached: an event queue , a priority list , and
an overflow list.
- Messages that arrive traverse list entries or
match list entries within a single portal table
index.


For portals server we use 1 portal table entry for the
receive buffers.


## Events and Event Queues

- Signal the end of a data transmission into or
out of a memory region.
- Hold acknowledgments for completed put
operations.
- Indicate when a list entry has been unlinked.


For the server we use 1 event queue both for send
and receive events.

## Memory Descriptors

- A memory descriptor describes a memory
region using a base address and length.
- PtlMDBind() function is used to create a
memory descriptor to be used by the initiator.
- PtlMDRelease() function releases the
internal resources associated with a memory
descriptor.

Memory descriptors are used by the portals server
to send replies to the client

## Match Lists and Match List Entries

- List entries identify a memory region.
- Adds match criteria to the basic memory
region description in the list entry(match bits).
- Matching list entries can be appended to
either the priority list or the overflow list
associated with a portal table entry.
- PTL_EVENT_AUTO_UNLINK when the buffer
space has been consumed.


For Portals server we use 5 match list entries for the
receive buffers attached to 1 portals table entry and
they match any request.

PTL_ME_MANAGE_LOCAL is used so the offset is
incremented by the length of the request locally
when messages arrive.

PTL_ME_NO_TRUNCATE is used so the length
provided in the incoming request cannot be reduced
to match the memory available in the region.

min_free is used with KV_MAX_SIZE so that when
length - local offset falls below this value, the match
list entry automatically unlinks.

## Matching flow
![matchflow](https://github.com/Thodorhs/pictures/blob/main/matchflow.jpg?raw=true)

## The whole picture
![wholepic](https://github.com/Thodorhs/pictures/blob/main/wholepic.jpg?raw=true)

# Portals Parallax Server

- Poller Thread
- Worker Thread
- Worker Request

## Poller Thread

- Poll event queue for events.
- Manage receive buffers.
- Manage receive buffer metadata (worker-poller counters) for safe unlink event.
- Manage send buffer memory.
- Schedule workers.
- Create and add request to worker queue.
- PTL_EVENT_PUT.
- PTL_EVENT_AUTO_UNLINK.
- PTL_EVENT_SEND.


## On event PTL_EVENT_PUT

- Schedule N threads, iterate worker
instance array choose one with less than
128 requests in queue.
- Notify worker after adding request in his
queue (sem_post).
- Increment poller counter associated with
buffer.


## On event PTL_EVENT_AUTO_UNLINK

- Arrives when match entry min free is
violated ... meaning buffer is full.
- Event caries buffer start pointer.
- At this point and until this match entry is re-appended portal_put_requests arrive at one of the other 4 appended match entries.
- Poller atomically checks buffer metadata until workercounter == pollercounter meaning all requests associated with this
buffer are completed.
- Reappends buffer.

## On event PTL_EVENT_SEND

- A put has completed at the initiator (worker replied). This event is logged after it is safe to reuse the buffer.
- Returns pointer to memory associated with server reply.
- Send buffer memory is one per worker and managed by buddy allocator.
- Server calls workers allocator free for the pointer arrived with PTL_EVENT_SEND.


## Worker Thread

- Manages send buffer
- Utilizes concurrent queue to store worker requests.
- Polls worker queue.
- Utilizes Buddy Allocator to a allocate memory from send buffer for replies.
- Executes parallax calls after allocating memory from Allocator.
- Uses Portals memory descriptors (MD) to reply to client.
- Sleeps on semaphore if queue is empty for x microseconds.

## Worker Request

- Created by Poller thread when PTL_EVENT_PUT event arrives from client.
- Struct that is enqued in worker queue so it can be consumed.

Each request holds information about:
- Client info (nid, pid).
- Pointer in receive buffer where Portals stored PTL_EVENT_PUT payload (Parallax request).
- user_ptr that points to the start of the receive buffer used for the event so worker thread can access buffer metadata (counters).

## The whole Parallax Portals Server picture.

![wholeserverpic](https://github.com/Thodorhs/pictures/blob/main/server_pic.jpg?raw=true)

*CARV ICS-FORTH, Theodoros Pontzouktzidis*
