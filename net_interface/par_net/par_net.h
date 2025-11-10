#ifndef PAR_NET_H
#define PAR_NET_H

#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"

#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "par_net_close.h"
#include "par_net_delete.h"
#include "par_net_get.h"
#include "par_net_open.h"
#include "par_net_put.h"
#ifdef USE_PAR_NET_METRICS
#include "par_net_metrics.h"
#endif
struct worker;
struct par_net_worker;

enum par_net_op {
	OPCODE_OPEN = 1,
	OPCODE_PUT,
	OPCODE_DEL,
	OPCODE_GET,
	OPCODE_CLOSE,
	OPCODE_SCAN,
	OPCODE_SYNC,
  OPCODE_METRICS,
	OPCODE_MAX,
};

struct par_net_header {
	uint32_t total_bytes;
	uint32_t opcode;
#ifdef USE_INFINIBAND
	uint64_t payload_buf_vaddr;
	uint64_t payload_size;
	uint32_t request_id;
	uint32_t payload_rkey;
	uint8_t inline_flag;
#endif
} __attribute__((packed));

typedef struct par_net_header *(*par_call)(struct worker *worker, void *args);
typedef struct par_net_header *(*par_portals_call)(struct par_net_worker *par_net_worker, void *args);
typedef void (*par_ib_call)(struct par_net_worker *par_net_worker, void *args, struct par_net_header *reply_header);

/**
  *  @brief Takes the first byte of the serialized stream and translates it to
  *  an opcode to see which of the deserialization function should be called
  *
  *  @param buffer
  *
  *  @return the uint8_t opcode
  *
  */
uint32_t par_net_header_get_opcode(char *buffer);

/**
  *  @brief Sends buffer to the server
  *
  *  @param buffer
  *  @param buffer_len
  *
  *  @return reply buffer on success and NULL on failure
  */
char *par_net_send(char *buffer, size_t *buffer_len);


#endif
