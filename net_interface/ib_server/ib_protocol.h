#pragma once
#include <stdint.h>

typedef enum {
	IB_OP_OPEN = 0,
	IB_OP_CLOSE = 1,
	IB_OP_WRITE = 2,
	IB_OP_READ = 3,
	IB_OP_DEL = 4,
	IB_OP_SCAN = 5
} ib_opcode;

typedef struct __attribute__((packed)) {
	ib_opcode op;
	uint8_t db_id;
	uint8_t inline_flag;
	uint64_t virtual_address;
	uint8_t buffer[18];
} ib_header;

_Static_assert(sizeof(ib_header) == 32, "ib_header must be 32 bytes");
