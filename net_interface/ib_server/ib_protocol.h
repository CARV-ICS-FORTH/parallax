#pragma once
#include <stdint.h>

enum op_code { OP_OPEN = 0, OP_WRITE = 1, OP_READ = 2, OP_DEL = 3, OP_SCAN = 4, OP_CLOSE = 5 };

struct __attribute__((packed)) protocol_header {
	uint64_t virtual_address;
	uint64_t size;
	uint64_t db_id;
	enum op_code op;
	uint32_t rkey;
	uint8_t inline_flag;
	uint8_t future_use[31];
};

_Static_assert(sizeof(struct protocol_header) == 64, "protocol_header must be 64 bytes");
