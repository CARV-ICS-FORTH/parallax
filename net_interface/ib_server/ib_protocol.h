#pragma once
#include <stdint.h>

enum op_code { OP_OPEN = 0, OP_CLOSE = 1, OP_WRITE = 2, OP_READ = 3, OP_DEL = 4, OP_SCAN = 5 };

struct __attribute__((packed)) protocol_header {
	uint64_t virtual_address;
	enum op_code op;
	uint8_t db_id;
	uint8_t inline_flag;
	uint8_t future_use[18];
};
