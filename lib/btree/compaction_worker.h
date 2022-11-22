#ifndef COMPACTION_WORKER_H
#define COMPACTION_WORKER_H
#include "../allocator/volume_manager.h"
#include "btree.h"
#include "parallax/structures.h"
#include <stdint.h>
#include <uthash.h>
struct compaction_request {
	db_descriptor *db_desc;
	volume_descriptor *volume_desc;
	par_db_options *db_options;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
};

struct medium_log_segment_map {
	uint64_t id;
	uint64_t dev_offt;
	UT_hash_handle hh;
};
extern void *compaction(void *compaction_request);
#endif
