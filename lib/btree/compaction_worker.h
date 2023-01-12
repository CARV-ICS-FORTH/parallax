#ifndef COMPACTION_WORKER_H
#define COMPACTION_WORKER_H
#include "../allocator/volume_manager.h"
#include "btree.h"
#include "parallax/structures.h"
#include <stdint.h>
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

/**
 * @brief compaction_worker executes compaction function in the context of a
 * pthread. It compacts two levels and writes the resulting level in the
 * device. Src level can be either in memory (L0) or on the device. Dst level
 * is always on the device.
 * @param compaction_request contains the necessary info for performing the
 * compaction.
 */
extern void *compaction(void *compaction_request);
#endif
