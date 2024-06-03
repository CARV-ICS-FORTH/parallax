#ifndef COMPACTION_WORKER_H
#define COMPACTION_WORKER_H
#include "../btree.h"
#include <stdint.h>
struct compaction_request;
struct par_db_options;

struct compaction_request *compaction_create_req(db_descriptor *db_desc, struct par_db_options *db_options,
						 uint64_t l0_start, uint64_t l0_end, uint8_t src_level,
						 uint8_t src_tree, uint8_t dst_level, uint8_t dst_tree);

void compaction_destroy_req(struct compaction_request *);

void compaction_set_dst_tree(struct compaction_request *comp_req, uint8_t tree_id);

uint8_t compaction_get_dst_level(struct compaction_request *comp_req);

uint8_t compaction_get_src_tree(struct compaction_request *comp_req);

uint8_t compaction_get_src_level(struct compaction_request *comp_req);

/**
 * @brief compaction_worker executes compaction function in the context of a
 * pthread. It compacts two levels and writes the resulting level in the
 * device. Src level can be either in memory (L0) or on the device. Dst level
 * is always on the device.
 * @param compaction_request contains the necessary info for performing the
 * compaction.
 */
void *compaction(void *compaction_request);

void compaction_close(struct compaction_request *comp_req);
#endif
