#ifndef COMPACTION_DAEMON_H
#define COMPACTION_DAEMON_H
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "kv_pairs.h"
#include "parallax/structures.h"
#include <stdint.h>
#include <uthash.h>

/*
 * Checks for pending compactions. It is responsible to check for dependencies
 * between two levels before triggering a compaction.
*/

void *compaction_daemon(void *args);
// static void comp_get_space(struct comp_level_write_cursor *c, uint32_t height, nodeType_t type);

#endif // COMPACTION_DAEMON_H
