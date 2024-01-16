#ifndef SST_H
#define SST_H
#include "btree.h"
#include "medium_log_LRU_cache.h"
#include <stdbool.h>
#include <stdint.h>
struct sst;
struct sst_iter;
struct kv_splice;
struct key_splice;
struct device_level;
struct pbf;
struct db_descriptor;
struct medium_log_LRU_cache;

struct sst *sst_create(uint32_t size, uint64_t txn_id, db_handle *handle, uint32_t level_id,
		       struct medium_log_LRU_cache *medium_log_LRU_cache);
bool sst_append_KV_pair(struct sst *sst, struct kv_splice_base *splice);
bool sst_flush(struct sst *sst);
bool sst_remove(struct sst *sst, uint64_t txn_id);
struct pbf *sst_get_bloom_filter(struct sst *sst);
struct leaf_node *level_get_leaf(struct sst *sst, struct key_splice *key_splice);
#endif
