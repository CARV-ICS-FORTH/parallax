#ifndef SST_H
#define SST_H
#include "btree.h"
#include "medium_log_LRU_cache.h"
#include <stdbool.h>
#include <stdint.h>
struct sst;
struct sst_meta;
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
bool sst_close(struct sst *sst);
//sst meta staff follow
struct sst_meta *sst_get_meta(struct sst *sst);
struct leaf_node *sst_meta_get_leaf(struct sst_meta *sst, struct key_splice *key_splice);
uint64_t sst_meta_get_first_leaf_offt(struct sst_meta *sst);
struct key_splice *sst_meta_get_first_guard(struct sst_meta *sst);
struct key_splice *sst_meta_get_last_guard(struct sst_meta *sst);
uint64_t sst_meta_get_dev_offt(struct sst_meta *sst);
size_t sst_meta_get_size(struct sst_meta *sst);
uint64_t sst_meta_get_root(struct sst_meta *sst);
uint32_t sst_meta_get_first_leaf_relative_offt(struct sst_meta *sst);
bool sst_meta_get_next_relative_leaf_offt(uint32_t *offt, char *sst_buffer);
#endif
