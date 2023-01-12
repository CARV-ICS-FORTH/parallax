// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MEDIUM_LOG_CACHE_H
#define MEDIUM_LOG_CACHE_H
#include "btree.h"
#include <stdint.h>
struct medium_log_LRU_cache;

struct mlog_cache_max_segment_info {
	uint64_t max_segment_id;
	uint64_t max_segment_offt;
};

struct medium_log_LRU_cache *mlog_cache_init_LRU(db_handle *handle);
void mlog_cache_add_to_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt, char *chunk_buf);
int mlog_cache_chunk_exists_in_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt);
char *mlog_cache_get_chunk_from_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt);
void mlog_cache_destroy_LRU(struct medium_log_LRU_cache *chunk_cache);
char *mlog_cache_fetch_kv_from_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t kv_dev_offt);

/**
 * @brief Returns the max segment id and its corresponding offset that this cache has touched.
 * @param chunk_cache pointer to the cache object
 */
struct mlog_cache_max_segment_info mlog_cache_find_max_segment_info(struct medium_log_LRU_cache *chunk_cache);

#endif
