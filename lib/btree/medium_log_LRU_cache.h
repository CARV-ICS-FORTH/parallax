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
#include <sys/types.h>
#include <uthash.h>
struct wcursor_level_write_cursor;
struct write_dynamic_leaf_args;

struct chunk_list {
	struct chunk_listnode *head;
	struct chunk_listnode *tail;
	uint32_t size;
};

struct chunk_listnode {
	struct chunk_listnode *next;
	char *chunk_buf;
	uint64_t chunk_offt;
};

struct chunk_hash_entry {
	uint64_t chunk_offt; /* key */
	struct chunk_listnode *chunk_ptr; /* pointer to list node */
	UT_hash_handle hh;
};

//LRU consists of a hashtable and a list. The hash table has pointers to the assosiated list nodes
//the chunk informations are stored in the list nodes
//chunk offsets serve as keys in the hash function
struct chunk_LRU_cache {
	struct chunk_hash_entry **chunks_hash_table;
	struct chunk_list *chunks_list;
	uint64_t hash_table_count;
	uint64_t hash_table_capacity;
};

struct chunk_LRU_cache *init_LRU(db_handle *handle);
void add_to_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt, char *chunk_buf);
int chunk_exists_in_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt);
char *get_chunk_from_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt);
void destroy_LRU(struct chunk_LRU_cache *chunk_cache);
void fetch_segment_chunk(struct wcursor_level_write_cursor *w_cursor, uint64_t log_chunk_dev_offt, char *segment_buf,
			 ssize_t size);

char *fetch_kv_from_LRU(struct wcursor_level_write_cursor *w_cursor, uint64_t kv_dev_offt);

#endif
