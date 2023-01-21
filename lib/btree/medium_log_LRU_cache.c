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

#include "medium_log_LRU_cache.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "conf.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uthash.h>

struct medium_log_segment_map {
	uint64_t id;
	uint64_t dev_offt;
	UT_hash_handle hh;
};

struct mlog_cache_chunk_list {
	struct mlog_cache_chunk_listnode *head;
	struct mlog_cache_chunk_listnode *tail;
	uint32_t size;
};

struct mlog_cache_chunk_listnode {
	struct mlog_cache_chunk_listnode *next;
	char *chunk_buf;
	uint64_t chunk_offt;
};

struct mlog_cache_chunk_hash_entry {
	uint64_t chunk_offt; /* key */
	struct mlog_cache_chunk_listnode *chunk_ptr; /* pointer to list node */
	UT_hash_handle hh;
};

//LRU consists of a hashtable and a list. The hash table has pointers to the assosiated list nodes
//the chunk informations are stored in the list nodes
//chunk offsets serve as keys in the hash function
struct medium_log_LRU_cache {
	struct mlog_cache_chunk_hash_entry **chunks_hash_table;
	struct mlog_cache_chunk_list *chunks_list;
	uint64_t hash_table_count;
	uint64_t hash_table_capacity;
	struct medium_log_segment_map *medium_log_segment_map;
	int file_desc;
};

struct mlog_cache_max_segment_info mlog_cache_find_max_segment_info(struct medium_log_LRU_cache *chunk_cache)
{
	struct mlog_cache_max_segment_info max_segment = { 0 };

	struct medium_log_segment_map *current_entry = NULL;
	struct medium_log_segment_map *tmp = NULL;
	HASH_ITER(hh, chunk_cache->medium_log_segment_map, current_entry, tmp)
	{
		/* Suprresses possible null pointer dereference of cppcheck*/
		assert(current_entry);
		uint64_t segment_id = current_entry->id;
		if (UINT64_MAX == segment_id) {
			struct segment_header *segment = REAL_ADDRESS(current_entry->dev_offt);
			segment_id = segment->segment_id;
		}

		if (segment_id >= max_segment.max_segment_id) {
			max_segment.max_segment_id = segment_id;
			max_segment.max_segment_offt = current_entry->dev_offt;
		}
		HASH_DEL(chunk_cache->medium_log_segment_map, current_entry);
		free(current_entry);
	}
	return max_segment;
}

int mlog_cache_chunk_exists_in_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt)
{
	assert(chunk_cache != NULL);
	struct mlog_cache_chunk_hash_entry *chunk;

	HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);

	return chunk != NULL;
}

static void mlog_cache_fetch_chunk(struct medium_log_LRU_cache *chunk_cache, uint64_t log_chunk_dev_offt,
				   char *segment_buf, ssize_t size)
{
	off_t dev_offt = log_chunk_dev_offt;
	ssize_t bytes_to_read = 0;

	while (bytes_to_read < size) {
		ssize_t bytes = pread(chunk_cache->file_desc, &segment_buf[bytes_to_read], size - bytes_to_read,
				      dev_offt + bytes_to_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code dev offt was: %lu", dev_offt);
			perror("Error");
			assert(0);
			BUG_ON();
		}
		bytes_to_read += bytes;
	}

	// if (w_cursor->level_id != w_cursor->handle->db_desc->level_medium_inplace)
	// 	return;

	uint64_t segment_dev_offt = log_chunk_dev_offt - (log_chunk_dev_offt % SEGMENT_SIZE);

	struct medium_log_segment_map *entry = NULL;
	//log_debug("Searching segment offt: %lu log chunk offt %lu mod %lu", segment_dev_offt, log_chunk_dev_offt,
	//	  log_chunk_dev_offt % SEGMENT_SIZE);
	HASH_FIND_PTR(chunk_cache->medium_log_segment_map, &segment_dev_offt, entry);

	/*Never seen it before*/
	bool found = true;

	if (!entry) {
		entry = calloc(1, sizeof(*entry));
		entry->dev_offt = segment_dev_offt;
		found = false;
	}

	/*Already seen and set its id, nothing to do*/
	if (found && entry->id != UINT64_MAX)
		return;

	entry->dev_offt = segment_dev_offt;
	entry->id = UINT64_MAX;

	if (0 == log_chunk_dev_offt % SEGMENT_SIZE) {
		struct segment_header *segment = (struct segment_header *)segment_buf;
		entry->id = segment->segment_id;
	}

	if (!found)
		HASH_ADD_PTR(chunk_cache->medium_log_segment_map, dev_offt, entry);
}

char *mlog_cache_fetch_kv_from_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t kv_dev_offt)
{
	char *segment_chunk = NULL, *kv_in_seg = NULL;
	uint64_t segment_offset, which_chunk, segment_chunk_offt;
	segment_offset = kv_dev_offt - (kv_dev_offt % SEGMENT_SIZE);

	which_chunk = (kv_dev_offt % SEGMENT_SIZE) / LOG_CHUNK_SIZE;

	segment_chunk_offt = segment_offset + (which_chunk * LOG_CHUNK_SIZE);

	if (!mlog_cache_chunk_exists_in_LRU(chunk_cache, segment_chunk_offt)) {
		if (posix_memalign((void **)&segment_chunk, ALIGNMENT_SIZE, LOG_CHUNK_SIZE + KB(4)) != 0) {
			log_fatal("MEMALIGN FAILED");
			BUG_ON();
		}
		mlog_cache_fetch_chunk(chunk_cache, segment_chunk_offt, segment_chunk, LOG_CHUNK_SIZE + KB(4));
		mlog_cache_add_to_LRU(chunk_cache, segment_chunk_offt, segment_chunk);
	} else
		segment_chunk = mlog_cache_get_chunk_from_LRU(chunk_cache, segment_chunk_offt);
	kv_in_seg = &segment_chunk[(kv_dev_offt % SEGMENT_SIZE) - (which_chunk * LOG_CHUNK_SIZE)];

	return kv_in_seg;
}

static struct mlog_cache_chunk_list *mlog_cache_create_list(void)
{
	struct mlog_cache_chunk_list *new_list =
		(struct mlog_cache_chunk_list *)calloc(1, sizeof(struct mlog_cache_chunk_list));

	return new_list;
}

static void mlog_cache_add_last(struct mlog_cache_chunk_list *list, char *chunk_buf, uint64_t chunk_offt)
{
	assert(list != NULL);
	struct mlog_cache_chunk_listnode *new_node =
		(struct mlog_cache_chunk_listnode *)calloc(1, sizeof(struct mlog_cache_chunk_listnode));

	if (!new_node) {
		log_fatal("Error calloc did not allocate memory!");
		BUG_ON();
	}

	new_node->chunk_buf = chunk_buf;
	new_node->chunk_offt = chunk_offt;

	if (list->size != 0) {
		list->tail->next = new_node;
		list->tail = list->tail->next;
	} else {
		list->head = new_node;
		list->tail = new_node;
	}

	++list->size;
}

//remove from head
static void mlog_cache_remove_first(struct mlog_cache_chunk_list *list)
{
	assert(list != NULL);
	assert(list->head != NULL);

	struct mlog_cache_chunk_listnode *pfront = list->head;
	list->head = list->head->next;
	--list->size;
	free(pfront);
}

//move node at the end of the list
static void mlog_cache_move_to_tail(struct mlog_cache_chunk_list *list, const struct mlog_cache_chunk_listnode *node)
{
	assert(list != NULL);
	assert(node != NULL);

	struct mlog_cache_chunk_listnode *pfront = NULL;
	struct mlog_cache_chunk_listnode *pback = NULL;

	for (pfront = list->head; pfront != node; pback = pfront, pfront = pfront->next)
		;

	if (pback == NULL) {
		if (list->size != 1) {
			list->head = list->head->next;
			pfront->next = NULL;
			list->tail->next = pfront;
			list->tail = list->tail->next;
		}

		return;
	}

	//corner case the found node is already tail
	if (pfront == list->tail)
		return;

	//internal node in list
	pback->next = pfront->next;
	pfront->next = NULL;
	list->tail->next = pfront;
	list->tail = pfront;
}

struct medium_log_LRU_cache *mlog_cache_init_LRU(struct db_handle *handle)
{
	uint64_t chunk_size = KB(256);
	uint64_t LRU_cache_size = handle->db_options.options[MEDIUM_LOG_LRU_CACHE_SIZE].value;

	log_info("Init LRU with %lu chunks", LRU_cache_size / chunk_size);
	struct medium_log_LRU_cache *new_LRU =
		(struct medium_log_LRU_cache *)calloc(1UL, sizeof(struct medium_log_LRU_cache));
	if (new_LRU == NULL) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		BUG_ON();
	}

	new_LRU->chunks_hash_table =
		(struct mlog_cache_chunk_hash_entry **)calloc(1UL, sizeof(struct mlog_cache_chunk_hash_entry *));
	if (new_LRU->chunks_hash_table == NULL) {
		log_fatal("Calloc returned NULL, not enough memory, exiting...");
		BUG_ON();
	}

	*(new_LRU->chunks_hash_table) = NULL; /* needed by uthash api */
	new_LRU->hash_table_capacity = LRU_cache_size / chunk_size;
	new_LRU->chunks_list = mlog_cache_create_list();
	new_LRU->file_desc = handle->db_desc->db_volume->vol_fd;

	return new_LRU;
}

void mlog_cache_add_to_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt, char *chunk_buf)
{
	assert(chunk_cache != NULL);
	assert(chunk_cache->chunks_list != NULL);

	//remove oldest chunk (head of list) from LRU
	if (chunk_cache->hash_table_count == chunk_cache->hash_table_capacity) {
		struct mlog_cache_chunk_hash_entry *oldest_used_chunk = NULL;

		HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_cache->chunks_list->head->chunk_offt,
			  sizeof(uint64_t), oldest_used_chunk);

		if (!oldest_used_chunk)
			BUG_ON();

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wnull-dereference"
#endif

		HASH_DEL(*(chunk_cache->chunks_hash_table), oldest_used_chunk);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
		mlog_cache_remove_first(chunk_cache->chunks_list);
		--chunk_cache->hash_table_count;
	}

	//always adds on tail,as it is the newest chunk
	mlog_cache_add_last(chunk_cache->chunks_list, chunk_buf, chunk_offt);

	struct mlog_cache_chunk_hash_entry *new_entry;
	new_entry = (struct mlog_cache_chunk_hash_entry *)calloc(1, sizeof(struct mlog_cache_chunk_hash_entry));

	if (!new_entry) {
		log_fatal("Error calloc did not allocate memory!");
		BUG_ON();
	}

	new_entry->chunk_offt = chunk_offt;
	new_entry->chunk_ptr = chunk_cache->chunks_list->tail;
	HASH_ADD(hh, *(chunk_cache->chunks_hash_table), chunk_offt, sizeof(uint64_t), new_entry);

	assert(new_entry->chunk_ptr->chunk_offt == chunk_offt);

	++chunk_cache->hash_table_count;
	//log_info("hash chunks %lu list nodes %d", LRU_cache->hash_table_count, LRU_cache->chunks_list->size);
}

char *mlog_cache_get_chunk_from_LRU(struct medium_log_LRU_cache *chunk_cache, uint64_t chunk_offt)
{
	assert(chunk_cache != NULL);
	struct mlog_cache_chunk_hash_entry *chunk = NULL;
	HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);

	if (!chunk)
		return BUG_ON();

	mlog_cache_move_to_tail(chunk_cache->chunks_list, chunk->chunk_ptr);
	assert(chunk->chunk_ptr->chunk_offt == chunk_offt);
	return chunk->chunk_ptr->chunk_buf;
}

static void mlog_cache_free_LRU_hashtable(struct mlog_cache_chunk_hash_entry **hash_table)
{
	struct mlog_cache_chunk_hash_entry *current_entry, *tmp;

	HASH_ITER(hh, *(hash_table), current_entry, tmp)
	{
		HASH_DEL(*(hash_table), current_entry);
		free(current_entry);
	}
	free(hash_table);
}

static void mlog_cache_free_LRU_list(struct mlog_cache_chunk_list *list)
{
	assert(list != NULL);
	struct mlog_cache_chunk_listnode *pfront, *pback;

	pfront = list->head;
	pback = NULL;
	while (pfront != NULL) {
		pback = pfront;
		pfront = pfront->next;
		free(pback);
	}
}

void mlog_cache_destroy_LRU(struct medium_log_LRU_cache *chunk_cache)
{
	assert(chunk_cache != NULL);

	log_info("Compaction done! Destroying the LRU for medium log to in place");
	mlog_cache_free_LRU_hashtable(chunk_cache->chunks_hash_table);
	mlog_cache_free_LRU_list(chunk_cache->chunks_list);
	free(chunk_cache->chunks_list);
	free(chunk_cache);
}
