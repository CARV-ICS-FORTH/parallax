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
#include "conf.h"
#include "set_options.h"
#include <assert.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <uthash.h>

struct chunk_list *create_list(void)
{
	struct chunk_list *new_list = (struct chunk_list *)calloc(1, sizeof(struct chunk_list));

	return new_list;
}

//add to tail
void add_to_list(struct chunk_list *list, char *chunk_buf, uint64_t chunk_offt)
{
	assert(list != NULL);
	struct chunk_listnode *new_node = (struct chunk_listnode *)calloc(1, sizeof(struct chunk_listnode));

	if (!new_node) {
		log_fatal("Error calloc did not allocate memory!");
		exit(EXIT_FAILURE);
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
void remove_from_list(struct chunk_list *list)
{
	assert(list != NULL);
	assert(list->head != NULL);

	struct chunk_listnode *pfront = list->head;
	list->head = list->head->next;
	--list->size;
	free(pfront);
}

//move node at the end of the list
void move_node_to_tail(struct chunk_list *list, struct chunk_listnode *node)
{
	assert(list != NULL);
	assert(node != NULL);

	struct chunk_listnode *pfront, *pback;
	pfront = list->head;
	pback = NULL;

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

void print_list(struct chunk_list *list)
{
	assert(list != NULL);
	struct chunk_listnode *iter;
	uint32_t i = 1;

	log_info("[");
	for (iter = list->head; iter != NULL; iter = iter->next) {
		log_info("%lu, ", iter->chunk_offt);
		i++;
	}
	log_info("]");
	log_info("list size %d , i %d", list->size, i);
}

void print_hash_table(struct chunk_hash_entry **hash_table)
{
	struct chunk_hash_entry *current_entry, *tmp;
	uint64_t i = 0;
	log_info("HashTable:");
	HASH_ITER(hh, *(hash_table), current_entry, tmp)
	{
		log_info("%lu: %lu", i, current_entry->chunk_offt);
	}
}

struct chunk_LRU_cache *init_LRU(void)
{
	struct lib_option *option;
	uint64_t LRU_cache_size;
	uint64_t chunk_size = KB(256);
	struct lib_option *dboptions = NULL;

	parse_options(&dboptions);

	HASH_FIND_STR(dboptions, "medium_log_LRU_cache_size", option);
	check_option("medium_log_LRU_cache_size", option);
	LRU_cache_size = MB(option->value.count);

	log_info("Init LRU with %lu chunks", LRU_cache_size / chunk_size);
	struct chunk_LRU_cache *new_LRU = (struct chunk_LRU_cache *)calloc(1, sizeof(struct chunk_LRU_cache));
	if (new_LRU == NULL) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		exit(EXIT_FAILURE);
	}

	new_LRU->chunks_hash_table = (struct chunk_hash_entry **)calloc(1, sizeof(struct chunk_hash_entry *));
	if (new_LRU->chunks_hash_table == NULL) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		exit(EXIT_FAILURE);
	}

	*(new_LRU->chunks_hash_table) = NULL; /* needed by uthash api */
	new_LRU->hash_table_capacity = LRU_cache_size / chunk_size;
	new_LRU->chunks_list = create_list();

	return new_LRU;
}

void add_to_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt, char *chunk_buf)
{
	assert(chunk_cache != NULL);
	assert(chunk_cache->chunks_list != NULL);

	//remove oldest chunk (head of list) from LRU
	if (chunk_cache->hash_table_count == chunk_cache->hash_table_capacity) {
		struct chunk_hash_entry *oldest_used_chunk;
		HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_cache->chunks_list->head->chunk_offt,
			  sizeof(uint64_t), oldest_used_chunk);

		HASH_DEL(*(chunk_cache->chunks_hash_table), oldest_used_chunk);

		remove_from_list(chunk_cache->chunks_list);
		--chunk_cache->hash_table_count;
	}

	//always adds on tail,as it is the newest chunk
	add_to_list(chunk_cache->chunks_list, chunk_buf, chunk_offt);

	struct chunk_hash_entry *new_entry;
	new_entry = (struct chunk_hash_entry *)calloc(1, sizeof(struct chunk_hash_entry));

	if (!new_entry) {
		log_fatal("Error calloc did not allocate memory!");
		exit(EXIT_FAILURE);
	}

	new_entry->chunk_offt = chunk_offt;
	new_entry->chunk_ptr = chunk_cache->chunks_list->tail;
	HASH_ADD(hh, *(chunk_cache->chunks_hash_table), chunk_offt, sizeof(uint64_t), new_entry);

	assert(new_entry->chunk_ptr->chunk_offt == chunk_offt);

	++chunk_cache->hash_table_count;
	//log_info("hash chunks %lu list nodes %d", LRU_cache->hash_table_count, LRU_cache->chunks_list->size);
}

int chunk_exists_in_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt)
{
	assert(chunk_cache != NULL);
	struct chunk_hash_entry *chunk;

	HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);

	return chunk != NULL;
}

char *get_chunk_from_LRU(struct chunk_LRU_cache *chunk_cache, uint64_t chunk_offt)
{
	assert(chunk_cache != NULL);
	struct chunk_hash_entry *chunk;
	HASH_FIND(hh, *(chunk_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);
	move_node_to_tail(chunk_cache->chunks_list, chunk->chunk_ptr);
	assert(chunk->chunk_ptr->chunk_offt == chunk_offt);
	return chunk->chunk_ptr->chunk_buf;
}

static void free_LRU_hashtable(struct chunk_hash_entry **hash_table)
{
	struct chunk_hash_entry *current_entry, *tmp;

	HASH_ITER(hh, *(hash_table), current_entry, tmp)
	{
		HASH_DEL(*(hash_table), current_entry);
		free(current_entry);
	}
	free(hash_table);
}

static void free_LRU_list(struct chunk_list *list)
{
	assert(list != NULL);
	struct chunk_listnode *pfront, *pback;

	pfront = list->head;
	pback = NULL;
	while (pfront != NULL) {
		pback = pfront;
		pfront = pfront->next;
		free(pback);
	}
}

void destroy_LRU(struct chunk_LRU_cache *chunk_cache)
{
	assert(chunk_cache != NULL);

	log_info("Compaction done! Destroying the LRU for medium log to in place");
	free_LRU_hashtable(chunk_cache->chunks_hash_table);
	free_LRU_list(chunk_cache->chunks_list);
	free(chunk_cache->chunks_list);
	free(chunk_cache);
}
