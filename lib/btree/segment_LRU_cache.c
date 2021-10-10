#include "segment_LRU_cache.h"
#include "assert.h"
#include "set_options.h"
#include "stdio.h"
#include "log.h"
#include "conf.h"
#include <stdlib.h>

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
	new_node->chunk_buf = chunk_buf;
	new_node->chunk_offt = chunk_offt;

	//list is empty
	if (list->size == 0) {
		list->head = new_node;
		list->tail = new_node;
	} else {
		list->tail->next = new_node;
		list->tail = list->tail->next;
	}
	list->size++;
}

//remove from head
void remove_from_list(struct chunk_list *list)
{
	assert(list != NULL);
	assert(list->head != NULL);

	struct chunk_listnode *pfront = list->head;
	list->head = list->head->next;
	list->size--;
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

	while (pfront != node) {
		pback = pfront;
		pfront = pfront->next;
	}

	//corner case segment is first, we dont know if there is 1 segment or many
	if (pback == NULL) {
		//one 1 segment in list, so it is the last
		if (list->size == 1)
			return;
		else {
			//pfront is at head
			list->head = list->head->next;
			pfront->next = NULL;
			list->tail->next = pfront;
			list->tail = list->tail->next;
			return;
		}
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
	struct chunk_listnode *iter = list->head;
	printf("[");
	uint32_t i = 1;
	while (iter != NULL) {
		printf("%lu, ", iter->chunk_offt);
		iter = iter->next;
		i++;
	}
	printf("]\n");
	printf("list size %d , i %d\n", list->size, i);
}

void print_hash_table(struct chunk_hash_entry **hash_table)
{
	struct chunk_hash_entry *current_entry, *tmp;

	printf("HashTable:\n");
	uint64_t i = 0;
	HASH_ITER(hh, *(hash_table), current_entry, tmp)
	{
		printf("%lu: %lu\n", i, current_entry->chunk_offt);
	}
}

struct chunk_LRU_cache *init_LRU(void)
{
	struct lib_option *dboptions = NULL;
	struct lib_option *option;
	parse_options(&dboptions);
	uint64_t LRU_cache_size;
	uint64_t chunk_size = KB(256);
	HASH_FIND_STR(dboptions, "segment_LRU_cache_size", option);
	check_option("segment_LRU_cache_size", option);
	LRU_cache_size = MB(option->value.count);

	log_info("Init LRU with %lu chunks", LRU_cache_size / chunk_size);
	struct chunk_LRU_cache *new_LRU = (struct chunk_LRU_cache *)calloc(1, sizeof(struct chunk_LRU_cache));
	new_LRU->chunks_hash_table = (struct chunk_hash_entry **)calloc(1, sizeof(struct chunk_hash_entry *));

	*(new_LRU->chunks_hash_table) = NULL; /* needed by uthash api */
	new_LRU->hash_table_capacity = LRU_cache_size / chunk_size;
	new_LRU->chunks_list = create_list();

	return new_LRU;
}

void add_to_LRU(struct chunk_LRU_cache *LRU_cache, uint64_t chunk_offt, char *chunk_buf)
{
	assert(LRU_cache != NULL);
	assert(LRU_cache->chunks_list != NULL);

	//remove oldest chunk (head of list) from LRU
	if (LRU_cache->hash_table_count == LRU_cache->hash_table_capacity) {
		struct chunk_hash_entry *oldest_used_chunk;
		HASH_FIND(hh, *(LRU_cache->chunks_hash_table), &LRU_cache->chunks_list->head->chunk_offt,
			  sizeof(uint64_t), oldest_used_chunk);

		HASH_DEL(*(LRU_cache->chunks_hash_table), oldest_used_chunk);

		remove_from_list(LRU_cache->chunks_list);
		LRU_cache->hash_table_count--;
	}

	//always adds on tail,as it is the newest chunk
	add_to_list(LRU_cache->chunks_list, chunk_buf, chunk_offt);

	struct chunk_hash_entry *new_entry;
	new_entry = (struct chunk_hash_entry *)calloc(1, sizeof(struct chunk_hash_entry));
	new_entry->chunk_offt = chunk_offt;
	new_entry->chunk_ptr = LRU_cache->chunks_list->tail;
	HASH_ADD(hh, *(LRU_cache->chunks_hash_table), chunk_offt, sizeof(uint64_t), new_entry);

	assert(new_entry->chunk_ptr->chunk_offt == chunk_offt);

	LRU_cache->hash_table_count++;
	//log_info("hash chunks %lu list nodes %d", LRU_cache->hash_table_count, LRU_cache->chunks_list->size);
}

int chunk_exists_in_LRU(struct chunk_LRU_cache *LRU_cache, uint64_t chunk_offt)
{
	assert(LRU_cache != NULL);
	struct chunk_hash_entry *chunk;
	HASH_FIND(hh, *(LRU_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);

	if (chunk == NULL)
		return 0;

	return 1;
}

char *get_chunk_from_LRU(struct chunk_LRU_cache *LRU_cache, uint64_t chunk_offt)
{
	assert(LRU_cache != NULL);

	struct chunk_hash_entry *chunk;
	HASH_FIND(hh, *(LRU_cache->chunks_hash_table), &chunk_offt, sizeof(uint64_t), chunk);

	move_node_to_tail(LRU_cache->chunks_list, chunk->chunk_ptr);

	assert(chunk->chunk_ptr->chunk_offt == chunk_offt);

	return chunk->chunk_ptr->chunk_buf;
}

static void free_LRU_hashtable(struct chunk_hash_entry **hash_table)
{
	struct chunk_hash_entry *current_entry, *tmp;

	HASH_ITER(hh, *(hash_table), current_entry, tmp)
	{
		HASH_DEL(*(hash_table), current_entry); /* delete it (users advances to next) */
		free(current_entry); /* free it */
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

void destroy_LRU(struct chunk_LRU_cache *LRU_cache)
{
	assert(LRU_cache != NULL);

	log_info("Compaction done! Destroying the LRU for medium log to in place");
	free_LRU_hashtable(LRU_cache->chunks_hash_table);
	free_LRU_list(LRU_cache->chunks_list);
	free(LRU_cache->chunks_list);
	free(LRU_cache);
}
