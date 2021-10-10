#ifndef SEGMENT_LRU_CACHE_H_
#define SEGMENT_LRU_CACHE_H_
#include <stdint.h>
#include "uthash.h"

struct chunk_list {
	uint32_t size;
	struct chunk_listnode *head;
	struct chunk_listnode *tail;
};

struct chunk_listnode {
	char *chunk_buf;
	uint64_t chunk_offt;
	struct chunk_listnode *next;
};

struct chunk_hash_entry {
	uint64_t chunk_offt; /* key */
	struct chunk_listnode *chunk_ptr; /* pointer to list node */
	UT_hash_handle hh;
};

//LRU consists of a hashtable and a list. The hash table has pointers to the assosiated list nodes
//the chunk informations are stored in the list nodes
struct chunk_LRU_cache {
	struct chunk_hash_entry **chunks_hash_table;
	struct chunk_list *chunks_list;
	uint64_t hash_table_count;
	uint64_t hash_table_capacity;
};

struct chunk_LRU_cache *init_LRU(void);
void add_to_LRU(struct chunk_LRU_cache *, uint64_t, char *);
int chunk_exists_in_LRU(struct chunk_LRU_cache *, uint64_t);
char *get_chunk_from_LRU(struct chunk_LRU_cache *, uint64_t);
void destroy_LRU(struct chunk_LRU_cache *);

#endif // SEGMENT_LRU_CACHE_H_
