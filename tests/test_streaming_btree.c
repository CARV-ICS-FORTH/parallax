#define _GNU_SOURCE
//#define KREONR
#include <stdio.h>
#include <assert.h>
#include "../build/external-deps/log/src/log.h"
#include "../kreon_lib/allocator/allocator.h"
#include "../kreon_lib/btree/btree.h"
#include "../TucanaServer/server_regions.h"
#include "../TucanaServer/replica_utilities.h"
#include "../utilities/macros.h"
#define VOLUME_NAME "/usr/local/gesalous/master.dat"
#define DB_NAME "db.dat"
#define NUM_OF_KEYS 20000000
#define KEY_VALUE_SIZE 1024
#define VALUE_SIZE 900
#define PREFIX "userrrrrrrrrrrrrrrrrrr"
#define OFFSET 100000000

typedef struct key {
	uint32_t key_size;
	char key_buf[0];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[0];
} value;
void *__find_key_addr_in_leaf(node_header *leaf, void *key);

void check_leaf_node(node_header *leaf)
{
	void *prev;
	void *curr;
	void *addr;
	int64_t ret;
	uint64_t i;
	if (leaf->numberOfEntriesInNode == 1) {
		return;
	}
	addr = (void *)(uint64_t)leaf + sizeof(node_header);
	curr = (void *)*(uint64_t *)addr + MAPPED;

	for (i = 1; i < leaf->numberOfEntriesInNode; i++) {
		addr += 8;
		prev = curr;
		curr = (void *)*(uint64_t *)addr + MAPPED;
		ret = _tucana_key_cmp(prev, curr, KV_FORMAT, KV_FORMAT);
		if (ret > 0) {
			log_info("FATAL corrupted leaf index at index %llu total entries %llu\n", (LLU)i,
				 (LLU)leaf->numberOfEntriesInNode);
			log_info("previous key is: %s\n", (char *)prev + sizeof(int32_t));
			log_info("curr key is: %s\n", (char *)curr + sizeof(int32_t));
			raise(SIGINT);
			exit(-1);
		}
		log_info("previous key is: %d : %s\n", *(uint32_t *)prev, (char *)prev + sizeof(int32_t));
		log_info("curr key is: %d : %s\n", *(uint32_t *)curr, (char *)curr + sizeof(int32_t));
	}
}

/*this function will be reused in various places such as deletes*/
void *_lookup_key(db_handle *handle, void *key)
{
	node_header *curr_node;
	node_header *next_node;
	void *key_addr_in_leaf = NULL;
	void *next_addr;
	void *addr;
	int32_t index_key_len;

	uint64_t v1;
	uint64_t v2;

	//curr_node = handle->db_desc->replica_forest.tree_roots[0];
	curr_node = NULL;
	assert(0);
	assert(curr_node != NULL);
	while (curr_node->type != leafNode && curr_node->type != leafRootNode) {
		v2 = curr_node->v2;
		next_addr = _index_node_binary_search(curr_node, key, KV_FORMAT);
		next_node = (void *)(MAPPED + *(uint64_t *)next_addr);
		v1 = curr_node->v1;

		if (v1 != v2) {
			log_info("failed at node height %d v1 %llu v2 %llu\n", curr_node->height, (LLU)curr_node->v1,
				 (LLU)curr_node->v2);
			exit(EXIT_FAILURE);
		}
		curr_node = next_node;
	}
	//check_leaf_node(curr_node);
	v2 = curr_node->v2;
	key_addr_in_leaf = __find_key_addr_in_leaf(curr_node, key);
	if (key_addr_in_leaf != NULL) {
		key_addr_in_leaf = (void *)MAPPED + *(uint64_t *)key_addr_in_leaf;
		index_key_len = *(int32_t *)key_addr_in_leaf;
		addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
	}

	v1 = curr_node->v1;
	if (v1 != v2) {
		log_info("failed at node height %d v1 %llu v2 %llu\n", curr_node->height, (LLU)curr_node->v1,
			 (LLU)curr_node->v2);
		exit(EXIT_FAILURE);
	}
	if (key_addr_in_leaf == NULL) {
		log_info("FATAL key %d : %s not found\n", *(uint32_t *)key, key + sizeof(uint32_t));
		exit(EXIT_FAILURE);
	}
	return addr; /*key not found at the outer tree*/
}

int main()
{
	char prefix[12];
	char key_buf[KEY_VALUE_SIZE];
	kv_location location;
	_tucana_region_S region;
	uint64_t size = 100 * 1024 * 1024 * 1024L;
	uint64_t i;
	int32_t j;
	memset(key_buf, 0xAD, KEY_VALUE_SIZE);
	memcpy(key_buf + sizeof(uint32_t), PREFIX, strlen(PREFIX));
	memcpy(prefix, key_buf + sizeof(uint32_t), PREFIX_SIZE);
	/*open db*/
	db_handle *handle = db_open(VOLUME_NAME, 0, size, DB_NAME, CREATE_DB);
	region.db = handle;
	_calculate_btree_index_nodes(&region, NUM_OF_KEYS);
	bt_insert_req req;
	for (i = 0; i < NUM_OF_KEYS; i++) {
		sprintf(key_buf + sizeof(uint32_t) + strlen(PREFIX), "%llu", (LLU)i + OFFSET);
		*(uint32_t *)key_buf = strlen(key_buf + 4);
		*(uint32_t *)(key_buf + sizeof(uint32_t) + *(uint32_t *)key_buf) = 900;

		req.handle = handle;
		req.kv_size = *(uint32_t *)key_buf + 908;

		req.key_value_buf = key_buf;
		req.level_id = 0;
		req.key_format = KV_FORMAT;
		req.append_to_log = 1;
		req.gc_request = 0;
		req.recovery_request = 0;
		_insert_key_value(&req);

		//append_entry_to_leaf_node(&region, location.kv_addr, prefix, 0);
		if (i % 100000 == 0) {
			log_info("added key %llu size is %d %s\n", (LLU)i, *(uint32_t *)key_buf,
				 key_buf + sizeof(uint32_t));
		}
	}

	for (j = (MAX_TREE_HEIGHT - 1); j >= 0; j--) {
		if (region.last_node_per_level[j] != NULL) {
			//handle->db_desc->replica_forest.tree_roots[0] = region.last_node_per_level[j];

			break;
		}
	}

	/*done now look-up every key*/
	for (i = 0; i < NUM_OF_KEYS; i++) {
		sprintf(key_buf + sizeof(uint32_t) + strlen(PREFIX), "%llu", (LLU)i + OFFSET);
		*(uint32_t *)key_buf = strlen(key_buf + 4);
		if (i % 100000 == 0) {
			log_info("read key %llu size is %d %s\n", (LLU)i, *(uint32_t *)key_buf,
				 key_buf + sizeof(uint32_t));
		}
		assert(_lookup_key(handle, key_buf) != NULL);
	}
	log_info("Test passed successfully! :-)\n");
	return SUCCESS;
}
