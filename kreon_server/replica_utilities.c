#include <assert.h>
#include "metadata.h"
#include "../kreon_lib/btree/segment_allocator.h"
#include <log.h>

#define NUM_BUCKETS 1024
#define SIZE(x) *(uint32_t *)x
#define SE floor(log2(BUFFER_SEGMENT_SIZE) + 1);

typedef struct prefix_table {
	char prefix[PREFIX_SIZE];
} prefix_table;

/*functions for building efficiently index at replicas*/
void *_ru_get_space_for_tree(struct krm_region_desc *r_desc, int32_t tree_id, uint32_t size)
{
	//void *addr;
	//segment_header *new_segment;
	//uint64_t available_space;
	assert(size % DEVICE_BLOCK_SIZE == 0 && size <= (BUFFER_SEGMENT_SIZE - sizeof(segment_header)));
	log_fatal("gesalous fix it!");
	exit(EXIT_FAILURE);
	return NULL;
#if 0
	if (r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id] == NULL) {
		r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id] =
			allocate(r_desc->m_state->db->volume_desc, BUFFER_SEGMENT_SIZE, -1, NEW_REPLICA_FOREST_TREE);
		r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] = sizeof(segment_header);
		r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id]->next_segment = NULL;
		r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id]->prev_segment = NULL;
		log_info("Initialized new tree in the forest with id %d\n", tree_id);
	}

	/*check if we have enough space within the current segment*/
	if (r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] % BUFFER_SEGMENT_SIZE == 0) {
		available_space = 0;
	} else {
		available_space = BUFFER_SEGMENT_SIZE -
				  (r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] % BUFFER_SEGMENT_SIZE);
	}

	if (available_space >= size) {
		addr = (void *)(uint64_t)r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id] +
		       (r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] % BUFFER_SEGMENT_SIZE);
		r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] += size;
	} else {
		//log_info("new segment needed for the tree\n");

		/*pad remaining remaining space*/
		r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] +=
			(BUFFER_SEGMENT_SIZE -
			 r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] % BUFFER_SEGMENT_SIZE);
		new_segment = (segment_header *)allocate(r_desc->m_state->db->volume_desc, BUFFER_SEGMENT_SIZE, -1,
							 SPACE_FOR_FOREST_TREE);
		r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] += sizeof(segment_header);
		new_segment->next_segment = r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id];
		new_segment->prev_segment = NULL;
		r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id] = new_segment;
		addr = (void *)(uint64_t)r_desc->m_state->db->db_desc->replica_forest.tree_segment_list[tree_id] +
		       (r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] % BUFFER_SEGMENT_SIZE);
		r_desc->m_state->db->db_desc->replica_forest.end_of_log[tree_id] += size;
	}
	return addr;
#endif
}

node_header *_ru_create_tree_node(struct krm_region_desc *r_desc, int tree_id, int node_height, int type)
{
	node_header *node = NULL;
	if (type == leafNode) {
		node = (node_header *)_ru_get_space_for_tree(r_desc, tree_id, DEVICE_BLOCK_SIZE);
		node->type = leafNode;
		node->epoch = r_desc->db->volume_desc->mem_catalogue->epoch;
		node->numberOfEntriesInNode = 0;
		node->fragmentation = 0;
		node->v1 = 0;
		node->v2 = 0;
		node->first_IN_log_header = NULL;
		node->last_IN_log_header = NULL;
		node->key_log_size = 0;
		node->height = node_height;
	} else {
		node = (node_header *)_ru_get_space_for_tree(r_desc, tree_id, DEVICE_BLOCK_SIZE);
		node->type = internalNode;
		node->epoch = r_desc->db->volume_desc->mem_catalogue->epoch;
		node->numberOfEntriesInNode = 0;
		node->fragmentation = 0;
		node->v1 = 0;
		node->v2 = 0;
		node->first_IN_log_header =
			(IN_log_header *)((uint64_t)_ru_get_space_for_tree(r_desc, tree_id, KEY_BLOCK_SIZE) - MAPPED);
		node->last_IN_log_header = node->first_IN_log_header;
		node->key_log_size = sizeof(IN_log_header);
		node->height = node_height;
	}
	return node;
}

void _ru_append_pivot_to_index(struct krm_region_desc *r_desc, node_header *left_brother, void *pivot,
			       node_header *right_brother, int tree_id, int node_height)
{
	node_header *new_node = NULL;
	IN_log_header *last_d_header = NULL;
	IN_log_header *d_header = NULL;
	void *pivot_for_the_upper_level;
	int entries_limit = index_order;
	uint32_t key_len;
	void *key_addr = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;

	if (r_desc->m_state->cur_nodes_per_level[node_height] == 0 &&
	    r_desc->m_state->last_node_per_level[node_height] == NULL) {
		r_desc->m_state->last_node_per_level[node_height] =
			_ru_create_tree_node(r_desc, tree_id, node_height, internalNode);
		++r_desc->m_state->cur_nodes_per_level[node_height];
	}

	else if (r_desc->m_state->cur_nodes_per_level[node_height] ==
		 r_desc->m_state->num_of_nodes_per_level[node_height] - 1) {
		entries_limit = r_desc->m_state->entries_in_semilast_node[node_height];
	}

	else if (r_desc->m_state->cur_nodes_per_level[node_height] ==
		 r_desc->m_state->num_of_nodes_per_level[node_height]) {
		entries_limit = r_desc->m_state->entries_in_last_node[node_height];
	}

	if (r_desc->m_state->last_node_per_level[node_height]->numberOfEntriesInNode == entries_limit) {
		new_node = _ru_create_tree_node(r_desc, tree_id, node_height, internalNode);
		/*add pivot to index node, right rotate*/
		pivot_for_the_upper_level =
			(void *)(uint64_t)r_desc->m_state->last_node_per_level[node_height] + sizeof(node_header) +
			((r_desc->m_state->last_node_per_level[node_height]->numberOfEntriesInNode - 1) * 2 *
			 sizeof(uint64_t)) +
			sizeof(uint64_t);
		pivot_for_the_upper_level = (void *)MAPPED + *(uint64_t *)pivot_for_the_upper_level;

		_ru_append_pivot_to_index(r_desc, r_desc->m_state->last_node_per_level[node_height],
					  pivot_for_the_upper_level, new_node, tree_id, node_height + 1);

		--r_desc->m_state->last_node_per_level[node_height]->numberOfEntriesInNode;
		r_desc->m_state->last_node_per_level[node_height] = new_node;
	}

	/*append the pivot  to the private key log and add the addr*/
	key_len = *(uint32_t *)pivot;
	if (r_desc->m_state->last_node_per_level[node_height]->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space =
			(int32_t)KEY_BLOCK_SIZE -
			(r_desc->m_state->last_node_per_level[node_height]->key_log_size % (int32_t)KEY_BLOCK_SIZE);

	req_space = (key_len + sizeof(uint32_t));
	if (avail_space < req_space) { /*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space + sizeof(node_header)) / KEY_BLOCK_SIZE;
		if ((req_space + sizeof(node_header)) % KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space = allocated_space * KEY_BLOCK_SIZE;

		d_header = _ru_get_space_for_tree(r_desc, tree_id, allocated_space);
		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)r_desc->m_state->last_node_per_level[node_height]
								   ->last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		r_desc->m_state->last_node_per_level[node_height]->last_IN_log_header = last_d_header->next;
		r_desc->m_state->last_node_per_level[node_height]->key_log_size +=
			(avail_space + sizeof(uint64_t)); /* position the log to the newly added block*/
		assert(r_desc->m_state->last_node_per_level[node_height]->key_log_size < 9000);
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)r_desc->m_state->last_node_per_level[node_height]->last_IN_log_header +
		   (uint64_t)(r_desc->m_state->last_node_per_level[node_height]->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, pivot, sizeof(uint32_t) + key_len); /*key length */
	r_desc->m_state->last_node_per_level[node_height]->key_log_size += sizeof(uint32_t) + key_len;

	/*finally add the pivot entry*/
	void *addr = (void *)((uint64_t)r_desc->m_state->last_node_per_level[node_height] + sizeof(node_header) +
			      r_desc->m_state->last_node_per_level[node_height]->numberOfEntriesInNode * 2 *
				      sizeof(uint64_t));
	*(uint64_t *)addr = (uint64_t)left_brother - MAPPED;
	*(uint64_t *)(addr + sizeof(uint64_t)) = (uint64_t)key_addr - MAPPED;
	*(uint64_t *)(addr + (2 * sizeof(uint64_t))) = (uint64_t)right_brother - MAPPED;

	++r_desc->m_state->last_node_per_level[node_height]->numberOfEntriesInNode;
	return;
}
#if 0
void ru_append_entry_to_leaf_node(struct krm_region_desc *r_desc, void *pointer_to_kv_pair, void *prefix,
				  int32_t tree_id)
{
	node_header *new_node = NULL;
	uint64_t *pointers_to_kv_pairs;
	prefix_table *table;
	uint32_t entries_limit = leaf_order;

	/*debugging staff*/
	//if(*(uint32_t *)pointer_to_kv_pair > 30 || *(uint32_t *)pointer_to_kv_pair == 0){
	//	log_info("Faulty pointer size %"PRIu32"\n",*(uint32_t *)pointer_to_kv_pair);
	//	raise(SIGINT);
	//	exit(EXIT_FAILURE);
	//}

	if (r_desc->m_state->cur_nodes_per_level[0] == 0 && r_desc->m_state->last_node_per_level[0] == NULL) {
		r_desc->m_state->last_node_per_level[0] = _ru_create_tree_node(r_desc, tree_id, 0, leafNode);
		++r_desc->m_state->cur_nodes_per_level[0];
	}

	else if (r_desc->m_state->num_of_nodes_per_level[0] > 1 &&
		 (r_desc->m_state->cur_nodes_per_level[0] == r_desc->m_state->num_of_nodes_per_level[0] - 1)) {
		entries_limit = r_desc->m_state->entries_in_semilast_node[0];
	}

	else if (r_desc->m_state->num_of_nodes_per_level[0] > 1 &&
		 (r_desc->m_state->cur_nodes_per_level[0] == r_desc->m_state->num_of_nodes_per_level[0])) {
		entries_limit = r_desc->m_state->entries_in_last_node[0];
	}

	if (r_desc->m_state->last_node_per_level[0]->numberOfEntriesInNode == entries_limit) {
		new_node = _ru_create_tree_node(r_desc, tree_id, 0, leafNode);
		/*add pivot to index node*/
		_ru_append_pivot_to_index(r_desc, r_desc->m_state->last_node_per_level[0], pointer_to_kv_pair, new_node,
					  tree_id, 1);
		r_desc->m_state->last_node_per_level[0] = new_node;
	}

	/*add_entry_to_btree_node*/
	pointers_to_kv_pairs = (uint64_t *)((uint64_t)r_desc->m_state->last_node_per_level[0] + sizeof(node_header));
	table = (prefix_table *)((uint64_t)r_desc->m_state->last_node_per_level[0] + sizeof(node_header) +
				 (leaf_order * sizeof(uint64_t)));

	pointers_to_kv_pairs[r_desc->m_state->last_node_per_level[0]->numberOfEntriesInNode] =
		(uint64_t)pointer_to_kv_pair - MAPPED;
	table[r_desc->m_state->last_node_per_level[0]->numberOfEntriesInNode] = *(prefix_table *)prefix;
	++r_desc->m_state->last_node_per_level[0]->numberOfEntriesInNode;

	return;
}
#endif

#if 0
void _ru_calculate_btree_index_nodes(struct krm_region_desc *r_desc, uint64_t num_of_keys)
{
	int level_id = 0;
	memset(r_desc->m_state->num_of_nodes_per_level, 0x00, sizeof(r_desc->m_state->num_of_nodes_per_level));
	memset(r_desc->m_state->cur_nodes_per_level, 0x00, sizeof(r_desc->m_state->cur_nodes_per_level));
	memset(r_desc->m_state->entries_in_semilast_node, 0x00, sizeof(r_desc->m_state->entries_in_semilast_node));
	memset(r_desc->m_state->entries_in_last_node, 0x00, sizeof(r_desc->m_state->entries_in_last_node));
	memset(r_desc->m_state->last_node_per_level, 0x00, sizeof(r_desc->m_state->last_node_per_level));

	/*first calculate leaves needed*/
	r_desc->m_state->num_of_nodes_per_level[level_id] = num_of_keys / leaf_order;
	if (r_desc->m_state->num_of_nodes_per_level[level_id] > 1 ||
	    (r_desc->m_state->num_of_nodes_per_level[level_id] == 1 && num_of_keys % leaf_order > 0)) {
		if (num_of_keys % leaf_order != 0) {
			/*borrow from left to have at least leaf_order/2 from left brother*/
			++r_desc->m_state->num_of_nodes_per_level[level_id];
			if (num_of_keys % leaf_order < (leaf_order / 2)) {
				r_desc->m_state->entries_in_semilast_node[level_id] =
					leaf_order - ((leaf_order / 2) - (num_of_keys % leaf_order));
				r_desc->m_state->entries_in_last_node[level_id] = leaf_order / 2;
			} else {
				r_desc->m_state->entries_in_semilast_node[level_id] = leaf_order;
				r_desc->m_state->entries_in_last_node[level_id] = num_of_keys % leaf_order;
			}
		} else {
			r_desc->m_state->entries_in_semilast_node[level_id] = leaf_order;
			r_desc->m_state->entries_in_last_node[level_id] = leaf_order;
		}
	} else {
		r_desc->m_state->entries_in_semilast_node[level_id] = 0;
		r_desc->m_state->entries_in_last_node[level_id] = num_of_keys;
		log_info("What ? num of nodes for level %d = %llu\n", level_id,
			 (LLU)r_desc->m_state->num_of_nodes_per_level[level_id]);
		return;
	}

	level_id = 1;
	while (level_id < RU_MAX_TREE_HEIGHT) {
		if (r_desc->m_state->num_of_nodes_per_level[level_id - 1] % index_order != 0) {
			r_desc->m_state->num_of_nodes_per_level[level_id] =
				r_desc->m_state->num_of_nodes_per_level[level_id - 1] / index_order;
			++r_desc->m_state->num_of_nodes_per_level[level_id];

			r_desc->m_state->entries_in_last_node[level_id] =
				r_desc->m_state->num_of_nodes_per_level[level_id - 1] % index_order;

			if (r_desc->m_state->entries_in_last_node[level_id] < index_order / 2) {
				r_desc->m_state->entries_in_semilast_node[level_id] =
					index_order -
					((index_order / 2) - r_desc->m_state->entries_in_last_node[level_id]);
				r_desc->m_state->entries_in_last_node[level_id] = index_order / 2;
			} else {
				r_desc->m_state->entries_in_semilast_node[level_id] = index_order;
				r_desc->m_state->entries_in_last_node[level_id] = num_of_keys % index_order;
			}

		} else {
			r_desc->m_state->num_of_nodes_per_level[level_id] =
				r_desc->m_state->num_of_nodes_per_level[level_id - 1] / index_order;
			r_desc->m_state->entries_in_semilast_node[level_id] = index_order;
			r_desc->m_state->entries_in_last_node[level_id] = index_order;
		}

		if (r_desc->m_state->num_of_nodes_per_level[level_id] == 1) {
			r_desc->m_state->entries_in_semilast_node[level_id] = 0;
			r_desc->m_state->entries_in_last_node[level_id] =
				r_desc->m_state->num_of_nodes_per_level[level_id - 1];
			/*done we are ready*/
			break;
		}
		++level_id;
	}

	assert(level_id != RU_MAX_TREE_HEIGHT - 1);
#if 0
	level_id = 0;
	while(level_id < MAX_TREE_HEIGHT){

		if(r_desc->m_state->num_of_nodes_per_level[level_id] == 0){
			log_info("calculation end\n");
			break;
		}
		log_info("\t\t Level %d num_of_nodes %llu semilast has %llu last has %llu index_order %d leaf_order %d\n",level_id,(LLU)r_desc->m_state->num_of_nodes_per_level[level_id],
				(LLU)r_desc->m_state->entries_in_semilast_node[level_id], (LLU)r_desc->m_state->entries_in_last_node[level_id], index_order, leaf_order);
		++level_id;
	}
#endif

	return;
}
#endif
/*####################################################*/

void init_backup_db_segment_table(db_handle *handle)
{
	assert(0);
	//handle->db_desc->backup_segment_table = NULL;
	//handle->db_desc->spill_segment_table = NULL;
	return;
}

int commit_kv_log_metadata(db_handle *handle)
{
	/*write log info*/
	if (handle->db_desc->KV_log_first_segment != NULL)
		handle->db_desc->commit_log->first_kv_log =
			(segment_header *)((uint64_t)handle->db_desc->KV_log_first_segment - MAPPED);
	else
		handle->db_desc->commit_log->first_kv_log = NULL;
	if (handle->db_desc->KV_log_last_segment != NULL)
		handle->db_desc->commit_log->last_kv_log =
			(segment_header *)((uint64_t)handle->db_desc->KV_log_last_segment - MAPPED);
	else
		handle->db_desc->commit_log->last_kv_log = NULL;
	handle->db_desc->commit_log->kv_log_size = handle->db_desc->KV_log_size;

	//if(msync(handle->db_desc->commit_log,sizeof(commit_log_info),MS_SYNC) == -1){
	//	log_info("FATAL msync failed\n");
	//	exit(EXIT_FAILURE);
	//}

	return KREON_OK;
}

int ru_flush_replica_log_buffer(db_handle *handle, segment_header *master_log_segment, void *buffer,
				uint64_t end_of_log, uint64_t bytes_to_pad, uint64_t segment_id)
{
	segment_header *s_header;
	segment_header *disk_segment_header;
	uint64_t buffer_offset;
	uint64_t buffer_bytes_to_write;
#ifdef EXPLICIT_IO
	int64_t total_bytes_written = 0;
	int64_t bytes_written;
	int64_t offset;
#endif
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#else
	SPIN_LOCK(&handle->db_desc->lock_log);
#endif
	/*pad remaining bytes with 0s*/
	if (handle->db_desc->KV_log_size == 0 ||
	    (handle->db_desc->KV_log_size > 0 && handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE == 0)) {
		buffer_offset = 0;
	} else {
		buffer_offset = handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE;
	}

	buffer_bytes_to_write = end_of_log - handle->db_desc->KV_log_size;
	assert(buffer_bytes_to_write == BUFFER_SEGMENT_SIZE || buffer_bytes_to_write == bytes_to_pad);
	if (bytes_to_pad > 0) {
		memset((buffer + buffer_offset + buffer_bytes_to_write) - bytes_to_pad, 0x00, bytes_to_pad);
	}
	s_header = (segment_header *)buffer;

	/****************** assert check *********************/
	if (handle->db_desc->KV_log_last_segment != NULL &&
	    handle->db_desc->KV_log_last_segment->segment_id != segment_id) {
		if (handle->db_desc->KV_log_last_segment->segment_id + 1 != segment_id) {
			log_info(" No sequential segment ids last %llu current %llu db %s\n",
				 (LLU)handle->db_desc->KV_log_last_segment->segment_id, (LLU)segment_id,
				 handle->db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		//log_info("Sequential segment ids last %llu current %llu db %s\n",
		//		(LLU)handle->db_desc->KV_log_last_segment->segment_id,(LLU)segment_id,handle->db_desc->db_name);
	}

	/****************************************************/
	if (handle->db_desc->KV_log_last_segment == NULL ||
	    handle->db_desc->KV_log_last_segment->segment_id < segment_id) {
		memset(s_header->garbage_bytes, 0x00, 2 * MAX_COUNTER_VERSIONS * sizeof(uint64_t));
		s_header->segment_id = segment_id;
		s_header->next_segment = NULL;
		if (handle->db_desc->KV_log_last_segment != NULL) {
			s_header->prev_segment =
				(segment_header *)((uint64_t)handle->db_desc->KV_log_last_segment - MAPPED);
		} else {
			s_header->prev_segment = NULL;
		}

		disk_segment_header = (segment_header *)seg_get_raw_log_segment(handle->volume_desc);
		if (handle->db_desc->KV_log_last_segment != NULL) {
			handle->db_desc->KV_log_last_segment->next_segment =
				(segment_header *)((uint64_t)disk_segment_header - MAPPED);
		}

		handle->db_desc->KV_log_last_segment = disk_segment_header;

		if (handle->db_desc->KV_log_first_segment == NULL) {
			log_info("initializing first segment for db %s\n", handle->db_desc->db_name);
			handle->db_desc->KV_log_first_segment = handle->db_desc->KV_log_last_segment;
		}

		/*add the mapping as well*/
		map_entry *s = (map_entry *)malloc(sizeof(map_entry));
		s->key = (uint64_t)master_log_segment;
		s->value = (uint64_t)disk_segment_header - MAPPED;
		//log_info("Mappings adding entry remote %llu to local %llu\n", master_log_segment, s->value);
		assert(0);
		//HASH_ADD_PTR(handle->db_desc->backup_segment_table, key, s);
		//handle->db_desc->last_master_segment = s->key;
		//handle->db_desc->last_local_mapping = s->value;
	} else if (handle->db_desc->KV_log_last_segment->segment_id == segment_id) {
		disk_segment_header = handle->db_desc->KV_log_last_segment;
	} else {
		log_info("FATAL id out of range\n");
		exit(EXIT_FAILURE);
	}

	handle->db_desc->KV_log_size = end_of_log;

#ifdef EXPLICIT_IO
	int64_t offset = (uint64_t)disk_segment_header - MAPPED;
	offset += buffer_offset;
	if (lseek(FD, offset, SEEK_SET) < offset) {
		log_info("FATAL seek failed\n");
		exit(EXIT_FAILURE);
	}
	int64_t bytes_written = 0;
	int64_t total_bytes_written = 0;
	do {
		bytes_written = write(FD, buffer + buffer_offset + total_bytes_written,
				      buffer_bytes_to_write - total_bytes_written);
		if (bytes_written < 0) {
			log_info("FATAL ERROR:failed to write log buffer\n");
			perror("Error is :");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	} while (total_bytes_written < buffer_bytes_to_write);
#else
	memcpy((void *)((uint64_t)disk_segment_header + buffer_offset), buffer + buffer_offset, buffer_bytes_to_write);
	if (handle->db_desc->KV_log_last_segment->segment_id != segment_id) {
		log_info("FATAL buffer offset  %llu\n buffer bytes to write %llu\n", (LLU)buffer_offset,
			 (LLU)buffer_bytes_to_write);
		assert(0);
	}
	memset(s_header->garbage_bytes, 0x00, 2 * MAX_COUNTER_VERSIONS * sizeof(uint64_t));
#if 0
	//test code that checks the contents of the log buffer, useful for debugging
	uint64_t i = 0;
	void *addr = buffer+buffer_offset + 4096;
	while(i < buffer_bytes_to_write){
		log_info("key %d:%s  i %"PRIu64" buffer_bytes_to_write %"PRIu64"\n",*(uint32_t *)addr, addr+sizeof(uint32_t), i, buffer_bytes_to_write);
		addr+= (*(uint32_t *)addr + sizeof(uint32_t));
		i+= (*(uint32_t *)addr + sizeof(uint32_t));//key
		addr+= (*(uint32_t *)addr + sizeof(uint32_t));
		i+= (*(uint32_t *)addr + sizeof(uint32_t));//key
		log_info("value %d\n",*(uint32_t *)addr);
		if(*(uint32_t *)addr == 0)
			break;
	}
	log_info("Padding was %"PRIu64" bytes to write %"PRIu64" i %"PRIu64"\n",buffer_bytes_to_write - i, buffer_bytes_to_write, i);
#endif
#endif

	commit_kv_log_metadata(handle);

#if LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle->db_desc->lock_log);
#else
	SPIN_UNLOCK(&handle->db_desc->lock_log);
#endif

	return KREON_OK;
}
