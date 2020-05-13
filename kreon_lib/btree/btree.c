/** @file btree.c
 *  @brief kreon system implementation
 *
 *  @TODO Extended Summary
 *	@author Giorgos Saloustros (gesalous@ics.forth.gr)
 *	@author Anastasios Papagiannis (apapag@ics.forth.gr)
 *	@author Pilar Gonzalez-ferez (pilar@ics.forth.gr)
 *	@author Giorgos Xanthakis (gxanth@ics.forth.gr)
 *	@author Angelos Bilas (bilas@ics.forth.gr)
 **/
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <emmintrin.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "btree.h"
#include "gc.h"
#include "segment_allocator.h"
#include "../../utilities/macros.h"
#include "../allocator/dmap-ioctl.h"
#include "../scanner/scanner.h"
#include "../btree/stats.h"
#include "../btree/assertions.h"
#include "../btree/conf.h"
#include <log.h>

#define PREFIX_STATISTICS_NO
#define MIN(x, y) ((x > y) ? (y) : (x))

#define SYSTEM_NAME "kreon"

#define USE_SYNC
#undef USE_SYNC
#define DEVICE_BLOCK_SIZE 4096
#define DB_STILL_ACTIVE 0x01
#define COULD_NOT_FIND_DB 0x02

#define LOG_SEGMENT_CHUNK 262144

/*stats counters*/
extern uint64_t internal_tree_cow_for_leaf;
extern uint64_t internal_tree_cow_for_index;
extern uint64_t written_buffered_bytes;
extern char *pointer_to_kv_in_log;
extern volatile uint64_t snapshot_v1;
extern volatile uint64_t snapshot_v2;

extern unsigned long long ins_prefix_hit_l0;
extern unsigned long long ins_prefix_hit_l1;
extern unsigned long long ins_prefix_miss_l0;
extern unsigned long long ins_prefix_miss_l1;
extern unsigned long long ins_hack_hit;
extern unsigned long long ins_hack_miss;

uint64_t countgoto = 0;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t log_buffer_lock;
/*number of locks per level*/
uint32_t size_per_height[MAX_HEIGHT] = { 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32 };

#define PAGE_SIZE 4096
#define LEAF_ROOT_NODE_SPLITTED 0xFC

#define MUTATION_LOG_SIZE 2048
#define STATIC 0x01
#define DYNAMIC 0x02
#define MUTATION_BATCH_EXPANDED 0x03
#define FAILURE 0

static uint8_t _writers_join_as_readers(bt_insert_req *ins_req);
static uint8_t _concurrent_insert(bt_insert_req *ins_req);

void assert_index_node(node_header *node);
static inline void move_leaf_data(leaf_node *leaf, int32_t middle)
{
	char *src_addr, *dst_addr;
	const size_t nitems = leaf->header.numberOfEntriesInNode - middle;
	if (nitems == 0)
		return;

	src_addr = (char *)(&(leaf->pointer[middle]));
	dst_addr = src_addr + sizeof(uint64_t);
	memmove(dst_addr, src_addr, nitems * sizeof(uint64_t));

	src_addr = (char *)(&(leaf->prefix[middle]));
	dst_addr = src_addr + PREFIX_SIZE;
	memmove(dst_addr, src_addr, nitems * PREFIX_SIZE);
}

#ifdef PREFIX_STATISTICS
static inline void update_leaf_index_stats(char key_format)
{
	if (key_format == KV_FORMAT)
		__sync_fetch_and_add(&ins_prefix_miss_l0, 1);
	else
		__sync_fetch_and_add(&ins_prefix_miss_l1, 1);
}
#endif

static bt_split_result split_index(node_header *node, bt_insert_req *ins_req);
void _sent_flush_command_to_replica(db_descriptor *db_desc, int padded_space, int SYNC);

int __update_leaf_index(bt_insert_req *req, leaf_node *leaf, void *key_buf);
bt_split_result split_leaf(bt_insert_req *req, leaf_node *node);

/*Buffering aware functions*/
void *__find_key(db_handle *handle, void *key, char SEARCH_MODE);
void *__find_key_addr_in_leaf(leaf_node *leaf, struct splice *key);
void spill_buffer(void *_spill_req);

void destroy_spill_request(NODE *node);

void assert_leaf_node(node_header *leaf);
/*functions used for debugging*/
// static void print_node(node_header *node);

#if 0
thread_dest *__attribute__((noinline)) __dequeue_for_tickets(db_descriptor *db_desc)
{
	thread_dest *prev;
	thread_dest *empty = NULL;

	prev = db_desc->ticket_array;
	while (!__sync_bool_compare_and_swap(&db_desc->ticket_array, prev, empty)) {
		_mm_pause();
		prev = db_desc->ticket_array;
	}

	return prev;
}

void __attribute__((noinline)) __wait1(db_descriptor *db_desc)
{
	while (!db_desc->ticket_array)
		_mm_pause();
}

void __attribute__((noinline)) __wait2(thread_dest *prev)
{
	while (prev->ready)
		_mm_pause();
}

void __attribute__((noinline)) __wait_for_ticket(thread_dest *new_node)
{
	while (!new_node->ready)
		_mm_pause();
}

void *dynamic_ticket_log(db_handle *handle)
{
	segment_header *d_header;
	void *key_addr; /*address at the device*/
	db_descriptor *db_desc = handle->db_desc;
	uint32_t available_space_in_log;
	uint32_t kv_size = 0;
	uint32_t allocated_space;
	thread_dest *prev;
	thread_dest *next = NULL;
	thread_dest *empty = NULL;
/*append data part in the data log*/
empty_list:
	__wait1(db_desc);

	prev = __dequeue_for_tickets(db_desc);

	while (1) {
		if (prev) {
			__wait2(prev);
			next = (void *)prev->next;
			kv_size = prev->kv_size;
		}

		if (likely(handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0))
			available_space_in_log =
				BUFFER_SEGMENT_SIZE - (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
		else
			available_space_in_log = 0;

		if (unlikely(available_space_in_log < kv_size)) {
			/*pad with zeroes remaining bytes in segment*/
			key_addr = (void *)((uint64_t)handle->db_desc->KV_log_last_segment +
					    (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
			memset(key_addr, 0x00, available_space_in_log);

			allocated_space = kv_size + sizeof(segment_header);
			allocated_space += BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
			/** this allocate() is left intentionally. KV log allocates space
       * only from allocator
       * */
			d_header = (segment_header *)allocate_segment(handle, allocated_space, KV_LOG_ID,
								      KV_LOG_EXPANSION);
			memset(d_header->garbage_bytes, 0x00, 2 * MAX_COUNTER_VERSIONS * sizeof(uint64_t));
			d_header->next_segment = NULL;
			handle->db_desc->KV_log_last_segment->next_segment = (void *)((uint64_t)d_header - MAPPED);
			handle->db_desc->KV_log_last_segment = d_header;
			handle->db_desc->KV_log_size +=
				(available_space_in_log +
				 sizeof(segment_header)); /* position the log to the newly added block */
		}

		if (prev) {
			key_addr = (void *)((uint64_t)db_desc->KV_log_last_segment +
					    (db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
			db_desc->KV_log_size += kv_size;
			prev->kv_dest = key_addr;
			prev->ready = 1;
			kv_size = 0;
			__sync_synchronize();
		}

		if (!next)
			goto empty_list;
		prev = next;
	}
}

thread_dest *__attribute__((noinline)) __enqueue_for_ticket(insertKV_request *req, thread_dest *new_node)
{
	thread_dest *temp = req->handle->db_desc->ticket_array;
	while (!__sync_bool_compare_and_swap(&req->handle->db_desc->ticket_array, temp, new_node)) {
		_mm_pause();
		temp = req->handle->db_desc->ticket_array;
	}
	return temp;
}


static inline uint32_t jenkins_one_at_a_time_hash(char *key, int32_t len){
    uint32_t hash;
    int32_t i;

    for(hash = i = 0; i < len; ++i){
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}
#endif

int prefix_compare(char *l, char *r, size_t prefix_size)
{
	return memcmp(l, r, prefix_size);
}

/*XXX TODO XXX REMOVE HEIGHT UNUSED VARIABLE*/
void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height)
{
	log_info("gesalous fix update free_buffered");
#if 0
	db_handle *handle = (db_handle *)_handle;
	uint64_t segment_id = (uint64_t)address - (uint64_t)handle->volume_desc->bitmap_end;
	segment_id = segment_id - (segment_id % BUFFER_SEGMENT_SIZE);
	segment_id = segment_id / BUFFER_SEGMENT_SIZE;
#ifdef AGGRESIVE_FREE_POLICY
	__sync_fetch_and_sub(&(((db_handle *)_handle)->db_desc->zero_level_memory_size), (unsigned long long)num_bytes);

	handle->volume_desc->segment_utilization_vector[segment_id] += (num_bytes / DEVICE_BLOCK_SIZE);
	if (handle->volume_desc->segment_utilization_vector[segment_id] >= SEGMENT_MEMORY_THREASHOLD)
		handle->volume_desc->segment_utilization_vector[segment_id] = 0;
#else
	handle->volume_desc->segment_utilization_vector[segment_id] += (num_bytes / DEVICE_BLOCK_SIZE);
	if (handle->volume_desc->segment_utilization_vector[segment_id] >= SEGMENT_MEMORY_THREASHOLD) {
		__sync_fetch_and_sub(&(((db_handle *)_handle)->db_desc->zero_level_memory_size),
				     (unsigned long long)BUFFER_SEGMENT_SIZE);
		/*dimap hook, release dram frame*/
		if (dmap_dontneed(FD, ((uint64_t)address - MAPPED) / PAGE_SIZE, BUFFER_SEGMENT_SIZE / PAGE_SIZE) != 0) {
			log_fatal("fatal ioctl failed");
			exit(EXIT_FAILURE);
		}
		handle->volume_desc->segment_utilization_vector[segment_id] = 0;
		if (handle->db_desc->throttle_clients == STOP_INSERTS_DUE_TO_MEMORY_PRESSURE &&
		    handle->db_desc->zero_level_memory_size <= ZERO_LEVEL_MEMORY_UPPER_BOUND) {
			handle->db_desc->throttle_clients = NORMAL_OPERATION;
			log_info("releasing clients");
		}
	}
#endif
#endif
	return;
}

/**
 * @param   index_key: address of the index_key
 * @param   index_key_len: length of the index_key in encoded form first 2
 * significant bytes row_key_size least 2 significant bytes quallifier size
 * @param   query_key: address of query_key
 * @param   query_key_len: query_key length again in encoded form
 */

int64_t _tucana_key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format)
{
	int64_t ret;
	uint32_t size;
	/*we need the left most entry*/
	if (query_key_buf == NULL)
		return 1;

	if (index_key_format == KV_FORMAT && query_key_format == KV_FORMAT) {
		size = *(uint32_t *)index_key_buf;
		if (size > *(uint32_t *)query_key_buf)
			size = *(uint32_t *)query_key_buf;

		ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t), size);
		if (ret != 0)
			return ret;
		else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
			return 0;

		else { /*larger key wins*/

			if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
				return 1;
			else
				return -1;
		}
	} else if (index_key_format == KV_FORMAT && query_key_format == KV_PREFIX) {
		if (*(uint32_t *)index_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf + sizeof(uint32_t), query_key_buf, PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(index_key_buf + sizeof(uint32_t), query_key_buf,
					     *(int32_t *)index_key_buf);
		if (ret == 0) { /* we have a tie, prefix didn't help, fetch query_key form KV log*/

			query_key_buf = (void *)(*(uint64_t *)(query_key_buf + PREFIX_SIZE));

			size = *(uint32_t *)index_key_buf;
			if (size > *(uint32_t *)query_key_buf)
				size = *(uint32_t *)query_key_buf;

			ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t),
				     size);

			if (ret != 0)
				return ret;
			else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;

			else { /*larger key wins*/
				if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		} else
			return ret;
	} else if (index_key_format == KV_PREFIX && query_key_format == KV_FORMAT) {
		if (*(uint32_t *)query_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf, query_key_buf + sizeof(uint32_t), PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(index_key_buf, query_key_buf + sizeof(uint32_t),
					     *(int32_t *)query_key_buf);
		if (ret == 0) { /* we have a tie, prefix didn't help, fetch query_key form KV log*/
			index_key_buf = (void *)(*(uint64_t *)(index_key_buf + PREFIX_SIZE));

			size = *(uint32_t *)query_key_buf;
			if (size > *(uint32_t *)index_key_buf)
				size = *(uint32_t *)index_key_buf;

			ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t),
				     size);
			if (ret != 0)
				return ret;
			else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;
			else { /*larger key wins*/

				if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		} else
			return ret;
	} else {
		printf("%s: FATAL, combination not supported please check\n", __func__);
		exit(-1);
	}
	return 0;
}

static void init_level_locktable(db_descriptor *database, uint8_t level_id)
{
	unsigned int i, j;
	lock_table *init;

	for (i = 0; i < MAX_HEIGHT; ++i) {
		if (posix_memalign((void **)&database->levels[level_id].level_lock_table[i], 4096,
				   sizeof(lock_table) * size_per_height[i]) != 0) {
			log_fatal("memalign failed");
			exit(EXIT_FAILURE);
		}
		init = database->levels[level_id].level_lock_table[i];

		for (j = 0; j < size_per_height[i]; ++j) {
			if (RWLOCK_INIT(&init[j].rx_lock, NULL) != 0) {
				log_fatal("failed to initialize lock_table for level %u lock", level_id);
				exit(EXIT_FAILURE);
			}
		}
	}
}

static void destroy_level_locktable(db_descriptor *database, uint8_t level_id)
{
	int i;

	for (i = 0; i < MAX_HEIGHT; ++i)
		free(&database->levels[level_id].level_lock_table[i]);
}

/**
 * @param   blockSize
 * @param   db_name
 * @return  db_handle
 **/
db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG)
{
	db_handle *handle;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	char *key;
	uint64_t val;
	int i = 0;
	int digits;
	uint8_t level_id, tree_id;

	fprintf(stderr, "\n%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n", "\033[0;32m", __FILE__, __func__,
		__LINE__, volumeName, start, size, db_name, "\033[0m");

	MUTEX_LOCK(&init_lock);

	if (mappedVolumes == NULL) {
		mappedVolumes = init_list(&destroy_volume_node);
		/*calculate max leaf,index order*/
		leaf_order = (LEAF_NODE_SIZE - sizeof(node_header)) / (sizeof(uint64_t) + PREFIX_SIZE);
		while (leaf_order % 2 != 0)
			--leaf_order;
		index_order = (INDEX_NODE_SIZE - sizeof(node_header)) / (2 * sizeof(uint64_t));
		index_order -= 2; /*more space for extra pointer, and for rebalacing (merge)*/
		while (index_order % 2 != 1)
			--index_order;

		if ((LEAF_NODE_SIZE - sizeof(node_header)) % 8 != 0) {
			log_fatal("Misaligned node header for leaf nodes, scans will not work");
			exit(EXIT_FAILURE);
		}
		if ((INDEX_NODE_SIZE - sizeof(node_header)) % 16 != 0) {
			log_fatal("Misaligned node header for index nodes, scans will not work "
				  "size of node_header %ld",
				  sizeof(node_header));
			exit(EXIT_FAILURE);
		}
		log_info("index order set to: %d leaf order is set to %d sizeof "
			 "node_header = %lu",
			 index_order, leaf_order, sizeof(node_header));
	}
	/*Is requested volume already mapped?, construct key which will be
	 * volumeName|start*/
	val = start;
	digits = 0;
	while (val > 0) {
		val = val / 10;
		digits++;
	}
	if (digits == 0)
		digits = 1;

	key = malloc(strlen(volumeName) + digits + 1);
	strcpy(key, volumeName);
	sprintf(key + strlen(volumeName), "%llu", (LLU)start);
	key[strlen(volumeName) + digits] = '\0';
	log_info("Searching volume %s", key);
	volume_desc = (volume_descriptor *)find_element(mappedVolumes, key);

	if (volume_desc == NULL) {
		volume_desc = malloc(sizeof(volume_descriptor));
		volume_desc->state = VOLUME_IS_OPEN;
		volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;
		volume_desc->last_snapshot = get_timestamp();
		volume_desc->last_commit = get_timestamp();
		volume_desc->last_sync = get_timestamp();

		volume_desc->volume_name = malloc(strlen(volumeName) + 1);
		strcpy(volume_desc->volume_name, volumeName);
		volume_desc->volume_id = malloc(strlen(key) + 1);
		strcpy(volume_desc->volume_id, key);
		volume_desc->open_databases = init_list(&destoy_db_list_node);
		volume_desc->offset = start;
		volume_desc->size = size;
		/*allocator lock*/
		MUTEX_INIT(&(volume_desc->allocator_lock), NULL);
		/*free operations log*/
		MUTEX_INIT(&(volume_desc->FREE_LOG_LOCK), NULL);
		allocator_init(volume_desc);
		add_first(mappedVolumes, volume_desc, key);
		volume_desc->reference_count++;
		/*soft state about the in use pages of level-0 for each BUFFER_SEGMENT_SIZE
* segment inside the volume*/
		volume_desc->segment_utilization_vector_size =
			((volume_desc->volume_superblock->dev_size_in_blocks -
			  (1 + FREE_LOG_SIZE + volume_desc->volume_superblock->bitmap_size_in_blocks)) /
			 (SEGMENT_SIZE / DEVICE_BLOCK_SIZE)) *
			2;
		volume_desc->segment_utilization_vector =
			(uint16_t *)malloc(volume_desc->segment_utilization_vector_size);
		if (volume_desc->segment_utilization_vector == NULL) {
			log_fatal("failed to allocate memory for segment utilization vector of "
				  "size %lu",
				  volume_desc->segment_utilization_vector_size);
			exit(EXIT_FAILURE);
		}
		memset(volume_desc->segment_utilization_vector, 0x00, volume_desc->segment_utilization_vector_size);

		log_info("volume %s state created max_tries %d", volume_desc->volume_name, MAX_ALLOCATION_TRIES);
	} else {
		log_info("Volume already mapped");
		volume_desc->reference_count++;
	}
	/*Before searching the actual volume's catalogue take a look at the current
* open databases*/
	db_desc = find_element(volume_desc->open_databases, db_name);
	if (db_desc != NULL) {
		log_info("DB %s already open for volume %s", db_name, key);
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		db_desc->reference_count++;
		MUTEX_UNLOCK(&init_lock);
		free(key);
		return handle;
	} else {
		pr_db_group *db_group;
		pr_db_entry *db_entry;
		int32_t empty_group;
		int32_t empty_index;
		int32_t j;

		log_info("Searching volume's %s catalogue for db %s...", volume_desc->volume_name, db_name);
		empty_group = -1;
		empty_index = -1;
		/*we are going to search system's catalogue to find the root_r of the
* corresponding database*/
		for (i = 0; i < NUM_OF_DB_GROUPS; i++) {
			/*is group empty?*/
			if (volume_desc->mem_catalogue->db_group_index[i] != 0) {
				db_group = (pr_db_group *)(MAPPED +
							   (uint64_t)volume_desc->mem_catalogue->db_group_index[i]);
				for (j = 0; j < GROUP_SIZE; j++) {
					/*empty slot keep in mind*/
					if (db_group->db_entries[j].valid == 0 && empty_index == -1) {
						/*Remember the location of the first empty slot within the group*/
						// log_info("empty slot %d in group %d\n", i, j);
						empty_group = i;
						empty_index = j;
					}
					if (db_group->db_entries[j].valid) {
						/*hosts a database*/
						db_entry = &db_group->db_entries[j];
						//log_info("entry at %s looking for %s offset %llu", (uint64_t)db_entry->db_name,
						//	 db_name, db_entry->offset[0]);
						if (strcmp((const char *)db_entry->db_name, (const char *)db_name) ==
						    0) {
							/*found database, recover state and create the appropriate handle and store it in the open_db's list*/
							log_info("database: %s found at index [%d,%d]",
								 db_entry->db_name, i, j);
							handle = malloc(sizeof(db_handle));
							memset(handle, 0x00, sizeof(db_handle));
							db_desc = malloc(sizeof(db_descriptor));

							handle->volume_desc = volume_desc;
							handle->db_desc = db_desc;
							/*initialize database descriptor, soft state first*/
							db_desc->reference_count = 0;
							db_desc->group_id = i;
							db_desc->group_index = j;
							/*restore db name, in memory*/
							memset(db_desc->db_name, 0x00, MAX_DB_NAME_SIZE);
							strcpy(db_desc->db_name, db_entry->db_name);
							db_desc->dirty = 0;

							/*restore now persistent state of all levels*/
							for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
								db_desc->levels[level_id].level_size = 0;
								for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL;
								     tree_id++) {
									/*segments info per level*/
									if (db_entry->first_segment
										    [(level_id * NUM_TREES_PER_LEVEL) +
										     tree_id] != 0) {
										db_desc->levels[level_id]
											.first_segment[tree_id] =
											(segment_header
												 *)(MAPPED +
												    db_entry->first_segment
													    [(level_id *
													      NUM_TREES_PER_LEVEL) +
													     tree_id]);
										db_desc->levels[level_id]
											.last_segment[tree_id] =
											(segment_header
												 *)(MAPPED +
												    db_entry->last_segment
													    [(level_id *
													      NUM_TREES_PER_LEVEL) +
													     tree_id]);
										db_desc->levels[level_id]
											.offset[tree_id] =
											db_entry->offset
												[(level_id *
												  NUM_TREES_PER_LEVEL) +
												 tree_id];
									} else {
										db_desc->levels[level_id]
											.first_segment[tree_id] = NULL;

										db_desc->levels[level_id]
											.last_segment[tree_id] = NULL;
										db_desc->levels[level_id]
											.offset[tree_id] = 0;
									}
									/*total keys*/
									db_desc->levels[level_id].total_keys[tree_id] =
										db_entry->total_keys
											[(level_id *
											  NUM_TREES_PER_LEVEL) +
											 tree_id];
									/*finally the roots*/
									if (db_entry->root_r[(level_id *
											      NUM_TREES_PER_LEVEL) +
											     tree_id] != 0) {
										db_desc->levels[level_id]
											.root_r[tree_id] =
											(node_header
												 *)(MAPPED +
												    db_entry->root_r
													    [(level_id *
													      NUM_TREES_PER_LEVEL) +
													     tree_id]);
										log_warn(
											"Recovered root r of [%lu][%lu] = %llu ",
											level_id, tree_id,
											db_desc->levels[level_id]
												.root_r[tree_id]);
									} else
										db_desc->levels[level_id]
											.root_r[tree_id] = NULL;

									db_desc->levels[level_id].root_w[tree_id] =
										NULL;
								}
							}
#if 0
							/*recover replica L1 forest if needed*/
							if (db_entry->replica_forest != NULL) {
								memcpy((void *)&db_desc->replica_forest,
								       (void *)MAPPED +
									       (uint64_t)db_entry->replica_forest,
								       sizeof(forest));
								for (i = 0; i < MAX_FOREST_SIZE; i++) {
									if (db_desc->replica_forest.tree_status[i] ==
									    PERSISTED) {
										db_desc->replica_forest
											.tree_segment_list[i] =
											(segment_header *)MAPPED +
											*(uint64_t *)db_entry
												 ->replica_forest
												 ->tree_segment_list[i];
										db_desc->replica_forest.dev / nvme0n1 =
											(node_header *)MAPPED +
											*(uint64_t *)db_entry
												 ->replica_forest
												 ->tree_roots[i];
									} else if (db_desc->replica_forest
												   .tree_status[i] !=
											   NOT_USED ||
										   db_desc->replica_forest
												   .tree_status[i] !=
											   PERSISTED) {
										DPRINT("XXX TODO XXX needs recovery of space !\n");
										exit(EXIT_FAILURE);
									} else if (db_desc->replica_forest
											   .tree_status[i] ==
										   NOT_USED) {
										db_desc->replica_forest
											.tree_segment_list[i] = NULL;
										db_desc->replica_forest.tree_roots[i] =
											NULL;
									} else {
										DPRINT("FATAL DBs forest flags in inconsistent state\n");
										exit(EXIT_FAILURE);
									}
								}
								DPRINT("-*-*-*- Recovered db's level 1 forest used in replica "
								       "mode * - * - *\n");
							} else {
								DPRINT(" - * - forest not present? skipping - * - *\n");
								memset(&db_desc->replica_forest, 0x00, sizeof(forest));
							}
/*done with replica forest*/
#endif
							/*recover KV log for this database*/
							db_desc->commit_log =
								(commit_log_info *)(MAPPED +
										    ((uint64_t)db_entry->commit_log));
							if (db_desc->commit_log->first_kv_log != NULL)
								db_desc->KV_log_first_segment =
									(segment_header *)(MAPPED +
											   (uint64_t)db_desc->commit_log
												   ->first_kv_log);
							else
								db_desc->KV_log_first_segment = NULL;

							if (db_desc->commit_log->last_kv_log != NULL)
								db_desc->KV_log_last_segment =
									(segment_header *)(MAPPED +
											   (uint64_t)db_desc->commit_log
												   ->last_kv_log);
							else
								db_desc->KV_log_last_segment = NULL;

							db_desc->KV_log_size = db_desc->commit_log->kv_log_size;
							db_desc->L0_start_log_offset = db_entry->L0_start_log_offset;
							db_desc->L0_end_log_offset = db_entry->L0_end_log_offset;

							log_info("KV log segments first: %llu last: %llu log_size %llu",
								 (LLU)db_desc->KV_log_first_segment,
								 (LLU)db_desc->KV_log_last_segment,
								 (LLU)db_desc->KV_log_size);
							log_info("L0 start log offset %llu end %llu",
								 db_desc->L0_start_log_offset,
								 db_desc->L0_end_log_offset);

							goto finish_init;
						}
					}
				}
			} else if (empty_group == -1)
				empty_group = i;
		}
		if (CREATE_FLAG != CREATE_DB && CREATE_FLAG != O_CREATE_REPLICA_DB) {
			DPRINT("DB not found instructed not to create one returning NULL\n");
			return NULL;
		}
		/*db not found allocate a new slot for it*/
		if (empty_group == -1 && empty_index == -1) {
			log_info("FATAL MAX DBS %d reached", NUM_OF_DB_GROUPS * GROUP_SIZE);
			exit(EXIT_FAILURE);
		}

		//log_info("mem epoch %llu", volume_desc->mem_catalogue->epoch);
		if (empty_index == -1) {
			/*space found in empty group*/
			pr_db_group *new_group = get_space_for_system(volume_desc, sizeof(pr_db_group));
			memset(new_group, 0x00, sizeof(pr_db_group));
			new_group->epoch = volume_desc->mem_catalogue->epoch;
			volume_desc->mem_catalogue->db_group_index[empty_group] =
				(pr_db_group *)((uint64_t)new_group - MAPPED);
			empty_index = 0;
			log_info("allocated new pr_db_group epoch at %llu volume epoch %llu", new_group->epoch,
				 volume_desc->mem_catalogue->epoch);
		}
		log_info("database %s not found, allocating slot [%d,%d] for it", (const char *)db_name, empty_group,
			 empty_index);
		pr_db_group *cur_group =
			(pr_db_group *)(MAPPED + (uint64_t)volume_desc->mem_catalogue->db_group_index[empty_group]);
		db_entry = &cur_group->db_entries[empty_index];
		db_entry->valid = 1;
		// db_entry = (pr_db_entry *)(MAPPED +
		// (uint64_t)volume_desc->mem_catalogue->db_group_index[empty_group] +
		//			   (uint64_t)DB_ENTRY_SIZE + (uint64_t)(empty_index *
		// DB_ENTRY_SIZE));
		// db_entry->replica_forest = NULL;
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		db_desc = (db_descriptor *)malloc(sizeof(db_descriptor));

		/*this nullifies replica also*/
		memset(db_desc, 0x00, sizeof(db_descriptor));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		/*initialize database descriptor, soft state first*/
		db_desc->reference_count = 0;
		db_desc->group_id = empty_group;
		db_desc->group_index = empty_index;

		//log_info("mem epoch %llu", volume_desc->mem_catalogue->epoch);
		/*stored db name, in memory*/
		memset(db_entry->db_name, 0x00, MAX_DB_NAME_SIZE);
		strcpy(db_entry->db_name, db_name);
		memset(db_desc->db_name, 0x00, MAX_DB_NAME_SIZE);
		strcpy(db_desc->db_name, db_name);
		db_desc->dirty = 0x01;
		/*init all persistent fields levels*/
		for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
			for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
				db_desc->levels[level_id].root_r[tree_id] = NULL;
				db_desc->levels[level_id].root_w[tree_id] = NULL;
				db_desc->levels[level_id].total_keys[tree_id] = 0;
				db_desc->levels[level_id].first_segment[tree_id] = NULL;
				db_desc->levels[level_id].last_segment[tree_id] = NULL;
				db_desc->levels[level_id].offset[tree_id] = 0;
			}
		}
		/*initialize KV log for this db*/
		db_desc->commit_log = (commit_log_info *)get_space_for_system(volume_desc, sizeof(commit_log_info));
		/*get a page for commit_log info*/
		if (CREATE_FLAG != CREATE_DB) {
			DPRINT("replica db ommiting KV log initialization\n");
			db_desc->KV_log_first_segment = NULL;
			db_desc->KV_log_last_segment = NULL;
			db_desc->KV_log_size = 0;
			db_desc->L0_start_log_offset = 0;
			db_desc->L0_end_log_offset = 0;

			db_desc->commit_log->first_kv_log = NULL;
			db_desc->commit_log->last_kv_log = NULL;
			db_desc->commit_log->kv_log_size = 0;
		} else {
			log_info("Primary db initializing KV log");
			db_desc->KV_log_first_segment = seg_get_raw_log_segment(volume_desc);
			memset((void *)db_desc->KV_log_first_segment->garbage_bytes, 0x00,
			       2 * MAX_COUNTER_VERSIONS * sizeof(uint64_t));
			db_desc->KV_log_last_segment = db_desc->KV_log_first_segment;
			db_desc->KV_log_last_segment->segment_id = 0;
			db_desc->KV_log_last_segment->next_segment = NULL;
			db_desc->KV_log_last_segment->prev_segment = NULL;
			db_desc->KV_log_size = sizeof(segment_header);
			db_desc->L0_start_log_offset = sizeof(segment_header);
			db_desc->L0_end_log_offset = sizeof(segment_header);
			/*get a page for commit_log info*/
			db_desc->commit_log->first_kv_log =
				(segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
			db_desc->commit_log->last_kv_log =
				(segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
			db_desc->commit_log->kv_log_size = (uint64_t)db_desc->KV_log_size;
			/*persist commit log information, this location stays permanent, there no
* need to rewrite it during snapshot()*/
			db_entry->commit_log = (uint64_t)db_desc->commit_log - MAPPED;
		}
	}

finish_init:
	/*init soft state for all levels*/
	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_INIT(&db_desc->levels[level_id].guard_of_level.rx_lock, NULL);
		MUTEX_INIT(&db_desc->levels[level_id].spill_trigger, NULL);
		MUTEX_INIT(&db_desc->levels[level_id].level_allocation_lock, NULL);
		init_level_locktable(db_desc, level_id);
		db_desc->levels[level_id].level_size = 0;
		db_desc->levels[level_id].active_writers = 0;
		db_desc->levels[level_id].outstanding_spill_ops = 0;
		/*check again which tree should be active*/
		db_desc->levels[level_id].active_tree = 0;

		for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			db_desc->levels[level_id].tree_status[tree_id] = NO_SPILLING;
		}
	}
#if LOG_WITH_MUTEX
	MUTEX_INIT(&db_desc->lock_log, NULL);
#else
	SPINLOCK_INIT(&db_desc->lock_log, PTHREAD_PROCESS_PRIVATE);
#endif
	SPINLOCK_INIT(&db_desc->back_up_segment_table_lock, PTHREAD_PROCESS_PRIVATE);

	add_first(volume_desc->open_databases, db_desc, db_name);
	MUTEX_UNLOCK(&init_lock);
	free(key);

	if (CREATE_FLAG == CREATE_DB) {
		log_info("opened primary db");
		db_desc->db_mode = PRIMARY_DB;
	} else {
		log_info("opened replica db");
		db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
	}
#if 0
		else{
		log_info("opened replica db");
		db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		log_info("Initializing  segment table");
		init_backup_db_segment_table(handle);
	}
	db_desc->log_buffer = NULL;
	db_desc->latest_proposal_start_segment_offset = 0;
#endif
	/*recovery checks*/
	log_info("performing recovery checks for db: %s", db_desc->db_name);
	/*where is L0 located at the log?*/
	if (db_desc->L0_end_log_offset > db_desc->L0_start_log_offset) {
		log_info("L0 present performing recovery checks ...");
		if (db_desc->L0_end_log_offset < db_desc->commit_log->kv_log_size) {
			log_info("Commit log: %llu is ahead of L0: %llu replaying "
				 "missing log parts",
				 (LLU)db_desc->commit_log->kv_log_size, (LLU)db_desc->L0_end_log_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.recovery_start_log_offset = db_desc->L0_end_log_offset;
			recovery_worker(&rh);
			log_info("recovery completed successfully");
		} else if (db_desc->L0_end_log_offset == db_desc->commit_log->kv_log_size)
			log_info("no recovery needed for db: %s ready :-)\n", db_desc->db_name);
		else {
			log_fatal("Boom! Corrupted state for db: %s :-(", db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
	} else if (db_desc->L0_end_log_offset == db_desc->L0_start_log_offset) {
		log_info("L0 is absent L1 ends at %llu replaying missing parts", (LLU)db_desc->L0_end_log_offset);
		if (db_desc->L0_end_log_offset < db_desc->commit_log->kv_log_size) {
			log_info("Commit log (%llu) is ahead of L0 end (%llu) replaying missing "
				 "log parts",
				 (LLU)db_desc->commit_log->kv_log_size, (LLU)db_desc->L0_end_log_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.recovery_start_log_offset = db_desc->L0_end_log_offset;
			recovery_worker(&rh);
			log_info("recovery completed successfully");
		} else if (db_desc->L0_end_log_offset == db_desc->commit_log->kv_log_size)
			log_info("no recovery needed for db: %s ready :-)\n", db_desc->db_name);
		else {
			log_fatal("FATAL corrupted state for db: %s :-(", db_desc->db_name);
			exit(EXIT_FAILURE);
		}
	} else {
		log_fatal("FATAL Corrupted state detected");
		exit(EXIT_FAILURE);
	}
	return handle;
}

char db_close(db_handle *handle)
{
	/*verify that this is a valid db*/
	if (find_element(handle->volume_desc->open_databases, handle->db_desc->db_name) == NULL) {
		log_fatal("FATAL received close for db: %s that is not listed as open", handle->db_desc->db_name);
		exit(EXIT_FAILURE);
	}

	log_info("closing region/db %s snapshotting volume\n", handle->db_desc->db_name);
	handle->db_desc->db_mode = DB_IS_CLOSING;
	snapshot(handle->volume_desc);
/*stop log appenders*/
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#else
	SPIN_LOCK(&handle->db_desc->lock_log);
#endif
	/*stop all writers at all levels*/
	uint8_t level_id;
	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);
		spin_loop(&(handle->db_desc->levels[level_id].active_writers), 0);
	}

	destroy_level_locktable(handle->db_desc, 0);

	if (remove_element(handle->volume_desc->open_databases, handle->db_desc) != 1) {
		log_info("Could not find db: %s", handle->db_desc->db_name);
		MUTEX_UNLOCK(&init_lock);
		return COULD_NOT_FIND_DB;
	}
	return KREON_OK;
}

void destroy_spill_request(NODE *node)
{
	free(node->data); /*the actual spill_request*/
	free(node);
}

void spill_database(db_handle *handle)
{
	if (handle)
		log_warn("Spill database deprecated");
#if 0
	int32_t i;

	if (handle->db_desc->db_mode != PRIMARY_DB) {
		log_info("ommiting spill for back up db");
		return;
	}
	if (memcmp(handle->db_desc->tree_status, DB_NO_SPILLING, NUM_OF_TREES_PER_LEVEL) != 0) {
		log_info("Nothing to do spill operation already active");
		return;
	}
	RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock);
	spin_loop(&handle->db_desc->count_writers_level_0, 0);

	/*switch to another tree, but which?*/
	for (i = 0; i < NUM_OF_TREES_PER_LEVEL; i++) {
		if (i != handle->db_desc->active_tree && handle->db_desc->tree_status[i] != SPILLING_IN_PROGRESS) {
			int32_t level_id = handle->db_desc->active_tree;
			handle->db_desc->tree_status[level_id] = SPILLING_IN_PROGRESS;
			handle->db_desc->active_tree = i;

			/*spawn a spiller thread*/
			spill_request *spill_req =
				(spill_request *)malloc(sizeof(spill_request)); /*XXX TODO XXX MEMORY LEAK*/
			spill_req->db_desc = handle->db_desc;
			spill_req->volume_desc = handle->volume_desc;

			if (handle->db_desc->root_w[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else if (handle->db_desc->root_r[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_r[level_id];
			else {
				log_info("empty level-0, nothing to do");
				free(spill_req);
				handle->db_desc->tree_status[level_id] = NO_SPILLING;
				break;
			}
			if (handle->db_desc->root_w[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else
				spill_req->src_root = handle->db_desc->root_r[level_id];

			spill_req->src_tree_id = level_id;
			spill_req->dst_tree_id = NUM_OF_TREES_PER_LEVEL;
			spill_req->start_key = NULL;
			spill_req->end_key = NULL;
			handle->db_desc->count_active_spillers = 1;

			if (pthread_create(&(handle->db_desc->spiller), NULL, (void *)spill_buffer,
					   (void *)spill_req) != 0) {
				log_info("FATAL: error creating spiller thread");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	RWLOCK_UNLOCK(&handle->db_desc->guard_level_0.rx_lock);
#endif
}

/*method for closing a database*/
void flush_volume(volume_descriptor *volume_desc, char force_spill)
{
#if 0
  db_descriptor *db_desc;
	db_handle *handles;
	handles = (db_handle *)malloc(sizeof(db_handle) * volume_desc->open_databases->size);

	int db_id = 0;
	NODE *node;
	int i;

	while (1) {
		log_info("Waiting for pending spills to finish");
		node = get_first(volume_desc->open_databases);
		while (node != NULL) {
			db_desc = (db_descriptor *)(node->data);
			/*wait for pending spills for this db to finish*/
			i = 0;
			while (i < TOTAL_TREES) {
				if (db_desc->tree_status[i] == SPILLING_IN_PROGRESS) {
					log_info("Waiting for db %s to finish spills", db_desc->db_name);
					sleep(4);
					i = 0;
				} else
					i++;
			}
			node = node->next;
		}
		log_info("ok... no pending spills\n");

		if (force_spill == SPILL_ALL_DBS_IMMEDIATELY) {
			node = get_first(volume_desc->open_databases);
			while (node != NULL) {
				handles[db_id].db_desc = (db_descriptor *)(node->data);
				handles[db_id].volume_desc = volume_desc;
				spill_database(&handles[db_id]);
				++db_id;
				node = node->next;
			}
			force_spill = SPILLS_ISSUED;
		} else
			break;
	}
	log_info("Finally, snapshoting volume\n");
	snapshot(volume_desc);
	free(handles);
	return;
#endif
}

uint8_t insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size, uint32_t value_size)
{
	bt_insert_req ins_req;
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
	uint32_t kv_size;

	/*throttle control check*/
	while (handle->db_desc->levels[0].level_size > ZERO_LEVEL_MEMORY_UPPER_BOUND &&
	       handle->db_desc->levels[0].outstanding_spill_ops) {
		usleep(THROTTLE_SLEEP_TIME);
	}

	kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + value_size + sizeof(uint64_t);
#ifndef NDEBUG
	assert(kv_size <= KV_MAX_SIZE);
#endif

	if (kv_size > KV_MAX_SIZE) {
		log_fatal("Key buffer overflow");
		exit(EXIT_FAILURE);
	}
	/*prepare the request*/
	*(uint32_t *)key_buf = key_size;
	memcpy((void *)(uint64_t)key_buf + sizeof(uint32_t), key, key_size);
	*(uint32_t *)((uint64_t)key_buf + sizeof(uint32_t) + key_size) = value_size;
	memcpy((void *)(uint64_t)key_buf + sizeof(uint32_t) + key_size + sizeof(uint32_t), value, value_size);
	ins_req.metadata.handle = handle;
	ins_req.key_value_buf = key_buf;
	ins_req.metadata.level_id = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;

	return _insert_key_value(&ins_req);
}

void extract_keyvalue_size(log_operation *req, metadata_tologop *data_size)
{
	switch (req->optype_tolog) {
	case insertOp:
		data_size->key_len = *(uint32_t *)req->ins_req->key_value_buf;
		data_size->value_len =
			*(uint32_t *)(req->ins_req->key_value_buf + sizeof(uint32_t) + (data_size->key_len));
		data_size->kv_size = req->metadata->kv_size;
		break;
	case deleteOp:
		data_size->key_len = *(uint32_t *)req->del_req->key_buf;
		data_size->value_len = 0;
		data_size->kv_size = data_size->key_len + (sizeof(uint32_t) * 2);
		break;
	default:
		log_fatal("Trying to append unknown operation in log! ");
		exit(EXIT_FAILURE);
	}
}

void write_keyvalue_inlog(log_operation *req, metadata_tologop *data_size, char *addr_inlog)
{
	switch (req->optype_tolog) {
	case insertOp:
		memcpy(addr_inlog, req->ins_req->key_value_buf,
		       sizeof(data_size->key_len) + data_size->key_len + sizeof(data_size->value_len) +
			       data_size->value_len);
		break;
	case deleteOp:
		memcpy(addr_inlog, req->del_req->key_buf, sizeof(data_size->key_len) + data_size->key_len);
		addr_inlog += (sizeof(data_size->key_len) + data_size->key_len);
		memcpy(addr_inlog, &data_size->value_len, sizeof(data_size->value_len));
		break;
	default:
		log_fatal("Trying to append unknown operation in log! ");
		exit(EXIT_FAILURE);
	}
}

void *append_key_value_to_log(log_operation *req)
{
	segment_header *d_header;
	void *addr_inlog; /*address at the device*/
	metadata_tologop data_size;
	uint32_t available_space_in_log;
	uint32_t allocated_space;
	db_handle *handle = req->metadata->handle;
	extract_keyvalue_size(req, &data_size);

#ifdef LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_lock(&handle->db_desc->lock_log);
#endif
	/*append data part in the data log*/
	if (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0)
		available_space_in_log = BUFFER_SEGMENT_SIZE - (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	if (available_space_in_log < data_size.kv_size) {
		/*fill info for kreon master here*/
		req->metadata->log_segment_addr = (uint64_t)handle->db_desc->KV_log_last_segment - MAPPED;
		req->metadata->log_offset_full_event = handle->db_desc->KV_log_size;
		req->metadata->segment_id = handle->db_desc->KV_log_last_segment->segment_id;
		req->metadata->log_padding = available_space_in_log;
		req->metadata->end_of_log = handle->db_desc->KV_log_size + available_space_in_log;
		req->metadata->segment_full_event = 1;

		/*pad with zeroes remaining bytes in segment*/
		addr_inlog = (void *)((uint64_t)handle->db_desc->KV_log_last_segment +
				      (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
		memset(addr_inlog, 0x00, available_space_in_log);

		allocated_space = data_size.kv_size + sizeof(segment_header);
		allocated_space += BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);

		d_header = seg_get_raw_log_segment(handle->volume_desc);
		memset(d_header->garbage_bytes, 0x00, 2 * MAX_COUNTER_VERSIONS * sizeof(uint64_t));
		d_header->next_segment = NULL;
		handle->db_desc->KV_log_last_segment->next_segment = (void *)((uint64_t)d_header - MAPPED);
		handle->db_desc->KV_log_last_segment = d_header;
		/* position the log to the newly added block*/
		handle->db_desc->KV_log_size += (available_space_in_log + sizeof(segment_header));
	}
	addr_inlog = (void *)((uint64_t)handle->db_desc->KV_log_last_segment +
			      (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
	handle->db_desc->KV_log_size += data_size.kv_size;

#ifdef LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_unlock(&handle->db_desc->lock_log);
#endif

	write_keyvalue_inlog(req, &data_size, addr_inlog);

	return addr_inlog;
}

static void spill_trigger(bt_spill_request *req)
{
	log_info("Trigerring spill for db %s and level %u", req->db_desc->db_name, req->src_level);
	if (pthread_create(&(req->db_desc->levels[req->src_level].spiller[req->src_tree]), NULL, (void *)spill_buffer,
			   (void *)req) != 0) {
		log_fatal("FATAL: error creating spiller thread");
		exit(EXIT_FAILURE);
	}
}

static void prepare_dbdescriptor_forspill(spill_data_totrigger *data)
{
	data->db_desc->levels[data->level_id].tree_status[data->tree_to_spill] = SPILLING_IN_PROGRESS;
	data->db_desc->levels[data->level_id].active_tree = data->active_tree;
	data->db_desc->levels[data->level_id].level_size = 0;
	__sync_fetch_and_add(&data->db_desc->levels[data->level_id].outstanding_spill_ops, 1);
}

static void rollback_dbdescriptor_before_spill(spill_data_totrigger *data)
{
	data->db_desc->levels[data->level_id].tree_status[data->tree_to_spill] = NO_SPILLING;
	data->db_desc->levels[data->level_id].active_tree = data->prev_active_tree;
	data->db_desc->levels[data->level_id].level_size = data->prev_level_size;
	__sync_fetch_and_sub(&data->db_desc->levels[data->level_id].outstanding_spill_ops, 1);
}

bt_spill_request *bt_spill_check(db_handle *handle, uint8_t level_id)
{
	spill_data_totrigger data = { .db_desc = handle->db_desc, .level_id = level_id };
	bt_spill_request *spill_req = NULL;
	db_descriptor *db_desc = handle->db_desc;
	int to_spill_tree_id;
	int i, j;

	if (level_id >= 1) {
		log_warn("Spills not yet activated for levels >= 1 tell gesalous to fix "
			 "them :-)");
		return NULL;
	}

	if (db_desc->levels[level_id].in_recovery_mode) {
		log_warn("no spills during recovery ");
		return NULL;
	}

	/*do we need to trigger a spill, we allow only one pending spill per DB*/
	if (db_desc->levels[level_id].level_size >= (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
	    db_desc->levels[level_id].outstanding_spill_ops == 0) {
		/*check again*/
		MUTEX_LOCK(&db_desc->levels[level_id].spill_trigger);
		if (db_desc->levels[level_id].level_size >= (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
		    db_desc->levels[level_id].outstanding_spill_ops == 0) {
			/*Close the door for L0, acquire read guard lock*/
			if (RWLOCK_WRLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock)) {
				log_fatal("Failed to acquire guard lock of level %u", level_id);
				exit(EXIT_FAILURE);
			}

			/* log_info("Initiating spill for db %s and level %u waiting for L0 to empty", db_desc->db_name, */
			/* 	 level_id); */
			spin_loop(&db_desc->levels[level_id].active_writers, 0);
			/* log_info("DB %s: No active writers for level %u spawning spill thread", db_desc->db_name, */
			/* 	 level_id); */

			/*switch to another tree within the level, but which?*/
			for (i = 0; i < NUM_TREES_PER_LEVEL; i++) {
				if (i != db_desc->levels[level_id].active_tree) {
					to_spill_tree_id = db_desc->levels[level_id].active_tree;
					data.prev_active_tree = db_desc->levels[level_id].active_tree;
					data.prev_level_size = db_desc->levels[level_id].level_size;
					data.tree_to_spill = to_spill_tree_id;
					data.active_tree = i;
					prepare_dbdescriptor_forspill(&data);

					spill_req = (bt_spill_request *)malloc(sizeof(bt_spill_request));
					spill_req->db_desc = db_desc;
					spill_req->volume_desc = handle->volume_desc;

					/*set source*/
					if (db_desc->levels[level_id].root_w[to_spill_tree_id] != NULL)
						spill_req->src_root =
							db_desc->levels[level_id].root_w[to_spill_tree_id];
					else
						spill_req->src_root =
							handle->db_desc->levels[level_id].root_r[to_spill_tree_id];
					level_descriptor *level;
					uint8_t dst_level;
					uint8_t dst_active_tree;
					spill_req->src_level = level_id;
					spill_req->src_tree = to_spill_tree_id;
					dst_level = level_id + 1;
					dst_active_tree = handle->db_desc->levels[dst_level].active_tree;
					level = &handle->db_desc->levels[dst_level];

					/*Set destination choose a tree of level i+1*/
					spill_req->dst_level = dst_level;
					if (level[dst_level].tree_status[dst_active_tree] == NO_SPILLING) {
						spill_req->dst_tree = dst_active_tree;
						level[dst_level].tree_status[dst_active_tree] = SPILLING_IN_PROGRESS;
					} else {
						for (j = 0; j < NUM_TREES_PER_LEVEL; j++) {
							if (j != dst_active_tree &&
							    level[dst_level].tree_status[j] == NO_SPILLING) {
								spill_req->dst_tree = j;
								level[dst_level].tree_status[j] = SPILLING_IN_PROGRESS;
								break;
							}
						}
						if (j == NUM_TREES_PER_LEVEL) {
							/* log_warn( */
							/* 	"[Should not happen] max spill operations at destination level %u aborting spill try", */
							/* 	dst_level); */

							rollback_dbdescriptor_before_spill(&data);
							free(spill_req);
							spill_req = NULL;
							goto exit;
						}
					}
					if (level_id == 0) {
						spill_req->l0_start = handle->db_desc->L0_start_log_offset;
						spill_req->l0_end = handle->db_desc->L0_end_log_offset;
					} else {
						spill_req->l0_start = 0;
						spill_req->l0_end = 0;
					}

					spill_req->start_key = NULL;
					spill_req->end_key = NULL;
					spill_req->src_tree = to_spill_tree_id;
					spill_req->dst_tree = NUM_TREES_PER_LEVEL;
					spill_req->l0_start = db_desc->L0_start_log_offset;
					spill_req->l0_end = db_desc->L0_end_log_offset;

					spill_req->start_key = NULL;
					spill_req->end_key = NULL;
					spill_req->src_level = level_id;
					break;
				}
			}

		exit:
			/*open the L0 door */
			if (RWLOCK_UNLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock)) {
				log_fatal("Failed to acquire guard lock");
				exit(EXIT_FAILURE);
			}
		}
		pthread_mutex_unlock(&db_desc->levels[level_id].spill_trigger);
	}
	return spill_req;
}

uint8_t _insert_key_value(bt_insert_req *ins_req)
{
	db_descriptor *db_desc;
	unsigned key_size;
	unsigned val_size;
	uint8_t rc;

	db_desc = ins_req->metadata.handle->db_desc;
	db_desc->dirty = 0x01;

	if (ins_req->metadata.key_format == KV_FORMAT) {
		key_size = *(uint32_t *)ins_req->key_value_buf;
		val_size = *(uint32_t *)(ins_req->key_value_buf + 4 + key_size);
		ins_req->metadata.kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + val_size;
	} else
		ins_req->metadata.kv_size = -1;
	rc = SUCCESS;
	if (_writers_join_as_readers(ins_req) == SUCCESS)
		rc = SUCCESS;
	else if (_concurrent_insert(ins_req) != SUCCESS) {
		log_warn("insert failed!");
		rc = FAILED;
	}
	bt_spill_request *spill = bt_spill_check(ins_req->metadata.handle, 0);
	if (spill != NULL)
		spill_trigger(spill);
	return rc;
}

#if 0
/**
 * handle: handle of the db that the insert operation will take place
 * key_buf: the address at the device where the key value pair has been written
 * log_offset: The log offset where key_buf corresponds at the KV_log
 * INSERT_FLAGS: extra commands: 1st byte LEVEL (0,1,..,N) | 2nd byte APPEND or
 * DO_NOT_APPEND
 **/
uint8_t _insert_index_entry(db_handle *handle, kv_location * location, int INSERT_FLAGS)
{

    insertKV_request req;
    db_descriptor *db_desc;
    lock_table * db_guard;
    int64_t * num_of_level_writers;
    int index_level = 2;/*0, 1, 2, ... N(future)*/
    int tries = 0;
    int primary_op = 0;
    int rc;
    /*inserts take place one of the trees in level 0*/
    db_desc = handle->db_desc;
    db_desc->dirty = 0x01;

    req.handle = handle;
    req.key_value_buf = location->kv_addr;
    req.insert_flags = INSERT_FLAGS;/*Insert to L0 or not.Append to log or not.*/
    req.allocator_desc.handle = handle;

    /*allocator to use, depending on the level*/
    if( (INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == DONOT_APPEND_TO_LOG){
        /*append or recovery*/
        req.allocator_desc.allocate_space = &allocate_segment;
        req.allocator_desc.free_space = &free_buffered;
        /*active tree of level 0*/
        req.allocator_desc.level_id = db_desc->active_tree;
        req.level_id = db_desc->active_tree;
        req.key_format = KV_FORMAT;
        req.guard_of_level = &(db_desc->guard_level_0);
        req.level_lock_table = db_desc->multiwrite_level_0;
        index_level = 0;
        num_of_level_writers = &db_desc->count_writers_level_0;
        db_guard = &handle->db_desc->guard_level_0;
        if((INSERT_FLAGS & 0x000000FF)==PRIMARY_L0_INSERT){
            primary_op = 1;
            if(location->log_offset > db_desc->L0_end_log_offset)
                db_desc->L0_end_log_offset = location->log_offset;
        }
    }
#ifdef SCAN_REORGANIZATION
    else if (INSERT_FLAGS == SCAN_REORGANIZE){/*scan reorganization command, update directly to level-1*/
        req.allocator_desc.level_id = NUM_OF_TREES_PER_LEVEL;
        req.allocator_desc.allocate_space = &allocate_segment;
        req.allocator_desc.free_space = &free_block;
        req.level_id = NUM_OF_TREES_PER_LEVEL;
        req.key_format = KV_FORMAT;
    }
#endif
    /*Spill either local or remote */
    else if ((INSERT_FLAGS & 0xFF000000) == INSERT_TO_L1_INDEX){
        req.allocator_desc.allocate_space = &allocate_segment;
        req.allocator_desc.free_space = &free_block;
        req.allocator_desc.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
        req.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
        req.key_format = KV_PREFIX;
        req.guard_of_level = &db_desc->guard_level_1;
        req.level_lock_table = db_desc->multiwrite_level_1;
        index_level = 1;
        num_of_level_writers = &db_desc->count_writers_level_1;
        db_guard = &handle->db_desc->guard_level_1;
    }
    else if((INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == APPEND_TO_LOG){
        DPRINT("FATAL insert mode not supported\n");
        exit(EXIT_FAILURE);
    } else {
        DPRINT("FATAL UNKNOWN INSERT MODE\n");
        exit(EXIT_FAILURE);
    }

    while(1){
        if(RWLOCK_WRLOCK(&db_guard->rx_lock) !=0){
            printf("[%s:%s:%d] ERROR locking guard\n",__func__,__FILE__,__LINE__);
            exit(-1);
        }
        /*increase corresponding level's writers count*/
        if(!primary_op)
            __sync_fetch_and_add(num_of_level_writers,1);
        /*which is the active tree?*/
        if(index_level == 0){
            req.level_id=db_desc->active_tree;
            req.allocator_desc.level_id = db_desc->active_tree;
        }
        if(tries == 0){
            if(_writers_join_as_readers(&req) == SUCCESS){
                __sync_fetch_and_sub(num_of_level_writers,1);
                rc = SUCCESS;
                break;
            } else {
                if(!primary_op)
                    __sync_fetch_and_sub(num_of_level_writers,1);
                ++tries;
                continue;
            }
        }
        else if(tries == 1) {
            if(_concurrent_insert(&req) != SUCCESS){
                DPRINT("FATAL function failed\n!");
                exit(EXIT_FAILURE);
            }
            __sync_fetch_and_sub(num_of_level_writers,1);
            rc = SUCCESS;
            break;
        }
        else{
            DPRINT("FATAL insert failied\n");
            exit(EXIT_FAILURE);
        }
    }
    /*
       if((INSERT_FLAGS & 0x000000FF) != RECOVERY_OPERATION)
       _spill_check(req.handle,0);
       else
       _spill_check(req.handle,1);
       */
    return rc;
}
#endif

#if 0
/*
 * gesalous added at 01/07/2014 18:29 function that frees all the blocks of a
 * node
 * Note add equivalent function to segment_allocator
 * */
void free_logical_node(allocator_descriptor *allocator_desc, node_header *node_index)
{
	if (node_index->type == leafNode || node_index->type == leafRootNode) {
		(*allocator_desc->free_space)(allocator_desc->handle, node_index, NODE_SIZE, allocator_desc->level_id);
		return;
	} else if (node_index->type == internalNode || node_index->type == rootNode) {
		/*for IN, BIN, root nodes free the key log as well*/
		if (node_index->first_IN_log_header == NULL) {
			log_fatal("NULL log for index?");
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		IN_log_header *curr = (IN_log_header *)(MAPPED + (uint64_t)node_index->first_IN_log_header);
		IN_log_header *last = (IN_log_header *)(MAPPED + (uint64_t)node_index->last_IN_log_header);
		IN_log_header *to_free;
		while ((uint64_t)curr != (uint64_t)last) {
			to_free = curr;
			curr = (IN_log_header *)((uint64_t)MAPPED + (uint64_t)curr->next);
			(*allocator_desc->free_space)(allocator_desc->handle, to_free, KEY_BLOCK_SIZE,
						      allocator_desc->level_id);
		}
		(*allocator_desc->free_space)(allocator_desc->handle, last, KEY_BLOCK_SIZE, allocator_desc->level_id);
		/*finally node_header*/
		(*allocator_desc->free_space)(allocator_desc->handle, node_index, NODE_SIZE, allocator_desc->level_id);
	} else {
		log_fatal("FATAL corrupted node!");
		exit(EXIT_FAILURE);
	}
	return;
}
#endif

static inline void *lookup_in_tree(void *key, node_header *node)
{
	node_header *curr_node;
	void *key_addr_in_leaf;
	void *next_addr;
	uint64_t v1 = 0, v2 = 0;
	uint32_t tries;
	uint32_t index_key_len;
	tries = 0;
retry:
	if (++tries > 10000000) {
		log_fatal("possible deadlock detected failed to read after 100K tries v2 "
			  "is %llu v1 is %llu",
			  v2, v1);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	curr_node = node;

	while (curr_node->type != leafNode && curr_node->type != leafRootNode) {
		v2 = curr_node->v2;
		next_addr = _index_node_binary_search((index_node *)curr_node, key, KV_FORMAT);
		v1 = curr_node->v1;

		if (v1 != v2) {
			// log_info("failed at node height %d v1 %llu v2 % llu\n",
			// curr_node->height, (LLU)curr_node->v1,
			//	 (LLU)curr_node->v2);
			++tries;
			goto retry;
		}

		curr_node = (void *)(MAPPED + *(uint64_t *)next_addr);
	}
	v2 = curr_node->v2;
	/* log_debug("curr node - MAPPEd %p",MAPPED-(uint64_t)curr_node); */
	key_addr_in_leaf = __find_key_addr_in_leaf((leaf_node *)curr_node, (struct splice *)key);
	v1 = curr_node->v1;

	if (v1 != v2) {
		// log_info("failed at node height %d v1 %llu v2 % llu\n",
		// curr_node->height, (LLU)curr_node->v1,
		//	 (LLU)curr_node->v2);
		++tries;
		goto retry;
	}

	if (key_addr_in_leaf == NULL) /*snapshot and retry, only for outer tree case*/
		return NULL;

	key_addr_in_leaf = (void *)MAPPED + *(uint64_t *)key_addr_in_leaf;
	index_key_len = *(uint32_t *)key_addr_in_leaf;

	return (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
}

/*this function will be reused in various places such as deletes*/
void *__find_key(db_handle *handle, void *key, char SEARCH_MODE)
{
	void *value;
	node_header *root_w;
	node_header *root_r;
	uint32_t active_tree;
	uint8_t level_id;
	uint8_t tree_id;
	value = NULL;

	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		/*first look the current active tree of the level*/
		active_tree = handle->db_desc->levels[level_id].active_tree;
		// log_warn("active tree of level %lu is %lu", level_id, active_tree);
		root_w = handle->db_desc->levels[level_id].root_w[active_tree];
		root_r = handle->db_desc->levels[level_id].root_r[active_tree];

		if (root_w != NULL) {
			/* if (level_id == 1) */
			/* 	BREAKPOINT; */
			value = lookup_in_tree(key, root_w);
		} else if (root_r != NULL)
			value = lookup_in_tree(key, root_r);

		if (value != NULL)
			goto finish;

		/*search the rest trees of the level*/
		for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			if (tree_id != active_tree) {
				root_w = handle->db_desc->levels[level_id].root_w[tree_id];
				root_r = handle->db_desc->levels[level_id].root_w[tree_id];
				if (root_w != NULL)
					value = lookup_in_tree(key, root_w);
				else if (root_r != NULL) {
					root_r = handle->db_desc->levels[level_id].root_r[tree_id];
					value = lookup_in_tree(key, root_r);
				}
				if (value != NULL)
					goto finish;
			}
		}
	}

finish:

	return value ? value : NULL;
}

/* returns the addr where the value of the KV pair resides */
/* TODO: make this return the offset from MAPPED, not a pointer
 * to the offset */
void *__find_key_addr_in_leaf(leaf_node *leaf, struct splice *key)
{
	int32_t start_idx = 0, end_idx = leaf->header.numberOfEntriesInNode - 1;
	char key_buf_prefix[PREFIX_SIZE] = { '\0' };

	memcpy(key_buf_prefix, key->data, MIN(key->size, PREFIX_SIZE));

	while (start_idx <= end_idx) {
		int32_t middle = (start_idx + end_idx) / 2;

		int32_t ret = prefix_compare(leaf->prefix[middle], key_buf_prefix, PREFIX_SIZE);
		if (ret < 0)
			start_idx = middle + 1;
		else if (ret > 0)
			end_idx = middle - 1;
		else {
			void *index_key = (void *)(MAPPED + leaf->pointer[middle]);
			ret = _tucana_key_cmp(index_key, key, KV_FORMAT, KV_FORMAT);
			if (ret == 0)
				return &(leaf->pointer[middle]);
			else if (ret < 0)
				start_idx = middle + 1;
			else
				end_idx = middle - 1;
		}
	}

	return NULL;
}

void *find_key(db_handle *handle, void *key, uint32_t key_size)
{
	char buf[4000];
	void *key_buf = &(buf[0]);
	void *value;

	if (key_size <= (4000 - sizeof(uint32_t))) {
		key_buf = &(buf[0]);
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t), key, key_size);
		value = __find_key(handle, key_buf, SEARCH_DIRTY_TREE);
	} else {
		key_buf = malloc(key_size + sizeof(uint32_t));
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t), key, key_size);
		value = __find_key(handle, key_buf, SEARCH_DIRTY_TREE);
		free(key_buf);
	}

	return value;
}

/**
 * @param   node:
 * @param   left_child:
 * @param   right_child:
 * @param   key:
 * @param   key_len:
 |block_header|pointer_to_node|pointer_to_key|pointer_to_node |
 pointer_to_key|...
*/
int8_t update_index(index_node *node, node_header *left_child, node_header *right_child, void *key_buf)
{
	int64_t ret = 0;
	void *addr;
	void *dest_addr;
	uint64_t entry_val = 0;
	void *index_key_buf;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.numberOfEntriesInNode - 1;
	size_t num_of_bytes;

	addr = (void *)(uint64_t)node + sizeof(node_header);

	if (node->header.numberOfEntriesInNode > 0) {
		while (1) {
			middle = (start_idx + end_idx) / 2;
			addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) + sizeof(uint64_t) +
			       (uint64_t)(middle * 2 * sizeof(uint64_t));
			index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, KV_FORMAT);
			if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					// addr is the same
					break;
			} else if (ret == 0) {
				log_fatal("key already present*");
				raise(SIGINT);
				exit(EXIT_FAILURE);
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					if (middle >= (int64_t)node->header.numberOfEntriesInNode) {
						middle = node->header.numberOfEntriesInNode;
						addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) +
						       (uint64_t)(middle * 2 * sizeof(uint64_t)) + sizeof(uint64_t);
					} else
						addr += (2 * sizeof(uint64_t));
					break;
				}
			}
		}

		dest_addr = addr + (2 * sizeof(uint64_t));
		num_of_bytes = (node->header.numberOfEntriesInNode - middle) * 2 * sizeof(uint64_t);
		memmove(dest_addr, addr, num_of_bytes);
		addr -= sizeof(uint64_t);
	} else
		addr = (void *)node + sizeof(node_header);

	/*update the entry*/
	if (left_child != 0)
		entry_val = (uint64_t)left_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr, &entry_val, sizeof(uint64_t));
	addr += sizeof(uint64_t);
	entry_val = (uint64_t)key_buf - MAPPED;
	memcpy(addr, &entry_val, sizeof(uint64_t));

	addr += sizeof(uint64_t);
	if (right_child != 0)
		entry_val = (uint64_t)right_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr, &entry_val, sizeof(uint64_t));
	return 1;
}

/**
 * @param   handle: database handle
 * @param   node: address of the index node where the key should be inserted
 * @param   left_child: address to the left child (full not absolute)
 * @param   right_child: address to the left child (full not absolute)
 * @param   key: address of the key to be inserted
 * @param   key_len: size of the key
 */
void insert_key_at_index(db_handle *handle, int level_id, index_node *node, node_header *left_child,
			 node_header *right_child, void *key_buf, char allocation_code)
{
	void *key_addr = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;
	IN_log_header *d_header = NULL;
	IN_log_header *last_d_header = NULL;

	uint32_t key_len = *(uint32_t *)key_buf;
	int8_t ret;

	//assert_index_node(node);
	if (node->header.key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - (node->header.key_log_size % (int32_t)KEY_BLOCK_SIZE);

	req_space = (key_len + sizeof(uint32_t));
	if (avail_space < req_space) {
		/*room not sufficient get new block*/
		allocated_space = (req_space + sizeof(IN_log_header)) / KEY_BLOCK_SIZE;
		if ((req_space + sizeof(IN_log_header)) % KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space *= KEY_BLOCK_SIZE;

		if (allocated_space > KEY_BLOCK_SIZE) {
			log_fatal("Cannot host index key larger than KEY_BLOCK_SIZE");
			exit(EXIT_FAILURE);
		}
		d_header =
			seg_get_IN_log_block(handle->volume_desc, &handle->db_desc->levels[level_id], allocation_code);

		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)node->header.last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		node->header.last_IN_log_header = last_d_header->next;
		node->header.key_log_size +=
			(avail_space + sizeof(IN_log_header)); /* position the log to the newly added block*/
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)node->header.last_IN_log_header +
		   (uint64_t)(node->header.key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(uint32_t) + key_len); /*key length */
	node->header.key_log_size += (sizeof(uint32_t) + key_len);

	ret = update_index(node, left_child, right_child, key_addr);
	if (ret)
		node->header.numberOfEntriesInNode++;
	//assert_index_node(node);
}

/*
 * gesalous: Added at 13/06/2014 16:22. After the insertion of a leaf it's
 * corresponding index will be updated
 * for later use in efficient searching.
 */
int __update_leaf_index(bt_insert_req *req, leaf_node *leaf, void *key_buf)
{
	void *index_key_buf, *addr;
	int64_t ret = 1;
	int32_t start_idx, end_idx, middle = 0;
	char *index_key_prefix = NULL;
	char key_buf_prefix[PREFIX_SIZE] = { '\0' };
	uint64_t pointer = 0;

	start_idx = 0;
	end_idx = leaf->header.numberOfEntriesInNode - 1;
	addr = &(leaf->pointer[0]);

	if (req->metadata.key_format == KV_FORMAT) {
		int32_t row_len = *(int32_t *)key_buf;
		memcpy(key_buf_prefix, (void *)((uint64_t)key_buf + sizeof(int32_t)), MIN(row_len, PREFIX_SIZE));
	} else { /* operation coming from spill request (i.e. KV_PREFIX) */
		memcpy(key_buf_prefix, key_buf, PREFIX_SIZE);
	}

	while (leaf->header.numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;
		addr = &(leaf->pointer[middle]);
		index_key_prefix = leaf->prefix[middle];

		ret = prefix_compare(index_key_prefix, key_buf_prefix, PREFIX_SIZE);
		if (ret < 0) {
			//update_leaf_index_stats(req->key_format);
			goto up_leaf_1;
		} else if (ret > 0) {
			//update_leaf_index_stats(req->key_format);
			goto up_leaf_2;
		}

#ifdef PREFIX_STATISTICS
		if (key_format == KV_PREFIX)
			__sync_fetch_and_add(&ins_hack_miss, 1);
#endif
		//update_leaf_index_stats(req->key_format);

		index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, req->metadata.key_format);
		if (ret == 0) {
			if (req->metadata.gc_request && pointer_to_kv_in_log != index_key_buf)
				return ret;
			break;
		} else if (ret < 0) {
		up_leaf_1:
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				middle++;
				move_leaf_data(leaf, middle);
				break;
			}
		} else if (ret > 0) {
		up_leaf_2:
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				move_leaf_data(leaf, middle);
				break;
			}
		}
	}

	/*setup the pointer*/
	if (req->metadata.key_format == KV_FORMAT)
		pointer = (uint64_t)key_buf - MAPPED;
	else /* KV_PREFIX */
		pointer = (*(uint64_t *)(key_buf + PREFIX_SIZE)) - MAPPED;
	/*setup the prefix*/
	leaf->pointer[middle] = pointer;
	memcpy(&leaf->prefix[middle], key_buf_prefix, PREFIX_SIZE);

	return ret;
}

char *node_type(nodeType_t type)
{
	switch (type) {
	case leafNode:
		return "leafNode";
	case leafRootNode:
		return "leafRootnode";
	case rootNode:
		return "rootNode";
	case internalNode:
		return "internalNode";
	default:
		assert(0);
	}
}

void assert_leaf_node(node_header *leaf)
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
			log_fatal("corrupted leaf index at index %llu total entries %llu", (LLU)i,
				  (LLU)leaf->numberOfEntriesInNode);
			printf("previous key is: %s\n", (char *)prev + sizeof(int32_t));
			printf("curr key is: %s\n", (char *)curr + sizeof(int32_t));
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
	}
}

void print_key(void *key)
{
	char tmp[32];
	memset(tmp, 0, 32);
	memcpy(tmp, ((char *)key) + sizeof(uint32_t), 16);
	printf("|%s|\n", tmp);
}

/**
 * gesalous 05/06/2014 17:30
 * added method for splitting an index node
 * @ struct btree_hanlde * handle: The handle of the B+ tree
 * @ node_header * req->node: Node to be splitted
 * @ void * key : pointer to key
 */
static bt_split_result split_index(node_header *node, bt_insert_req *ins_req)
{
	bt_split_result result;
	node_header *left_child;
	node_header *right_child;
	node_header *tmp_index;
	void *full_addr;
	void *key_buf;
	uint32_t i = 0;
	//assert_index_node(node);
	result.left_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->volume_desc,
		&ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id], INDEX_SPLIT);
	result.right_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->volume_desc,
		&ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id], INDEX_SPLIT);

	// result.left_child->v1++; /*lamport counter*/
	// result.right_child->v1++; /*lamport counter*/

#ifdef USE_SYNC
	__sync_synchronize();
#endif

	/*initialize*/
	full_addr = (void *)((uint64_t)node + (uint64_t)sizeof(node_header));
	/*set node heights*/
	result.left_child->height = node->height;
	result.right_child->height = node->height;

	for (i = 0; i < node->numberOfEntriesInNode; i++) {
		if (i < node->numberOfEntriesInNode / 2)
			tmp_index = result.left_child;
		else
			tmp_index = result.right_child;

		left_child = (node_header *)(MAPPED + *(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		key_buf = (void *)(MAPPED + *(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		right_child = (node_header *)(MAPPED + *(uint64_t *)full_addr);
		if (i == node->numberOfEntriesInNode / 2) {
			result.middle_key_buf = key_buf;
			continue; /*middle key not needed, is going to the upper level*/
		}

		insert_key_at_index(ins_req->metadata.handle, ins_req->metadata.level_id, (index_node *)tmp_index,
				    left_child, right_child, key_buf, KEY_LOG_SPLIT);
	}

	// result.left_child->v2++; /*lamport counter*/
	// result.right_child->v2++; /*lamport counter*/
	//assert_index_node(result.left_child);
	//assert_index_node(result.right_child);
	return result;
}

/**
 *  gesalous 26/05/2014 added method. Appends a key-value pair in a leaf node.
 *  returns 0 on success 1 on failure. Changed the default layout of leafs
 **/
/*Unused allocation_code XXX TODO XXX REMOVE */
int insert_KV_at_leaf(bt_insert_req *ins_req, node_header *leaf)
{
	void *key_addr = NULL;
	int ret;
	uint8_t level_id;
	uint8_t active_tree;

	level_id = ins_req->metadata.level_id;
	active_tree = ins_req->metadata.handle->db_desc->levels[level_id].active_tree;

	if (ins_req->metadata.append_to_log && ins_req->metadata.key_format == KV_FORMAT) {
		log_operation append_op = { .metadata = &ins_req->metadata,
					    .optype_tolog = insertOp,
					    .ins_req = ins_req };
		key_addr = append_key_value_to_log(&append_op);
	} else if (!ins_req->metadata.append_to_log && ins_req->metadata.key_format == KV_PREFIX)
		key_addr = ins_req->key_value_buf;

	else {
		log_fatal("Wrong combination of key format / append_to_log option");
		exit(EXIT_FAILURE);
	}

	if (__update_leaf_index(ins_req, (leaf_node *)leaf, key_addr) != 0) {
		++leaf->numberOfEntriesInNode;
		__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].total_keys[active_tree]), 1);
		ret = 1;
	} else {
		/*if key already present at the leaf, must be an update or an append*/
		leaf->fragmentation++;
		ret = 0;
	}

	return ret;
}

bt_split_result split_leaf(bt_insert_req *req, leaf_node *node)
{
	leaf_node *node_copy;
	bt_split_result rep;
	uint8_t level_id = req->metadata.level_id;
	/*cow check*/
	if (node->header.epoch <= req->metadata.handle->volume_desc->dev_catalogue->epoch) {
		level_id = req->metadata.level_id;
		node_copy = seg_get_leaf_node_header(req->metadata.handle->volume_desc,
						     &req->metadata.handle->db_desc->levels[level_id], COW_FOR_LEAF);

		memcpy(node_copy, node, LEAF_NODE_SIZE);
		node_copy->header.epoch = req->metadata.handle->volume_desc->mem_catalogue->epoch;
		node = node_copy;
	}

	rep.left_lchild = node;
	// rep.left_lchild->header.v1++;
	/*right leaf*/
	rep.right_lchild = seg_get_leaf_node(req->metadata.handle->volume_desc,
					     &req->metadata.handle->db_desc->levels[level_id], LEAF_SPLIT);
#ifdef USE_SYNC
	__sync_synchronize();
#endif

	rep.middle_key_buf = (void *)(MAPPED + node->pointer[node->header.numberOfEntriesInNode / 2]);
	/* pointers */
	memcpy(&(rep.right_lchild->pointer[0]), &(node->pointer[node->header.numberOfEntriesInNode / 2]),
	       ((node->header.numberOfEntriesInNode / 2) + (node->header.numberOfEntriesInNode % 2)) *
		       sizeof(uint64_t));

	/* prefixes */
	memcpy(&(rep.right_lchild->prefix[0]), &(node->prefix[node->header.numberOfEntriesInNode / 2]),
	       ((node->header.numberOfEntriesInNode / 2) + (node->header.numberOfEntriesInNode % 2)) * PREFIX_SIZE);

	rep.right_lchild->header.numberOfEntriesInNode =
		(node->header.numberOfEntriesInNode / 2) + (node->header.numberOfEntriesInNode % 2);
	rep.right_lchild->header.type = leafNode;

	rep.right_lchild->header.height = node->header.height;
	/*left leaf*/
	rep.left_lchild->header.height = node->header.height;
	rep.left_lchild->header.numberOfEntriesInNode = node->header.numberOfEntriesInNode / 2;

	if (node->header.type == leafRootNode) {
		rep.left_lchild->header.type = leafNode;
		// printf("[%s:%s:%d] leafRoot node splitted\n",__FILE__,__func__,__LINE__);
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = KREON_OK;

	// rep.left_lchild->header.v2++; /*lamport counter*/
	// rep.right_lchild->header.v2++; /*lamport counter*/
	return rep;
}

/**
 *	gesalous added at 30/05/2014 14:00, performs a binary search at an
 *index(root, internal node) and returns the index. We have
 *  a separate search function for index and leaves due to their different
 *format
 *  Updated (26/10/2016 17:05) key_buf can be in two formats
 *
 **/
void *_index_node_binary_search(index_node *node, void *key_buf, char query_key_format)
{
	void *addr = NULL;
	void *index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.numberOfEntriesInNode - 1;
	int32_t numberOfEntriesInNode = node->header.numberOfEntriesInNode;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if (ret == 0) {
			// log_debug("I passed from this corner case1 %s",
			// (char*)(index_key_buf+4));
			addr = &(node->p[middle].right[0]);
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case2 %s",
				// (char*)(index_key_buf+4));
				addr = &(node->p[middle].left[0]);
				middle--;
				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case3 %s",
				// (char*)(index_key_buf+4));
				addr = &(node->p[middle].right[0]);
				middle++;
				break;
			}
		}
	}

	if (middle < 0) {
		// log_debug("I passed from this corner case4 %s",
		// (char*)(index_key_buf+4));
		addr = &(node->p[0].left[0]);
	} else if (middle >= (int64_t)node->header.numberOfEntriesInNode) {
		// log_debug("I passed from this corner case5 %s",
		// (char*)(index_key_buf+4));
		/* log_debug("I passed from this corner case2 %s",
* (char*)(index_key_buf+4)); */
		addr = &(node->p[node->header.numberOfEntriesInNode - 1].right[0]);
	}
	// log_debug("END");
	return addr;
}

void spill_buffer(void *_spill_req)
{
	bt_spill_request *spill_req = (bt_spill_request *)_spill_req;
	db_descriptor *db_desc;
	level_scanner *level_sc;
	bt_insert_req ins_req;
	int32_t local_spilled_keys = 0;
	int i, rc = 100;
#ifndef NDEBUG
	int printfirstkey = 0;
#endif
	log_info("starting spill worker...");
	assert(spill_req->dst_tree > 0 && spill_req->dst_tree < 255);
	/*Initialize a scan object*/
	db_desc = spill_req->db_desc;
	log_info("Ops when %d joining function are %d", spill_req->src_level,
		 db_desc->levels[spill_req->src_level].outstanding_spill_ops);
	db_handle handle;
	handle.db_desc = spill_req->db_desc;
	handle.volume_desc = spill_req->volume_desc;

	level_sc = _init_spill_buffer_scanner(&handle, spill_req->src_root, NULL);
	assert(level_sc != NULL);
	int32_t num_of_keys = (SPILL_BUFFER_SIZE - (2 * sizeof(uint32_t))) / (PREFIX_SIZE + sizeof(uint64_t));

	do {
		while (handle.volume_desc->snap_preemption == SNAP_INTERRUPT_ENABLE)
			usleep(50000);

		db_desc->dirty = 0x01;
		if (handle.db_desc->db_mode == DB_IS_CLOSING) {
			log_info("db is closing bye bye from spiller");
			__sync_fetch_and_sub(&db_desc->levels[spill_req->src_level].outstanding_spill_ops, 1);
			return;
		}

		ins_req.metadata.handle = &handle;
		ins_req.metadata.level_id = spill_req->src_level + 1;
		ins_req.metadata.key_format = KV_PREFIX;
		ins_req.metadata.append_to_log = 0;
		ins_req.metadata.gc_request = 0;
		ins_req.metadata.recovery_request = 0;

		for (i = 0; i < num_of_keys; i++) {
			ins_req.key_value_buf = level_sc->keyValue;
#ifndef NDEBUG
			if (i == 0 && printfirstkey == 0) {
				log_info("First key_value %s",
					 (char *)(*(uint64_t *)((ins_req.key_value_buf + PREFIX_SIZE)) + 4));
				printfirstkey = 1;
			}
#endif
			_insert_key_value(&ins_req);
			rc = _get_next_KV(level_sc);
			if (rc == END_OF_DATABASE)
				break;

			++local_spilled_keys;
			//_sync_fetch_and_add(&db_desc->spilled_keys,1);
			if (spill_req->end_key != NULL &&
			    _tucana_key_cmp(level_sc->keyValue, spill_req->end_key, KV_PREFIX, KV_FORMAT) >= 0) {
				log_info("STOP KEY REACHED %s", (char *)spill_req->end_key + 4);
				goto finish_spill;
			}
		}
	} while (rc != END_OF_DATABASE);
finish_spill: /*Unused label*/

	_close_spill_buffer_scanner(level_sc, spill_req->src_root);
	log_info("local spilled keys %d", local_spilled_keys);
	/*Clean up code, Free the buffer tree was occupying. free_block() used
	 * intentionally*/

	__sync_fetch_and_sub(&db_desc->levels[spill_req->src_level].outstanding_spill_ops, 1);
	if (db_desc->levels[spill_req->src_tree].outstanding_spill_ops == 0) {
		log_info("last spiller cleaning up level %u remains", spill_req->src_level);
		level_scanner *sc = _init_spill_buffer_scanner(&handle, spill_req->src_root, NULL);

		_close_spill_buffer_scanner(sc, spill_req->src_root);
		segment_header *segment;

		segment = (void *)db_desc->levels[spill_req->src_level].first_segment[spill_req->src_tree];
		// size = db_desc->segments[(spill_req->src_tree_id * 3) + 1];
		while (1) {
			// if (size != BUFFER_SEGMENT_SIZE) {
			//	log_fatal("FATAL corrupted segment size %llu should be %llu",
			//(LLU)size,
			//		  (LLU)BUFFER_SEGMENT_SIZE);
			//	exit(EXIT_FAILURE);
			//}
			uint64_t s_id =
				((uint64_t)segment - (uint64_t)handle.volume_desc->bitmap_end) / BUFFER_SEGMENT_SIZE;
			// printf("[%s:%s:%d] freeing %llu size %llu s_id %llu freed pages
			// %llu\n",__FILE__,__func__,__LINE__,(LLU)free_addr,(LLU)size,(LLU)s_id,(LLU)handle->volume_desc->segment_utilization_vector[s_id]);
			if (handle.volume_desc->segment_utilization_vector[s_id] != 0 &&
			    handle.volume_desc->segment_utilization_vector[s_id] < SEGMENT_MEMORY_THREASHOLD) {
				// printf("[%s:%s:%d] last segment
				// remains\n",__FILE__,__func__,__LINE__);
				/*dimap hook, release dram frame*/
				/*if(dmap_dontneed(FD, ((uint64_t)free_addr-MAPPED)/PAGE_SIZE,
				  BUFFER_SEGMENT_SIZE/PAGE_SIZE)!=0){
				  printf("[%s:%s:%d] fatal ioctl failed\n",__FILE__,__func__,__LINE__);
				  exit(-1);
				  }
				  __sync_fetch_and_sub(&(handle->db_desc->zero_level_memory_size), (unsigned long
				  long)handle->volume_desc->segment_utilization_vector[s_id]*4096);
				*/
				handle.volume_desc->segment_utilization_vector[s_id] = 0;
			}
			free_raw_segment(handle.volume_desc, segment);
			if (segment->next_segment == NULL)
				break;
			segment = (segment_header *)(MAPPED + (uint64_t)segment->next_segment);
		}

		/*assert check
		  if(db_desc->spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
		  printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller
		  id
		  %d\n",__FILE__,__func__,__LINE__,(LLU)db_desc->spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id],
		  spill_req->src_tree_id);
		  exit(EXIT_FAILURE);
		  }*/
		/*buffered tree out*/
		db_desc->levels[spill_req->src_level].total_keys[spill_req->src_tree] = 0;
		db_desc->levels[spill_req->src_level].first_segment[spill_req->src_tree] = NULL;
		db_desc->levels[spill_req->src_level].last_segment[spill_req->src_tree] = NULL;
		db_desc->levels[spill_req->src_level].offset[spill_req->src_tree] = 0;
		db_desc->levels[spill_req->src_level].root_r[spill_req->src_tree] = NULL;
		db_desc->levels[spill_req->src_level].root_w[spill_req->src_tree] = NULL;
		db_desc->levels[spill_req->src_level].tree_status[spill_req->src_tree] = NO_SPILLING;
		if (spill_req->src_tree == 0)
			db_desc->L0_start_log_offset = spill_req->l0_end;
	}
	log_info("spill finished for level %u", spill_req->src_level);

	free(spill_req);
}

/*functions used for debugging*/
void assert_index_node(node_header *node)
{
	uint32_t k;
	void *key_tmp;
	void *key_tmp_prev = NULL;
	void *addr;
	node_header *child;
	addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header);
	if (node->numberOfEntriesInNode == 0)
		return;
	//	if(node->height > 1)
	//	log_info("Checking node of height %lu\n",node->height);
	for (k = 0; k < node->numberOfEntriesInNode; k++) {
		/*check child type*/
		child = (node_header *)(MAPPED + *(uint64_t *)addr);
		if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
		    child->type != leafRootNode) {
			log_fatal("corrupted child at index for child %llu type is %d\n", (LLU)(uint64_t)child - MAPPED,
				  child->type);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		addr += sizeof(uint64_t);
		key_tmp = (void *)MAPPED + *(uint64_t *)addr;
		// log_info("key %s\n", (char *)key_tmp + sizeof(int32_t));

		if (key_tmp_prev != NULL) {
			if (_tucana_key_cmp(key_tmp_prev, key_tmp, KV_FORMAT, KV_FORMAT) >= 0) {
				log_fatal("corrupted index %d:%s something else %d:%s\n", *(uint32_t *)key_tmp_prev,
					  key_tmp_prev + 4, *(uint32_t *)key_tmp, key_tmp + 4);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
		}

		key_tmp_prev = key_tmp;
		addr += sizeof(uint64_t);
	}
	child = (node_header *)(MAPPED + *(uint64_t *)addr);
	if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
	    child->type != leafRootNode) {
		log_fatal("Corrupted last child at index");
		exit(EXIT_FAILURE);
	}
	// printf("\t\tpointer to last child %llu\n", (LLU)(uint64_t)child-MAPPED);
}
#if 0
#endif

void print_node(node_header *node)
{
	printf("\n***Node synopsis***\n");
	if (node == NULL) {
		printf("NULL\n");
		return;
	}
	// printf("DEVICE OFFSET = %llu\n", (uint64_t)node - MAPPED);
	printf("type = %d\n", node->type);
	printf("total entries = %llu\n", (LLU)node->numberOfEntriesInNode);
	printf("epoch = %llu\n", (LLU)node->epoch);
	printf("height = %llu\n", (LLU)node->height);
	printf("fragmentation = %llu\n", (LLU)node->fragmentation);
}

uint64_t hash(uint64_t x)
{
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table *_find_position(lock_table **table, node_header *node)
{
	unsigned long position;
	lock_table *return_value;

	if (node->height < 0 || node->height >= MAX_HEIGHT) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	position = hash((uint64_t)node) % size_per_height[node->height];
	// log_info("node %llu height %d position %lu size of height %d", node,
	// node->height, position, size_per_height[node->height]);
	return_value = table[node->height];
	return &return_value[position];
}

void _unlock_upper_levels(lock_table *node[], unsigned size, unsigned release)
{
	unsigned i;
	for (i = release; i < size; ++i)
		if (RWLOCK_UNLOCK(&node[i]->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			exit(EXIT_FAILURE);
		}
}

#if 0
node_header *allocate_root(insertKV_request *req, node_header *son)
{
	node_header *node_copy = (*req->allocator_desc.allocate_space)((void *)req->allocator_desc.handle, NODE_SIZE,
								       req->allocator_desc.level_id, NEW_ROOT);
	memcpy(node_copy, son, NODE_SIZE);
	node_copy->epoch = req->handle->volume_desc->soft_superindex->epoch;
	node_copy->v1 = 0;
	node_copy->v2 = 0;
	return node_copy;
}
node_header *rcuLock(node_header *node, db_descriptor *db_desc, insertKV_request *req)
{
	if (node && (node->type == leafRootNode || node->type == rootNode)) {
		MUTEX_LOCK(&db_desc->rcu_root);
		__sync_fetch_and_add(&db_desc->rcu_root_v1, 1);
		return (req->level_id != NUM_OF_TREES_PER_LEVEL) ? db_desc->root_w[db_desc->active_tree] :
								   db_desc->root_w[NUM_OF_TREES_PER_LEVEL];
	}

	return NULL;
}

void rcuUnlock(node_header *node, db_descriptor *db_desc, insertKV_request *req)
{
	int i = (req->level_id != NUM_OF_TREES_PER_LEVEL) ? db_desc->active_tree : NUM_OF_TREES_PER_LEVEL;
	if (node)
		db_desc->root_w[i] = node;

	__sync_fetch_and_add(&db_desc->rcu_root_v2, 1);
	assert(db_desc->rcu_root_v1 == db_desc->rcu_root_v2);
	MUTEX_UNLOCK(&db_desc->rcu_root);
}

int splitValidation(node_header *father, node_header *son, db_descriptor *db_desc, split_request *split_req,
		    uint32_t order, split_data *data, insertKV_request *req)
{
	node_header *flag = NULL;
	int flow_control = 0;
	uint32_t temp_order;
	data->son = data->father = NULL;

	if (son->type == leafRootNode || son->type == rootNode || (father && father->type == rootNode)) {
		flag = rcuLock(son, db_desc, req);
		if (!flag) {
			flag = rcuLock(father, db_desc, req);
			if (flag)
				flow_control = 1;
		} else {
			flow_control = 2;
		}

		if (flag->type == leafRootNode)
			temp_order = leaf_order;
		else
			temp_order = index_order;
		if (flow_control == 2) { // son = root
			if (son->numberOfEntriesInNode != flag->numberOfEntriesInNode || son->height != flag->height ||
			    flag->numberOfEntriesInNode < temp_order) {
				rcuUnlock(NULL, db_desc, req);
				data->son = data->father = NULL;
				return -1;
			}

			if (flag->type == leafRootNode || flag->type == rootNode) {
				data->son = flag;
				return 1;
			}
			assert(0);

		} else if (flow_control == 1) {
			if (father->numberOfEntriesInNode != flag->numberOfEntriesInNode ||
			    father->height != flag->height || flag->numberOfEntriesInNode >= index_order ||
			    (flag->height - son->height) != 1) {
				rcuUnlock(NULL, db_desc, req);
				data->son = data->father = NULL;
				return -1;
			}

			if (flag->type == rootNode) { // I am a root child and i should acquire
				// its lock in order to insert the pivot
				// after the split.
				data->father = flag;
				return 1;
			}
			assert(0);
		}
	}
	if (son->type == leafRootNode || son->type == rootNode)
		assert(0);
	if (father && father->type == rootNode)
		assert(0);
	return 0;
}
#endif

void init_leaf_node(leaf_node *node)
{
	node->header.fragmentation = 0;
	node->header.v1 = 0;
	node->header.v2 = 0;
	node->header.first_IN_log_header = NULL;
	node->header.last_IN_log_header = NULL;
	node->header.key_log_size = 0;
	node->header.height = 0;
	node->header.type = leafNode;
	node->header.numberOfEntriesInNode = 0;
}

static void init_index_node(index_node *node)
{
	node->header.fragmentation = 0;
	node->header.v1 = 0;
	node->header.v2 = 0;
	node->header.type = internalNode;
	node->header.numberOfEntriesInNode = 0;
}

uint8_t _concurrent_insert(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	bt_split_result split_res;
	lock_table *lock;
	void *next_addr;
	pr_system_catalogue *mem_catalogue;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;

	index_node *new_index_node;
	node_header *node_copy;
	node_header *father;
	node_header *son;
	uint64_t addr;
	int64_t ret;
	unsigned size; /*Size of upper_level_nodes*/
	unsigned release; /*Counter to know the position that releasing should begin
           */
	uint32_t order;

	// remove some warnings here
	(void)ret;
	(void)addr;

	lock_table *guard_of_level;
	int64_t *num_level_writers;
	uint32_t level_id;
	uint32_t active_tree;

	volume_desc = ins_req->metadata.handle->volume_desc;
	db_desc = ins_req->metadata.handle->db_desc;
	level_id = ins_req->metadata.level_id;
	guard_of_level = &(db_desc->levels[level_id].guard_of_level);
	num_level_writers = &db_desc->levels[level_id].active_writers;

	release = 0;
	size = 0;

	int retry = 0;
release_and_retry:
	if (retry) {
		retry = 0;
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
	}

	retry = 1;
	size = 0;
	release = 0;
	if (RWLOCK_WRLOCK(&guard_of_level->rx_lock)) {
		log_fatal("Failed to acquire guard lock for level %u", level_id);
		exit(EXIT_FAILURE);
	}
	/*level's guard lock aquired*/
	upper_level_nodes[size++] = guard_of_level;
	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);
	if (ins_req->metadata.level_id == 0)
		active_tree = db_desc->levels[level_id].active_tree;
	else
		active_tree = ins_req->metadata.tree_id;

	mem_catalogue = ins_req->metadata.handle->volume_desc->mem_catalogue;

	father = NULL;

	/*cow logic follows*/
	if (db_desc->levels[level_id].root_w[active_tree] == NULL) {
		if (db_desc->levels[level_id].root_r[active_tree] != NULL) {
			if (db_desc->levels[level_id].root_r[active_tree]->type == rootNode) {
				index_node *t = seg_get_index_node_header(ins_req->metadata.handle->volume_desc,
									  &db_desc->levels[level_id], NEW_ROOT);
				memcpy(t, db_desc->levels[level_id].root_r[active_tree], INDEX_NODE_SIZE);
				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[active_tree] = (node_header *)t;
			} else {
				/*Tree too small consists only of 1 leafRootNode*/
				leaf_node *t = seg_get_leaf_node_header(ins_req->metadata.handle->volume_desc,
									&db_desc->levels[level_id], COW_FOR_LEAF);
				memcpy(t, db_desc->levels[level_id].root_r[active_tree], LEAF_NODE_SIZE);
				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[active_tree] = (node_header *)t;
			}
		} else {
			/*we are allocating a new tree*/

			log_info("Allocating new active tree %d for level id %d epoch is at %llu", active_tree,
				 level_id, (LLU)mem_catalogue->epoch);

			leaf_node *t = seg_get_leaf_node(ins_req->metadata.handle->volume_desc,
							 &db_desc->levels[level_id], NEW_ROOT);
			init_leaf_node(t);
			t->header.type = leafRootNode;
			t->header.epoch = mem_catalogue->epoch;
			db_desc->levels[level_id].root_w[active_tree] = (node_header *)t;
		}
	}
	/*acquiring lock of the current root*/
	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[active_tree]);
	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}
	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[active_tree];

	while (1) {
		if (son->type == leafNode || son->type == leafRootNode)
			order = leaf_order;
		else
			order = index_order;
		/*Check if father is safe it should be*/
		if (father) {
			unsigned int father_order;
			if (father->type == leafNode || father->type == leafRootNode)
				father_order = leaf_order;
			else
				father_order = index_order;
			assert(father->epoch > volume_desc->dev_catalogue->epoch);
			assert(father->numberOfEntriesInNode < father_order);
		}
		if (son->numberOfEntriesInNode >= order) {
			/*Overflow split*/
			if (son->height > 0) {
				son->v1++;
				split_res = split_index(son, ins_req);
				/*node has splitted, free it*/
				seg_free_index_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						    (index_node *)son);
				// free_logical_node(&(req->allocator_desc), son);
				son->v2++;
			} else {
				son->v1++;
				split_res = split_leaf(ins_req, (leaf_node *)son);
				if ((uint64_t)son != (uint64_t)split_res.left_child) {
					/*cow happened*/
					seg_free_leaf_node(ins_req->metadata.handle->volume_desc,
							   &ins_req->metadata.handle->db_desc->levels[level_id],
							   (leaf_node *)son);
					/*fix the dangling lamport*/
					split_res.left_child->v2++;
				} else
					son->v2++;
			}
			/*Insert pivot at father*/
			if (father != NULL) {
				/*lamport counter*/
				father->v1++;
				insert_key_at_index(ins_req->metadata.handle, level_id, (index_node *)father,
						    split_res.left_child, split_res.right_child,
						    split_res.middle_key_buf, KEY_LOG_EXPANSION);

				// log_info("pivot Key is %d:%s\n", *(uint32_t
				// *)split_res.middle_key_buf,
				//	 split_res.middle_key_buf + 4);
				// log_info("key at root entries now %llu checking health now",
				//	 father->numberOfEntriesInNode);
				// if (split_res.left_child->type != leafNode) {
				//	assert_index_node(split_res.left_child);
				//	assert_index_node(split_res.right_child);
				//}
				// assert_index_node(father);
				// log_info("node healthy!");

				/*lamport counter*/
				father->v2++;
			} else {
				/*Root was splitted*/
				// log_info("new root");
				new_index_node = seg_get_index_node(ins_req->metadata.handle->volume_desc,
								    &db_desc->levels[level_id], NEW_ROOT);
				init_index_node(new_index_node);
				new_index_node->header.type = rootNode;
				new_index_node->header.v1++; /*lamport counter*/
				son->v1++;
				insert_key_at_index(ins_req->metadata.handle, level_id, new_index_node,
						    split_res.left_child, split_res.right_child,
						    split_res.middle_key_buf, KEY_LOG_EXPANSION);

				new_index_node->header.v2++; /*lamport counter*/
				son->v2++;
				/*new write root of the tree*/
				db_desc->levels[level_id].root_w[active_tree] = (node_header *)new_index_node;
			}
			goto release_and_retry;
		} else if (son->epoch <= volume_desc->dev_catalogue->epoch) {
			/*Cow*/
			if (son->height > 0) {
				node_copy =
					(node_header *)seg_get_index_node_header(ins_req->metadata.handle->volume_desc,
										 &db_desc->levels[level_id],
										 COW_FOR_INDEX);
				memcpy(node_copy, son, INDEX_NODE_SIZE);
				seg_free_index_node_header(ins_req->metadata.handle->volume_desc,
							   &db_desc->levels[level_id], son);

			} else {
				node_copy =
					(node_header *)seg_get_leaf_node_header(ins_req->metadata.handle->volume_desc,
										&db_desc->levels[level_id],
										COW_FOR_LEAF);
				memcpy(node_copy, son, LEAF_NODE_SIZE);
				seg_free_leaf_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						   (leaf_node *)son);
			}
			node_copy->epoch = mem_catalogue->epoch;
			son = node_copy;
			/*Update father's pointer*/
			if (father != NULL) {
				father->v1++; /*lamport counter*/
				*(uint64_t *)next_addr = (uint64_t)node_copy - MAPPED;
				father->v2++; /*lamport counter*/
			} else { /*We COWED the root*/
				db_desc->levels[level_id].root_w[active_tree] = node_copy;
			}
			// log_info("son->epoch = %llu volume_desc->dev_catalogue->epoch %llu mem
			// "
			//        "epoch %llu",
			//         son->epoch, volume_desc->dev_catalogue->epoch,
			//         volume_desc->mem_catalogue->epoch);
			goto release_and_retry;
		}

		if (son->height == 0)
			break;
		/*Finding the next node to traverse*/
		next_addr = _index_node_binary_search((index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);
		father = son;
		/*Taking the lock of the next node before its traversal*/
		lock = _find_position(ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table,
				      (node_header *)(MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;
		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc %d");
			exit(EXIT_FAILURE);
		}
		/*Node acquired */
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);
		if (son->type == leafNode || son->type == leafRootNode)
			order = leaf_order;
		else
			order = index_order;
		/*if the node is not safe hold its ancestor's lock else release locks from
* ancestors */
		if (!(son->epoch <= volume_desc->dev_catalogue->epoch || son->numberOfEntriesInNode >= order)) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if (son->type != leafRootNode)
		assert((size - 1) - release == 0);

	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		exit(EXIT_FAILURE);
	}

	son->v1++; /*lamport counter*/
	ret = insert_KV_at_leaf(ins_req, son);
	son->v2++; /*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return SUCCESS;
}

static uint8_t _writers_join_as_readers(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	void *next_addr;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	node_header *son;
	lock_table *lock;

	uint64_t addr;
	int64_t ret;
	unsigned size; /*Size of upper_level_nodes*/
	unsigned release; /*Counter to know the position that releasing should begin
           */
	uint32_t order;

	// remove some warnings here
	(void)ret;
	(void)addr;
	uint32_t level_id;
	uint32_t active_tree;
	lock_table *guard_of_level;
	int64_t *num_level_writers;

	volume_desc = ins_req->metadata.handle->volume_desc;
	db_desc = ins_req->metadata.handle->db_desc;
	level_id = ins_req->metadata.level_id;
	guard_of_level = &db_desc->levels[level_id].guard_of_level;
	num_level_writers = &db_desc->levels[level_id].active_writers;

	size = 0;
	release = 0;

	/*
* Caution no retry here, we just optimistically try to insert,
* if we donot succeed we try with concurrent_insert
*/
	/*Acquire read guard lock*/
	if (RWLOCK_RDLOCK(&guard_of_level->rx_lock)) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}
	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);
	upper_level_nodes[size++] = guard_of_level;
	/*now check which is the current active tree, within the level*/
	if (ins_req->metadata.level_id == 0)
		active_tree = db_desc->levels[level_id].active_tree;
	else
		active_tree = ins_req->metadata.tree_id;

	if (db_desc->levels[level_id].root_w[active_tree] == NULL ||
	    db_desc->levels[level_id].root_w[active_tree]->type == leafRootNode) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return FAILURE;
	}

	/*acquire read lock of the current root*/
	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[active_tree]);
	if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}
	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[active_tree];
	while (1) {
		if (son->type == leafNode || son->type == leafRootNode)
			order = leaf_order;
		else
			order = index_order;
		if (son->numberOfEntriesInNode >= order) {
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return FAILURE;
		} else if (son->epoch <= volume_desc->dev_catalogue->epoch) {
			/*failed needs COW*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return FAILURE;
		}

		/*Find the next node to traverse*/
		next_addr = _index_node_binary_search((index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);
		if (son->height == 0)
			break;
		/*Acquire the lock of the next node before its traversal*/
		lock = _find_position(db_desc->levels[level_id].level_lock_table,
				      (node_header *)(MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;
		if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			exit(EXIT_FAILURE);
		}
		/*lock of node acquired */
		_unlock_upper_levels(upper_level_nodes, size - 1, release);
		release = size - 1;
	}

	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      (node_header *)(MAPPED + *(uint64_t *)next_addr));
	upper_level_nodes[size++] = lock;
	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR unlocking");
		exit(EXIT_FAILURE);
	}

	if (son->numberOfEntriesInNode >= (uint32_t)leaf_order || son->epoch <= volume_desc->dev_catalogue->epoch) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return FAILURE;
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		exit(EXIT_FAILURE);
	}
	son->v1++; /*lamport counter*/
	ret = insert_KV_at_leaf(ins_req, son);
	son->v2++; /*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return SUCCESS;
}
