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
#include "../allocator/dmap-ioctl.h"
//#include "../../fake_blk/include/fake_blk_ioctl.h"
#include <pthread.h>
#include "../scanner/scanner.h"
#include "../btree/stats.h"
#include "../btree/assertions.h"
#include "../btree/conf.h"

#define PREFIX_STATISTICS_NO


#define SYSTEM_NAME "kreon"

#define USE_SYNC
#undef USE_SYNC

#define DB_STILL_ACTIVE 0x01
#define COULD_NOT_FIND_DB 0x02

/*stats counters*/
extern uint64_t internal_tree_cow_for_leaf;
extern uint64_t internal_tree_cow_for_index;
extern uint64_t written_buffered_bytes;

extern unsigned long long ins_prefix_hit_l0;
extern unsigned long long ins_prefix_hit_l1;
extern unsigned long long ins_prefix_miss_l0;
extern unsigned long long ins_prefix_miss_l1;
extern unsigned long long ins_hack_hit;
extern unsigned long long ins_hack_miss;
volatile extern uint64_t snapshot_v1;
volatile extern uint64_t snapshot_v2;
extern db_handle* single_db;
extern char* pointer_to_kv_in_log;

int32_t index_order;
int32_t leaf_order;
char * DB_NO_SPILLING = NULL;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
/*number of locks per level*/
uint32_t size_per_height[MAX_HEIGHT]={8192,4096,2048,1024,512,256,128,64,32};

#define SPILLING_IN_PROGRESS 0x01
#define NO_SPILLING 0x00
#define PAGE_SIZE 4096
#define LEAF_ROOT_NODE_SPLITTED 0xFC

#define MUTATION_LOG_SIZE 2048
#define STATIC 0x01
#define DYNAMIC 0x02
#define MUTATION_BATCH_EXPANDED 0x03
#define FAILURE 0
void insertKeyAtIndex(allocator_descriptor * allocator_desc, node_header * node, node_header * left_child, node_header * right_child, void *key_buf, char allocation_code);
int8_t update_index(node_header* node, node_header * left_child, node_header * right_child, void *key_buf);
void split_index(split_request *req, split_reply * rep);

int __update_leaf_index(insertKV_request *req, leaf_node *leaf, void *key_buf, char key_format);

int split_leaf(split_request *req, split_reply *rep);

/*Buffering aware functions*/
void * __find_key(db_handle * handle, void *key, node_header * root, char SEARCH_MODE);
void *__find_key_addr_in_leaf(leaf_node *leaf, struct splice *key);
void spill_buffer(void * _spill_req);

void destroy_spill_request(NODE *node);
void * createEmptyNode(allocator_descriptor * allocator_desc, db_handle *handle, nodeType_t type, char allocation_code);

#ifdef DEBUG_TUCANA_2
static void assert_index_node(node_header * node);
void assert_leaf_node(node_header * leaf);
/*functions used for debugging*/
void print_node(node_header * node);
#endif

/*the size of both prefixes is 8 bytes FIXED!*/
int prefix_compare(char *l, char *r, size_t unused){
	return memcmp(l, r, unused);
}

/*free function for buffered trees, does nothing for now*/



/*XXX TODO XXX REMOVE HEIGHT UNUSED VARIABLE*/
void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height)
{

	db_handle * handle = (db_handle *)_handle;
	uint64_t segment_id = (uint64_t)address - (uint64_t)handle->volume_desc->bitmap_end;
	segment_id = segment_id - (segment_id%BUFFER_SEGMENT_SIZE);
	segment_id = segment_id/BUFFER_SEGMENT_SIZE;
#ifdef AGGRESIVE_FREE_POLICY
	__sync_fetch_and_sub(&(((db_handle *)_handle)->db_desc->zero_level_memory_size), (unsigned long long)num_bytes);

	handle->volume_desc->segment_utilization_vector[segment_id] += (num_bytes/DEVICE_BLOCK_SIZE);
	if(handle->volume_desc->segment_utilization_vector[segment_id] >= SEGMENT_MEMORY_THREASHOLD)
		handle->volume_desc->segment_utilization_vector[segment_id] = 0;
#else
	handle->volume_desc->segment_utilization_vector[segment_id] += (num_bytes/DEVICE_BLOCK_SIZE);
	if(handle->volume_desc->segment_utilization_vector[segment_id] >= SEGMENT_MEMORY_THREASHOLD)
	{
		__sync_fetch_and_sub(&(((db_handle *)_handle)->db_desc->zero_level_memory_size), (unsigned long long)BUFFER_SEGMENT_SIZE);
		/*dimap hook, release dram frame*/
		if(dmap_dontneed(FD, ((uint64_t)address-MAPPED)/PAGE_SIZE, BUFFER_SEGMENT_SIZE/PAGE_SIZE)!=0)
		{
			printf("[%s:%s:%d] fatal ioctl failed\n",__FILE__,__func__,__LINE__);
			exit(-1);
		}
		handle->volume_desc->segment_utilization_vector[segment_id] = 0;
		if(handle->db_desc->throttle_clients == STOP_INSERTS_DUE_TO_MEMORY_PRESSURE &&
		   handle->db_desc->zero_level_memory_size <= ZERO_LEVEL_MEMORY_UPPER_BOUND)
		{
			handle->db_desc->throttle_clients = NORMAL_OPERATION;
			printf("[%s:%s:%d] releasing clients\n",__FILE__,__func__,__LINE__);
		}
	}
#endif
	return;
}

/**
 * @param   index_key: address of the index_key
 * @param   index_key_len: length of the index_key in encoded form first 2 significant bytes row_key_size least 2 significant bytes quallifier size
 * @param   query_key: address of query_key
 * @param   query_key_len: query_key length again in encoded form
 */

int64_t _tucana_key_cmp(void *index_key_buf,void *query_key_buf,char index_key_format,char query_key_format){

	int64_t ret;
	uint32_t size;
	/*we need the left most entry*/
	if(query_key_buf == NULL)
		return 1;

	if(index_key_format == KV_FORMAT && query_key_format == KV_FORMAT){

		size = *(uint32_t *)index_key_buf;
		if(size > *(uint32_t *)query_key_buf)
			size = *(uint32_t *)query_key_buf;

		ret = memcmp((void *)index_key_buf+sizeof(uint32_t),(void *)query_key_buf+sizeof(uint32_t), size);
		if(ret != 0)
			return ret;
		else if(ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
			return 0;

		else{/*larger key wins*/

			if(*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
				return 1;
			else
				return -1;
		}
	}
	else if(index_key_format == KV_FORMAT && query_key_format == KV_PREFIX){

		if(*(uint32_t *)index_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf+sizeof(uint32_t), query_key_buf, PREFIX_SIZE);
		else//check here TODO
			ret = prefix_compare(index_key_buf+sizeof(uint32_t), query_key_buf, *(int32_t *)index_key_buf);
		if(ret == 0){/* we have a tie, prefix didn't help, fetch query_key form KV log*/

			query_key_buf = (void *)(*(uint64_t *)(query_key_buf+PREFIX_SIZE));

			size = *(uint32_t *)index_key_buf;
			if(size > *(uint32_t *)query_key_buf)
				size = *(uint32_t *)query_key_buf;

			ret = memcmp((void *)index_key_buf+sizeof(uint32_t),(void *)query_key_buf+sizeof(uint32_t), size);

			if(ret != 0)
				return ret;
			else if(ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;

			else{/*larger key wins*/
				if(*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		}
		else
			return ret;
	}
	else if (index_key_format == KV_PREFIX && query_key_format == KV_FORMAT){

		if(*(uint32_t *)query_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf, query_key_buf+sizeof(uint32_t), PREFIX_SIZE);
		else//check here TODO
			ret = prefix_compare(index_key_buf, query_key_buf+sizeof(uint32_t), *(int32_t *)query_key_buf);
		if(ret == 0){/* we have a tie, prefix didn't help, fetch query_key form KV log*/
			index_key_buf = (void *)(*(uint64_t *)(index_key_buf+PREFIX_SIZE));

			size = *(uint32_t *)query_key_buf;
			if(size > *(uint32_t *)index_key_buf)
				size = *(uint32_t *)index_key_buf;


			ret = memcmp((void *)index_key_buf+sizeof(uint32_t),(void *)query_key_buf+sizeof(uint32_t), size);
			if(ret != 0)
				return ret;
			else if(ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;
			else{/*larger key wins*/

				if(*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		}
		else
			return ret;
	}else {
		printf("[%s %s %d]: FATAL, combination not supported please check\n", __func__,__FILE__,__LINE__);
		exit(-1);
	}
	return 0;
}

/**
 * @param   blockSize
 * @param   db_name
 * @return  db_handle
 **/
db_handle * db_open(char * volumeName, uint64_t start, uint64_t size, char * db_name, char CREATE_FLAG){

	db_handle * handle;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	char * key;
	uint64_t val;
	int  i,m;
	int digits;
	int new_db = 0;

	i = 0;
	fprintf(stderr, "%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n","\033[0;32m", __FILE__,__func__, __LINE__, volumeName, start, size, db_name, "\033[0m");
	MUTEX_LOCK(&init_lock);

	/*just once, generic initialization for DB_NO_SPILLING mask*/
	if(DB_NO_SPILLING == NULL){
		DB_NO_SPILLING = (char *)malloc(sizeof(char)*NUM_OF_TREES_PER_LEVEL);
		memset(&DB_NO_SPILLING[0],NO_SPILLING,sizeof(char)*NUM_OF_TREES_PER_LEVEL);
	}

	if(mappedVolumes == NULL){
		mappedVolumes= initList(&destroy_volume_node);
		/*calculate max leaf,index order*/
		leaf_order  = (DEVICE_BLOCK_SIZE - sizeof(node_header)) / (sizeof(uint64_t)+PREFIX_SIZE);
		index_order = (DEVICE_BLOCK_SIZE - sizeof(node_header)) / (2*sizeof(uint64_t));
		index_order-= 2;/*more space for extra pointer, and for rebalacing (merge)*/
		while(index_order%2 != 1)
			--index_order;

		if((NODE_SIZE-sizeof(node_header))%8 != 0){
			printf("[%s:%s:%d] Misaligned block header for leaf nodes, scans will not work\n",__FILE__,__func__,__LINE__);
			exit(-1);
		}
		if((NODE_SIZE-sizeof(node_header))%16 != 0){
			printf("[%s:%s:%d]: Misaligned block header for index nodes, scans will not work size of node_header %ld\n",__FILE__,__func__,__LINE__, sizeof(node_header));
			exit(-1);
		}
		printf("[%s:%s:%d] index order is set to: %d leaf order is set to %d sizeof node_header = %lu\n",
		       __FILE__,__func__,__LINE__,index_order, leaf_order, sizeof(node_header));
	}
	/*Is requested volume already mapped?, construct key which will be volumeName|start*/
	val = start;
	digits = 0;
	while(val > 0){
		val = val/10;
		digits++;
	}
	if(digits == 0)
		digits = 1;

	key = malloc(strlen(volumeName) + digits + 1);
	strcpy(key,volumeName);
	sprintf(key+strlen(volumeName), "%llu", (LLU)start);
	key[strlen(volumeName)+digits] = '\0';
	volume_desc = (volume_descriptor *)findElement(mappedVolumes, key);


	if(volume_desc == NULL){

		volume_desc = malloc(sizeof(volume_descriptor));
		volume_desc->state = VOLUME_IS_OPEN;
		volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;
		volume_desc->last_snapshot = get_timestamp();
		volume_desc->last_commit = get_timestamp();
		volume_desc->last_sync = get_timestamp();

		volume_desc->volume_name = malloc(strlen(volumeName)+1);
		strcpy(volume_desc->volume_name, volumeName);
		volume_desc->volume_id = malloc(strlen(key)+1);
		strcpy(volume_desc->volume_id, key);
		volume_desc->open_databases = initList(&destoy_db_list_node);
		volume_desc->offset = start;
		volume_desc->size  = size;
		MUTEX_INIT(&(volume_desc->allocator_lock),NULL);
		/*hack*/
		MUTEX_INIT(&(volume_desc->lock_log),NULL);
		allocator_init(volume_desc);
		addFirst(mappedVolumes, volume_desc, key);
		volume_desc->reference_count++;
		/*soft state about the in use pages of level-0 for each BUFFER_SEGMENT_SIZE segment inside the volume*/
		volume_desc->segment_ulitization_vector_size = ((volume_desc->volume_superblock->dev_size_in_blocks - (1+FREE_LOG_SIZE+volume_desc->volume_superblock->bitmap_size_in_blocks))/(BUFFER_SEGMENT_SIZE/DEVICE_BLOCK_SIZE)) * 2;
		volume_desc->segment_utilization_vector = (uint16_t*)malloc(volume_desc->segment_ulitization_vector_size);
		memset(volume_desc->segment_utilization_vector,0x00,volume_desc->segment_ulitization_vector_size);

		printf("[%s:%s:%d] volume %s state created max_tries %d\n",__FILE__,__func__,__LINE__,volume_desc->volume_name,MAX_ALLOCATION_TRIES);
	} else {
		printf("[%s:%s:%d] Volume already mapped\n",__FILE__,__func__,__LINE__);
		volume_desc->reference_count++;
	}
	/*Before searching the actual volume's catalogue take a look at the current open databases*/
	db_desc = findElement(volume_desc->open_databases, db_name);
	superindex_db_entry * db_entry;

	if(db_desc != NULL) {
		printf("[%s:%s:%d] DB %s already open for volume %s\n",__FILE__,__func__,__LINE__,db_name,key);
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		db_desc->reference_count++;
		db_desc->active_tree = 0;
		for(m=0;m<TOTAL_TREES;m++)
			db_desc->tree_status[m] = NO_SPILLING;
		MUTEX_UNLOCK(&init_lock);
		free(key);
		return handle;
	} else {
		int32_t empty_group;
		int32_t empty_index;
		int32_t j;

		printf("[%s:%s:%d] searching %s's  catalogue for db %s\n",__FILE__,__func__,__LINE__,SYSTEM_NAME,db_name);

		empty_group = -1;
		empty_index = -1;
		/*we are going to search system's catalogue to find the root_r of the corresponding database*/
		for(i=0;i<NUM_OF_DB_GROUPS; i++){
			/*is group empty?*/

			if(volume_desc->soft_superindex->db_group_index[i] != 0){
				for(j=0;j<GROUP_SIZE;j++){
					db_entry = (superindex_db_entry *)(MAPPED+ (uint64_t)volume_desc->soft_superindex->db_group_index[i] + (uint64_t)DB_ENTRY_SIZE+(uint64_t)(j*DB_ENTRY_SIZE));
					if(*(int32_t *)db_entry == 0){/*empty slot keep in mind*/

						if(empty_index == -1){
							printf("[%s:%s:%d] empty slot %d in group %d\n",__FILE__,__func__,__LINE__,i,j);
							empty_group = i;
							empty_index = j;
						}
					}
					else if(strcmp((const char *)db_entry->db_name,(const char *)db_name) == 0){/*found it*/
						/*database found, restore state,
						 * recover state if needed and
						 * create the appropriate handle
						 * and store it in the open_db's
						 * list
						 */
						printf("[:%s:%s:%d] database: %s found at index [%d,%d]\n",__FILE__,__func__,__LINE__,db_entry->db_name,i,j);
						handle = malloc(sizeof(db_handle));
						memset(handle, 0x00, sizeof(db_handle));
						db_desc = malloc(sizeof(db_descriptor));
						db_desc->zero_level_memory_size = 0;
						handle->volume_desc = volume_desc;
						handle->db_desc = db_desc;
						/*initialize database descriptor, soft state first*/
						db_desc->reference_count = 0;
						db_desc->group_id = i;
						db_desc->group_index = j;
						/*restore db name, in memory*/
						memset(db_desc->db_name,0x00,MAX_DB_NAME_SIZE);
						strcpy(db_desc->db_name, db_entry->db_name);

						db_desc->dirty = 0;
						/*restore now persistent state*/
#ifdef SCAN_REORGANIZATION
						db_desc->leaf_id = db_entry->leaf_id;
						memset(db_desc->scan_access_counter,0x00,COUNTER_SIZE);
#endif
						/*total keys*/
						for(m=0;m<TOTAL_TREES;m++){
							db_desc->total_keys[m] = db_entry->total_keys[m];
							if(db_entry->segments[m*3] != 0){

								db_desc->segments[m*3] = MAPPED+db_entry->segments[m*3];/*start of segment*/
								db_desc->segments[(m*3)+1] = db_entry->segments[(m*3)+1];/*size of segment*/
								db_desc->segments[(m*3)+2] = db_entry->segments[(m*3)+2];/*position of segment*/
							} else {
								db_desc->segments[m*3] = 0;/*start of segment*/
								db_desc->segments[(m*3)+1] = 0;/*size of segment*/
								db_desc->segments[(m*3)+2] = 0;/*position of segment*/
							}
							/*restore root_r of each level*/
							if(db_entry->root_r[m] != NULL)
								db_desc->root_r[m] = (node_header *)(MAPPED + (uint64_t)db_entry->root_r[m]);
							else
								db_desc->root_r[m] = NULL;
							printf("[%s:%s::%d] root_r[%d] = %llu stored = %llu\n",__FILE__,__func__,__LINE__,m,(LLU)db_desc->root_r[m],(LLU)db_entry->root_r[m]);
						}
						/*recover KV log for this database*/
						if(db_entry->g_first_kv_log != NULL)
							db_desc->g_first_kv_log = (block_header *)(MAPPED+ (uint64_t)db_entry->g_first_kv_log);
						else
							db_desc->g_first_kv_log = NULL;

						if(db_entry->g_last_kv_log != NULL)
							db_desc->g_last_kv_log = (block_header *)(MAPPED+ (uint64_t)db_entry->g_last_kv_log);
						else
							db_desc->g_last_kv_log = NULL;

						db_desc->g_kv_log_size = db_entry->g_kv_log_size;
						db_desc->commit_log =  (commit_log_info *)(MAPPED + ((uint64_t)db_entry->commit_log));
						printf("[%s:%s:%d] g_kv log segments first: %llu last: %llu log_size %llu\n",__FILE__,__func__,__LINE__,
						       (LLU)db_desc->g_first_kv_log,(LLU)db_desc->g_last_kv_log, (LLU)db_desc->g_kv_log_size);
						printf("[%s:%s:%d] commit log segments first: %llu last: %llu commit_log_size %llu\n",__FILE__,__func__,__LINE__,
						       (LLU)(uint64_t)(db_desc->commit_log->first_kv_log)+MAPPED,(LLU)(uint64_t)(db_desc->commit_log->last_kv_log)+MAPPED,(LLU)db_desc->commit_log->kv_log_size);

						/*nullify write roots*/
						memset(db_desc->root_w, 0x00, sizeof(uint64_t)*TOTAL_TREES);
						goto finish_init;
					}
				}
			}
			else if(empty_group == -1)
				empty_group = i;
		}
		if(CREATE_FLAG != O_CREATE_DB && CREATE_FLAG != O_CREATE_REPLICA_DB){
			printf("[%s:%s:%d] DB not found instructed not to create one returning NULL\n",__FILE__,__func__,__LINE__);
			return NULL;
		}
		/*db not found allocate a new slot for it*/
		if(empty_group == -1 && empty_index == -1){
			printf("[%s:%s:%d] FATAL MAX DBS %d reached\n",__FILE__,__func__,__LINE__,NUM_OF_DB_GROUPS*GROUP_SIZE);
			exit(-1);
		}
		if(empty_index == -1){
			/*space found in empty group*/
			superindex_db_group * new_group  = (superindex_db_group *)allocate_segment(volume_desc, DEVICE_BLOCK_SIZE,SYSTEM_ID, NEW_GROUP);
			memset(new_group,0x00,DEVICE_BLOCK_SIZE);
			new_group->epoch = volume_desc->soft_superindex->epoch;
			volume_desc->soft_superindex->db_group_index[empty_group] = (superindex_db_group *)((uint64_t)new_group-MAPPED);
			empty_index = 0;
		}
		printf("[%s:%s:%d] database %s not found, allocating slot [%d,%d] for it\n", __FILE__,__func__,__LINE__,(const char *)db_name,empty_group,empty_index);
		db_entry = (superindex_db_entry*)(MAPPED + (uint64_t)volume_desc->soft_superindex->db_group_index[empty_group] +(uint64_t)DB_ENTRY_SIZE+(uint64_t)(empty_index*DB_ENTRY_SIZE));
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		db_desc = (db_descriptor *)malloc(sizeof(db_descriptor));
#ifdef SCAN_REORGANIZATION
		db_desc->leaf_id = 0;
		memset(db_desc->scan_access_counter,0x00,COUNTER_SIZE);
#endif
		db_desc->zero_level_memory_size = 0;
		memset(db_desc,0x00,sizeof(db_descriptor));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		/*initialize database descriptor, soft state first*/
		db_desc->reference_count = 0;
		db_desc->group_id = empty_group;
		db_desc->group_index = empty_index;

		/*stored db name, in memory*/
		memset(db_entry->db_name,0x00, MAX_DB_NAME_SIZE);
		strcpy(db_entry->db_name,db_name);
		memset(db_desc->db_name,0x00,MAX_DB_NAME_SIZE);
		strcpy(db_desc->db_name,db_name);
		db_desc->dirty = 0x01;
		/*segments where persistent trees live*/
		memset(db_desc->segments,0x00,sizeof(uint64_t)*TOTAL_TREES*3);
		memset(db_entry->segments,0x00,sizeof(uint64_t)*TOTAL_TREES*3);

		/*restore root_r of each level*/
		memset(db_desc->root_r,0x00,sizeof(node_header *)*TOTAL_TREES);
		memset(db_entry->root_r,0x00,sizeof(node_header *)*TOTAL_TREES);
		/*nullify write roots*/
		memset(db_desc->root_w, 0x00, sizeof(node_header *)*TOTAL_TREES);
		/*finally initialize total keys for each level*/
		memset(db_desc->total_keys,0x00,sizeof(uint64_t)*TOTAL_TREES);
		memset(db_entry->total_keys,0x00,sizeof(uint64_t)*TOTAL_TREES);
		/*initialize KV log for this db*/
		db_desc->g_first_kv_log = (block_header *)allocate_segment(handle,BUFFER_SEGMENT_SIZE, KV_LOG_ID,KV_LOG_EXPANSION);
		memset(db_desc->g_first_kv_log->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
		db_desc->g_first_kv_log->next_block = NULL;
		db_desc->g_last_kv_log = db_desc->g_first_kv_log;
		db_desc->g_kv_log_size = sizeof(block_header);
		/*get a page for commit_log info*/
		db_desc->commit_log = (commit_log_info *)allocate_segment(volume_desc, DEVICE_BLOCK_SIZE,SYSTEM_ID, NEW_COMMIT_LOG_INFO);

		db_entry->g_first_kv_log = (block_header *)((uint64_t)db_desc->g_first_kv_log - MAPPED);
		db_entry->g_last_kv_log = (block_header *)((uint64_t)db_desc->g_last_kv_log - MAPPED);
		db_entry->g_kv_log_size = (uint64_t)db_desc->g_kv_log_size;
		db_desc->commit_log->first_kv_log = db_entry->g_first_kv_log;
		db_desc->commit_log->last_kv_log = db_entry->g_last_kv_log;
		db_desc->commit_log->kv_log_size =  db_entry->g_kv_log_size;
		/*persist commit log information, this location stays permanent
		 * there no need to rewrite it during snapshot()*/
		db_entry->commit_log = (commit_log_info *)((uint64_t)db_desc->commit_log - MAPPED);

		new_db = 1;
	}
	/*finally, finish initialization*/
finish_init:
	if (MUTEX_INIT(&volume_desc->gc_mutex, NULL) != 0){
		fprintf(stderr,"GC MUTEX INIT FAILED\n");
		exit(-1);
	}

	if (pthread_cond_init(&volume_desc->gc_cond, NULL) != 0){
		fprintf(stderr,"GC cond init failed\n");
		exit(-1);
	}

#if GARBAGE_COLLECTION
	if(pthread_create(&volume_desc->gc_log_cleaner, NULL, (void *) gc_log_entries,volume_desc) == -1){
		fprintf(stderr, "FATAL Error starting gc thread system exiting\n");
		exit(-1);
	}
#endif
	//db_desc->spilled_keys = 0;
	MUTEX_INIT(&db_desc->rcu_root,NULL);
	MUTEX_INIT(&db_desc->rcu_root,NULL);
	MUTEX_INIT(&db_desc->spill_trigger,NULL);
	db_desc->rcu_root_v1 = db_desc->rcu_root_v2 = 0;
	db_desc->spill_v1 = db_desc->spill_v2 = 0;
	db_desc->createEmptyNode = &createEmptyNode;
	db_desc->atomic_spill = 0;
#ifdef LOG_WITH_MUTEX
	pthread_mutex_init(&db_desc->lock_log, NULL);
#elif SPINLOCK
	SPINLOCK_INIT(&db_desc->lock_log,PTHREAD_PROCESS_PRIVATE);
#endif
	db_desc->active_tree = 0;
	/*which tree is the active one?*/
	single_db = handle;
	/*we are allocating a new tree*/

	for(m=0;m<TOTAL_TREES;m++)
		db_desc->tree_status[m] = NO_SPILLING;

	addFirst(volume_desc->open_databases, db_desc, db_name);
	MUTEX_UNLOCK(&init_lock);
	free(key);

	if(CREATE_FLAG == O_CREATE_DB){
		printf("[%s:%s:%d] opened primary db\n",__FILE__,__func__,__LINE__);
		db_desc->db_mode = PRIMARY_DB;
	} else {
		printf("[%s:%s:%d] opened replica db\n",__FILE__,__func__,__LINE__);
		db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		init_backup_db_segment_table(handle);
	}

	/*for replica only*/
	db_desc->g_first_backup_kv_log = NULL;
	db_desc->g_last_backup_kv_log = NULL;
	db_desc->g_backup_kv_log_size = 0;

	_init_locktable(db_desc);
	db_desc->count_writers_level_0 = 0;
	db_desc->count_writers_level_1 = 0;
	db_desc->count_active_spillers = 0;

	/*XXX TODO XXX recovery stub*/
	if( MAPPED+(uint64_t)db_desc->commit_log->last_kv_log != (uint64_t)db_desc->g_last_kv_log
	    ||  db_desc->commit_log->kv_log_size != db_desc->g_kv_log_size){
		printf("[%s:%s:%d] initiating db recovery\n",__FILE__,__func__,__LINE__);
		recovery_request rh;
		rh.volume_desc = volume_desc;
		rh.db_desc = db_desc;
		recovery_worker(&rh);
		printf("[%s:%s:%d] recovery done successfully\n",__FILE__,__func__,__LINE__);
	}
	printf("[%s:%s:%d] db %s ready :-)\n",__FILE__,__func__,__LINE__,db_desc->db_name);

	if(new_db)
		init_index(handle);
	else{
		for(i=0;i<TOTAL_TREES;i++){
			if(db_desc->root_r[i] != NULL){
				if(i!=4){
					allocator_descriptor temp;
					temp.allocate_space = &allocate_segment;
					temp.handle = NULL;
					temp.level_id = 0;

					/*Level 0*/
					allocate_segment(handle,BUFFER_SEGMENT_SIZE,i,NEW_LEVEL_0_TREE);
					db_desc->root_w[i] = (node_header *)db_desc->createEmptyNode(&temp, handle, leafRootNode, NEW_ROOT);
					memcpy(db_desc->root_w[i],db_desc->root_r[i],NODE_SIZE);
					db_desc->root_w[i]->epoch += 2;
					cow_nodes_related_toroot(db_desc,db_desc->root_w[i]);
				}else{
					/*Level 1*/
					allocator_descriptor temp;
					temp.allocate_space = &allocate_segment;
					temp.handle = NULL;
					temp.level_id = NUM_OF_TREES_PER_LEVEL;

					allocate_segment(handle,BUFFER_SEGMENT_SIZE,4,NEW_LEVEL_1_TREE);
					db_desc->root_w[4] = (node_header *)db_desc->createEmptyNode(&temp, handle, leafRootNode, NEW_ROOT);
					memcpy(db_desc->root_w[4],db_desc->root_r[4],NODE_SIZE);
					db_desc->root_w[4]->epoch += 2;
					cow_nodes_related_toroot(db_desc,db_desc->root_w[4]);
				}
			}
		}
	}
	assert(leaf_order == LN_LENGTH);
	assert(index_order == IN_LENGTH);
	return handle;
}

void init_index(db_handle* handle)
{
	allocator_descriptor temp;
	temp.allocate_space = &allocate_segment;
	temp.free_space = &free_buffered;
	temp.handle = handle;

	temp.level_id = 0;
	allocate_segment(handle, BUFFER_SEGMENT_SIZE, handle->db_desc->active_tree, NEW_LEVEL_0_TREE);
	handle->db_desc->root_w[handle->db_desc->active_tree] = (node_header *)createEmptyNode(&temp, handle, leafRootNode, NEW_ROOT);

	temp.level_id = 1;
	allocate_segment(handle, BUFFER_SEGMENT_SIZE, NUM_OF_TREES_PER_LEVEL, NEW_LEVEL_1_TREE);
	handle->db_desc->root_w[NUM_OF_TREES_PER_LEVEL] = (node_header *)createEmptyNode(&temp, handle, leafRootNode, NEW_ROOT);
}

char db_close(db_handle *handle){

	handle->db_desc->db_mode = DB_IS_CLOSING;
	/*spinning*/
	/*wait level 0 writers for this db to finish*/
	spin_loop(&(handle->db_desc->count_writers_level_0), 0);
	/*wait level 1 writers for this db*/
	spin_loop(&(handle->db_desc->count_writers_level_1), 1);
	/*wait spillers fot this db*/
	spin_loop(&(handle->db_desc->count_active_spillers), 0);
	printf("[%s:%s:%d] closing region, prior call to DB_CLOSE_NOTIFY needed!\n",__FILE__,__func__,__LINE__);


	commit_kv_log(handle->volume_desc, handle->db_desc, UNIQUE_DB);
	_destroy_locktable(handle->db_desc);
	if(handle->db_desc->backup_segment_table != NULL){
		map_entry *current, *tmp;
		HASH_ITER(hh,handle->db_desc->backup_segment_table,current,tmp) {
			HASH_DEL(handle->db_desc->backup_segment_table, current);  /* delete it (users advances to next) */
			free(current);/* free it */
		}
	}

	if(removeElement(handle->volume_desc->open_databases, handle->db_desc) != 1){
		printf("[%s:%s:%d] could not find db: %s\n",__FILE__,__func__,__LINE__, handle->db_desc->db_name);
		MUTEX_UNLOCK(&init_lock);
		return COULD_NOT_FIND_DB;
	}
	free(handle->db_desc);
	return KREON_OK;
}

void destroy_spill_request(NODE *node){
	free(node->data);/*the actual spill_request*/
	free(node);
}


void spill_database(db_handle * handle){
	int32_t i;

	fprintf(stderr, "[%s:%s:%d] Initializaing spill\n",__FILE__,__func__,__LINE__);

	if(memcmp(handle->db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) != 0){
		printf("[%s:%s:%d] Nothing to do spill operation already active\n",__FILE__,__func__,__LINE__);
		return;
	}

	spin_loop(&handle->db_desc->count_writers_level_0,0);
	fprintf(stderr, "[%s:%s:%d] Initializaing spill passed spin_loop\n",__FILE__,__func__,__LINE__);

	/*switch to another tree, but which?*/
	for(i=0;i<NUM_OF_TREES_PER_LEVEL;i++){
		if(i!= handle->db_desc->active_tree && handle->db_desc->tree_status[i] != SPILLING_IN_PROGRESS){
			int32_t level_id = handle->db_desc->active_tree;
			handle->db_desc->tree_status[level_id] = SPILLING_IN_PROGRESS;
			handle->db_desc->active_tree = i;

			/*spawn a spiller thread*/
			spill_request * spill_req = (spill_request *)malloc(sizeof(spill_request));/*XXX TODO XXX MEMORY LEAK*/
			spill_req->handle = handle;
			if(handle->db_desc->root_w[level_id]!=NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else if(handle->db_desc->root_r[level_id]!=NULL)
				spill_req->src_root = handle->db_desc->root_r[level_id];
			else{
				printf("[%s:%s:%d] empty level-0, nothing to do\n",__FILE__,__func__,__LINE__);
				free(spill_req);
				handle->db_desc->tree_status[level_id] = NO_SPILLING;
				break;
			}
			if(handle->db_desc->root_w[level_id]!=NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else
				spill_req->src_root = handle->db_desc->root_r[level_id];

			spill_req->src_tree_id = level_id;
			spill_req->dst_tree_id = NUM_OF_TREES_PER_LEVEL;
			spill_req->start_key = NULL;
			spill_req->end_key = NULL;
			handle->db_desc->count_active_spillers=1;
			if(pthread_create(&handle->db_desc->spiller[0],NULL,(void *)spill_buffer, (void *)spill_req)!=0){
				printf("[%s:%s:%d] FATAL: error creating spiller thread\n",__FILE__,__func__,__LINE__);
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
}

/*method for closing a database*/
void flush_volume(volume_descriptor *volume_desc, char force_spill)
{
	db_descriptor * db_desc;
	db_handle * handles;
	handles = (db_handle *)malloc(sizeof(db_handle)*volume_desc->open_databases->size);


	int db_id = 0;
	NODE *node;
	int i;

	while(1){
		printf("[%s:%s:%d] waiting for pending spills to finish\n",__FILE__,__func__,__LINE__);
		node = getFirst(volume_desc->open_databases);
		while(node != NULL){
			db_desc = (db_descriptor *) (node->data);
			/*wait for pending spills for this db to finish*/
			i = 0;
			while(i<TOTAL_TREES){
				if(db_desc->tree_status[i] == SPILLING_IN_PROGRESS){
					printf("[%s:%s:%d] waiting for db %s to finish spills, status %d, i = %d\n",__FILE__,__func__,__LINE__, db_desc->db_name, db_desc->tree_status[i], i);
					sleep(4);
					i = 0;
				}
				else
					i++;
			}
			node = node->next;
		}
		printf("[%s:%s:%d] ok... no pending spills\n",__FILE__,__func__,__LINE__);

		if(force_spill == SPILL_ALL_DBS_IMMEDIATELY){

			node = getFirst(volume_desc->open_databases);
			while(node != NULL){
				handles[db_id].db_desc =  (db_descriptor *) (node->data);
				handles[db_id].volume_desc =  volume_desc;
				spill_database(&handles[db_id]);
				++db_id;
				node = node->next;
			}
			force_spill = SPILLS_ISSUED;
		}
		else
			break;
	}
	printf("[%s:%s:%d] Finally, snapshoting volume\n",__FILE__,__func__,__LINE__);
	snapshot(volume_desc);
	free(handles);
	return;
}


/*XXX TODO XXX fix function to enable atomic insert batch*/
uint8_t insert_write_batch(db_handle * handle, mutation_batch * batch){

	printf("[%s:%s:%d]FATAL ERROR FUNCTION needs fix\n",__FILE__,__func__,__LINE__);
	exit(EXIT_FAILURE);
	void * key;
	void * value;
	uint32_t pos = 0;
	uint32_t idx = 0;
	uint8_t status = SUCCESS;
	/*throttle control check*/
	printf("[%s:%s:%d]Warning Unchecked function\n",__FILE__,__func__,__LINE__);
	while(handle->db_desc->zero_level_memory_size > ZERO_LEVEL_MEMORY_UPPER_BOUND){
		usleep(THROTTLE_SLEEP_TIME);
	}
	/*parse the batch operation log and put it in the tree*/
	while( (batch->num_of_mutations == DYNAMIC_KEYS) || (idx < batch->num_of_mutations)){
		key = (void *)((uint64_t)batch->buffer + pos);
		pos += (sizeof(uint32_t)+*(uint32_t *)key);
		value = (void *)((uint64_t)batch->buffer + pos);
		pos += (sizeof(uint32_t)+*(uint32_t *)value);
		status = _insert_key_value(handle, key, INSERT_TO_L0_INDEX | APPEND_TO_LOG);
		idx++;
		if(status != SUCCESS || pos >= batch->size)
			break;
	}
	return status;
}

uint8_t insert_key_value(db_handle * handle, void *key, void * value, uint32_t key_size, uint32_t value_size)
{
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
#ifndef NDEBUG
	uint32_t kv_size;
#endif
	uint8_t status = SUCCESS;
	uint64_t v1,v2;
	/*throttle control check*/
	while(handle->db_desc->zero_level_memory_size > ZERO_LEVEL_MEMORY_UPPER_BOUND){
		usleep(THROTTLE_SLEEP_TIME);
	}
	/*do staff here*/
#ifndef NDEBUG
	kv_size = sizeof(uint32_t)+key_size+sizeof(uint32_t)+value_size + sizeof(uint64_t);
	assert(kv_size <= KV_MAX_SIZE);
#endif
	//void * key_buf = malloc(sizeof(uint32_t)+key_size+sizeof(int32_t)+value_size);
	*(uint32_t *)key_buf = key_size;
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t),key,key_size);
	*(uint32_t *)((uint64_t)key_buf+sizeof(uint32_t)+key_size) = value_size;
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t)+key_size+sizeof(uint32_t),value,value_size);
retry:
	v2 = snapshot_v2;
	v1 = snapshot_v1;
	if(v1 != v2) {
		usleep(THROTTLE_SLEEP_TIME);
		goto retry;
	}

	//void * data_buf =(void *) (uint64_t)key_buf+sizeof(uint32_t)+key_size;/*Unused Variable*/
#if INSERT_TO_INDEX
	// *(uint64_t *)(data_buf+sizeof(uint32_t)+value_size) = (uint64_t)log_address - MAPPED;
	status = _insert_key_value(handle, key_buf, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG);
#endif

	//free(key_buf);
	return status;
}

/**
 * Private function, used for integration with tucanaserver, returns pointer
 * addr where the value was written
 *
 **/

void * append_key_value_to_log(db_handle *handle, void *key_value, char KEY_VALUE_FORMAT){

	block_header * d_header;
	void *key_addr;/*address at the device*/
	void *data_addr;/*address at the device*/
	uint32_t key_len;
	uint32_t value_len;
	uint32_t available_space_in_log;
	uint32_t kv_size;
	uint32_t allocated_space;
#ifdef USER_MCS
	qnode_t lock_node;
#endif
	if(KEY_VALUE_FORMAT == KEYSIZE_BUF_DATASIZE_BUF){
		key_len = *(uint32_t *)key_value;
		value_len = *(uint32_t *)(key_value+sizeof(uint32_t)+key_len);
		/* printf("[%s:%s:%d] key len %d value len %d\n",__FILE__,__func__,__LINE__,key_len, value_len); */
	}
	else if(KEY_VALUE_FORMAT == KEYSIZE_DATASIZE_BUF){
		key_len = *(uint32_t *)key_value;
		value_len = *(uint32_t *)(key_value + sizeof(uint32_t));
		/* printf("[%s:%s:%d] key len %d value len %d\n",__FILE__,__func__,__LINE__,key_len, value_len); */

	} else {
		printf("[%s:%s:%d] FATAL unknown format\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
	kv_size = sizeof(uint32_t) + key_len + sizeof(uint32_t) + value_len;
#ifdef LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_lock(&handle->db_desc->lock_log);
#else
	acquire(&handle->db_desc->lock_log,&lock_node);
#endif
	/*append data part in the data log*/
	if(handle->db_desc->g_kv_log_size % BUFFER_SEGMENT_SIZE != 0)
		available_space_in_log = BUFFER_SEGMENT_SIZE-(handle->db_desc->g_kv_log_size % BUFFER_SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	if(available_space_in_log < kv_size){
		/*pad with zeroes remaining bytes in segment*/
		key_addr = (void*)((uint64_t)handle->db_desc->g_last_kv_log+(handle->db_desc->g_kv_log_size % BUFFER_SEGMENT_SIZE));
		memset(key_addr,0x00,available_space_in_log);

		allocated_space = kv_size + sizeof(block_header);
		allocated_space +=  BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
		/*this allocate() is left intentionally. KV log allocates space only from allocator*/
		d_header = (block_header *)allocate_segment(handle,allocated_space,KV_LOG_ID, KV_LOG_EXPANSION);
		memset(d_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
		d_header->next_block = NULL;
		handle->db_desc->g_last_kv_log->next_block = (void *)((uint64_t)d_header - MAPPED);
		handle->db_desc->g_last_kv_log = d_header;
		handle->db_desc->g_kv_log_size += (available_space_in_log + sizeof(block_header)); /* position the log to the newly added block */
	}
	key_addr = (void*)((uint64_t)handle->db_desc->g_last_kv_log+(handle->db_desc->g_kv_log_size % BUFFER_SEGMENT_SIZE));
	data_addr = (void *)((uint64_t)key_addr + sizeof(int32_t) + key_len);
	handle->db_desc->g_kv_log_size += kv_size;
#ifdef LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_unlock(&handle->db_desc->lock_log);
#else
	release(&handle->db_desc->lock_log,&lock_node);
#endif

	if(KEY_VALUE_FORMAT == KEYSIZE_DATASIZE_BUF){
		*(uint32_t *)key_addr = key_len;
		memcpy(key_addr+sizeof(uint32_t),key_value+(2*sizeof(uint32_t)),key_len);
		*(uint32_t *)data_addr = value_len;
		memcpy(data_addr + sizeof(uint32_t),key_value+(2*sizeof(uint32_t))+key_len,value_len);
	} else{
		*(uint32_t *)key_addr = key_len;
		memcpy(key_addr+sizeof(uint32_t),key_value+sizeof(uint32_t),key_len);
		*(uint32_t *)data_addr = value_len;
		memcpy(data_addr+sizeof(uint32_t), key_value+sizeof(uint32_t)+key_len+sizeof(uint32_t), value_len);
	}
	return key_addr;
}


/* *
 * inserts to L1, called during spills from L0 to primary L1 and back-up server's L1
 * key_tag: key_prefix|pointer_to_log
 * */
uint8_t insert_to_L1_index(db_handle *handle, void * key_tag){
	return _insert_key_value(handle, key_tag, INSERT_TO_L1_INDEX);/*XXX TODO XXX CHECK AGAIN*/
}


/**
 * This function is used only internally and we ll be either called by
 * insert_key_value or by insert_write_batch locking of the database takes
 * place at the these function prior to the call.
 **/
uint8_t _insert_key_value(db_handle * handle, void *key_buf, int INSERT_FLAGS){
	insertKV_request req;
	db_descriptor *db_desc;
	uint64_t v1,v2;
	/*inserts take place one of the trees in level 0*/
	db_desc = handle->db_desc;
	db_desc->dirty = 0x01;
	req.handle = handle;
	req.key_value_buf = key_buf;
	req.insert_mode = INSERT_FLAGS;/*Insert to L0 or not.Append to log or not.*/
	req.allocator_desc.handle = handle;
	req.gc_request = 0;
	/*allocator to use, depending on the level*/
	if( (INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == DO_NOT_APPEND_TO_LOG){

		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_buffered;
		/*active tree of level 0*/
		req.allocator_desc.level_id = db_desc->active_tree;
		req.level_id = db_desc->active_tree;
		req.key_format = KV_FORMAT;
		req.key_value_buf = key_buf;/*place in the log where the actual kv pair was written in append_to_log*/
	}
	else if((INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == APPEND_TO_LOG){
		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_buffered;
		req.allocator_desc.level_id = db_desc->active_tree;/*active tree of level 0*/
		req.level_id = 0;/*Will be set to the proper value when we acquire the guard lock in concurrent insert.*/
		req.key_format = KV_FORMAT;
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
	/*Spill commands to Level 1 or Level 2 */
	else if ((INSERT_FLAGS&0xFF000000) == INSERT_TO_L1_INDEX){
		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_block;
		req.allocator_desc.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
		req.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
		req.key_format = KV_PREFIX;
		//printf("[%s:%s:%d] key is %s\n",__FILE__,__func__,__LINE__, *(uint64_t *)(req.key_value_buf+PREFIX_SIZE) +4);
		//printf("[%s:%s:%d] LEVEL ID IS %d\n",__FILE__,__func__,__LINE__,req.level_id);
	}else  {
		printf("[%s:%s:%d] FATAL UNKNOWN INSERT MODE\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
retry:
	v2 = snapshot_v2;
	v1 = snapshot_v1;
	while(v1 != v2) {
		goto retry;
	}

	if(_writers_join_as_readers(&req)==FAILURE){
		_concurrent_insert(&req);
	}
	return SUCCESS;
}

uint8_t update_key_value_pointer(db_handle * handle, void *key, void * value, uint32_t key_size, uint32_t value_size)
{
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
#ifndef NDEBUG
	uint32_t kv_size;
#endif
	uint8_t status = SUCCESS;
	/*throttle control check*/
	while(handle->db_desc->zero_level_memory_size > ZERO_LEVEL_MEMORY_UPPER_BOUND){
		usleep(THROTTLE_SLEEP_TIME);
	}
	/*do staff here*/
#ifndef NDEBUG
	kv_size = sizeof(uint32_t)+key_size+sizeof(uint32_t)+value_size + sizeof(uint64_t);
	assert(kv_size <= KV_MAX_SIZE);
#endif
	*(uint32_t *)key_buf = key_size;
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t),key,key_size);
	*(uint32_t *)((uint64_t)key_buf+sizeof(uint32_t)+key_size) = value_size;
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t)+key_size+sizeof(uint32_t),value,value_size);

#if INSERT_TO_INDEX
	status = _insert_key_value(handle, key_buf, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG);
#endif

	//free(key_buf);
	return status;

}

uint8_t _update_key_value_pointer(db_handle * handle, void *key_buf, int INSERT_FLAGS){
	insertKV_request req;
	db_descriptor *db_desc;
	uint64_t v1,v2;
	/*inserts take place one of the trees in level 0*/
	db_desc = handle->db_desc;
	db_desc->dirty = 0x01;
	req.handle = handle;
	req.key_value_buf = key_buf;
	req.insert_mode = INSERT_FLAGS;/*Insert to L0 or not.Append to log or not.*/
	req.allocator_desc.handle = handle;
	req.gc_request = 1;

	/*allocator to use, depending on the level*/
	if( (INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == DO_NOT_APPEND_TO_LOG){

		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_buffered;
		/*active tree of level 0*/
		req.allocator_desc.level_id = db_desc->active_tree;
		req.level_id = db_desc->active_tree;
		req.key_format = KV_FORMAT;
		req.key_value_buf = key_buf;/*place in the log where the actual kv pair was written in append_to_log*/
	}
	else if((INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == APPEND_TO_LOG){
		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_buffered;
		req.allocator_desc.level_id = db_desc->active_tree;/*active tree of level 0*/
		req.level_id = 0;/*Will be set to the proper value when we acquire the guard lock in concurrent insert.*/
		req.key_format = KV_FORMAT;
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
	/*Spill commands to Level 1 or Level 2 */
	else if ((INSERT_FLAGS&0xFF000000) == INSERT_TO_L1_INDEX){
		req.allocator_desc.allocate_space = &allocate_segment;
		req.allocator_desc.free_space = &free_block;
		req.allocator_desc.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
		req.level_id = (INSERT_FLAGS&0x0000FF00) >> 8;
		req.key_format = KV_PREFIX;
		//printf("[%s:%s:%d] key is %s\n",__FILE__,__func__,__LINE__, *(uint64_t *)(req.key_value_buf+PREFIX_SIZE) +4);
		//printf("[%s:%s:%d] LEVEL ID IS %d\n",__FILE__,__func__,__LINE__,req.level_id);
	}else  {
		printf("[%s:%s:%d] FATAL UNKNOWN INSERT MODE\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
retry:
	v2 = snapshot_v2;
	v1 = snapshot_v1;
	while(v1 != v2) {
		goto retry;
	}

	if(_writers_join_as_readers(&req)==FAILURE){
		_concurrent_insert(&req);
	}
	return SUCCESS;
}

void _create_spill_ranges(node_header * root,spill_request * spill_req[]){

	unsigned i,range;
	void *addr;
	void * pivots[NUM_OF_SPILL_THREADS_PER_DB-1];
	void * last_root_pivot_addr=(void *)((uint64_t)root+sizeof(node_header)+sizeof(uint64_t)+(root->num_entries-1)*16);
	void * last_child_pivot_addr=NULL;
	unsigned samples_per_child = (NUM_OF_SPILL_THREADS_PER_DB - 1)/root->num_entries;
	node_header * child;
	unsigned j;

	memset(pivots,0x0,sizeof(void *)*(NUM_OF_SPILL_THREADS_PER_DB-1));
	if(root->num_entries >= (NUM_OF_SPILL_THREADS_PER_DB-1)){
		/* void * tmp=(void*) ((uint64_t)root+sizeof(node_header)+8); */
		/* printf("[%s:%s:%d] FIRST_ROOT_KEY %s\n",__FILE__,__func__,__LINE__, (char *)(MAPPED+*(uint64_t*)tmp)+4); */
		/* printf("[%s:%s:%d] LAST_ROOT_KEY %s\n",__FILE__,__func__,__LINE__,(char *)(MAPPED+*(uint64_t*)last_root_pivot_addr)+4); */
		addr = (void *)((uint64_t)root+sizeof(node_header)+sizeof(uint64_t));
		pivots[0]=(void *)(MAPPED +*(uint64_t *)addr);
#if NUM_OF_SPILL_THREADS_PER_DB > 1
		range = root->num_entries/(NUM_OF_SPILL_THREADS_PER_DB - 1);
#else
		range = root->num_entries;
#endif
		for(i=1;i<(NUM_OF_SPILL_THREADS_PER_DB-1);++i){

			addr += ((range)*(sizeof(uint64_t)*2));
			if(addr > last_root_pivot_addr)
				addr=last_root_pivot_addr;
			pivots[i]=(void *)(MAPPED +*(uint64_t *)addr);
		}
	}else{
		printf("[%s:%s:%d] Calculating spill ranges from children\n",__FILE__,__func__,__LINE__);
		int idx=0;
		for(i=0;i < (root->num_entries+1) ;++i){
			child=(node_header *)(MAPPED+*(uint64_t*)((uint64_t)root+sizeof(node_header)+i*16));
			last_child_pivot_addr=(void *)((uint64_t)child+sizeof(node_header)+sizeof(uint64_t)+(child->num_entries-1)*16);
			range=child->num_entries/samples_per_child;
			addr=(void *)((uint64_t)child+sizeof(node_header)+sizeof(uint64_t));
			pivots[idx++] = (void *)(MAPPED +*(uint64_t *)addr);
			for(j=1;j<samples_per_child;++j){

				addr += (range)*(sizeof(uint64_t)*2);

				if(addr > last_child_pivot_addr)
					addr=last_child_pivot_addr;
				if(idx == (NUM_OF_SPILL_THREADS_PER_DB))
					break;

				pivots[idx++]=(void *)(MAPPED +*(uint64_t *)addr);
			}
		}
	}
	i=0;
	spill_req[0]->start_key=NULL;
	spill_req[0]->end_key=pivots[i];

	for (i = 1; i < (NUM_OF_SPILL_THREADS_PER_DB-1); ++i) {
		spill_req[i]->start_key=spill_req[i-1]->end_key;
		spill_req[i]->end_key=pivots[i];
	}

	spill_req[i]->start_key=spill_req[i-1]->end_key;
	spill_req[i]->end_key=NULL;
#ifndef NDEBUG
	for (i = 0; i < NUM_OF_SPILL_THREADS_PER_DB; ++i) {
		if(spill_req[i]->start_key!=NULL)
			printf("[%s:%s:%d] START KEY %s\n",__FILE__,__func__,__LINE__,(char *)spill_req[i]->start_key+4);
		else
			printf("[%s:%s:%d] START_KEY NULL\n",__FILE__,__func__,__LINE__);
		if(spill_req[i]->end_key!=NULL)
			printf("[%s:%s:%d] END_KEY %s\n",__FILE__,__func__,__LINE__,(char *)(spill_req[i]->end_key+4));
		else
			printf("[%s:%s:%d] END_KEY NULL\n",__FILE__,__func__,__LINE__);
	}
#endif
}

/*gesalous added at 01/07/2014 18:29 function that frees all the blocks of a node*/
void free_logical_node(allocator_descriptor * allocator_desc, node_header * node_index){

	if(node_index->type == leafNode || node_index->type == leafRootNode){
		(*allocator_desc->free_space)(allocator_desc->handle,node_index,NODE_SIZE,allocator_desc->level_id);
		return;
	}
	else if(node_index->type == internalNode || node_index->type == rootNode){
		/*for IN, BIN, root nodes free the key log as well*/
		if(node_index->first_key_block == NULL){
			printf("[%s:%s:%d] NULL log for index?\n",__FILE__,__func__,__LINE__);
			raise(SIGINT);
			exit(-1);
		}
		block_header * curr = (block_header *) (MAPPED + (uint64_t)node_index->first_key_block);
		block_header *last = (block_header *)(MAPPED + (uint64_t)node_index->last_key_block);
		block_header * to_free;
		while((uint64_t)curr != (uint64_t)last)
		{
			to_free = curr;
			curr = (block_header *) ((uint64_t)MAPPED + (uint64_t)curr->next_block);
			(*allocator_desc->free_space)(allocator_desc->handle, to_free, KEY_BLOCK_SIZE, allocator_desc->level_id);
		}
		(*allocator_desc->free_space)(allocator_desc->handle, last, KEY_BLOCK_SIZE, allocator_desc->level_id);
		/*finally node_header*/
		(*allocator_desc->free_space)(allocator_desc->handle, node_index, NODE_SIZE, allocator_desc->level_id);
	} else {
		printf("[%s:%s:%d] FATAL corrupted node!\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	return;
}

/*this function will be reused in various places such as deletes*/
void * __find_key(db_handle * handle, void *key, node_header * unused, char SEARCH_MODE)
{
	node_header *	curr_node;
	void *		key_addr_in_leaf = NULL;
	void *		next_addr;
	node_header **	tree_hierarchy;
	volatile uint64_t	v1,v2;
	int32_t		tree_id;
	int32_t		index_key_len;
	int		count_retries	 = -1;
retry:
	if(SEARCH_MODE == SEARCH_PERSISTENT_TREE)
		tree_hierarchy =  handle->db_desc->root_r;
	else if(SEARCH_MODE == SEARCH_DIRTY_TREE)
		tree_hierarchy = handle->db_desc->root_w;
	else{
		printf("[%s:%s:%d] unknown search mode, FATAL\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	++count_retries;

	/* if(count_retries==10000){ */
	/* 	printf("[%s:%s:%d] Retried %d times aborting\n",__FILE__,__func__,__LINE__,count_retries); */
	/* 	exit(-1); */
	/* } */
	for(tree_id=0;tree_id<TOTAL_TREES;tree_id++){
		if(tree_hierarchy[tree_id] != NULL)
			curr_node = tree_hierarchy[tree_id];
		else if(tree_hierarchy[tree_id] == NULL && SEARCH_MODE == SEARCH_DIRTY_TREE){
			if(handle->db_desc->root_r[tree_id] != NULL)
				curr_node = handle->db_desc->root_r[tree_id];
			else
				continue;/*empty tree*/
		} else
			continue;
		int i = 0;
		/*During traversal we need to search also the buffers, findLeadNode function is probably useless now*/
		while(curr_node->type != leafNode && curr_node->type != leafRootNode){

			v2 = curr_node->v2;
			next_addr = _index_node_binary_search((index_node *)curr_node, key, KV_FORMAT);
			v1 = curr_node->v1;

			if(v1 != v2){
				/* printf("[%s:%s:%d] failed at node height %d v1 %llu v2 %llu\n",__FILE__,__func__,__LINE__,curr_node->height,(LLU)curr_node->v1, (LLU)curr_node->v2); */
				goto retry;
			}
			if(tree_hierarchy[tree_id] != NULL)
				if(curr_node->type == rootNode && curr_node != tree_hierarchy[tree_id]){
					/* printf("[%s:%s:%d] failed at node height %d v1 %llu v2 %llu %d\n",__FILE__,__func__,__LINE__,curr_node->height,(LLU)curr_node->v1, (LLU)curr_node->v2,i); */
					goto retry;
				}
			++i;

			curr_node = (void *)(MAPPED + *(uint64_t *)next_addr);
		}
		v2 = curr_node->v2;
		/* log_debug("curr node - MAPPEd %p",MAPPED-(uint64_t)curr_node); */
		key_addr_in_leaf = __find_key_addr_in_leaf((leaf_node *)curr_node, (struct splice *)key);
		v1 = curr_node->v1;

		if(v1 != v2){
			//printf("[%s:%s:%d] failed at node height %d v1 %llu v2 %llu\n",__FILE__,__func__,__LINE__,curr_node->height,(LLU)curr_node->v1,(LLU)curr_node->v2);
			goto retry;
		}

		if(key_addr_in_leaf == NULL)/*snapshot and retry, only for outer tree case*/
			continue;

		key_addr_in_leaf =(void *) MAPPED + *(uint64_t *)key_addr_in_leaf;
		index_key_len = *(int32_t *)key_addr_in_leaf;

		return (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
	}
	return NULL;/*key not found at the outer tree*/
}

/* returns the addr where the value of the KV pair resides */
/* TODO: make this return the offset from MAPPED, not a pointer
 * to the offset */
void *__find_key_addr_in_leaf(leaf_node *leaf, struct splice *key)
{
	int32_t start_idx = 0, end_idx = leaf->header.num_entries - 1;
	char key_buf_prefix[PREFIX_SIZE] = { '\0' };

	memcpy(key_buf_prefix, key->data, MIN(key->size, PREFIX_SIZE));

	while(start_idx <= end_idx){
		int32_t middle = (start_idx + end_idx) / 2;

#ifdef NEW_LEAF_LAYOUT
		int32_t ret = prefix_compare(leaf->p[middle].prefix, key_buf_prefix, PREFIX_SIZE);
#else
		int32_t ret = prefix_compare(leaf->prefix[middle], key_buf_prefix, PREFIX_SIZE);
#endif
		if(ret < 0)
			start_idx = middle + 1;
		else if(ret > 0)
			end_idx = middle - 1;
		else{
#ifdef NEW_LEAF_LAYOUT
			void *index_key = (void *)(MAPPED + leaf->p[middle].pointer);
#else
			void *index_key = (void *)(MAPPED + leaf->pointer[middle]);
#endif
			ret = _tucana_key_cmp(index_key, key, KV_FORMAT, KV_FORMAT);
			if(ret == 0)
#ifdef NEW_LEAF_LAYOUT
				return &(leaf->p[middle].pointer);
#else
				return &(leaf->pointer[middle]);
#endif
			else if(ret < 0)
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

	if(key_size <= (4000 - sizeof(uint32_t))){
		key_buf = &(buf[0]);
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t), key, key_size);
		value =  __find_key(handle, key_buf, NULL, SEARCH_DIRTY_TREE);
	}else{
		key_buf = malloc(key_size + sizeof(uint32_t));
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t),key,key_size);
		value = __find_key(handle, key_buf, NULL, SEARCH_DIRTY_TREE);
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
 |block_header|pointer_to_node|pointer_to_key|pointer_to_node | pointer_to_key|...
*/
int8_t update_index(node_header* node, node_header * left_child, node_header * right_child, void *key_buf){
	int64_t ret = 0;
	void * addr;
	void * dest_addr;
	uint64_t entry_val = 0;
	void * index_key_buf;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->num_entries-1;
	size_t num_of_bytes;

	addr = (void *)(uint64_t)node + sizeof(node_header);

	if(node->num_entries > 0){

		while(1){
			middle = (start_idx + end_idx)/2;
			addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header)+sizeof(uint64_t)+(uint64_t)(middle*2*sizeof(uint64_t));
			index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, KV_FORMAT);
			if(ret > 0)
			{
				end_idx = middle - 1;
				if(start_idx > end_idx)
					//addr is the same
					break;
			}
			else if(ret == 0)
			{
				/* printf("[%s:%s:%d]FATAL key already present \n",__FILE__,__func__,__LINE__); */
				return 0;
				node->num_entries--;
				raise(SIGINT);
				exit(1);
			}
			else
			{
				start_idx = middle+1;
				if(start_idx > end_idx)
				{
					middle++;
					if(middle >= node->num_entries)
					{
						middle = node->num_entries;
						addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) + (uint64_t)(middle*2*sizeof(uint64_t))+sizeof(uint64_t);
					}
					else
						addr += (2*sizeof(uint64_t));
					break;
				}
			}
		}

		dest_addr = addr + (2*sizeof(uint64_t));
		num_of_bytes = (node->num_entries - middle)*2*sizeof(uint64_t);
		memmove(dest_addr,addr,num_of_bytes);
		addr -= sizeof(uint64_t);
	}
	else
		addr = (void *)node + sizeof(node_header);

	/*update the entry*/
	if(left_child != 0)
		entry_val = (uint64_t)left_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr,&entry_val,sizeof(uint64_t));
	addr += sizeof(uint64_t);
	entry_val = (uint64_t)key_buf - MAPPED;
	memcpy(addr,&entry_val,sizeof(uint64_t));

	addr += sizeof(uint64_t);
	if(right_child != 0)
		entry_val = (uint64_t)right_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr,&entry_val,sizeof(uint64_t));
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
void insertKeyAtIndex(allocator_descriptor *allocator_desc, node_header * node, node_header * left_child, node_header * right_child, void *key_buf, char allocation_code)
{
	void * key_addr = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;
	block_header * d_header = NULL;
	block_header * last_d_header = NULL;
	int8_t ret;
	uint32_t key_len = *(uint32_t *)key_buf;
	if(node->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - ( node->key_log_size % (int32_t)KEY_BLOCK_SIZE );

	req_space = (key_len + sizeof(uint32_t));
	if(avail_space < req_space){/*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space+sizeof(node_header))/KEY_BLOCK_SIZE;
		if((req_space+sizeof(node_header))%KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space *= KEY_BLOCK_SIZE;

		d_header = (*allocator_desc->allocate_space)(allocator_desc->handle, allocated_space, allocator_desc->level_id, allocation_code);

		d_header->next_block = NULL;
		last_d_header = (block_header *)(MAPPED + (uint64_t)node->last_key_block);
		last_d_header->next_block = (void *)((uint64_t)d_header - MAPPED);
		node->last_key_block = last_d_header->next_block;
		node->key_log_size += (avail_space +  sizeof(uint64_t));/* position the log to the newly added block*/
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)node->last_key_block + (uint64_t)(node->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(uint32_t) + key_len);/*key length */
	node->key_log_size += sizeof(uint32_t) + key_len;

	ret = update_index(node, left_child, right_child, key_addr);
	if(ret)
		node->num_entries++;
}

static inline void move_leaf_data(leaf_node *leaf, int32_t middle)
{
#ifdef NEW_LEAF_LAYOUT
	const size_t nitems = leaf->header.num_entries - middle;
	char *src_addr = (char *)(&(leaf->p[middle]));
  char *dst_addr = src_addr + sizeof(leaf_entry);

  memmove(dst_addr, src_addr, nitems * sizeof(leaf_entry));
#else
	char *src_addr, *dst_addr;
	const size_t nitems = leaf->header.num_entries - middle;

	src_addr = (char *)(&(leaf->pointer[middle]));
	dst_addr = src_addr + sizeof(uint64_t);
	memmove(dst_addr, src_addr, nitems * sizeof(uint64_t));

	src_addr = (char *)(&(leaf->prefix[middle]));
	dst_addr = src_addr + PREFIX_SIZE;
	memmove(dst_addr, src_addr, nitems * PREFIX_SIZE);
#endif
}

static inline void update_leaf_index_stats(char key_format)
{
#ifdef PREFIX_STATISTICS
	if(key_format == KV_FORMAT)
		__sync_fetch_and_add(&ins_prefix_miss_l0, 1);
	else
		__sync_fetch_and_add(&ins_prefix_miss_l1, 1);
#endif
}


/*
 * gesalous: Added at 13/06/2014 16:22. After the insertion of a leaf it's corresponding index will be updated
 * for later use in efficient searching.
 */
int __update_leaf_index(insertKV_request *req, leaf_node *leaf, void *key_buf, char key_format)
{
	void *index_key_buf, *addr;
	int64_t ret = 1;
	int32_t start_idx, end_idx, middle = 0;
	char *index_key_prefix = NULL;
	char key_buf_prefix[PREFIX_SIZE] = { '\0' };
	uint64_t pointer = 0;

	start_idx = 0;
	end_idx = leaf->header.num_entries - 1;
#ifdef NEW_LEAF_LAYOUT
	addr = &(leaf->p[0].pointer);
#else
	addr = &(leaf->pointer[0]);
#endif

	if(key_format == KV_FORMAT){
		int32_t row_len = *(int32_t *)key_buf;
		memcpy(key_buf_prefix, (void *)((uint64_t)key_buf + sizeof(int32_t)), MIN(row_len, PREFIX_SIZE));
	}else{ /* operation coming from spill request (i.e. KV_PREFIX) */
		memcpy(key_buf_prefix, key_buf, PREFIX_SIZE);
	}

	while(leaf->header.num_entries > 0){

		middle = (start_idx + end_idx) / 2;
#ifdef NEW_LEAF_LAYOUT
		addr = &(leaf->p[middle].pointer);
		index_key_prefix = leaf->p[middle].prefix;
#else
		addr = &(leaf->pointer[middle]);
		index_key_prefix = leaf->prefix[middle];
#endif

		ret = prefix_compare(index_key_prefix, key_buf_prefix, PREFIX_SIZE);
		if(ret < 0){
			update_leaf_index_stats(key_format);
			goto up_leaf_1;
		}else if(ret > 0){
			update_leaf_index_stats(key_format);
			goto up_leaf_2;
		}

#ifdef PREFIX_STATISTICS
		if(key_format == KV_PREFIX)
			__sync_fetch_and_add(&ins_hack_miss, 1);
#endif
		update_leaf_index_stats(key_format);

		index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, key_format);
		if(ret == 0){

			if(req->gc_request == 1 && pointer_to_kv_in_log != index_key_buf)
				return ret;

			/* Its an update, mark the hole in the KV log metadata
			 * finally mark garbage bytes, please note that all allocations take place at BUFFER_SEGMENT_SIZE granularity
			 * and addresses returned by the allocator are aligned in BUFFER_SEGMENT_SIZE.
			 * to find the start of the log block given the deleted_key
			 */
			uint64_t absolute_addr = (uint64_t)index_key_buf - MAPPED;
			uint64_t distance  = (absolute_addr % BUFFER_SEGMENT_SIZE);
			block_header *block = (block_header *)((uint64_t)index_key_buf - distance);
			uint32_t idx = 2 * (req->handle->volume_desc->soft_superindex->epoch % MAX_COUNTER_VERSIONS);

			if(block->garbage_bytes[idx] <= req->handle->volume_desc->dev_superindex->epoch){
				uint32_t previous_idx = 2 * ((req->handle->volume_desc->dev_superindex->epoch) % MAX_COUNTER_VERSIONS);
				block->garbage_bytes[idx] = req->handle->volume_desc->soft_superindex->epoch;
				block->garbage_bytes[idx + 1] = block->garbage_bytes[previous_idx + 1];
			}

			block->garbage_bytes[idx+1] +=  *(uint32_t *)index_key_buf +  *(uint32_t *)(index_key_buf+sizeof(uint32_t)+*(uint32_t *)index_key_buf) + (2*sizeof(uint32_t));
			break;
		}
		else if(ret < 0){
up_leaf_1:
			start_idx = middle+1;
			if(start_idx > end_idx){
				middle++;
				move_leaf_data(leaf, middle);
				break;
			}
		}else if(ret > 0){
up_leaf_2:
			end_idx = middle-1;
			if(start_idx > end_idx){
				move_leaf_data(leaf, middle);
				break;
			}
		}
	}

	/*setup the pointer*/
	if(key_format == KV_FORMAT)
		pointer = (uint64_t)key_buf - MAPPED;
	else /* KV_PREFIX */
		pointer = (*(uint64_t *)(key_buf + PREFIX_SIZE)) - MAPPED;
	/*setup the prefix*/
#ifdef NEW_LEAF_LAYOUT
	leaf->p[middle].pointer = pointer;
	memcpy(&leaf->p[middle].prefix, key_buf_prefix, PREFIX_SIZE);
#else
	leaf->pointer[middle] = pointer;
	memcpy(&leaf->prefix[middle], key_buf_prefix, PREFIX_SIZE);
#endif

	return ret;
}

void assert_leaf_node(node_header * leaf)
{
	void * prev;
	void * curr;
	void * addr;
	int64_t ret;
	int i;
	if(leaf->num_entries == 1)
	{
		return;
	}
	addr = (void *)(uint64_t)leaf + sizeof(node_header);
	curr = (void *)*(uint64_t *)addr+MAPPED;

	for(i=1;i<leaf->num_entries;i++)
	{
		addr += 8;
		prev = curr;
		curr = (void *)*(uint64_t *)addr+MAPPED;
		ret = _tucana_key_cmp(prev, curr, KV_FORMAT, KV_FORMAT);
		if(ret > 0)
		{
			printf("[%s:%s:%d] FATAL corrupted leaf index at index %d total entries %" PRIu64 "\n",__FILE__, __func__,__LINE__, i, leaf->num_entries);
			printf("previous key is: %s\n", (char *)prev+sizeof(int32_t));
			printf("curr key is: %s\n", (char *)curr+sizeof(int32_t));
			raise(SIGINT);
			exit(-1);
		}
	}
}

void print_key(const char *pre, void * key)
{
	//printf("%s:%s:%d NOT IMPLEMENTED in non HBase mode!\n", __FILE__, __func__, __LINE__);
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
void split_index(split_request *req, split_reply * rep){
	node_header * left_child;
	node_header * right_child;
	node_header * tmp_index;
	int32_t i = 0;
	void * full_addr;
	void * key_buf;

	rep->left_child = (node_header *)createEmptyNode( &(req->allocator_desc),  req->handle, internalNode, INDEX_SPLIT);/*left index*/
	rep->right_child = (node_header *)createEmptyNode(&(req->allocator_desc), req->handle, internalNode, INDEX_SPLIT);/*right index*/
	rep->left_child->v1++;/*lamport counter*/
	rep->right_child->v1++;/*lamport counter*/
#ifdef USE_SYNC
	__sync_synchronize();
#endif
	/*initialize*/
	full_addr = (void *)((uint64_t)req->node + (uint64_t)sizeof(node_header));
	/*set node heights*/
	rep->left_child->height = req->node->height;
	rep->right_child->height = req->node->height;

	for(i=0;i<req->node->num_entries;i++)
	{
		if(i < req->node->num_entries/2)
			tmp_index = rep->left_child;
		else
			tmp_index = rep->right_child;

		left_child = (node_header *) (MAPPED + *(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		key_buf = (void *)(MAPPED + *(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		right_child = (node_header *)(MAPPED + *(uint64_t *)full_addr);
		if(i == req->node->num_entries/2){
			rep->middle_key_buf = key_buf;
			continue;/*middle key not needed, is going to the upper level*/
		}
		insertKeyAtIndex(&(req->allocator_desc), tmp_index, left_child, right_child,  key_buf, KEY_LOG_SPLIT);
	}

	rep->left_child->v2++;/*lamport counter*/
	rep->right_child->v2++;/*lamport counter*/
}

/**
 *	gesalous 26/05/2014 added method. Appends a key-value pair in a leaf node.
 *	returns 0 on success 1 on failure. Changed the default layout of leafs
 **/
/*Unused allocation_code XXX TODO XXX REMOVE */
int insertKVAtLeaf(insertKV_request *req, node_header * leaf, char allocation_code)
{
	void* log_address;
	void * key_addr = NULL;
	/*added at 18/10/2016 to replace the useless leaf->first_kv_block, leaf->last_kv_block, and leaf->log_size*/
	int ret;

	/*where are we now, read global log for this tree from its root
	 * Reminder: We do not perform a COW check before updating root_w
	 *	of the tree because by construction(see snapshot function the allocator)
	 * a non null root_w is always in non immutable state
	 */
	if(req->level_id < NUM_OF_TREES_PER_LEVEL){
		log_address = append_key_value_to_log(req->handle, req->key_value_buf,KEYSIZE_BUF_DATASIZE_BUF);
		req->key_value_buf = log_address;
	}

	if((req->insert_mode&0x00FF0000) == APPEND_TO_LOG){
		printf("[%s:%s:%d] FATAL APPEND_TO_LOG at insertKVAtLeaf unsupported\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
	if(req->key_format == KV_FORMAT && (req->insert_mode&0xFF000000) == INSERT_TO_L0_INDEX){
		key_addr = req->key_value_buf;
	}
	/*kv pair already in KVlog,part of spill request, format should be KV_PREFIX*/
	if(req->key_format == KV_PREFIX && (req->insert_mode&0xFF000000) == INSERT_TO_L1_INDEX){
		key_addr = req->key_value_buf;
	}

	if(__update_leaf_index(req, (leaf_node *)leaf, key_addr, req->key_format) != 0){
		leaf->num_entries++;
		__sync_fetch_and_add(&req->handle->db_desc->total_keys[req->level_id],1);
		ret = 1;
	}else{ /*if key already present at the leaf, must be an update or an append*/
		leaf->fragmentation++;
		ret = 0;
	}

	return ret;
}


int split_leaf(split_request *req, split_reply *rep)
{
	node_header* node_copy;
	int stat;


	/*cow check*/
	if(req->node->epoch <= req->handle->volume_desc->dev_superindex->epoch){

		node_copy = (*(req->allocator_desc.allocate_space))((void *)req->allocator_desc.handle, NODE_SIZE, req->allocator_desc.level_id, LEAF_SPLIT);
		memcpy(node_copy, req->node, NODE_SIZE);
		node_copy->v1 = 0;
		node_copy->v2 = 0;
		node_copy->epoch = req->handle->volume_desc->soft_superindex->epoch;
		(*req->allocator_desc.free_space)(req->allocator_desc.handle, req->node, NODE_SIZE, LEAF_SPLIT);
		req->node = node_copy;
	}

#ifdef ENABLE_REORGANIZATION
	insertKV_request insert_req;
	int i;
	/*reorganize the keys only for level 1, need to worry about concurrency level-1 staff happens with level-0*/
	if(req->allocator_desc.level_id >= NUM_OF_TREES_PER_LEVEL){
		uint64_t key_addresses[256];
		uint64_t data_addresses[256];

		insert_req.allocator_desc = req->allocator_desc;
		insert_req.handle = req->handle;
		insert_req.level_id = req->allocator_desc.level_id;
		insert_req.level_id = NUM_OF_TREES_PER_LEVEL;
		insert_req.key_format = KV_FORMAT;
		addr = (void *)((uint64_t)req->node)+sizeof(node_header);

		for(i=0;i<req->node->num_entries;i++){
			key_addresses[i] = MAPPED + *(uint64_t *)addr;
			/*let the 4KB page fault happen without locking the db, for level-0*/
			data_addresses[i] =  key_addresses[i]+sizeof(uint32_t)+*(uint32_t *)key_addresses[i];
			addr += sizeof(uint64_t);
		}
		//lock db
		MUTEX_LOCK(&(insert_req.handle->db_desc->write_lock));
		req->node->v1++;//lamport counter
		for(i=0;i<req->node->num_entries;i++){
			insert_req.key_buf = (void *)key_addresses[i];
			insert_req.data_buf = (void *)data_addresses[i];
			insertKVAtLeaf(&insert_req,req->node, REORGANIZATION);
		}
		//unlock db
		req->node->v2++;//lamport counter
		MUTEX_UNLOCK(&(insert_req.handle->db_desc->write_lock));
	}
#endif
	rep->left_child = req->node;
	rep->left_child->v1++;/*lamport counter*/
	/*right leaf*/
	rep->right_child = (node_header *)createEmptyNode(&(req->allocator_desc), req->handle, leafNode, LEAF_SPLIT);
	rep->right_child->v1++;/*lamport counter*/

#ifdef SCAN_REORGANIZATION
	if(req->allocator_desc.level_id >= NUM_OF_TREES_PER_LEVEL){
		rep->left_child->leaf_id = ++req->handle->db_desc->leaf_id;
		rep->right_child->leaf_id = ++req->handle->db_desc->leaf_id;
	}
#endif

#ifdef USE_SYNC
	__sync_synchronize();
#endif

#ifdef NEW_LEAF_LAYOUT
	rep->middle_key_buf = (void *)( MAPPED + req->lnode->p[req->node->num_entries / 2].pointer );

	/* pointers + prefixes */
	memcpy(
		&(rep->right_lchild->p[0]),
		&(req->lnode->p[req->node->num_entries / 2]),
		((req->node->num_entries / 2) + (req->node->num_entries % 2)) * sizeof(leaf_entry)
	);
#else
	rep->middle_key_buf = (void *)( MAPPED + req->lnode->pointer[req->node->num_entries / 2] );
	/* pointers */
	memcpy(
		&(rep->right_lchild->pointer[0]),
		&(req->lnode->pointer[req->node->num_entries / 2]),
		((req->node->num_entries / 2) + (req->node->num_entries % 2)) * sizeof(uint64_t)
	);

	/* prefixes */
	memcpy(
		&(rep->right_lchild->prefix[0]),
		&(req->lnode->prefix[req->node->num_entries / 2]),
	  ((req->node->num_entries / 2) + (req->node->num_entries % 2)) * PREFIX_SIZE
	);
#endif


	rep->right_child->num_entries = (req->node->num_entries/2)+(req->node->num_entries%2);
	rep->right_child->type = leafNode;

	rep->right_child->height = req->node->height;
	/*left leaf*/
	rep->left_child->height = req->node->height;
	rep->left_child->num_entries = req->node->num_entries/2;

	if(req->node->type == leafRootNode)
	{
		rep->left_child->type = leafNode;
		//printf("[%s:%s:%d] leafRoot node splitted\n",__FILE__,__func__,__LINE__);
		stat = LEAF_ROOT_NODE_SPLITTED;
	}
	else
		stat = KREON_OK;

	rep->left_child->v2++;/*lamport counter*/
	rep->right_child->v2++;/*lamport counter*/
	return stat;
}

/**
 *	gesalous added at 30/05/2014 14:00, performs a binary search at an index(root, internal node) and returns the index. We have
 *  a separate search function for index and leaves due to their different format
 *  Updated (26/10/2016 17:05) key_buf can be in two formats
 *
 **/


void * _index_node_binary_search(index_node *node, void *key_buf, char query_key_format)
{
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t num_entries = node->header.num_entries;

	while(num_entries > 0)
	{
		middle = (start_idx + end_idx) / 2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if(ret == 0){
			//log_debug("I passed from this corner case1 %s", (char*)(index_key_buf+4));
			addr = &(node->p[middle].right[0]);
			break;
		}
		else if(ret > 0){
			end_idx = middle - 1;
			if(start_idx > end_idx){
				//log_debug("I passed from this corner case2 %s", (char*)(index_key_buf+4));
				addr = &(node->p[middle].left[0]);
				middle--;
				break;
			}
		}
		else{ /* ret < 0 */
			start_idx = middle + 1;
			if(start_idx > end_idx){
				//log_debug("I passed from this corner case3 %s", (char*)(index_key_buf+4));
				addr = &(node->p[middle].right[0]);
				middle++;
				break;
			}
		}
	}

	if(middle < 0){
		//log_debug("I passed from this corner case4 %s", (char*)(index_key_buf+4));
		addr = &(node->p[0].left[0]);
	}else if(middle >= node->header.num_entries){
		//log_debug("I passed from this corner case5 %s", (char*)(index_key_buf+4));
		/* log_debug("I passed from this corner case2 %s", (char*)(index_key_buf+4)); */
		addr = &(node->p[node->header.num_entries - 1].right[0]);
	}
	//log_debug("END");
	return addr;
}

/**
 *  Fill block argument
 *  @param  handle
 *  @param  type
 *  @param  block
 *  @return void* btree header
 */
void * createEmptyNode(allocator_descriptor * allocator_desc, db_handle *handle, nodeType_t type, char allocation_code){
	node_header *ptr;
	block_header * bh;
	static db_handle *temp_handle = NULL;

	if(handle != NULL)
		temp_handle = handle;
	else{
		handle = temp_handle;
	}

	if(!allocator_desc->handle)
		allocator_desc->handle = handle;

	//printf("[%s:%s:%d] level id %d\n",__FILE__,__func__,__LINE__,allocator_desc->level_id);
	if(allocator_desc == NULL)
		ptr = (node_header *)allocate_segment(temp_handle, NODE_SIZE, temp_handle->db_desc->active_tree,allocation_code);
	else{
		ptr = (node_header *)(*allocator_desc->allocate_space)(allocator_desc->handle, NODE_SIZE, allocator_desc->level_id,allocation_code);
	}
	ptr->type = type;
	ptr->epoch = handle->volume_desc->soft_superindex->epoch;
	ptr->num_entries = 0;
	ptr->fragmentation  =  0;
	ptr->v1=0;
	ptr->v2=0;

	if(type == leafNode || type == leafRootNode)/*data log*/
	{
		ptr->first_key_block = NULL;
		ptr->last_key_block = NULL;
		ptr->key_log_size = 0;
		ptr->height = 0;
#ifdef SCAN_REORGANIZATION
		if(allocator_desc->level_id >= NUM_OF_TREES_PER_LEVEL) {
			ptr->leaf_id = ++handle->db_desc->leaf_id;
		}
#endif
	}
	else/*internal or root node(s)*/
	{
		/*key log for indexes*/
		bh = (block_header *)(*allocator_desc->allocate_space)(allocator_desc->handle, KEY_BLOCK_SIZE, allocator_desc->level_id,KEY_LOG_EXPANSION);
		bh->next_block = (void *)NULL;
		ptr->first_key_block  = (block_header *)((uint64_t)bh - MAPPED);
		ptr->last_key_block =  ptr->first_key_block;
		ptr->key_log_size = sizeof(uint64_t);
	}

	if(type == rootNode)/*increase node height by 1*/
	{
		ptr->height = handle->db_desc->root_w[allocator_desc->level_id]->height + 1;
	}
	return (void *)ptr;
}

void spill_buffer(void * _spill_req)
{
	int32_t local_spilled_keys = 0;

	printf("[%s:%s:%d] Initiating spill\n",__FILE__,__func__,__LINE__);

#ifdef PREFETCH_ENABLE
	char keys[TO_SPILL_KEYS * (PREFIX_SIZE + sizeof(uint64_t))];
	const int litemsz = PREFIX_SIZE + sizeof(uint64_t);
	double scan_num_of_keys = 0.0, scan_leaves_needed = 0.0;
#endif

	spill_request *spill_req = (spill_request *)_spill_req;
	db_handle *handle = spill_req->handle;
	db_descriptor *db_desc = handle->db_desc;
	level_scanner * level_sc;
	int i, rc = 100;

	if(spill_req->dst_tree_id < 0 || spill_req->dst_tree_id > 255){
		printf("[%s:%s:%d]FATAL spill_req->dst_tree_id EXCEEDED MAX VALUE\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}

	/*Initialize a scan object*/
	level_sc = _init_spill_buffer_scanner(handle, spill_req->src_root,spill_req->start_key);
	/*sanity check*/
	if(level_sc == NULL){
		printf("[%s:%s:%d] FATAL empty internall buffer during spill\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}

	do{
		int32_t num_of_keys = TO_SPILL_KEYS;
#ifdef PREFETCH_ENABLE
		/*1. Discover the leaves needed for the series of TO_SPILL_KEYS size*/
		num_of_keys = 0;
		struct dmap_prefetch prefetch_ioctl;
		int32_t leaves_needed = -1;
		while(1){
			node_header *leaf = get_addr_of_leaf(spill_req->handle, sc->keyValue, spill_req->dst_tree_id);
			memcpy(&keys[num_of_keys * litemsz], sc->keyValue, litemsz);
			num_of_keys++;

			if(leaf != NULL && (leaves_needed == -1 ||
					    (((uint64_t)leaf-MAPPED)/PAGE_SIZE != (uint64_t)prefetch_ioctl.pg_offset[leaves_needed])))
			{
				leaves_needed++;
				prefetch_ioctl.pg_offset[leaves_needed] = ((uint64_t)leaf-MAPPED)/PAGE_SIZE;
			}

			rc = _get_next_KV(sc);
			if(leaves_needed >= MAX_PREFETCH_SIZE - 1 || rc == END_OF_DATABASE || num_of_keys > TO_SPILL_KEYS)
				break;
		}

		leaves_needed++;
		prefetch_ioctl.num_pages = leaves_needed;

		if(dmap_prefetch_pages(FD, &prefetch_ioctl) != 0){
			fprintf(stderr, "[%s:%s:%d] FATAL dmap prefetch failed\n",__FILE__,__func__,__LINE__);
			exit(EXIT_FAILURE);
		}
#endif
		while(handle->volume_desc->snap_preemption == SNAP_INTERRUPT_ENABLE){
			usleep(50000);
		}
		db_desc->dirty = 0x01;
		if(handle->db_desc->db_mode == DB_IS_CLOSING){
			printf("[%s:%s:%d] db is closing bye bye from spiller\n",__FILE__,__func__,__LINE__);
			__sync_fetch_and_sub(&db_desc->count_active_spillers,1);
			return;
		}

		/*Is there any notification that this db is closing? if so exit*/

		//printf("[%s:%s:%d] spilling a batch of %d keys\n",__FILE__,__func__,__LINE__,num_of_keys);
		for(i = 0; i < num_of_keys; i++){
#ifdef PREFETCH_ENABLE
			_insert_key_value(spill_req->handle, (void *)&keys[i * litemsz], NULL, spill_req->dst_tree_id);
#else
			_insert_key_value(spill_req->handle, level_sc->keyValue,INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (spill_req->dst_tree_id << 8));
			++local_spilled_keys;
			//_sync_fetch_and_add(&db_desc->spilled_keys,1);

			rc = _get_next_KV(level_sc);

			if(rc == END_OF_DATABASE)
				break;
#ifndef NDEBUG
			if (spill_req->end_key !=NULL &&_tucana_key_cmp(level_sc->keyValue,spill_req->end_key,KV_PREFIX,KV_FORMAT) >= 0) {
				printf("[%s:%s:%d] STOP KEY REACHED %s\n",__FILE__,__func__,__LINE__,(char *)spill_req->end_key+4);
				goto finish_spill;
			}
#endif

#endif
		}
#ifdef PREFETCH_ENABLE
		/*XXX TODO XXX, we ll need this for calculating batching factor*/
		if(leaves_needed > 0){
			scan_num_of_keys += num_of_keys * 1.0;
			scan_leaves_needed += leaves_needed * 1.0;
		}
#endif

	}while(rc != END_OF_DATABASE);
#ifndef NDEBUG
finish_spill:
#endif
	_close_spill_buffer_scanner(level_sc, spill_req->src_root);
#ifdef PREFETCH_ENABLE
	fprintf(stderr, "SCANNER_END_BATCH_FACTOR=[%lf][keys_per_leaf]\n", scan_num_of_keys / scan_leaves_needed);
#endif
	/*sanity check
	  if(spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
	  printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
	  exit(EXIT_FAILURE);
	  }*/
	printf("[%s:%s:%d] local spilled keys %d\n",__FILE__,__func__,__LINE__,local_spilled_keys);
	/*Clean up code, Free the buffer tree was occupying. free_block() used intentionally*/
	__sync_fetch_and_sub(&db_desc->count_active_spillers,1);
	if(db_desc->count_active_spillers == 0){
		printf("[%s:%s:%d] last spiller cleaning up level 0 remains\n",__FILE__,__func__,__LINE__);
		void * free_addr = (void *)db_desc->segments[spill_req->src_tree_id*3];
		uint64_t size = db_desc->segments[(spill_req->src_tree_id*3)+1];

		while(1){
			if(size != BUFFER_SEGMENT_SIZE){
				fprintf(stderr, "[%s:%s:%d] FATAL corrupted segment size %llu should be %llu\n",__FILE__,__func__,__LINE__,(LLU)size,(LLU)BUFFER_SEGMENT_SIZE);
			        raise(SIGINT);
				exit(EXIT_FAILURE);
			}
			uint64_t s_id = ((uint64_t)free_addr - (uint64_t)spill_req->handle->volume_desc->bitmap_end)/BUFFER_SEGMENT_SIZE;
			//printf("[%s:%s:%d] freeing %llu size %llu s_id %llu freed pages %llu\n",__FILE__,__func__,__LINE__,(LLU)free_addr,(LLU)size,(LLU)s_id,(LLU)handle->volume_desc->segment_utilization_vector[s_id]);
			if(handle->volume_desc->segment_utilization_vector[s_id]!= 0 && handle->volume_desc->segment_utilization_vector[s_id] < SEGMENT_MEMORY_THREASHOLD){

				//printf("[%s:%s:%d] last segment remains\n",__FILE__,__func__,__LINE__);
				/*dimap hook, release dram frame*/
				/*if(dmap_dontneed(FD, ((uint64_t)free_addr-MAPPED)/PAGE_SIZE, BUFFER_SEGMENT_SIZE/PAGE_SIZE)!=0){
				  printf("[%s:%s:%d] fatal ioctl failed\n",__FILE__,__func__,__LINE__);
				  exit(-1);
				  }
				  __sync_fetch_and_sub(&(handle->db_desc->zero_level_memory_size), (unsigned long long)handle->volume_desc->segment_utilization_vector[s_id]*4096);
				*/
				handle->volume_desc->segment_utilization_vector[s_id] = 0;
			}
			free_block(spill_req->handle->volume_desc, free_addr, size, -1);
			if(*(uint64_t *)free_addr == 0x0000000000000000) /* that was the last for tree */
				break;

			free_addr = (void *)(MAPPED + *(uint64_t *)free_addr);
			size = *(uint64_t *)(free_addr+sizeof(uint64_t));
		}

		/*assert check
		  if(db_desc->spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
		  printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)db_desc->spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
		  exit(EXIT_FAILURE);
		  }*/
		/*buffered tree out*/
		db_desc->total_keys[spill_req->src_tree_id] = 0;
		db_desc->segments[spill_req->src_tree_id*3] = 0;
		db_desc->segments[(spill_req->src_tree_id*3)+1] = 0;
		db_desc->segments[(spill_req->src_tree_id*3)+2] = 0;
		db_desc->root_r[spill_req->src_tree_id] = NULL;
		db_desc->root_w[spill_req->src_tree_id] = NULL;
		//db_desc->spilled_keys=0;
		/*XXX TODO XXX REMOVE*/
		db_desc->zero_level_memory_size=0;
		db_desc->tree_status[spill_req->src_tree_id] = NO_SPILLING;
		spill_req->handle->db_desc->atomic_spill = 0;
	}

	free(spill_req);
	printf("[%s:%s:%d] spill finished\n",__FILE__,__func__,__LINE__);
}

/**
 * Creates a mutation batch, if size is set to <= 0 default size MUTATION_LOG_SIZE
 * will be set.
 *
 **/
mutation_batch * create_mutation_batch(int32_t size){
	mutation_batch * new_batch;
	if(size <= 0)
		size = MUTATION_LOG_SIZE;
	new_batch = (mutation_batch *)malloc(sizeof(mutation_batch)+size);
	new_batch->position = 0;
	new_batch->num_of_mutations = 0;
	new_batch->size = size;
	new_batch->buffer = (void *)((uint64_t)new_batch+sizeof(mutation_batch));
	new_batch->type = DYNAMIC;
	return new_batch;
}

mutation_batch * create_mutation_batch_from_buffer(void * buffer, uint32_t size, uint32_t num_of_mutations){

	mutation_batch * new_batch;
	new_batch = (mutation_batch *)malloc(sizeof(mutation_batch));
	new_batch->position = size;
	new_batch->num_of_mutations = num_of_mutations;
	new_batch->size = size;
	new_batch->buffer = buffer;
	new_batch->type = STATIC;
	return new_batch;
}

void initiate_mutation_batch_from_buffer(mutation_batch *batch,void * buffer,int32_t size,int32_t num_of_mutations){
	batch->position = size;
	batch->num_of_mutations = num_of_mutations;
	batch->size = size;
	batch->buffer = buffer;
	batch->type = STATIC;
}

void clear_mutation_batch(mutation_batch *mutation){
	mutation->position = 0;
	mutation->num_of_mutations = 0;
}

void destroy_mutation_batch(mutation_batch *mutation){

	if(mutation->type == DYNAMIC)
		free(mutation);
}

uint8_t add_mutation(mutation_batch * batch, void * key, void *value, uint32_t key_size, uint32_t value_size)
{
	uint8_t status = SUCCESS;
	while(key_size+value_size+(2*sizeof(uint32_t)) > (batch->size-batch->position))
	{
		if(batch->type == STATIC)
		{
			printf("[%s:%s:%d] unable to resize a static batch\n",__FILE__,__func__,__LINE__);
			return FAILED;
		}
		printf("[%s:%s:%d] mutation log overflow going to double its size from %d to %d bytes\n",__FILE__,__func__,__LINE__, batch->size, 2*batch->size);
		mutation_batch * new_batch = create_mutation_batch(2*batch->size);
		memset(new_batch,0x00,2*new_batch->size);
		memcpy(new_batch,batch,batch->size);
		new_batch->position = batch->position;
		new_batch->num_of_mutations = batch->num_of_mutations;
		new_batch->size = 2*batch->size;
		destroy_mutation_batch(batch);
		*(uint64_t *)batch = (uint64_t)new_batch;
		status = MUTATION_BATCH_EXPANDED;
	}

	*(uint32_t *)((uint64_t)batch->buffer + batch->position) = key_size;
	batch->position += sizeof(uint32_t);
	memcpy((void *)(uint64_t)batch->buffer + batch->position, key,key_size);
	batch->position += key_size;
	*(uint32_t *)((uint64_t)batch->buffer + batch->position) = value_size;
	batch->position += sizeof(uint32_t);
	memcpy((void *)(uint64_t)batch->buffer + batch->position, value,value_size);
	batch->position += value_size;
	batch->num_of_mutations ++ ;
	return status;
}

void parse_deleted_keys(db_descriptor *db_desc)
{
	/*
	  void * addr;
	  block_header * current_block;
	  uint64_t position;
	  uint64_t size;
	  uint64_t epoch;
	  uint64_t remaining;
	  int32_t entries = 0;
	  position = sizeof(block_header);
	  size = db_desc->delete_log_size;
	  current_block = db_desc->first_delete_log;
	  remaining = DELETE_BLOCK_SIZE - sizeof(block_header);
	  do
	  {
	  addr = (void *)(uint64_t)current_block + position%DELETE_BLOCK_SIZE;
	  epoch = *(uint64_t *)addr;
	  addr = (void *)MAPPED + *(uint64_t *)(addr+sizeof(uint64_t));
	  entries++;
	  printf("[%s:%s:%d] epoch %llu deleted key %s entries %d\n",__FILE__,__func__,__LINE__,(LLU)epoch, (char *)addr+4, entries);
	  position += sizeof(delete_key_request);
	  remaining -= sizeof(delete_key_request);
	  if(remaining < sizeof(delete_key_request))//time to move to next delete log block
	  {

	  printf("[%s:%s:%d] changing block\n",__FILE__,__func__,__LINE__);

	  current_block = current_block->next_block;
	  position += (remaining + sizeof(block_header));
	  if(current_block == NULL)
	  {
	  printf("[%s:%s:%d] end of delete log\n",__FILE__,__func__,__LINE__);
	  break;
	  }
	  remaining = DELETE_BLOCK_SIZE - sizeof(block_header);
	  }
	  }while(position < size);
	*/
}

/*functions used for debugging*/
void assert_index_node(node_header * node)
{
	int32_t k;
	void * key_tmp;
	void * key_tmp_prev = NULL;
	void * addr;
	node_header * child;
	addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header);
	/* printf("[%s:%s:%d]: current view of the index\n",__FILE__,__func__,__LINE__); */
	for(k=0;k<node->num_entries;k++){
		/*check child type*/
		child = (node_header *)(MAPPED + *(uint64_t *)addr);
		if(child->type!=rootNode && child->type!=internalNode && child->type != leafNode && child->type != leafRootNode)
		{
			printf("[%s:%s:%d] FATAL corrupted child at index for child %llu type is %d\n",__FILE__,__func__,__LINE__, (LLU)(uint64_t)child-MAPPED, child->type);
			exit(-1);
		}
		//printf("\tpointer to child %llu\n", (LLU)child-MAPPED);

		addr+=sizeof(uint64_t);
		key_tmp = (void *)MAPPED + *(uint64_t *)addr;
		/* printf("\tkey %s\n",(char *)key_tmp+sizeof(int32_t)); */

		if(key_tmp_prev != NULL)
		{
			if(_tucana_key_cmp(key_tmp_prev, key_tmp, KV_FORMAT, KV_FORMAT) >=0 )
				{
					printf("[%s:%s:%d] FATAL: corrupted index\n",__FILE__,__func__,__LINE__);
					raise(SIGINT);
					exit(-1);
				}
		}
		key_tmp_prev = key_tmp;
		addr+=sizeof(uint64_t);
	}
	child = (node_header *)(MAPPED + *(uint64_t *)addr);
	if(child->type!=rootNode && child->type!=internalNode && child->type != leafNode && child->type != leafRootNode)
	{
		printf("[%s:%s:%d] FATAL corrupted last child at index\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	//printf("\t\tpointer to last child %llu\n", (LLU)(uint64_t)child-MAPPED);
}

#ifdef DEBUG_TUCANA_2
void print_node(node_header * node){
	printf("\n***Node synopsis***\n");
	if(node == NULL)
	{
		printf("NULL\n");
		return;
	}
	//printf("DEVICE OFFSET = %llu\n", (uint64_t)node - MAPPED);
	printf("type = %d\n",node->type);
	printf("total entries = %d\n",node->num_entries);
	printf("epoch = %llu\n",(LLU)node->epoch);
	printf("height = %llu\n",(LLU)node->height);
	printf("fragmentation = %llu\n",(LLU)node->fragmentation);
}

#endif

void _init_locktable(db_descriptor* database){

	unsigned int i,j;
	lock_table* init;

	for(i=0;i<MAX_HEIGHT;++i){

		if(posix_memalign((void **)&database->multiwrite_level_0[i],4096,sizeof(lock_table)*size_per_height[i]) != 0){
			printf("[%s:%s:%d] fatal memalign failed\n",__FILE__,__func__,__LINE__);
		}
		init=database->multiwrite_level_0[i];

		for(j=0;j<size_per_height[i];++j){

			if(RWLOCK_INIT(&init[j].rx_lock,NULL)!=0){
				printf("[%s:%s:%d] failed to initialize lock_table for level 0 lock\n",__FILE__,__func__,__LINE__);
				exit(-1);
			}
		}

		if(posix_memalign((void **)&database->multiwrite_level_1[i],4096,sizeof(lock_table)*size_per_height[i]) != 0){
			printf("[%s:%s:%d] fatal memalign failed\n",__FILE__,__func__,__LINE__);
		}

		init=database->multiwrite_level_1[i];

		for(j=0;j<size_per_height[i];++j){

			if(RWLOCK_INIT(&init[j].rx_lock,NULL)!=0){
				printf("[%s:%s:%d] failed to initialize lock_table for level 1 lock\n",__FILE__,__func__,__LINE__);
				exit(-1);
			}
		}
	}
}

void _destroy_locktable(db_descriptor* database){

	int i;

	for(i=0;i<MAX_HEIGHT;++i){
		free(database->multiwrite_level_0[i]);
		free(database->multiwrite_level_1[i]);
	}

}

uint64_t hash(uint64_t x) {
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table * _find_position(lock_table** table,node_header* node,db_descriptor* db){

	unsigned long position;
	lock_table * return_value;

	if(node->height >= MAX_HEIGHT){
		printf("FATAL ERROR [%s: %s: %d]: MAX_HEIGHT exceeded rearrange values in size_per_height array \n",__func__,__FILE__,__LINE__);
		exit(-1);
	}

	position=hash((uint64_t)node)%size_per_height[node->height];
	return_value=table[node->height];
	return &return_value[position];
}


void _unlock_upper_levels(lock_table * node[],unsigned size,unsigned release){

	unsigned i;
	for(i=release;i<size;++i)
		if(RWLOCK_UNLOCK(&node[i]->rx_lock)!=0){
			printf("[%s:%s:%d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
}


node_header * allocate_root(insertKV_request* req,node_header* son){
	node_header* node_copy = (*req->allocator_desc.allocate_space)((void *)req->allocator_desc.handle, NODE_SIZE, req->allocator_desc.level_id, NEW_ROOT);
	memcpy(node_copy, son, NODE_SIZE);
	node_copy->v1=0;
	node_copy->v2=0;
	return node_copy;
}

node_header* rcuLock(node_header* node,db_descriptor* db_desc,insertKV_request * req){

	if(node&&(node->type == leafRootNode || node->type == rootNode)){
		MUTEX_LOCK(&db_desc->rcu_root);
		__sync_fetch_and_add(&db_desc->rcu_root_v1,1);
		return (req->level_id != NUM_OF_TREES_PER_LEVEL)? db_desc->root_w[db_desc->active_tree]:db_desc->root_w[NUM_OF_TREES_PER_LEVEL];
	}

	return NULL;
}

void rcuUnlock(node_header* node,db_descriptor* db_desc,insertKV_request * req){
	int i = (req->level_id != NUM_OF_TREES_PER_LEVEL)? db_desc->active_tree:NUM_OF_TREES_PER_LEVEL;
	if(node)
		db_desc->root_w[i] = node;

	__sync_fetch_and_add(&db_desc->rcu_root_v2,1);
	assert(db_desc->rcu_root_v1 == db_desc->rcu_root_v2);
	MUTEX_UNLOCK(&db_desc->rcu_root);

}

int splitValidation(node_header* father,node_header* son,db_descriptor* db_desc,split_request* split_req,uint32_t order,split_data* data,insertKV_request * req){
	node_header* flag = NULL;
	int flow_control = 0;
	uint32_t temp_order;
	data->son = data->father = NULL;

	if(son->type == leafRootNode || son->type == rootNode || (father && father->type ==rootNode)){
		flag = rcuLock(son,db_desc,req);
		if(!flag){
			flag = rcuLock(father,db_desc,req);
			if(flag)
				flow_control = 1;
		}else{
			flow_control = 2;
		}

		if(flag->type == leafRootNode)
			temp_order = leaf_order;
		else
			temp_order = index_order;
		if(flow_control == 2){//son = root
			if(son->num_entries !=flag->num_entries||son->height !=flag->height||flag->num_entries < temp_order){
				rcuUnlock(NULL,db_desc,req);
				data->son = data->father = NULL;
				return -1;
			}

			if(flag->type ==leafRootNode|| flag->type == rootNode){
				data->son = flag;
				return 1;
			}
			assert(0);

		}else if (flow_control == 1){
			if(father->num_entries != flag->num_entries||father->height != flag->height || flag->num_entries >= index_order || (flag->height - son->height) != 1){
				rcuUnlock(NULL,db_desc,req);
				data->son = data->father = NULL;
				return -1;
			}

			if(flag->type == rootNode){//I am a root child and i should acquire its lock in order to insert the pivot after the split.
				data->father = flag;
				return 1;
			}
			assert(0);
		}
	}
	if(son->type == leafRootNode || son->type == rootNode)
		assert(0);
	if(father&& father->type == rootNode)
		assert(0);
	return 0;
}


uint8_t _concurrent_insert(insertKV_request * req){
	spill_request * workers[NUM_OF_SPILL_THREADS_PER_DB];
	lock_table * upper_level_nodes[MAX_HEIGHT];/*The array with the locks that belong to this thread from upper levels*/
	void * next_addr;
	superindex * soft_superindex;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	split_request split_req;
	split_data data;
	split_reply split_rep;
	node_header * new_node;
	node_header * node_copy;
	node_header * father;
	node_header * son;
	lock_table * lock;
	lock_table ** level_lock_table;
	int64_t * writers_counter;
	uint64_t addr;
	volatile uint64_t v1,v2,v1_spill,v2_spill;
	int64_t ret;
	unsigned size=0;/*Size of upper_level_nodes*/
	unsigned release=0;/*Counter to know the position that releasing should begin */
	uint32_t order;
	node_header* flag = NULL;
	int TREE_LEVEL;
	int split_valid;
	// remove some warnings here
	(void)ret;
	(void)addr;
	int i,j;
	volume_desc = req->handle->volume_desc;
	db_desc = req->handle->db_desc;

	if((req->insert_mode&0xFF000000) == INSERT_TO_L0_INDEX){
		TREE_LEVEL = INSERT_TO_L0_INDEX;
		writers_counter=&db_desc->count_writers_level_0;
		level_lock_table=db_desc->multiwrite_level_0;
	} else if ((req->insert_mode&0xFF000000) == INSERT_TO_L1_INDEX){
		TREE_LEVEL = INSERT_TO_L1_INDEX;
		writers_counter=&db_desc->count_writers_level_1;
		level_lock_table=db_desc->multiwrite_level_1;
	}else{
		printf("[%s:%s:%d]UNKNOWN INSERT MODE\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
retry:
	flag = NULL;
	father = NULL;
	split_valid = 0;
	_unlock_upper_levels(upper_level_nodes,size,release);
	size=0;
	release=0;

	v2 = snapshot_v2;
	v1 = snapshot_v1;
	v2_spill = db_desc->spill_v2;
	v1_spill = db_desc->spill_v1;

	if(v1 != v2 || v1_spill != v2_spill) {
		usleep(THROTTLE_SLEEP_TIME);
		goto retry;
	}

	__sync_fetch_and_add(writers_counter,1);

	v2 = snapshot_v2;
	v1 = snapshot_v1;
	v2_spill = db_desc->spill_v2;
	v1_spill = db_desc->spill_v1;

	if(v1 != v2 || v1_spill != v2_spill) {
		__sync_fetch_and_sub(writers_counter,1);
		goto retry;
	}

	soft_superindex = req->handle->volume_desc->soft_superindex;

	if(req->level_id < NUM_OF_TREES_PER_LEVEL){
		req->level_id=db_desc->active_tree;
		req->allocator_desc.level_id = db_desc->active_tree;
	}

	v2 = db_desc->rcu_root_v2;
	son = db_desc->root_w[req->level_id];
	v1 = db_desc->rcu_root_v1;

	if(v1 != v2){
		__sync_fetch_and_sub(writers_counter,1);
		goto retry;
	}

	if(TREE_LEVEL == INSERT_TO_L0_INDEX &&
           db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
           memcmp(db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0){
		if(db_desc->atomic_spill){
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		if(MUTEX_TRYLOCK(&db_desc->spill_trigger) == 0)
			;
		else{
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		int check_if_spill_should_happen = TREE_LEVEL == INSERT_TO_L0_INDEX &&
			db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
			memcmp(db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0;

		if(!check_if_spill_should_happen || db_desc->atomic_spill == 1){
			MUTEX_UNLOCK(&db_desc->spill_trigger);
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		db_desc->atomic_spill = 1;
                printf("[%s:%s:%d] initiating spill\n",__FILE__,__func__,__LINE__);
                /*Wating for pending writers to finish*/
                /*spinning*/
		__sync_fetch_and_add(&db_desc->spill_v1,1);
                spin_loop(writers_counter,1);
              /*switch to another tree, but which?*/
                for(i=0;i<NUM_OF_TREES_PER_LEVEL;i++){
                        if(i!= req->level_id && db_desc->tree_status[i] != SPILLING_IN_PROGRESS){

				db_desc->active_tree = i;
				allocate_segment(req->handle,BUFFER_SEGMENT_SIZE,i,NEW_LEVEL_0_TREE);
				db_desc->root_w[i] = (node_header *)createEmptyNode(&(req->allocator_desc), req->handle, leafRootNode, NEW_ROOT);

				printf("[%s:%s:%d] New Active tree is %d\n",__FILE__,__func__,__LINE__,i);
                                db_desc->tree_status[req->level_id] = SPILLING_IN_PROGRESS;
				__sync_fetch_and_add(&db_desc->spill_v2,1);
                                /*spawn a spiller thread*/
                                for (j = 0; j < NUM_OF_SPILL_THREADS_PER_DB; ++j) {

                                        workers[j] = (spill_request *)malloc(sizeof(spill_request));/*XXX TODO XXX MEMORY LEAK WE HAVE TO FREE IT SOMEWHERE  */
                                        workers[j]->handle = req->handle;
                                        if(db_desc->root_w[req->level_id]!=NULL)
                                                workers[j]->src_root = db_desc->root_w[req->level_id];
                                        else
                                                workers[j]->src_root = db_desc->root_r[req->level_id];

                                        workers[j]->src_tree_id = req->level_id;
                                        workers[j]->dst_tree_id = NUM_OF_TREES_PER_LEVEL;
                                }
                                /*Create Spill Ranges*/
                                if(NUM_OF_SPILL_THREADS_PER_DB == 1){
					workers[0]->start_key = NULL;
					workers[0]->end_key = NULL;
                                }else{
                                        _create_spill_ranges(db_desc->root_w[req->level_id],workers);
                                }
                                db_desc->count_active_spillers = NUM_OF_SPILL_THREADS_PER_DB;
                                for (j = 0; j < NUM_OF_SPILL_THREADS_PER_DB; ++j)
                                        if(pthread_create(&db_desc->spiller[j],NULL,(void *)spill_buffer, (void *)workers[j])!=0){
                                                fprintf(stderr, "FATAL: error creating spiller thread\n");
                                                exit(-1);
                                        }
                                break;
                        }
                }
		MUTEX_UNLOCK(&db_desc->spill_trigger);
                __sync_fetch_and_sub(writers_counter,1);
                goto retry;
        }

	while(1){
		v2 = db_desc->rcu_root_v2;
		if(son->type == leafNode || son->type == leafRootNode)
			order = leaf_order;
		else
			order = index_order;
		/*Check if father is safe it should be*/
#if 0
		if(father){
			unsigned int father_order;
			if(father->type == leafNode || father->type == leafRootNode)
				father_order=leaf_order;
			else
				father_order=index_order;
			/* assert(father->epoch > volume_desc->dev_superindex->epoch); */
			/* assert(father->num_entries < father_order); */
		}
#endif
		v1 = db_desc->rcu_root_v1;
		if((son->type == leafRootNode || son->type == rootNode) && v1 != v2){
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		if(son->num_entries >= order){/*Overflow split*/
			split_valid = splitValidation(father,son,db_desc,&split_req,order,&data,req);
			if(split_valid == -1 ){
				__sync_fetch_and_sub(writers_counter,1);
				goto retry;
			}

			node_header* cow_root;
			if(data.son || data.father)
				cow_root = allocate_root(req,(data.son)?data.son:data.father);

			if(data.son)
				son = cow_root;
			if(data.father)
				father = cow_root;

			/*Split operation started*/
			split_req.handle = req->handle;
			split_req.node = son;
			split_req.allocator_desc.allocate_space = req->allocator_desc.allocate_space;
			split_req.allocator_desc.free_space = req->allocator_desc.free_space;
			split_req.allocator_desc.handle = req->allocator_desc.handle;
			split_req.allocator_desc.level_id = req->allocator_desc.level_id;

			if(son->height > 0){
				son->v1++;
				split_index(&split_req, &split_rep);
				/* free_logical_node(&(req->allocator_desc),son);/\*node has splitted, free it*\/ */
				son->v2++;
			}else{
				/* son->v1++; */
				split_leaf(&split_req, &split_rep);
				/* son->v2++; */
			}
			/*Insert pivot at father*/
			if(father!=NULL){
				father->v1++;/*lamport counter*/
				insertKeyAtIndex(&(req->allocator_desc),father,split_rep.left_child,split_rep.right_child,split_rep.middle_key_buf,KEY_LOG_EXPANSION);
				father->v2++;/*lamport counter*/

				if(split_valid == 1)
					rcuUnlock(father,db_desc,req);

			}else{
				/*Root was splitted*/
				new_node = createEmptyNode(&(req->allocator_desc),req->handle, rootNode, NEW_ROOT);
				/*lamport counter*/
				son->v1++;
				new_node->v1++;
				insertKeyAtIndex(&(req->allocator_desc),new_node,split_rep.left_child,split_rep.right_child,split_rep.middle_key_buf,KEY_LOG_EXPANSION);
				/*lamport counter*/
				new_node->v2++;
				son->v2++;
				rcuUnlock(new_node,db_desc,req);
			}

			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}else if(son->epoch <= volume_desc->dev_superindex->epoch){ /*Cow*/

#ifndef NDEBUG
			assert(son->type != leafRootNode);
			if(father)
				assert(father->type != rootNode);
#endif
			node_copy = (*req->allocator_desc.allocate_space)((void *)req->allocator_desc.handle, NODE_SIZE, req->allocator_desc.level_id, NEW_ROOT);
			memcpy(node_copy, son, NODE_SIZE);
			node_copy->epoch = soft_superindex->epoch;
			node_copy->v1=0;
			node_copy->v2=0;
			/*Update father's pointer*/
			if(father)
				father->v1++;/*lamport counter*/
			*(uint64_t *)next_addr = (uint64_t)node_copy-MAPPED;

			if(father)
				father->v2++;
			/* Free the node */
			(*req->allocator_desc.free_space)((void *)req->allocator_desc.handle,son,NODE_SIZE,req->allocator_desc.level_id);
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		if(son->height == 0)
			break;
		/*Finding the next node to traverse*/
		v2 = db_desc->rcu_root_v2;
		next_addr = _index_node_binary_search((index_node *)son, req->key_value_buf, req->key_format);
		father = son;
		node_header* temp = (node_header *) (MAPPED + *(uint64_t *)next_addr);
		/*Taking the lock of the next node before its traversal*/
		lock = _find_position(level_lock_table,temp,db_desc);
		v1 = db_desc->rcu_root_v1;
		if((temp->type==rootNode || temp->type==leafRootNode) && v1!=v2){
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		upper_level_nodes[size++]=lock;
		if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){
			printf("[%s %s %d] ERROR locking\n",__func__,__FILE__,__LINE__);
			raise(SIGINT);
			exit(-1);
		}
		/*Node acquired */
		son = temp;

		if(son->type == leafNode || son->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;
		/*if the node is not safe hold its ancestor's lock else release locks from ancestors */
		if(!(son->epoch <= volume_desc->dev_superindex->epoch||son->num_entries >= order)){
			_unlock_upper_levels(upper_level_nodes,size-1,release);
			release = size - 1;
		}
	}

	if(son->height!=0){
		printf("[%s:%s:%d] FATAL son corrupted\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	if(son->type == leafRootNode)
		flag = rcuLock(son,db_desc,req);
	if(flag){
		if(flag->type == leafNode || flag->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;
		if(flag->num_entries >= order|| flag != son || son->height != flag->height){
			rcuUnlock(NULL,db_desc,req);
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}
		flag = allocate_root(req,flag);
	}
	son->v1++;/*lamport counter*/
        if (!flag)
		 ret = insertKVAtLeaf(req, son, KV_LOG_EXPANSION);
        else{
		ret = insertKVAtLeaf(req, flag, KV_LOG_EXPANSION);
		rcuUnlock(flag, db_desc, req);
	}
        son->v2++;/*lamport counter*/

	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes,size,release);
	__sync_fetch_and_sub(writers_counter,1);
	return 1;
}


uint8_t _writers_join_as_readers(insertKV_request * req){

	lock_table * upper_level_nodes[MAX_HEIGHT];/*The array with the locks that belong to this thread from upper levels*/
	void * next_addr;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	node_header * son;
	lock_table * lock;
	node_header* flag=NULL;
	lock_table ** level_lock_table;
	int64_t * writers_counter;
	node_header*father;
	uint64_t addr;
	int64_t ret;
	unsigned size=0;/*Size of upper_level_nodes*/
	unsigned release=0;/*Counter to know the position that releasing should begin */
	uint32_t order;
	int TREE_LEVEL;
	volatile uint64_t v1,v2,v1_spill,v2_spill;
	// remove some warnings here
	(void)ret;
	(void)addr;

	volume_desc = req->handle->volume_desc;
	db_desc = req->handle->db_desc;

	if( (req->insert_mode&0xFF000000) == INSERT_TO_L0_INDEX){
		TREE_LEVEL = INSERT_TO_L0_INDEX;
		writers_counter=&db_desc->count_writers_level_0;
		level_lock_table=db_desc->multiwrite_level_0;
	} else if((req->insert_mode&0xFF000000) == INSERT_TO_L1_INDEX){
		TREE_LEVEL = INSERT_TO_L1_INDEX;
		writers_counter=&db_desc->count_writers_level_1;
		level_lock_table=db_desc->multiwrite_level_1;
	} else {
		printf("[%s:%s:%d] FATAL unkown insert mode\n",__FILE__,__func__,__LINE__);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
retry:
	_unlock_upper_levels(upper_level_nodes,size,release);
	size=0;
	release=0;

	v2 = snapshot_v2;
	v1 = snapshot_v1;
	v2_spill = db_desc->spill_v2;
	v1_spill = db_desc->spill_v1;

	if( v1 != v2 || v1_spill != v2_spill ) {
		usleep(THROTTLE_SLEEP_TIME);
		goto retry;
	}

	__sync_fetch_and_add(writers_counter,1);

	v2 = snapshot_v2;
	v1 = snapshot_v1;
	v2_spill = db_desc->spill_v2;
	v1_spill = db_desc->spill_v1;

	if(v1 != v2 || v1_spill != v2_spill) {
		__sync_fetch_and_sub(writers_counter,1);
		usleep(THROTTLE_SLEEP_TIME);
		goto retry;
	}

	if(req->level_id < NUM_OF_TREES_PER_LEVEL){
		req->level_id=db_desc->active_tree;
		req->allocator_desc.level_id = db_desc->active_tree;
	}

	v2 = db_desc->rcu_root_v2;
	son = db_desc->root_w[req->level_id];
	v1 = db_desc->rcu_root_v1;

	if(v1 != v2){
		__sync_fetch_and_sub(writers_counter,1);
		goto retry;
	}

	if(TREE_LEVEL == INSERT_TO_L0_INDEX &&
	   db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
	   memcmp(db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0){
		_unlock_upper_levels(upper_level_nodes,size,release);
		__sync_fetch_and_sub(writers_counter,1);
		return FAILURE;
	}

	while(1){
		if(son->type == leafNode || son->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;

		if(son->num_entries >= order){/*Overflow split*/
			/*Split operation started*/
			_unlock_upper_levels(upper_level_nodes,size,release);
			__sync_fetch_and_sub(writers_counter,1);
			return FAILURE;
		}else if(son->epoch <= volume_desc->dev_superindex->epoch){ /*Cow*/
			_unlock_upper_levels(upper_level_nodes,size,release);
			__sync_fetch_and_sub(writers_counter,1);
			return FAILURE;
		}

		if(son->height==0)
			break;
		/*Finding the next node to traverse*/
		v2 = db_desc->rcu_root_v2;
		father = son;
		next_addr = _index_node_binary_search((index_node *)son, req->key_value_buf, req->key_format);
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);
		v1 = db_desc->rcu_root_v1;

		if((father->type==rootNode||father->type==leafRootNode) && v1!=v2){
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		v2 = db_desc->rcu_root_v2;
		/*Taking the lock of the next node before its traversal*/
		lock = _find_position(level_lock_table,son,db_desc);
		v1 = db_desc->rcu_root_v1;

		if((son->type==rootNode || son->type==leafRootNode) && v1!=v2){
			__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		if(son->height == 0)
			break;

		upper_level_nodes[size++]=lock;
		if(RWLOCK_RDLOCK(&lock->rx_lock)!=0){
			printf("[%s %s %d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
		/*Node acquired */
		_unlock_upper_levels(upper_level_nodes,size-1,release);
		release=size-1;
	}

	if(son->type != leafRootNode){
		lock = _find_position(level_lock_table,son,db_desc);
		upper_level_nodes[size++]=lock;
		if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){
			printf("[%s %s %d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
	}

	if(son->num_entries >= leaf_order || son->epoch <= volume_desc->dev_superindex->epoch){
		_unlock_upper_levels(upper_level_nodes,size,release);
		__sync_fetch_and_sub(writers_counter,1);
		return FAILURE;
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if(son->height!=0){
		printf("[%s:%s:%d] FATAL son corrupted\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	if(son->type == leafRootNode){
		flag = rcuLock(son,db_desc,req);
		if(flag != son || flag->height != 0){
			rcuUnlock(NULL,db_desc,req);
			__sync_fetch_and_sub(writers_counter,1);
			return FAILURE;
		}
		flag = allocate_root(req,flag);
	}
	son->v1++;/*lamport counter*/

        if (!flag)
		ret = insertKVAtLeaf(req, son, KV_LOG_EXPANSION);
        else {
		ret = insertKVAtLeaf(req, flag, KV_LOG_EXPANSION);
		rcuUnlock(flag, db_desc, req);
        }

        son->v2++;/*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes,size,release);
	__sync_fetch_and_sub(writers_counter,1);
	return 1;
}
