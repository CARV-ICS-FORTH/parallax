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

#include "../../utilities/macros.h"
#include "../allocator/dmap-ioctl.h"
#include "../scanner/scanner.h"
//#include "../btree/stats.h"
#include "../btree/assertions.h"
#include "../btree/conf.h"
#include "../../kreon_server/conf.h"


#define PREFIX_STATISTICS_NO
#define MIN(x,y) ((x > y)?(y):(x))
#define KEY_SIZE(x) *(uint32_t *)x


#define SYSTEM_NAME "kreon"

#define USE_SYNC
#undef USE_SYNC

#define KV_MAX_SIZE 4096 + 8

#define DB_STILL_ACTIVE 0x01
#define COULD_NOT_FIND_DB 0x02

#define LOG_SEGMENT_CHUNK 262144

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


char * DB_NO_SPILLING = NULL;

uint64_t countgoto=0;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t log_buffer_lock;
/*number of locks per level*/
uint32_t size_per_height[MAX_HEIGHT]={8192,4096,2048,1024,512,256,128,64,32};


#define PAGE_SIZE 4096
#define LEAF_ROOT_NODE_SPLITTED 0xFC

#define MUTATION_LOG_SIZE 2048
#define STATIC 0x01
#define DYNAMIC 0x02
#define MUTATION_BATCH_EXPANDED 0x03
#define FAILURE 0

void insertKeyAtIndex(allocator_descriptor * allocator_desc, node_header * node, node_header * left_child, node_header * right_child, void *key_buf, char allocation_code);
void update_index(node_header* node, node_header * left_child, node_header * right_child, void *key_buf);
void split_index(split_request *req, split_reply * rep);
void _sent_flush_command_to_replica(db_descriptor* db_desc, int padded_space, int SYNC);

int __update_leaf_index(insertKV_request *req, node_header * leaf, void * key_buf, char key_format);
int split_leaf(split_request * req, split_reply *rep);

/*private functions to support delete operations*/
node_header *  __cow_in_node_header(allocator_descriptor * allocator_desc, db_handle * handle, node_header * node, int32_t size, int TYPE_OF_COW);
void __update_index_key_in_place(allocator_descriptor* allocator_desc, db_handle *handle, node_header * node, void * node_index_addr, void * key_buf, int32_t type);


/*added delete_request parameter*/
node_header * __merge_nodes(allocator_descriptor * allocator_desc, db_handle * handle, node_header * node_a, node_header * node_b);
void * __left_rotate(db_handle * handle, node_header * left_brother, node_header * self);
node_header * __right_rotate(db_handle *handle,node_header * self, node_header * right_brother);
int32_t __rebalance_controller(node_header * node, node_header * parent, uint64_t offset);


void _delete_key(delete_request * delete_req, delete_reply * delete_rep,  void *key);

/*Buffering aware functions*/
void * __find_key(db_handle * handle, void *key, node_header * root, char SEARCH_MODE);
void * __find_key_addr_in_leaf(node_header * leaf, void *key);
void spill_buffer(void * _spill_req);


void destroy_spill_request(NODE *node);
void * createEmptyNode(allocator_descriptor * allocator_desc, db_handle *handle, nodeType_t type, char allocation_code);

void mark_deleted_key(db_handle * handle, void *deleted_key_addr);
void _create_spill_ranges(node_header * root,spill_request * spill_req[]);

void _spill_check(db_handle *handle, char recovery_mode);


void assert_leaf_node(node_header * leaf);
#ifdef DEBUG_TUCANA_2
static void assert_index_node(node_header * node);
/*functions used for debugging*/
void print_node(node_header * node);
#endif

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

/*the size of both prefixes is 8 bytes FIXED!*/
int prefix_compare(char *l, char *r, size_t unused){
	return memcmp(l, r, unused);
}

/*free function for buffered trees, does nothing for now*/



/*XXX TODO XXX REMOVE HEIGHT UNUSED VARIABLE*/
void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height){

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

			query_key_buf = (void *)(*(uint64_t *)(query_key_buf+PREFIX_SIZE+HASH_SIZE));

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
		        index_key_buf = (void *)(*(uint64_t *)(index_key_buf+PREFIX_SIZE+HASH_SIZE));

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
		printf("%s: FATAL, combination not supported please check\n", __func__);
		exit(-1);
	}
	return 0;
}

/**
 * @param   blockSize
 * @param   db_name
 * @return  db_handle
 **/
db_handle * db_open(char * volumeName, uint64_t start, uint64_t size, char * db_name, char CREATE_FLAG)
{

	db_handle * handle;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	char * key;
	uint64_t val;
	int  i,m;
	int digits;

	i = 0;
	fprintf(stderr, "%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n","\033[0;32m", __FILE__,__func__, __LINE__, volumeName, start, size, db_name, "\033[0m");
	MUTEX_LOCK(&init_lock);
  /*just once, generic initialization for DB_NO_SPILLING mask*/
	if(DB_NO_SPILLING == NULL){
		DB_NO_SPILLING = (char *)malloc(sizeof(char)*NUM_OF_TREES_PER_LEVEL);
		memset(&DB_NO_SPILLING[0],NO_SPILLING,sizeof(char)*NUM_OF_TREES_PER_LEVEL);
	}

	if(mappedVolumes == NULL){
		mappedVolumes= init_list(&destroy_volume_node);
		/*calculate max leaf,index order*/
		leaf_order  = (DEVICE_BLOCK_SIZE - sizeof(node_header)) / (sizeof(uint64_t)+PREFIX_SIZE+HASH_SIZE);
		while(leaf_order%2 != 0)
			--leaf_order;
		index_order = (DEVICE_BLOCK_SIZE - sizeof(node_header)) / (2*sizeof(uint64_t));
		index_order-= 2;/*more space for extra pointer, and for rebalacing (merge)*/
		while(index_order%2 != 1)
			--index_order;

		if((NODE_SIZE-sizeof(node_header))%8 != 0){
		  DPRINT("Misaligned block header for leaf nodes, scans will not work\n");
			exit(EXIT_FAILURE);
		}
		if((NODE_SIZE-sizeof(node_header))%16 != 0){
			DPRINT("Misaligned block header for index nodes, scans will not work size of node_header %ld\n",sizeof(node_header));
			exit(-1);
		}
		DPRINT("index order is set to: %d leaf order is set to %d sizeof node_header = %lu\n",
		       index_order, leaf_order, sizeof(node_header));
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
	DPRINT("searching volume %s\n",key);
	volume_desc = (volume_descriptor *)find_element(mappedVolumes, key);

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
		volume_desc->open_databases = init_list(&destoy_db_list_node);
		volume_desc->offset = start;
		volume_desc->size  = size;
		MUTEX_INIT(&(volume_desc->allocator_lock),NULL);
		/*hack*/
		MUTEX_INIT(&(volume_desc->FREE_LOG_LOCK),NULL);
		allocator_init(volume_desc);
		add_first(mappedVolumes, volume_desc, key);
		volume_desc->reference_count++;
		/*soft state about the in use pages of level-0 for each BUFFER_SEGMENT_SIZE segment inside the volume*/
		volume_desc->segment_ulitization_vector_size = ((volume_desc->volume_superblock->dev_size_in_blocks - (1+FREE_LOG_SIZE+volume_desc->volume_superblock->bitmap_size_in_blocks))/(BUFFER_SEGMENT_SIZE/DEVICE_BLOCK_SIZE)) * 2;
		volume_desc->segment_utilization_vector = (uint16_t*)malloc(volume_desc->segment_ulitization_vector_size);
		memset(volume_desc->segment_utilization_vector,0x00,volume_desc->segment_ulitization_vector_size);

		DPRINT("volume %s state created max_tries %d\n", volume_desc->volume_name,MAX_ALLOCATION_TRIES);
	} else {
		DPRINT("Volume already mapped\n");
		volume_desc->reference_count++;
	}
	/*Before searching the actual volume's catalogue take a look at the current open databases*/
	db_desc = find_element(volume_desc->open_databases, db_name);
	if(db_desc != NULL) {
		DPRINT("DB %s already open for volume %s\n",db_name,key);
    handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		db_desc->reference_count++;
		db_desc->active_tree = 0;
		for(m=0;m<TOTAL_TREES;m++)
			db_desc->tree_status[m] = NO_SPILLING;
		MUTEX_UNLOCK(&init_lock);
		/* pthread_mutex_unlock(&init_lock); */
		free(key);
		return handle;
	} else {
		superindex_db_entry * db_entry;
		int32_t empty_group;
		int32_t empty_index;
		int32_t j;

		DPRINT("searching %s's  catalogue for db %s\n",SYSTEM_NAME,db_name);
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
						DPRINT("database: %s found at index [%d,%d]\n",db_entry->db_name,i,j);
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
							
              DPRINT("root_r[%d] = %llu stored = %llu\n",m,(LLU)db_desc->root_r[m],(LLU)db_entry->root_r[m]);
						}

            /*recover replica L1 forest if needed*/
            if(db_entry->replica_forest != NULL ){
              memcpy((void *)&db_desc->replica_forest, (void *)MAPPED + (uint64_t)db_entry->replica_forest, sizeof(forest));
              for(i=0; i<MAX_FOREST_SIZE;i++){
                if(db_desc->replica_forest.tree_status[i] == PERSISTED){
                  db_desc->replica_forest.tree_segment_list[i] = (segment_header *)MAPPED + *(uint64_t *) db_entry->replica_forest->tree_segment_list[i];
                  db_desc->replica_forest.tree_roots[i] = (node_header *)MAPPED + *(uint64_t *) db_entry->replica_forest->tree_roots[i]; 
                }
                else if(db_desc->replica_forest.tree_status[i] != NOT_USED || 
                    db_desc->replica_forest.tree_status[i] != PERSISTED) {
                  DPRINT("XXX TODO XXX needs recovery of space !\n");
                  exit(EXIT_FAILURE);
                }
                else if(db_desc->replica_forest.tree_status[i] == NOT_USED){
                  db_desc->replica_forest.tree_segment_list[i] = NULL;
                  db_desc->replica_forest.tree_roots[i] = NULL;
                } else {
                  DPRINT("FATAL DBs forest flags in inconsistent state\n");
                  exit(EXIT_FAILURE);
                }
              }
              DPRINT("-*-*-*- Recovered db's level 1 forest used in replica mode * - * - *\n");
            } else {
              DPRINT(" - * - forest not present? skipping - * - *\n");
              memset(&db_desc->replica_forest,0x00,sizeof(forest));
            }
            /*done with replica forest*/
						/*recover KV log for this database*/
						db_desc->commit_log =  (commit_log_info *)(MAPPED + ((uint64_t)db_entry->commit_log));
						if(db_desc->commit_log->first_kv_log != NULL)
							db_desc->KV_log_first_segment = (segment_header *)(MAPPED+ (uint64_t)db_desc->commit_log->first_kv_log);
						else
							db_desc->KV_log_first_segment = NULL;

						if(db_desc->commit_log->last_kv_log != NULL)
							db_desc->KV_log_last_segment = (segment_header *)(MAPPED+ (uint64_t)db_desc->commit_log->last_kv_log);
						else
							db_desc->KV_log_last_segment = NULL;

						db_desc->KV_log_size = db_desc->commit_log->kv_log_size;
						db_desc->L0_start_log_offset = db_entry->L0_start_log_offset;
						db_desc->L0_end_log_offset = db_entry->L0_end_log_offset;

						DPRINT("KV log segments first: %llu last: %llu log_size %llu\n",
							(LLU)db_desc->KV_log_first_segment,(LLU)db_desc->KV_log_last_segment, (LLU)db_desc->KV_log_size);
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
			DPRINT("DB not found instructed not to create one returning NULL\n");
			return NULL;
		}
		/*db not found allocate a new slot for it*/
		if(empty_group == -1 && empty_index == -1){
			DPRINT("FATAL MAX DBS %d reached\n",NUM_OF_DB_GROUPS*GROUP_SIZE);
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
		DPRINT("database %s not found, allocating slot [%d,%d] for it\n",(const char *)db_name,empty_group,empty_index);
		db_entry = (superindex_db_entry*)(MAPPED + (uint64_t)volume_desc->soft_superindex->db_group_index[empty_group] +(uint64_t)DB_ENTRY_SIZE+(uint64_t)(empty_index*DB_ENTRY_SIZE));
		db_entry->replica_forest = NULL;
    handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		db_desc = (db_descriptor *)malloc(sizeof(db_descriptor));
#ifdef SCAN_REORGANIZATION
		db_desc->leaf_id = 0;
		memset(db_desc->scan_access_counter,0x00,COUNTER_SIZE);
#endif
		db_desc->zero_level_memory_size = 0;
    /*this nullifies replica also*/
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
		db_desc->commit_log = (commit_log_info *)allocate_segment(volume_desc, DEVICE_BLOCK_SIZE,SYSTEM_ID, NEW_COMMIT_LOG_INFO);
    /*get a page for commit_log info*/
		if(CREATE_FLAG != O_CREATE_DB){
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
			DPRINT("primary db initializing KV log\n");
			db_desc->KV_log_first_segment = (segment_header *)allocate_segment(handle,BUFFER_SEGMENT_SIZE, KV_LOG_ID,KV_LOG_EXPANSION);
			memset(db_desc->KV_log_first_segment->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
			db_desc->KV_log_last_segment = db_desc->KV_log_first_segment;
			db_desc->KV_log_last_segment->segment_id = 0;
			db_desc->KV_log_last_segment->next_segment = NULL;
			db_desc->KV_log_last_segment->prev_segment = NULL;
			db_desc->KV_log_size = sizeof(segment_header);
			db_desc->L0_start_log_offset = sizeof(segment_header);
			db_desc->L0_end_log_offset = sizeof(segment_header);
			/*get a page for commit_log info*/
			db_desc->commit_log->first_kv_log = (segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
			db_desc->commit_log->last_kv_log = (segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
			db_desc->commit_log->kv_log_size =   (uint64_t)db_desc->KV_log_size;
			/*persist commit log information, this location stays permanent, there no need to rewrite it during snapshot()*/
			db_entry->commit_log = (commit_log_info *)((uint64_t)db_desc->commit_log - MAPPED);
		}
	}
	/*finally, finish initialization*/
finish_init:
#if LOG_WITH_MUTEX
	MUTEX_INIT(&db_desc->lock_log,NULL);
#else
	SPINLOCK_INIT(&db_desc->lock_log,PTHREAD_PROCESS_PRIVATE);
#endif
	SPINLOCK_INIT(&db_desc->back_up_segment_table_lock,PTHREAD_PROCESS_PRIVATE);
	db_desc->active_tree = 0;
	for(m=0;m<TOTAL_TREES;m++)
		db_desc->tree_status[m] = NO_SPILLING;

	add_first(volume_desc->open_databases, db_desc, db_name);
	MUTEX_UNLOCK(&init_lock);
	free(key);

	if(CREATE_FLAG == O_CREATE_DB){
		DPRINT("opened primary db\n");
		db_desc->db_mode = PRIMARY_DB;

	} else {
#ifdef KREONR
		DPRINT("opened replica db\n");
		db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
    DPRINT("Initializing  segment table\n");
		init_backup_db_segment_table(handle);
#else
		//FIXME should report error
#endif
	}
#ifdef KREONR
	db_desc->log_buffer = NULL;
  db_desc->latest_proposal_start_segment_offset = 0;
#endif
	_init_locktable(db_desc);
	db_desc->count_writers_level_0 = 0;
	db_desc->count_writers_level_1 = 0;
	db_desc->count_active_spillers = 0;

	if(RWLOCK_INIT(&db_desc->guard_level_0.rx_lock,NULL)!=0){
		printf("[%s:%s:%d] failed to initialize db_desc guard lock\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}

	if(RWLOCK_INIT(&db_desc->guard_level_1.rx_lock,NULL)!=0){
		printf("[%s:%s:%d] failed to initialize db_desc guard lock\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}

	/*recovery checks*/
	printf("[%s:%s:%d] performing recovery checks for db: %s\n",__FILE__,__func__,__LINE__,db_desc->db_name);
	/*where is L0 located at the log?*/
	if(db_desc->L0_end_log_offset > db_desc->L0_start_log_offset){
		printf("[%s:%s:%d] L0 present performing recovery checks ...\n",__FILE__,__func__,__LINE__);
		if(db_desc->L0_end_log_offset < db_desc->commit_log->kv_log_size){
			printf("[%s:%s:%d] Commit log: %llu is ahead of L0: %llu replaying missing log parts\n",__FILE__,__func__,__LINE__,(LLU)db_desc->commit_log->kv_log_size,(LLU)db_desc->L0_end_log_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.recovery_start_log_offset = db_desc->L0_end_log_offset;
			recovery_worker(&rh);
			printf("[%s:%s:%d] recovery completed successfully\n",__FILE__,__func__,__LINE__);
		} else if(db_desc->L0_end_log_offset == db_desc->commit_log->kv_log_size)
			printf("[%s:%s:%d] no recovery needed for db: %s ready :-)\n",__FILE__,__func__,__LINE__,db_desc->db_name);
		else{
			printf("[%s:%s:%d] FATAL corrupted state for db: %s :-(\n",__FILE__,__func__,__LINE__,db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
	}
	else if(db_desc->L0_end_log_offset == db_desc->L0_start_log_offset){
		printf("[%s:%s:%d] L0 is absent L1 ends at %llu replaying missing parts\n",__FILE__,__func__,__LINE__,(LLU)db_desc->L0_end_log_offset);
		if(db_desc->L0_end_log_offset < db_desc->commit_log->kv_log_size){

			DPRINT("Commit log (%llu) is ahead of L0 end (%llu) replaying missing log parts\n",
				(LLU)db_desc->commit_log->kv_log_size,(LLU)db_desc->L0_end_log_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.recovery_start_log_offset = db_desc->L0_end_log_offset;
			recovery_worker(&rh);
			printf("[%s:%s:%d] recovery completed successfully\n",__FILE__,__func__,__LINE__);
		}
		else if(db_desc->L0_end_log_offset == db_desc->commit_log->kv_log_size)
			printf("[%s:%s:%d] no recovery needed for db: %s ready :-)\n",__FILE__,__func__,__LINE__,db_desc->db_name);
		else{
			printf("[%s:%s:%d] FATAL corrupted state for db: %s :-(\n",__FILE__,__func__,__LINE__,db_desc->db_name);
			exit(EXIT_FAILURE);
		}
	} else {
		printf("[%s:%s:%d] FATAL Corrupted state detected\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
	return handle;
}

char db_close(db_handle *handle)
{
	/*verify that this is a valid db*/
	if(find_element(handle->volume_desc->open_databases, handle->db_desc->db_name) == NULL){
		printf("[%s:%s:%d] FATAL received close for db: %s that is not listed as open\n",__FILE__,__func__,__LINE__, handle->db_desc->db_name);
		exit(EXIT_FAILURE);
	}

	printf("[%s:%s:%d] closing region, prior call to DB_CLOSE_NOTIFY needed! XXX TODO XXX\n",__FILE__,__func__,__LINE__);
	handle->db_desc->db_mode = DB_IS_CLOSING;
	/*stop log appenders*/
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#else
	SPIN_LOCK(&handle->db_desc->lock_log);
#endif
	/*stop new level 0 writers for this db*/
	RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock);
	/*wait level 0 writers for this db to finish*/
	spin_loop(&(handle->db_desc->count_writers_level_0), 0);
	/*stop new level 1 writers for this db*/
	RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock);
	/*wait level 1 writers for this db*/
	spin_loop(&(handle->db_desc->count_writers_level_1), 1);
	/*wait spillers fot this db*/
	spin_loop(&(handle->db_desc->count_active_spillers), 0);

	commit_kv_log(handle->volume_desc, handle->db_desc, UNIQUE_DB_ALREADY_LOCKED);
	_destroy_locktable(handle->db_desc);

#ifdef KREONR
	if(handle->db_desc->backup_segment_table != NULL){
		map_entry *current, *tmp;
		HASH_ITER(hh,handle->db_desc->backup_segment_table,current,tmp) {
			HASH_DEL(handle->db_desc->backup_segment_table, current);  /* delete it (users advances to next) */
			free(current);/* free it */
		}
	}
#endif

	if(remove_element(handle->volume_desc->open_databases, handle->db_desc) != 1){
		printf("[%s:%s:%d] could not find db: %s\n",__FILE__,__func__,__LINE__, handle->db_desc->db_name);
		MUTEX_UNLOCK(&init_lock);
		/* pthread_mutex_unlock(&init_lock); */
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

	if(handle->db_desc->db_mode != PRIMARY_DB){
		DPRINT("ommiting spill for back up db\n");
		return;
	}
	if(memcmp(handle->db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) != 0){
		DPRINT("Nothing to do spill operation already active\n");
		return;
	}
	RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock);
	spin_loop(&handle->db_desc->count_writers_level_0,0);

	/*switch to another tree, but which?*/
	for(i=0;i<NUM_OF_TREES_PER_LEVEL;i++){
		if(i!= handle->db_desc->active_tree && handle->db_desc->tree_status[i] != SPILLING_IN_PROGRESS){
			int32_t level_id = handle->db_desc->active_tree;
			handle->db_desc->tree_status[level_id] = SPILLING_IN_PROGRESS;
			handle->db_desc->active_tree = i;

			/*spawn a spiller thread*/
			spill_request * spill_req = (spill_request *)malloc(sizeof(spill_request));/*XXX TODO XXX MEMORY LEAK*/
			spill_req->db_desc = handle->db_desc;
			spill_req->volume_desc = handle->volume_desc;

			if(handle->db_desc->root_w[level_id]!=NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else if(handle->db_desc->root_r[level_id]!=NULL)
				spill_req->src_root = handle->db_desc->root_r[level_id];
			else{
				DPRINT("empty level-0, nothing to do\n");
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

			if(pthread_create(&(handle->db_desc->spiller[0]),NULL,(void *)spill_buffer, (void *)spill_req)!=0){
				DPRINT("FATAL: error creating spiller thread\n");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	RWLOCK_UNLOCK(&handle->db_desc->guard_level_0.rx_lock);
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
		DPRINT("Waiting for pending spills to finish\n");
		node = get_first(volume_desc->open_databases);
		while(node != NULL){
			db_desc = (db_descriptor *) (node->data);
			/*wait for pending spills for this db to finish*/
			i=0;
			while(i<TOTAL_TREES){
				if(db_desc->tree_status[i] == SPILLING_IN_PROGRESS){
					DPRINT("Waiting for db %s to finish spills\n",db_desc->db_name);
					sleep(4);
					i = 0;
				}
				else
					i++;
			}
			node = node->next;
		}
		DPRINT("ok... no pending spills\n");

		if(force_spill == SPILL_ALL_DBS_IMMEDIATELY){

			node = get_first(volume_desc->open_databases);
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
	DPRINT("Finally, snapshoting volume\n");
	snapshot(volume_desc);
	free(handles);
	return;
}


/*XXX TODO XXX 
 * @deprecated
 * fix function to enable atomic insert batch
 * */
uint8_t insert_write_batch(db_handle * handle, mutation_batch * batch){

	printf("[%s:%s:%d]FATAL ERROR FUNCTION is deprecated\n",__FILE__,__func__,__LINE__);
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
		//status = _insert_index_entry(handle, key, 0 ,INSERT_TO_L0_INDEX | APPEND_TO_LOG);
		idx++;
		if(status != SUCCESS || pos >= batch->size)
			break;
	}
	return status;
}

uint8_t insert_key_value(db_handle * handle, void *key, void * value, uint32_t key_size, uint32_t value_size){
	kv_location location;
	char key_buf[KV_MAX_SIZE];
	uint32_t kv_size;
	uint8_t status = SUCCESS;

	/*throttle control check*/
	while(handle->db_desc->zero_level_memory_size > ZERO_LEVEL_MEMORY_UPPER_BOUND){
		usleep(THROTTLE_SLEEP_TIME);
	}
	/*do staff here*/
	kv_size = sizeof(uint32_t)+key_size+sizeof(uint32_t)+value_size + sizeof(uint64_t);
	assert(kv_size <= KV_MAX_SIZE);
	//void * key_buf = malloc(sizeof(uint32_t)+key_size+sizeof(int32_t)+value_size);
	memcpy(key_buf, &key_size, sizeof(uint32_t));
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t),key,key_size);
	*(uint32_t *)((uint64_t)key_buf+sizeof(uint32_t)+key_size) = value_size;
	memcpy((void *)(uint64_t)key_buf+sizeof(uint32_t)+key_size+sizeof(uint32_t),value,value_size);
	_append_key_value_to_log(handle, key_buf,KEYSIZE_BUF_DATASIZE_BUF,&location, PRIMARY_L0_INSERT);
#if INSERT_TO_INDEX
	status = _insert_index_entry(handle, &location, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG | PRIMARY_L0_INSERT);
	//__sync_fetch_and_sub(&handle->db_desc->count_writers_level_0, 1);
	//_spill_check(handle);
#endif
	return status;
}


#ifdef KREONR
void _sent_flush_command_to_replica(db_descriptor* db_desc, int padded_space, int wait)
{
	tu_data_message_s *flush_segment_reply;
	void * addr = ((tu_data_message_s *)db_desc->log_buffer)->data;

	/*first 4KB are segment metadata*/
	*(uint64_t *)addr = (uint64_t)db_desc->KV_log_last_segment-MAPPED;
	//DPRINT(master current log segment = %llu\n",(uint64_t)handle->db_desc->KV_log_last_segment-MAPPED);
	*(uint64_t *)(addr + (sizeof(uint64_t))) =  db_desc->KV_log_size + padded_space;
	//DPRINT("end of log = %llu\n",handle->db_desc->KV_log_size + available_space_in_log);
	*(uint64_t *)(addr + (2*sizeof(uint64_t))) = padded_space;
	//DPRINT("num of bytes to pad = %llu\n",available_space_in_log);
	*(uint64_t *)(addr + (3*sizeof(uint64_t))) = db_desc->KV_log_last_segment->segment_id;
	//DPRINT("segment id = %llu\n", handle->db_desc->KV_log_last_segment->segment_id);
	/*base region key*/
	memcpy(addr + (4*sizeof(uint64_t)), db_desc->region_min_key, 4+*(uint32_t *)db_desc->region_min_key);

  /*ok metadata are ready next function will send them and notify the remote CPU*/
	/*__sync_fetch_and_add(&((*db_desc->data_conn)->pending_received_messages), 1); // XXX TODO nost sure if this is correct*/
	wake_up_replica_to_flush_segment(*db_desc->data_conn, db_desc->log_buffer, wait);

  if(wait == WAIT_REPLICA_TO_COMMIT){
    DPRINT("Flushing segment, waiting for replica ack\n");
	  flush_segment_reply = get_message_reply(*db_desc->data_conn, db_desc->log_buffer);
    assert((*db_desc->data_conn)->pending_received_messages == 1);
	  free_rdma_received_message(*db_desc->data_conn, db_desc->log_buffer);
    DPRINT("Flushing segment, replica acked :-)\n");
  } 
  /*in the case where we do not wait fore replica to reply spinning thread handles the rest*/
	db_desc->log_buffer = (void *)allocate_rdma_message(*db_desc->data_conn, 4096 + BUFFER_SEGMENT_SIZE, FLUSH_SEGMENT);
}
#endif

/**
 * appends key value to log, called only from master
 *
 **/
void  _append_key_value_to_log(db_handle *handle, void *key_value, char KEY_VALUE_FORMAT,kv_location * location, int32_t append_options)
{
	segment_header * s_header;
	void *key_addr;/*address at the device*/
	void *data_addr;/*address at the device*/
	uint32_t key_len;
	uint32_t value_len;
	uint32_t available_space_in_log;
	uint32_t kv_size;
	uint32_t allocated_space;
#ifdef KREONR
  uint32_t position_in_the_segment;
  uint64_t rdma_source_offset;
  void * rdma_source;
  uint32_t rdma_length;
  int RDMA = 0;
#endif

	key_len = *(uint32_t *)key_value;
	value_len = *(uint32_t *)(key_value+sizeof(uint32_t)+key_len);

	kv_size = sizeof(uint32_t) + key_len + sizeof(uint32_t) + value_len;
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#else
	SPIN_LOCK(&handle->db_desc->lock_log);
#endif
	if(append_options == PRIMARY_L0_INSERT)
		__sync_fetch_and_add(&handle->db_desc->count_writers_level_0, 1);

	/*append data part in the data log*/
	if(handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0)
		available_space_in_log = BUFFER_SEGMENT_SIZE-(handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	if(available_space_in_log < kv_size){
		/*pad with zeroes remaining bytes in segment*/
		key_addr = (void*)((uint64_t)handle->db_desc->KV_log_last_segment+(handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
		memset(key_addr,0x00,available_space_in_log);
#ifdef KREONR
	  if (handle->db_desc->data_conn != NULL){
      position_in_the_segment = handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE; 
      assert(handle->db_desc->latest_proposal_start_segment_offset <= position_in_the_segment); 
      /*RDMA possible remains to the remote side*/
      //DPRINT("Sending remains latest proposal %llu position in the segment %llu size %llu\n",
      //    (LLU)handle->db_desc->latest_proposal_start_segment_offset, (LLU)position_in_the_segment,
      //    (LLU)position_in_the_segment - handle->db_desc->latest_proposal_start_segment_offset);

		  rdma_kv_entry_to_replica(*handle->db_desc->data_conn, 
					handle->db_desc->log_buffer,
					handle->db_desc->latest_proposal_start_segment_offset,
					handle->db_desc->log_buffer + 4096 + handle->db_desc->latest_proposal_start_segment_offset,
					position_in_the_segment - handle->db_desc->latest_proposal_start_segment_offset,
					(*handle->db_desc->data_conn)->rdma_memory_regions->local_memory_region->lkey);

      _sent_flush_command_to_replica(handle->db_desc,available_space_in_log, 0);
      handle->db_desc->latest_proposal_start_segment_offset = 0; 
    }
#endif
		allocated_space = kv_size + sizeof(segment_header);
		allocated_space +=  BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
		/*this allocate() is left intentionally. KV log allocates space only from allocator*/
		s_header = (segment_header *)allocate_segment(handle,allocated_space,KV_LOG_ID, KV_LOG_EXPANSION);
		memset(s_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
		s_header->next_segment = NULL;
		s_header->prev_segment = (segment_header *)((uint64_t)handle->db_desc->KV_log_last_segment - MAPPED);
		handle->db_desc->KV_log_last_segment->next_segment = (void *)((uint64_t)s_header - MAPPED);
		handle->db_desc->KV_log_size += (available_space_in_log + sizeof(segment_header)); /* position the log to the newly added block */
		s_header->segment_id = handle->db_desc->KV_log_size/BUFFER_SEGMENT_SIZE;
		assert(s_header->segment_id == (handle->db_desc->KV_log_last_segment->segment_id+1));
		handle->db_desc->KV_log_last_segment = s_header;

	}
	location->log_offset = handle->db_desc->KV_log_size;
	key_addr = (void*)((uint64_t)handle->db_desc->KV_log_last_segment+(handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
	data_addr = (void *)((uint64_t)key_addr + sizeof(int32_t) + key_len);
#ifdef KREONR
  /*
  //RDMA to the remote side
	if(handle->db_desc->data_conn != NULL){

		rdma_kv_entry_to_replica(*handle->db_desc->data_conn,
					handle->db_desc->log_buffer,
					position_in_the_segment,
					key_value,
					kv_size,
					location->rdma_key);
    }
    */
#endif

  handle->db_desc->KV_log_size += kv_size;

#ifdef KREONR
  if(handle->db_desc->data_conn != NULL){
  
    /*RDMA to the remote side*/
    position_in_the_segment = handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE; 
    assert(handle->db_desc->latest_proposal_start_segment_offset <= position_in_the_segment); 
    if(position_in_the_segment - handle->db_desc->latest_proposal_start_segment_offset >= LOG_SEGMENT_CHUNK){
      RDMA = 1;
      rdma_source_offset = handle->db_desc->latest_proposal_start_segment_offset;
      rdma_source = handle->db_desc->log_buffer + 4096 + handle->db_desc->latest_proposal_start_segment_offset;
      rdma_length = position_in_the_segment - handle->db_desc->latest_proposal_start_segment_offset;
      handle->db_desc->latest_proposal_start_segment_offset = position_in_the_segment; 
    }
  
  }
#endif

#if LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle->db_desc->lock_log);
#else
	SPIN_UNLOCK(&handle->db_desc->lock_log);
#endif
	*(uint32_t *)key_addr = key_len;
	memcpy(key_addr+sizeof(uint32_t),key_value+sizeof(uint32_t),key_len);
	*(uint32_t *)data_addr = value_len;
	memcpy(data_addr+sizeof(uint32_t), key_value+sizeof(uint32_t)+key_len+sizeof(uint32_t), value_len);
	location->kv_addr = key_addr;

#ifdef KREONR
	if(RDMA){
    //DPRINT("Time to RDMA latest proosal %llu position in the segment %llu size %llu\n",
    //      (LLU)rdma_source_offset, (LLU)rdma_source%BUFFER_SEGMENT_SIZE,(LLU)rdma_length);
      
	  rdma_kv_entry_to_replica(*handle->db_desc->data_conn,
		  handle->db_desc->log_buffer,
			rdma_source_offset,
			rdma_source,
			rdma_length,
			(*handle->db_desc->data_conn)->rdma_memory_regions->local_memory_region->lkey);
    }
#endif
}



void _spill_check(db_handle *handle, char recovery_mode)
{
	spill_request * workers[NUM_OF_SPILL_THREADS_PER_DB];
	int to_spill_tree_id;
	int i,j;
	/*do we need to trigger a spill, we allow only one pending spill per DB*/
	if(handle->db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
	    memcmp(handle->db_desc->tree_status, DB_NO_SPILLING, NUM_OF_TREES_PER_LEVEL) == 0){
		
    /*Acquire lock of log*/
		if(recovery_mode != 1){
#if LOG_WITH_MUTEX
			MUTEX_LOCK(&handle->db_desc->lock_log);
#else
			SPIN_LOCK(&handle->db_desc->lock_log);
#endif
		}
    
    /*wait for L0 writers to complete*/
		spin_loop(&handle->db_desc->count_writers_level_0,0);

    /*Acquire guard lock*/
    if(RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock) !=0){
			 DPRINT("ERROR locking guard\n");
			 exit(EXIT_FAILURE);
		}

		 if(handle->db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
			memcmp(handle->db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0){

			commit_kv_log(handle->volume_desc, handle->db_desc, UNIQUE_DB_ALREADY_LOCKED);
			DPRINT("FLUSHED KV log remains, time for a spill :-)\n");
			/*switch to another tree, but which?*/
			for(i=0;i<NUM_OF_TREES_PER_LEVEL;i++){
				if(i!= handle->db_desc->active_tree){
					to_spill_tree_id = handle->db_desc->active_tree;
					handle->db_desc->tree_status[to_spill_tree_id] = SPILLING_IN_PROGRESS;
					handle->db_desc->active_tree = i;
					/*inform backup server that a new remote spill is going to take place*/
					level_scanner * level_sc;
					node_header * spill_root;
					if(handle->db_desc->root_w[to_spill_tree_id] != NULL)
						spill_root = handle->db_desc->root_w[to_spill_tree_id];
					else
						spill_root = handle->db_desc->root_r[to_spill_tree_id];

					level_sc = _init_spill_buffer_scanner(handle,spill_root ,NULL);
					_close_spill_buffer_scanner(level_sc, spill_root);

					 /*spawn a spiller thread*/
					 for (j = 0; j < NUM_OF_SPILL_THREADS_PER_DB; ++j) {
						 workers[j] = (spill_request *)malloc(sizeof(spill_request));/*XXX TODO XXX MEMORY LEAK WE HAVE TO FREE IT SOMEWHERE  */
						 workers[j]->db_desc = handle->db_desc;
						 workers[j]->volume_desc = handle->volume_desc;
						 if(handle->db_desc->root_w[to_spill_tree_id]!=NULL)
							 workers[j]->src_root = handle->db_desc->root_w[to_spill_tree_id];
						 else
							 workers[j]->src_root = handle->db_desc->root_r[to_spill_tree_id];

						 workers[j]->src_tree_id = to_spill_tree_id;
						 workers[j]->dst_tree_id = NUM_OF_TREES_PER_LEVEL;
						 workers[j]->l0_start = handle->db_desc->L0_start_log_offset;
						 workers[j]->l0_end = handle->db_desc->L0_end_log_offset;
					 }
					/*Create Spill Ranges*/
					if(NUM_OF_SPILL_THREADS_PER_DB == 1){
						 workers[0]->start_key = NULL;
						 workers[0]->end_key = NULL;
					 }else{
						 _create_spill_ranges(handle->db_desc->root_w[to_spill_tree_id],workers);
					 }
					 handle->db_desc->count_active_spillers = NUM_OF_SPILL_THREADS_PER_DB;
					 for (j = 0; j < NUM_OF_SPILL_THREADS_PER_DB; ++j){
						 if(pthread_create(&(handle->db_desc->spiller[j]),NULL,(void *)spill_buffer, (void *)workers[j])!=0){
							 fprintf(stderr, "FATAL: error creating spiller thread\n");
							 exit(-1);
						 }
					}
					break;
				}
			}
		}
		if(recovery_mode != 1){
#if LOG_WITH_MUTEX
			MUTEX_UNLOCK(&handle->db_desc->lock_log);
#else
      SPIN_UNLOCK(&handle->db_desc->lock_log);
#endif
		}
		/*unlock guard*/
		if(RWLOCK_UNLOCK(&handle->db_desc->guard_level_0.rx_lock) !=0){
			printf("[%s:%s:%d] ERROR locking\n",__func__,__FILE__,__LINE__);
			exit(EXIT_FAILURE);
		}
	}
	else
		return;
}


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
	if( (INSERT_FLAGS&0xFF000000) == INSERT_TO_L0_INDEX && (INSERT_FLAGS&0x00FF0000) == DO_NOT_APPEND_TO_LOG){
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



void _create_spill_ranges(node_header * root,spill_request * spill_req[])
{
	unsigned i,range;
	void *addr;
	void * pivots[NUM_OF_SPILL_THREADS_PER_DB-1];
	void * last_root_pivot_addr=(void *)((uint64_t)root+sizeof(node_header)+sizeof(uint64_t)+(root->numberOfEntriesInNode-1)*16);
	void * last_child_pivot_addr=NULL;
	unsigned samples_per_child = (NUM_OF_SPILL_THREADS_PER_DB - 1)/root->numberOfEntriesInNode;
	node_header * child;
	unsigned j;

	memset(pivots,0x0,sizeof(void *)*(NUM_OF_SPILL_THREADS_PER_DB-1));
	if(root->numberOfEntriesInNode >= (NUM_OF_SPILL_THREADS_PER_DB-1)){
		/* void * tmp=(void*) ((uint64_t)root+sizeof(node_header)+8); */
		/* printf("[%s:%s:%d] FIRST_ROOT_KEY %s\n",__FILE__,__func__,__LINE__, (char *)(MAPPED+*(uint64_t*)tmp)+4); */
		/* printf("[%s:%s:%d] LAST_ROOT_KEY %s\n",__FILE__,__func__,__LINE__,(char *)(MAPPED+*(uint64_t*)last_root_pivot_addr)+4); */
		addr = (void *)((uint64_t)root+sizeof(node_header)+sizeof(uint64_t));
		pivots[0]=(void *)(MAPPED +*(uint64_t *)addr);

		int div = NUM_OF_SPILL_THREADS_PER_DB - 1;
		if(div> 0)
			range=root->numberOfEntriesInNode/div;
		else
			range = 0;
		for(i=1;i<(NUM_OF_SPILL_THREADS_PER_DB-1);++i){

			addr += ((range)*(sizeof(uint64_t)*2));
			if(addr > last_root_pivot_addr)
				addr=last_root_pivot_addr;
			pivots[i]=(void *)(MAPPED +*(uint64_t *)addr);
		}
	}else{
		printf("[%s:%s:%d] Calculating spill ranges from children\n",__FILE__,__func__,__LINE__);
		int idx=0;
		for(i=0;i < (root->numberOfEntriesInNode+1) ;++i){
			child=(node_header *)(MAPPED+*(uint64_t*)((uint64_t)root+sizeof(node_header)+i*16));
			last_child_pivot_addr=(void *)((uint64_t)child+sizeof(node_header)+sizeof(uint64_t)+(child->numberOfEntriesInNode-1)*16);
			range=child->numberOfEntriesInNode/samples_per_child;
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
}

/*gesalous added at 01/07/2014 18:29 function that frees all the blocks of a node*/
void free_logical_node(allocator_descriptor * allocator_desc, node_header * node_index){

	if(node_index->type == leafNode || node_index->type == leafRootNode){
		(*allocator_desc->free_space)(allocator_desc->handle,node_index,NODE_SIZE,allocator_desc->level_id);
		return;
	}
	else if(node_index->type == internalNode || node_index->type == rootNode){
		/*for IN, BIN, root nodes free the key log as well*/
		if(node_index->first_IN_log_header == NULL){
			printf("[%s:%s:%d] NULL log for index?\n",__FILE__,__func__,__LINE__);
			raise(SIGINT);
			exit(-1);
		}
		IN_log_header * curr = (IN_log_header *) (MAPPED + (uint64_t)node_index->first_IN_log_header);
		IN_log_header *last = (IN_log_header *)(MAPPED + (uint64_t)node_index->last_IN_log_header);
		IN_log_header * to_free;
		while((uint64_t)curr != (uint64_t)last){
			to_free = curr;
			curr = (IN_log_header *) ((uint64_t)MAPPED + (uint64_t)curr->next);
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



uint8_t delete_key(db_handle *handle, void *key, uint32_t size){
	delete_request delete_req;
	delete_reply delete_rep;
	/*convert key in kreon format*/
	void * _key;
	uint32_t tries = 0;

	_key = malloc(sizeof(uint32_t)+size);
	*(uint32_t *)_key = size;
	memcpy(_key+sizeof(uint32_t),key,size);
	/* pthread_mutex_lock(&(handle->db_desc->write_lock)); */

	delete_req.parent = NULL;
	delete_req.handle = handle;
	delete_req.allocator_desc.handle = handle;
	while(tries < 2 ){
		/*first search level-0 tree*/
		if(tries == 0){
			delete_req.allocator_desc.allocate_space = &allocate_segment;
			delete_req.allocator_desc.free_space = &free_buffered;
			delete_req.allocator_desc.level_id = handle->db_desc->active_tree;/*active tree of level 0*/
		} else {
			delete_req.allocator_desc.allocate_space = &allocate_segment;
			delete_req.allocator_desc.free_space = &free_block;
			delete_req.allocator_desc.level_id = NUM_OF_TREES_PER_LEVEL;
		}
		tries++;

		if(handle->db_desc->root_w[delete_req.allocator_desc.level_id] == NULL) {
			if(handle->db_desc->root_r[delete_req.allocator_desc.level_id]!=NULL) {
				handle->db_desc->root_w[delete_req.allocator_desc.level_id] = (*(delete_req.allocator_desc.allocate_space))((void *)delete_req.allocator_desc.handle, NODE_SIZE, delete_req.allocator_desc.level_id,COW_FOR_INDEX);

				memcpy(handle->db_desc->root_w[delete_req.allocator_desc.level_id], handle->db_desc->root_r[delete_req.allocator_desc.level_id], NODE_SIZE);
				handle->db_desc->root_w[delete_req.allocator_desc.level_id]->epoch = handle->volume_desc->soft_superindex->epoch;
			}
			else
				handle->db_desc->root_w[delete_req.allocator_desc.level_id] = (node_header *)createEmptyNode(&(delete_req.allocator_desc), delete_req.allocator_desc.handle, leafRootNode, NEW_ROOT);

		}

		delete_req.self = handle->db_desc->root_w[delete_req.allocator_desc.level_id];

		_delete_key(&delete_req, &delete_rep, _key);
		if(delete_rep.status == KREON_OK){
			handle->db_desc->dirty = 0x01;
			break;
		}
	}
	/* pthread_mutex_unlock(&(handle->db_desc->write_lock)); */
	free(_key);
	return delete_rep.status;
}


void _delete_key(delete_request * delete_req, delete_reply * delete_rep,  void *key)
{
	delete_request down_level_delete_req;
	delete_reply down_level_delete_rep;
	void * child_node_index_addr;

	void * key_addr_in_leaf;
	void * pivot_src;
	void * pivot_dest;

	uint64_t num_bytes;
	int32_t action;
	int32_t my_order;

	if(delete_req->self->type == rootNode || delete_req->self->type == internalNode)
	{
		my_order = index_order;
		/*create the request and call the down level*/
		child_node_index_addr = _index_node_binary_search(delete_req->self, key, KV_FORMAT);

		down_level_delete_req.handle = delete_req->handle;
		down_level_delete_req.parent = delete_req->self;
		down_level_delete_req.self = (node_header *)(MAPPED+*(uint64_t *)child_node_index_addr);
		down_level_delete_req.offset = (uint64_t)child_node_index_addr - (uint64_t)delete_req->self;

		memcpy(&(down_level_delete_req.allocator_desc),&(delete_req->allocator_desc),sizeof(allocator_descriptor));

		_delete_key(&down_level_delete_req, &down_level_delete_rep, key);
		if(down_level_delete_rep.status == KREON_OK || down_level_delete_rep.status == KEY_NOT_FOUND)
		{
			delete_rep->status = down_level_delete_rep.status;
			return;
		}
		delete_rep->status = KREON_OK;
		/*what happened with my child?, we will surely need to update ourselves*/
		delete_rep->new_self = __cow_in_node_header(&(delete_req->allocator_desc),delete_req->handle, delete_req->self, NODE_SIZE, COW_FOR_INDEX);
		if((uint64_t)delete_rep->new_self != (uint64_t)delete_req->self)/* I just cowed myself*/
		{
			delete_rep->status = COW;
			child_node_index_addr = (void *)(uint64_t)delete_rep->new_self + down_level_delete_req.offset;
		}

		switch(down_level_delete_rep.status)
		{
		case COW:
			*(uint64_t *)child_node_index_addr = (uint64_t)down_level_delete_rep.new_self - MAPPED;
			break;
		case MERGE_WITH_RIGHT:
			/*root special case*/
			if(delete_rep->new_self->type == rootNode && delete_rep->new_self->numberOfEntriesInNode == 1)
			{
				/*merged node is the new leafRootNode*/
				delete_rep->new_self->type = leafRootNode;
				delete_req->handle->db_desc->root_w[delete_req->allocator_desc.level_id] = (node_header *)(uint64_t)down_level_delete_rep.new_self;
				free_logical_node(&delete_req->allocator_desc, delete_rep->new_self);
			}
			else
			{
				/*mark the new merged node*/
				*(uint64_t *)child_node_index_addr = (uint64_t)down_level_delete_rep.new_self - MAPPED;
				/*fix index*/
				num_bytes = ((uint64_t)delete_rep->new_self + sizeof(node_header)+sizeof(uint64_t) + (delete_rep->new_self->numberOfEntriesInNode*2*sizeof(uint64_t))) - (uint64_t)child_node_index_addr;
				num_bytes -= (2*sizeof(uint64_t));
				memmove(child_node_index_addr+sizeof(uint64_t), child_node_index_addr + (3*sizeof(uint64_t)),num_bytes);
				--delete_rep->new_self->numberOfEntriesInNode;
			}
			break;
		case MERGE_WITH_LEFT:
			/**
			 *	MWL B: Just remove the pivot, our side of the protocol
			 **/
			/*root special case*/
			if(delete_rep->new_self->type == rootNode && delete_rep->new_self->numberOfEntriesInNode == 1)
			{
				if(down_level_delete_rep.new_self->type == leafNode)
					down_level_delete_rep.new_self->type = leafRootNode;
				else
					down_level_delete_rep.new_self->type = rootNode;
				delete_req->handle->db_desc->root_w[delete_req->allocator_desc.level_id] = (node_header *)(uint64_t)down_level_delete_rep.new_self;
				free_logical_node(&delete_req->allocator_desc, delete_rep->new_self);
			}
			else
			{
				*(uint64_t *)(child_node_index_addr - (2*sizeof(uint64_t))) = (uint64_t)down_level_delete_rep.new_self - MAPPED;
				/*fix index*/
				num_bytes = ((uint64_t)delete_rep->new_self + sizeof(node_header)+sizeof(uint64_t) + (delete_rep->new_self->numberOfEntriesInNode*2*sizeof(uint64_t))) - (uint64_t)child_node_index_addr;
				num_bytes -= sizeof(uint64_t);
				memmove( child_node_index_addr-sizeof(uint64_t), child_node_index_addr+sizeof(uint64_t),num_bytes);
				delete_rep->new_self->numberOfEntriesInNode--;
			}
			break;
		case LEFT_ROTATE_LEAF:
			/* *
			 * LRL B side of protocol
			 * */
			*(uint64_t *)child_node_index_addr = (uint64_t)down_level_delete_rep.new_self - MAPPED;
			*(uint64_t *)(child_node_index_addr-(2*sizeof(uint64_t))) = (uint64_t)down_level_delete_rep.new_left_brother - MAPPED;
			__update_index_key_in_place(&(delete_req->allocator_desc), delete_req->handle,delete_rep->new_self,(void *)(uint64_t)child_node_index_addr-sizeof(uint64_t), down_level_delete_rep.key, LEFT_ROTATE_LEAF);
			break;
		case RIGHT_ROTATE_LEAF:
			/**
			 * RRL: B side of protocol, father updates children locations and fix its pivot
			 **/
			*(uint64_t *)child_node_index_addr = (uint64_t)down_level_delete_rep.new_self - MAPPED;
			*(uint64_t *)(child_node_index_addr+(2*sizeof(uint64_t))) = (uint64_t)down_level_delete_rep.new_right_brother-MAPPED;
			__update_index_key_in_place(&(delete_req->allocator_desc), delete_req->handle,delete_rep->new_self,(void *)(uint64_t)child_node_index_addr+sizeof(uint64_t), down_level_delete_rep.key, RIGHT_ROTATE_LEAF);
			break;
		case LEFT_ROTATE_INDEX:
			/*write my key to the right child*/
			if(delete_rep->new_self->type == rootNode)

				__update_index_key_in_place(&(delete_req->allocator_desc),delete_req->handle,
							    down_level_delete_rep.new_self,(void *)((uint64_t)down_level_delete_rep.new_self+sizeof(node_header)+sizeof(uint64_t)), (void *)MAPPED+*(uint64_t *)(child_node_index_addr-sizeof(uint64_t)), LEFT_ROTATE_INDEX);

			*(uint64_t *)child_node_index_addr = (uint64_t)down_level_delete_rep.new_self - MAPPED;
			*(uint64_t *)(child_node_index_addr - (2*sizeof(uint64_t))) = (uint64_t)down_level_delete_rep.new_left_brother - MAPPED;

			__update_index_key_in_place(&(delete_req->allocator_desc), delete_req->handle, delete_rep->new_self,  child_node_index_addr-sizeof(uint64_t), down_level_delete_rep.key, LEFT_ROTATE_INDEX);

			break;
		case RIGHT_ROTATE_INDEX:
			//printf("%s RRI parent writing my key %s to child\n", __func__,(char *)MAPPED + (*(uint64_t *)(child_node_index_addr+sizeof(uint64_t))+4));
			if(delete_rep->new_self->type == rootNode)
				printf("[%s:%s:%d] got root in RRI\n",__FILE__,__func__,__LINE__);

			__update_index_key_in_place(&(delete_req->allocator_desc),
						    delete_req->handle, down_level_delete_rep.new_self,
						    (void *)(((uint64_t)down_level_delete_rep.new_self+sizeof(node_header)+ (down_level_delete_rep.new_self->numberOfEntriesInNode*2*sizeof(uint64_t)))-sizeof(uint64_t)),
						    (void *)MAPPED+*(uint64_t *)(child_node_index_addr+sizeof(uint64_t)), RIGHT_ROTATE_INDEX);
			__update_index_key_in_place(&(delete_req->allocator_desc),delete_req->handle, delete_rep->new_self, (void *) (uint64_t)child_node_index_addr+sizeof(uint64_t), down_level_delete_rep.key, RIGHT_ROTATE_INDEX);
			*(uint64_t *)(child_node_index_addr+(2*sizeof(uint64_t))) = (uint64_t)down_level_delete_rep.new_right_brother - MAPPED;
			*(uint64_t *)(child_node_index_addr) = (uint64_t)down_level_delete_rep.new_self-MAPPED;
			break;
		default:
			printf("Unknown code exiting\n");
			exit(-1);
		}
	}
	else if(delete_req->self->type == leafNode || delete_req->self->type == leafRootNode)
	{
		void * kv_log_addr;
		my_order = leaf_order;
		key_addr_in_leaf = __find_key_addr_in_leaf(delete_req->self, key);

		if(key_addr_in_leaf == NULL){
			printf("[%s:%s:%d] key not found in leaf %llu\n",__FILE__,__func__,__LINE__,(LLU)delete_req->self);
			delete_rep->status = KEY_NOT_FOUND;
			return;
		}
		kv_log_addr = (void *)MAPPED+*(uint64_t *)key_addr_in_leaf;

		delete_rep->status = KREON_OK;
		/*COW check*/
		delete_rep->new_self = __cow_in_node_header(&(delete_req->allocator_desc),delete_req->handle, delete_req->self, NODE_SIZE, COW_FOR_LEAF);

		if((uint64_t)delete_rep->new_self != (uint64_t)delete_req->self){
			/*I just cowed myself*/
			delete_rep->status = COW;
			key_addr_in_leaf = (void *)(uint64_t)delete_rep->new_self + ( (uint64_t)key_addr_in_leaf - (uint64_t)delete_req->self);

			/*special case we touched root*/
			if(delete_req->self->type == leafRootNode || delete_req->self->type == rootNode)
				delete_req->handle->db_desc->root_w[delete_req->allocator_desc.level_id] = delete_rep->new_self;
		}
		int32_t position = ((uint64_t)key_addr_in_leaf - ((uint64_t)delete_rep->new_self+sizeof(node_header)))/sizeof(uint64_t);
		/*fix the index, pointers first*/
		memmove((void *)key_addr_in_leaf, (void *)(uint64_t)key_addr_in_leaf+sizeof(uint64_t), (delete_rep->new_self->numberOfEntriesInNode-(position+1))*sizeof(uint64_t));
		/*prefixes next*/
		key_addr_in_leaf = (void *)(uint64_t)delete_rep->new_self + sizeof(node_header)+(leaf_order*sizeof(uint64_t))+(position*PREFIX_SIZE);
		memmove((void *)(uint64_t)key_addr_in_leaf,(void *)(uint64_t)key_addr_in_leaf+PREFIX_SIZE,(delete_rep->new_self->numberOfEntriesInNode-(position+1))*PREFIX_SIZE);
    
    (delete_rep->new_self->numberOfEntriesInNode)--;
		/*mark the hole created in the KV log*/
		mark_deleted_key((void *)delete_req->handle, kv_log_addr);
	}
	else
	{
		printf("[%s:%s:%d] FATAL corrtupted node\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	/*finally, do we have an underflow?, applicable only for non root nodes*/
	if(delete_rep->new_self->type!=leafRootNode
	   && delete_rep->new_self->type!=rootNode
	   && delete_rep->new_self->numberOfEntriesInNode < (my_order/2))
	{
		node_header * left_brother;
		node_header * right_brother;
		/*ask rebalance controller what to do? 1. merge? 2. left_rotate? 3. right_rotate?*/
 		action = __rebalance_controller(delete_rep->new_self, delete_req->parent, delete_req->offset);

		switch(action)
		{
		case MERGE_WITH_LEFT:
			/**
			 *
			 * if(node->type == rootNode || node->type == leafRootNode)
			 * MWL A: our side of the protocol: merge with left brother and copy father's pivot
			 * to the appropriate place. Father will take care of the rest
			 * */
			left_brother = (node_header *)(MAPPED + *(uint64_t *)(((uint64_t)delete_req->parent+delete_req->offset)-(2*sizeof(uint64_t))));

			//printf("[%s:%s:%d] action to take for myself MWL my entries %d left brother entries %d type %d\n",__FILE__,__func__,__LINE__,delete_rep->new_self->numberOfEntriesInNode,left_brother->numberOfEntriesInNode, delete_rep->new_self->type);

			delete_rep->new_self =  __merge_nodes(&(delete_req->allocator_desc), delete_req->handle, left_brother, delete_rep->new_self);

			if(delete_rep->new_self->type!=leafNode)
			{
				/*copy father's pivot to the appropriate location*/
				pivot_src = (void *)(((uint64_t)delete_req->parent+delete_req->offset) - sizeof(uint64_t));
				pivot_src = (void *)(MAPPED + *(uint64_t *)pivot_src);
				pivot_dest = (void *)(uint64_t)delete_rep->new_self + sizeof(node_header)+(left_brother->numberOfEntriesInNode*2*sizeof(uint64_t))+sizeof(uint64_t);
				__update_index_key_in_place(&(delete_req->allocator_desc),delete_req->handle,delete_rep->new_self,      pivot_dest,pivot_src,MERGE_NODE);
			}
			delete_rep->status = MERGE_WITH_LEFT;
			break;

		case MERGE_WITH_RIGHT:
			/**
			 * MWR A side of protocol
			 **/
			right_brother = (node_header *)(MAPPED + *(uint64_t *)(((uint64_t)delete_req->parent+delete_req->offset)+(2*sizeof(uint64_t))));

			//printf("[%s:%s:%d] action to take for myself MWR my entries %d left brother entries %d type %d\n",__FILE__,__func__,__LINE__,delete_rep->new_self->numberOfEntriesInNode,right_brother->numberOfEntriesInNode, delete_rep->new_self->type);
			int32_t my_entries = delete_rep->new_self->numberOfEntriesInNode;
			delete_rep->new_self =  __merge_nodes(&(delete_req->allocator_desc),delete_req->handle, delete_rep->new_self, right_brother);

			if(delete_rep->new_self->type != leafNode)
			{
				/*copy father's pivot*/
				pivot_src  = (void *)(((uint64_t)delete_req->parent)+delete_req->offset)+sizeof(uint64_t);
				pivot_src = (void *)MAPPED + *(uint64_t *)pivot_src;
				pivot_dest = (void *)(uint64_t)delete_rep->new_self + sizeof(node_header)+(my_entries*2*sizeof(uint64_t))+sizeof(uint64_t);
				__update_index_key_in_place(&(delete_req->allocator_desc),delete_req->handle,delete_rep->new_self,           pivot_dest,pivot_src,MERGE_NODE);
			}
			delete_rep->status = MERGE_WITH_RIGHT;
			break;
		case LEFT_ROTATE_LEAF:
		case LEFT_ROTATE_INDEX:
			/**
			 * LRL: A side of the protocol borrow key from left brother, father will fix the pivots
			 **/
			//printf("[%s:%s:%d] action to take for myself LRL/LRI type %d\n",__FILE__,__func__,__LINE__, delete_rep->new_self->type);
			left_brother = (node_header *)(MAPPED + *(uint64_t *)(((uint64_t)delete_req->parent+delete_req->offset)-(2*sizeof(uint64_t))));
			delete_rep->new_left_brother = __cow_in_node_header(&(delete_req->allocator_desc),delete_req->handle, left_brother, NODE_SIZE, action);
			delete_rep->key = __left_rotate(delete_req->handle, delete_rep->new_left_brother, delete_rep->new_self);
			if(left_brother->type == leafNode)
				delete_rep->status = LEFT_ROTATE_LEAF;
			else
				delete_rep->status = LEFT_ROTATE_INDEX;
			break;

		case RIGHT_ROTATE_LEAF:
		case RIGHT_ROTATE_INDEX:
			/**
			 * RRL/RRI: A side of protocol borrow first key from right brother,
			 * father will fix the pivots
			 **/
			//printf("[%s:%s:%d] action to take for myself RRL/RRI type %d\n",__FILE__,__func__,__LINE__, delete_rep->new_self->type);
			right_brother = (node_header *)(MAPPED + *(uint64_t *)(((uint64_t)delete_req->parent)+delete_req->offset+(2*sizeof(uint64_t))));

			delete_rep->new_right_brother = __cow_in_node_header(&(delete_req->allocator_desc),delete_req->handle, right_brother, NODE_SIZE, RIGHT_ROTATE_LEAF);
			delete_rep->key = __right_rotate(delete_req->handle, delete_rep->new_self, delete_rep->new_right_brother);

			if(right_brother->type == leafNode)
  				delete_rep->status = RIGHT_ROTATE_LEAF;
			else
  				delete_rep->status = RIGHT_ROTATE_INDEX;
			break;
		}
	}
	return;
}

void mark_deleted_key(db_handle * handle, void * deleted_key_addr)
{
	segment_header * s_header;
	void * key_addr;
	uint32_t avail_space;
	uint32_t data_req_space;
	uint32_t allocated_space;
	/*XXX TODO XXX add lock log?*/
	/**
	 * Note deletes are appended in the KV log, with the following format
	 * key_size = 0; to seperate them from insert kvs
	 * epoch when the delete took place (is it surely needed?)
	 * addr in the kv log where the deleted entry resides
	 **/
	void * delete_key_request = malloc(20);
	*(uint32_t *)delete_key_request = 0;
	*(uint64_t *)(delete_key_request+sizeof(uint32_t)) = handle->volume_desc->soft_superindex->epoch;
	*(uint64_t *)(delete_key_request+sizeof(uint32_t)+sizeof(uint64_t)) = (uint64_t)deleted_key_addr - MAPPED;

	uint32_t garbage_bytes = sizeof(uint32_t) + *(uint32_t *)deleted_key_addr;//key staff
	garbage_bytes += (sizeof(uint32_t) + *(uint32_t *)(deleted_key_addr + garbage_bytes));//value staff

	/*append delete mutation in the log*/
	avail_space = (BUFFER_SEGMENT_SIZE - (handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE)) % BUFFER_SEGMENT_SIZE;
	data_req_space = 20;/*4 for 0 size, 8 bytes epoch, 8 bytes pointer to KV*/

	if(avail_space < data_req_space){

		allocated_space = data_req_space + sizeof(segment_header);
		allocated_space +=  BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
		/*this allocate() is left intentionally. KV log allocates space only from allocator*/
		s_header = (segment_header *)allocate_segment(handle,allocated_space,KV_LOG_ID,KV_LOG_EXPANSION);
		memset(s_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));

		s_header->next_segment = NULL;
		s_header->prev_segment =  handle->db_desc->KV_log_last_segment;
		handle->db_desc->KV_log_last_segment->next_segment = (void *)((uint64_t)s_header - MAPPED);
		handle->db_desc->KV_log_last_segment = s_header;
		handle->db_desc->KV_log_size += (avail_space + sizeof(segment_header));/*position the log to the newly added block*/
	}
	key_addr = (void*)(uint64_t)handle->db_desc->KV_log_last_segment+(handle->db_desc->KV_log_size%BUFFER_SEGMENT_SIZE);
	memcpy(key_addr,delete_key_request,20);
	free(delete_key_request);
	/*finally mark garbage bytes, please note that all allocations take place at BUFFER_SEGMENT_SIZE granularity
	 * and addresses returned by the allocator are aligned in BUFFER_SEGMENT_SIZE.
	 * to find the start of the log block given the deleted_key
	 **/
	uint64_t absolute_addr = (uint64_t)deleted_key_addr - MAPPED;
	uint64_t distance  = (absolute_addr%BUFFER_SEGMENT_SIZE);
	segment_header * block = (segment_header *)((uint64_t)deleted_key_addr - distance);
	uint32_t idx = 2*(handle->volume_desc->soft_superindex->epoch%MAX_COUNTER_VERSIONS);

	if(block->garbage_bytes[idx] <= handle->volume_desc->dev_superindex->epoch){

		printf("[%s:%s:%d] cow for garbage\n",__FILE__,__func__,__LINE__);
		uint32_t previous_idx = 2*((handle->volume_desc->dev_superindex->epoch)%MAX_COUNTER_VERSIONS);
		block->garbage_bytes[idx] = handle->volume_desc->soft_superindex->epoch;
		block->garbage_bytes[idx+1] = block->garbage_bytes[previous_idx+1];
		printf("[%s:%s:%d] garbage bytes now in block  %llu are %llu\n",__FILE__,__func__,__LINE__,(LLU)block,(LLU)block->garbage_bytes[idx+1]);
	}
	block->garbage_bytes[idx+1] += garbage_bytes;
	//printf("[%s:%s:%d] garbage bytes now in block %llu are %llu hole size %llu\n",__FILE__,__func__,__LINE__,(LLU)block,(LLU)block->garbage_bytes[idx+1],(LLU)garbage_bytes);
	if(block->garbage_bytes[idx+1] > BUFFER_SEGMENT_SIZE){
		printf("[%s:%s:%d] corruption, of log deletion metadata\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}
	return;
}

/*cow logic function*/
node_header *  __cow_in_node_header(allocator_descriptor * allocator_desc, db_handle * handle, node_header * node, int32_t size, int TYPE_OF_COW)
{
	node_header * node_copy;
	if(node->epoch <= handle->volume_desc->dev_superindex->epoch)/*cow logic, leaf bottom layer*/
	{
		node_copy = (*(allocator_desc->allocate_space))((void *)allocator_desc->handle, size, allocator_desc->level_id, TYPE_OF_COW);
		memcpy(node_copy, node, size);
		node_copy->epoch = handle->volume_desc->soft_superindex->epoch;
		/*special case we touched root node*/
		if(node_copy->type == leafRootNode || node_copy->type == rootNode)
			handle->db_desc->root_w[allocator_desc->level_id] = node_copy;

		(*allocator_desc->free_space)(allocator_desc->handle, node, size, TYPE_OF_COW);
		if(node->type == rootNode || node->type == leafRootNode)
		{
			printf("[%s:%s:%d] root changed\n",__FILE__,__func__,__LINE__);
			handle->db_desc->root_w[allocator_desc->level_id] = node_copy;
		}

		return node_copy;

	}
	else/*no COW needed*/
		return node;
}


void __update_index_key_in_place(allocator_descriptor* allocator_desc, db_handle *handle,
	node_header * node, void * node_index_addr, void * key_buf,int32_t type){

	void * key_addr;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;
	IN_log_header * d_header = NULL;
	IN_log_header * last_d_header = NULL;

	int key_len = *(uint32_t *)key_buf;

	if(node->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - ( node->key_log_size % (int32_t)KEY_BLOCK_SIZE );

	req_space = (key_len + sizeof(int32_t));
	if(avail_space < req_space ){ /*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space+sizeof(node_header))/KEY_BLOCK_SIZE;
		if((req_space+sizeof(node_header))%KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space *= KEY_BLOCK_SIZE;
		//error
		d_header = (*allocator_desc->allocate_space)(allocator_desc->handle, allocated_space, allocator_desc->level_id,NOT_IMPLEMENTED_YET);
		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)node->last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		node->last_IN_log_header = last_d_header->next;
		node->key_log_size += (avail_space +  sizeof(IN_log_header));/* position the log to the newly added block */
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)node->last_IN_log_header + (uint64_t)(node->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(int32_t) + key_len);/*key length */
	*(uint64_t *)node_index_addr = (uint64_t)key_addr - MAPPED;
	node->key_log_size += sizeof(int32_t) + key_len;
	if(type!=MERGE_NODE)
		++node->fragmentation;
}


/***
 * Caution: __merge_nodes, __left_rotate, and __right_rotate are meant to be used as private functions.
 * All functions do not perform any check about CoW
 ***/
node_header * __merge_nodes(allocator_descriptor * allocator_desc, db_handle * handle, node_header * node_a, node_header * node_b)
{
	node_header * new_node;
	void * addr;
	void * new_node_addr;
	int32_t offset = 0;
	int i = 0;

	if(node_a->type == leafNode && node_b->type == leafNode)
	{
		new_node = (*allocator_desc->allocate_space)(allocator_desc->handle, NODE_SIZE, allocator_desc->level_id, COW_FOR_LEAF);
		new_node->epoch = handle->volume_desc->soft_superindex->epoch;
		new_node->type = leafNode;
		new_node->height = node_a->height;
		/*pointers first*/
		memcpy((void*)(uint64_t)new_node+sizeof(node_header),(void *)(uint64_t)node_a+sizeof(node_header),node_a->numberOfEntriesInNode*sizeof(uint64_t));
		offset = sizeof(node_header)+(node_a->numberOfEntriesInNode*sizeof(uint64_t));
		memcpy((void *)(uint64_t)new_node + offset,(void *)(uint64_t)node_b + sizeof(node_header), node_b->numberOfEntriesInNode*sizeof(uint64_t));
		/*prefixes*/
		offset = sizeof(node_header)+(leaf_order*sizeof(uint64_t));
		memcpy((void *)(uint64_t)new_node+offset, (void *)(uint64_t)node_a+offset, node_a->numberOfEntriesInNode*PREFIX_SIZE);
		offset += (node_a->numberOfEntriesInNode * PREFIX_SIZE);
		memcpy((void *)(uint64_t)new_node+offset,(void *)(uint64_t)node_b+sizeof(node_header)+(leaf_order*sizeof(uint64_t)), node_b->numberOfEntriesInNode * PREFIX_SIZE);

    /*update the entries*/
		new_node->numberOfEntriesInNode = node_a->numberOfEntriesInNode + node_b->numberOfEntriesInNode;
	}
	else/*index node*/
	{
		new_node  = (node_header *)createEmptyNode(allocator_desc, handle, internalNode, COW_FOR_INDEX);
		/*node_a first*/
		new_node_addr = (void *) (uint64_t)new_node+sizeof(node_header);
		addr = (void *)(uint64_t)node_a + sizeof(node_header);
		for(i=0;i<node_a->numberOfEntriesInNode;i++)
		{
			*(uint64_t *)new_node_addr = *(uint64_t *)addr;

			new_node_addr += sizeof(uint64_t);
			addr += sizeof(uint64_t);
			__update_index_key_in_place(allocator_desc, handle,new_node, new_node_addr,(void *)MAPPED + *(uint64_t *)addr, MERGE_NODE);

			new_node_addr += sizeof(uint64_t);
			addr += sizeof(uint64_t);
		}
		/*don't forget last pointer :-)*/
		*(uint64_t *)new_node_addr = *(uint64_t *)addr;
		/*ok node_a copied to new_node*/

		/*node_b now*/


		new_node_addr += (2*sizeof(uint64_t));/*leave space to right father's key*/
		addr = (void *)(uint64_t)node_b + sizeof(node_header);
		for(i=0;i<node_b->numberOfEntriesInNode;i++)
		{
			*(uint64_t *)new_node_addr = *(uint64_t *)addr;
			new_node_addr += sizeof(uint64_t);
			addr += sizeof(uint64_t);
			__update_index_key_in_place(allocator_desc,handle,new_node, new_node_addr, (void *)MAPPED + *(uint64_t *)addr, MERGE_NODE);
			new_node_addr += sizeof(uint64_t);
			addr += sizeof(uint64_t);
		}
		/*don't forget last pointer :-)*/
		*(uint64_t *)new_node_addr = *(uint64_t *)addr;
		new_node->numberOfEntriesInNode = node_a->numberOfEntriesInNode + node_b->numberOfEntriesInNode +1;
	}
	/*XXX TODO XXX, fix this*/
	free_logical_node(allocator_desc, node_a);
	free_logical_node(allocator_desc, node_b);
	return new_node;
}


/*self will borrow a key from left brother*/
void * __left_rotate(db_handle * handle, node_header * left_brother, node_header * self)
{
	void * left_brother_last_key;

	if(self->type == leafNode)
	{
		/*make room for the pointers, in self*/
		memmove((void *)(uint64_t)self+sizeof(node_header)+sizeof(uint64_t),(void *)(uint64_t)self+sizeof(node_header),self->numberOfEntriesInNode*sizeof(uint64_t));
		/*make room for the prefixes, in self*/
		memmove((void *)(uint64_t)self+sizeof(node_header)+(leaf_order*sizeof(uint64_t))+PREFIX_SIZE,(void *)(uint64_t)self+sizeof(node_header)+(leaf_order*sizeof(uint64_t)), self->numberOfEntriesInNode*PREFIX_SIZE);
    /*insert the new key*/
		left_brother_last_key = (void *)(uint64_t)left_brother + sizeof(node_header) + ((left_brother->numberOfEntriesInNode-1)*sizeof(uint64_t));
		*(uint64_t *)((uint64_t)self+sizeof(node_header)) = *(uint64_t *)left_brother_last_key;/*pointer*/
		left_brother_last_key = (void *)(uint64_t)left_brother +sizeof(node_header)+(leaf_order*sizeof(uint64_t)+((left_brother->numberOfEntriesInNode-1)*PREFIX_SIZE));
		memcpy((void *)(uint64_t)self+sizeof(node_header)+(leaf_order*sizeof(uint64_t)),(void *)left_brother_last_key, PREFIX_SIZE);/*prefix*/

    left_brother->numberOfEntriesInNode--;
		self->numberOfEntriesInNode++;
		/*return new pivot to parent*/
		return (void *) MAPPED+*(uint64_t *)((uint64_t)self+sizeof(node_header));
	}
	else/*we have index node*/
	{
		/*1. make space in self*/
		memmove((void *)(uint64_t)self+sizeof(node_header)+(2*sizeof(uint64_t)),(void *)(uint64_t)self+sizeof(node_header), (self->numberOfEntriesInNode*2*sizeof(uint64_t))+sizeof(uint64_t));
		/*2. last key in left_brother*/
		left_brother_last_key = (void *)(uint64_t)left_brother + sizeof(node_header) + sizeof(uint64_t) +((left_brother->numberOfEntriesInNode-1)*2*sizeof(uint64_t));
		/*put last pointer of a as first pointer in b*/
		*(uint64_t *)((uint64_t)self+sizeof(node_header)) = *(uint64_t *)(left_brother_last_key+sizeof(uint64_t));
		--left_brother->numberOfEntriesInNode;
		++self->numberOfEntriesInNode;
		/*return last key addr of left brother, parent will handle the rest*/
		return (void *) MAPPED+	*(uint64_t *)left_brother_last_key;
	}
}

/*transfer a key from right_brother to self*/
/*Unused argument handle XXX TODO XXX REMOVE*/
node_header * __right_rotate(db_handle *handle,node_header * self, node_header * right_brother)
{
	/*first key of child_b*/
	uint64_t offset;
	if(self->type == leafNode)
	{
		/*add first key of right as last to self*/
		offset = sizeof(node_header)+(self->numberOfEntriesInNode*sizeof(uint64_t));
		*(uint64_t *)((uint64_t)self+offset) = *(uint64_t *)((uint64_t)right_brother + sizeof(node_header));/*pointer*/
		offset = sizeof(node_header) + (leaf_order*sizeof(uint64_t))+(self->numberOfEntriesInNode * PREFIX_SIZE);
		memcpy((void *)(uint64_t)self+offset, (void *)(uint64_t)right_brother+ sizeof(node_header)+(leaf_order*sizeof(uint64_t)),PREFIX_SIZE);/*prefix*/

    /*fix right brother*/
		memmove((void *)(uint64_t)right_brother+sizeof(node_header),(void *)(uint64_t)right_brother+sizeof(node_header)+sizeof(uint64_t), (right_brother->numberOfEntriesInNode-1)*sizeof(uint64_t));/*pointers*/
    memmove((void *)(uint64_t)right_brother+sizeof(node_header)+(leaf_order*sizeof(uint64_t)),(void *)(uint64_t)right_brother+sizeof(node_header)+(leaf_order*sizeof(uint64_t))+PREFIX_SIZE, (right_brother->numberOfEntriesInNode-1)*PREFIX_SIZE);/*prefixes*/

    /*update counters*/
		self->numberOfEntriesInNode++;
		right_brother->numberOfEntriesInNode--;
		/*return the pivot to parent*/
		return (void *)MAPPED+*(uint64_t *)((uint64_t)right_brother+sizeof(node_header));
	}
	else/*index node*/
	{
		/*first child of right_brother added as last child of self*/
		offset = sizeof(node_header)+sizeof(uint64_t)+(self->numberOfEntriesInNode*2*sizeof(uint64_t)) + sizeof(uint64_t);
		*(uint64_t *)((uint64_t)self+offset) = *(uint64_t *)((uint64_t)right_brother+sizeof(node_header));/*first pointer of child_b goes as last to child_a*/
		void * key = (void *)MAPPED+*(uint64_t *)((uint64_t)right_brother+sizeof(node_header)+sizeof(uint64_t));
		/*fix child_b*/
		memmove((void *)(uint64_t)right_brother+sizeof(node_header), (void *)(uint64_t)right_brother+sizeof(node_header)+(2*sizeof(uint64_t)), ((right_brother->numberOfEntriesInNode-1)*2*sizeof(uint64_t))+sizeof(uint64_t));
		++self->numberOfEntriesInNode;
		--right_brother->numberOfEntriesInNode;
		return key;/*parent will handle the rest*/
	}
}


/**private function used as a consultant service for underflow. nodes
 * possible actions are:
 *		MERGE_WITH_LEFT
 *		MERGE_WITH_RIGHT
 *		ROTATE_LEFT
 *		ROTATE_RIGHT
 @params node: the node facing the underflow
 parent: node's parent
 offset: offset on node in parent's index - needed for locating the left and right brother
**/
int32_t __rebalance_controller(node_header * node, node_header * parent, uint64_t offset)
{
	node_header * left_brother = NULL;
	node_header *right_brother = NULL;
	uint64_t position;
	int32_t order;
	/*in which position am I in my father's index?*/

	position = (offset-sizeof(node_header))/sizeof(uint64_t);

	if(node->type == leafNode)
		order = leaf_order;
	else
		order = index_order;


	if(position > 0)/*I have left brother, look how many entries it has*/
		left_brother = (node_header *)(MAPPED + *(uint64_t *)(((uint64_t)parent+offset) - 16));

	if(position < (parent->numberOfEntriesInNode*2)-1)/*I have right brother*/
		right_brother = (node_header *)(MAPPED + *(uint64_t *)((uint64_t)parent+offset+16));

	if(left_brother!= NULL && ((node->numberOfEntriesInNode + left_brother->numberOfEntriesInNode)<=order))/*merge with the left*/
	{
		return MERGE_WITH_LEFT;
	}
	else if(right_brother != NULL && ((node->numberOfEntriesInNode + right_brother->numberOfEntriesInNode)<=order))/*merger with the right*/
	{
#ifdef DEBUG_DELETE
		printf("[%s:%s:%d] commands MERGE_WITH_RIGHT\n",__FILE__,__func__,__LINE__);
#endif
		return MERGE_WITH_RIGHT;
	}
	/*merge is not possible, going for rotation*/
	if(left_brother!=NULL && left_brother->numberOfEntriesInNode >(order/2))/*take a key from the left and put it to child*/
	{
		if(node->type==leafNode)
		{
#ifdef DEBUG_DELETE
			printf("[%s:%s:%d] commands LEFT_ROTATE_LEAF\n",__FILE__,__func__,__LINE__);
#endif
			return LEFT_ROTATE_LEAF;
		}
		else
		{
#ifdef DEBUG_DELETE
			printf("[%s:%s:%d] commands LEFT_ROTATE_INDEX\n",__FILE__,__func__,__LINE__);
#endif
			return LEFT_ROTATE_INDEX;
		}
	}

	else if(right_brother != NULL && right_brother->numberOfEntriesInNode>(order/2))/*take a key from the right and put it to child*/
	{
		if(node->type==leafNode)
		{
#ifdef DEBUG_DELETE
			printf("[%s:%s:%d] commands RIGHT_ROTATE_LEAF\n", __FILE__, __func__,__LINE__);
#endif
			return RIGHT_ROTATE_LEAF;
		} else {
#ifdef DEBUG_DELETE
			printf("[%s:%s:%d] commands RIGHT_ROTATE_INDEX\n",__FILE__,__func__,__LINE__);
#endif
			return RIGHT_ROTATE_INDEX;
		}
	}
	return -1;
}

/*this function will be reused in various places such as deletes*/
void * __find_key(db_handle * handle, void *key, node_header * unused, char SEARCH_MODE){

	node_header * curr_node;
	node_header * next_node;
	void *key_addr_in_leaf = NULL;
	void * next_addr;
	void * addr;
	int32_t index_key_len;
	node_header ** tree_hierarchy;
	int32_t tree_id;
	uint64_t v1;
	uint64_t v2;
	int count_retries=-1;
	int retry = 0;
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

	if(count_retries==100000){
		DPRINT("Retried 10000 times aborting\n");
		exit(EXIT_FAILURE);
	}

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

		/*During traversal we need to search also the buffers, findLeadNode function is probably useless now*/
		while(curr_node->type != leafNode && curr_node->type != leafRootNode){
			v2 = curr_node->v2;
			next_addr = _index_node_binary_search(curr_node, key, KV_FORMAT);
			next_node = (void *)(MAPPED + *(uint64_t *)next_addr);
			v1 = curr_node->v1;

			if(v1 != v2){
				printf("[%s:%s:%d] failed at node height %d v1 %llu v2 %llu\n",__FILE__,__func__,__LINE__,curr_node->height,(LLU)curr_node->v1, (LLU)curr_node->v2);
				goto retry;
			}

			if(tree_hierarchy[tree_id] != NULL)
				if(curr_node->type == rootNode && curr_node != tree_hierarchy[tree_id]){
					printf("[%s:%s:%d] failed at node height %d v1 %llu v2 %llu\n",__FILE__,__func__,__LINE__,curr_node->height,(LLU)curr_node->v1, (LLU)curr_node->v2);
					goto retry;
				}
			curr_node = next_node;
		}

		v2 = curr_node->v2;
		key_addr_in_leaf = __find_key_addr_in_leaf(curr_node, key);
		if(key_addr_in_leaf != NULL){
			key_addr_in_leaf =(void *) MAPPED + *(uint64_t *)key_addr_in_leaf;
			index_key_len = *(int32_t *)key_addr_in_leaf;
			addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
		}
		else
			retry = 1;
		v1 = curr_node->v1;

		if(v1 != v2){
			//DPRINT("failed at node height %d v1 %llu v2 %llu\n", curr_node->height,(LLU)curr_node->v1,(LLU)curr_node->v2);
			goto retry;
		}
		if(key_addr_in_leaf == NULL)/*snapshot and retry, only for outer tree case*/
			continue;
		assert(*(uint32_t *)addr < 1100);
		return addr;
	}
	return NULL;/*key not found at the outer tree*/
}


/*returns the addr where the value of the KV pair resides*/
void * __find_key_addr_in_leaf(node_header * leaf, void *key)
{
	void * addr;
	void * index_key = NULL;
	char key_buf_prefix[PREFIX_SIZE];
	uint64_t *index_key_prefix;
	int32_t start_idx;
	int32_t end_idx;
	int32_t middle;
	int32_t size = *(int32_t *)key;
	int32_t ret;

	memset(key_buf_prefix, 0, PREFIX_SIZE);
	if(size < PREFIX_SIZE)
		memcpy(key_buf_prefix, (void *)((uint64_t)key + sizeof(int32_t) + OFFSET_IN_KEY), size);
	else
		memcpy(key_buf_prefix, (void *)((uint64_t)key + sizeof(int32_t) + OFFSET_IN_KEY), PREFIX_SIZE);

	start_idx = 0;
	end_idx = leaf->numberOfEntriesInNode - 1;

	while(start_idx <= end_idx){
		middle = (start_idx + end_idx) / 2;
		addr = (void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (middle * sizeof(uint64_t)));
		index_key_prefix = (uint64_t *)( (uint64_t)leaf + (uint64_t)sizeof(node_header) + (leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE) );

		ret = prefix_compare((char *)index_key_prefix, (char *)key_buf_prefix, PREFIX_SIZE);

		if(ret < 0)
			start_idx = middle + 1;

		else if(ret > 0)
			end_idx = middle - 1;


		/*prefix is the same compare full keys to be sure*/
		else{
			index_key = (void *)(MAPPED + *(uint64_t *)addr);
			int ret = _tucana_key_cmp(index_key, key, KV_FORMAT, KV_FORMAT);
			if(ret == 0)
				return addr;
			else if(ret < 0){
				start_idx = middle + 1;
			}
			else{
				end_idx = middle - 1;
			}
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
void update_index(node_header* node, node_header * left_child, node_header * right_child, void *key_buf){
	int64_t ret = 0;
	void * addr;
	void * dest_addr;
	uint64_t entry_val = 0;
#ifndef FIXED_SIZE_KEYS
	void * index_key_buf;
#endif
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->numberOfEntriesInNode-1;
	size_t num_of_bytes;

	addr = (void *)(uint64_t)node + sizeof(node_header);

	if(node->numberOfEntriesInNode > 0){

		while(1){
			middle = (start_idx + end_idx)/2;
			addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header)+sizeof(uint64_t)+(uint64_t)(middle*2*sizeof(uint64_t));
#ifndef FIXED_SIZE_KEYS
			index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, KV_FORMAT);
#else
			ret = memcmp(addr,&key_buf,sizeof(uint64_t));
#endif
			if(ret > 0)
			{
				end_idx = middle - 1;
				if(start_idx > end_idx)
					//addr is the same
					break;
			}
			else if(ret == 0)
			{
#ifndef FIXED_SIZE_KEYS
				printf("[%s:%s:%d]FATAL key already present %s %s\n",__FILE__,__func__,__LINE__, (char *)index_key_buf+4, (char *)key_buf+4);
				raise(SIGINT);
#else
				/* printf("[%s:%s:%d] FATAL key already present %llu\n",__FILE__,__func__,__LINE__,(LLU)*(uint64_t *)addr); */
#endif
				exit(1);
			}
			else
			{
				start_idx = middle+1;
				if(start_idx > end_idx)
				{
					middle++;
					if(middle >= node->numberOfEntriesInNode)
					{
						middle = node->numberOfEntriesInNode;
						addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) + (uint64_t)(middle*2*sizeof(uint64_t))+sizeof(uint64_t);
					}
					else
						addr += (2*sizeof(uint64_t));
					break;
				}
			}
		}

		dest_addr = addr + (2*sizeof(uint64_t));
		num_of_bytes = (node->numberOfEntriesInNode - middle)*2*sizeof(uint64_t);
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
#ifndef FIXED_SIZE_KEYS
	entry_val = (uint64_t)key_buf - MAPPED;
	memcpy(addr,&entry_val,sizeof(uint64_t));
#else
	memcpy((void *)addr,(void *)&key_buf,sizeof(uint64_t));
	printf("[%s:%s:%d] pivot is %llu\n",__FILE__,__func__,__LINE__,(LLU)*(uint64_t *)addr);
#endif

	addr += sizeof(uint64_t);
	if(right_child != 0)
		entry_val = (uint64_t)right_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr,&entry_val,sizeof(uint64_t));
	return;
}

/**
 * @param   handle: database handle
 * @param   node: address of the index node where the key should be inserted
 * @param   left_child: address to the left child (full not absolute)
 * @param   right_child: address to the left child (full not absolute)
 * @param   key: address of the key to be inserted
 * @param   key_len: size of the key
 */
void insertKeyAtIndex(allocator_descriptor *allocator_desc, node_header * node, node_header * left_child, node_header * right_child, void *key_buf, char allocation_code){
#ifndef FIXED_SIZE_KEYS
	void * key_addr = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;
	IN_log_header * d_header = NULL;
	IN_log_header * last_d_header = NULL;

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
		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)node->last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		node->last_IN_log_header = last_d_header->next;
		node->key_log_size += (avail_space +  sizeof(uint64_t));/* position the log to the newly added block*/
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)node->last_IN_log_header + (uint64_t)(node->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(uint32_t) + key_len);/*key length */
	node->key_log_size += sizeof(uint32_t) + key_len;

	update_index(node, left_child, right_child, key_addr);

#else
	/*fixed sized keys, case pivots are 8 bytes*/
	update_index(node, left_child, right_child, key_buf);
#endif
	node->numberOfEntriesInNode++;
	return;
}


/*
 * gesalous: Added at 13/06/2014 16:22. After the insertion of a leaf it's corresponding index will be updated
 * for later use in efficient searching.
 *
 */
int __update_leaf_index(insertKV_request *req, node_header * leaf, void * key_buf, char key_format){
	void *addr;
	void *dest_addr;
	void *index_key_buf;
	uint64_t num_of_bytes;
	int64_t ret = -1;
	int32_t start_idx;
	int32_t end_idx;
	int32_t middle = 0;
	uint64_t *index_key_prefix;
	char key_buf_prefix[PREFIX_SIZE];

	/*assert_leaf_node(leaf);*/
	start_idx = 0;
	end_idx = leaf->numberOfEntriesInNode - 1;
	addr = (void *)((uint64_t)leaf + (uint64_t)sizeof(node_header));
	ret = 1;

	if(key_format == KV_FORMAT){
		int32_t row_len = *(int32_t *)key_buf;

		if(row_len < PREFIX_SIZE){
			memset(key_buf_prefix, 0, PREFIX_SIZE * sizeof(char));
			memcpy(key_buf_prefix, (void *)((uint64_t)key_buf + sizeof(int32_t) + OFFSET_IN_KEY), row_len);
		}
		else
			memcpy(key_buf_prefix, (void *)((uint64_t)key_buf + sizeof(int32_t) + OFFSET_IN_KEY), PREFIX_SIZE);
	} else { /*operation coming from spill request*/
		memcpy(key_buf_prefix, key_buf, PREFIX_SIZE);

		/*optimization that works only for single threaded spills!,ommit
		  if(leaf == req->handle->db_desc->last_spilled_leaf){
		  start_idx = req->handle->db_desc->last_spilled_position + 1;
		  if(start_idx > end_idx){
		  middle = start_idx;
		  addr = (void *)((uint64_t)leaf +(uint64_t)sizeof(node_header)+(uint64_t)(middle*sizeof(uint64_t)));
		  goto up_leaf_3;
		  }
		  }*/
	}

	while(leaf->numberOfEntriesInNode > 0){

		middle = (start_idx + end_idx) / 2;
		addr = (void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(middle * sizeof(uint64_t))); // pointer
		index_key_prefix = (uint64_t *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE));
		ret = prefix_compare((char *)index_key_prefix, key_buf_prefix, PREFIX_SIZE);
		if(ret < 0)
		{
#ifdef PREFIX_STATISTICS
			if(key_format == KV_FORMAT)
				__sync_fetch_and_add(&ins_prefix_hit_l0, 1);
			else
				__sync_fetch_and_add(&ins_prefix_hit_l1, 1);
#endif

			goto up_leaf_1;
		}
		else if(ret > 0)
		{
#ifdef PREFIX_STATISTICS
			if(key_format == KV_FO__sync_fetch_and_add(&ins_prefix_hit_l0, 1);
			else
				__sync_fetch_and_add(&ins_prefix_hit_l1, 1);
#endif

			goto up_leaf_2;
		}

#ifdef PREFIX_STATISTICS
		if(key_format == KV_PREFIX)
		{
			__sync_fetch_and_add(&ins_hack_miss, 1);
		}

		if(key_format == KV_FORMAT)
			__sync_fetch_and_add(&ins_prefix_miss_l0, 1);
		else
			__sync_fetch_and_add(&ins_prefix_miss_l1, 1);
#endif
		index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, key_format);
		if(ret == 0){
#ifdef ENABLE_GARBAGE_STATS
			/**	its an update, mark the hole in the KV log metadata
			 *	finally mark garbage bytes, please note that all allocations take place at BUFFER_SEGMENT_SIZE granularity
			 * and addresses returned by the allocator are aligned in BUFFER_SEGMENT_SIZE.
			 * to find the start of the log block given the deleted_key
			 **/
			uint64_t absolute_addr = (uint64_t)index_key_buf - MAPPED;
			uint64_t distance  = (absolute_addr%BUFFER_SEGMENT_SIZE);
			segment_header * segment = (segment_header *)((uint64_t)index_key_buf - distance);
			uint32_t idx = 2*(req->handle->volume_desc->soft_superindex->epoch%MAX_COUNTER_VERSIONS);

			if(segment->garbage_bytes[idx] <= req->handle->volume_desc->dev_superindex->epoch){
				uint32_t previous_idx = 2*((req->handle->volume_desc->dev_superindex->epoch)%MAX_COUNTER_VERSIONS);
				segment->garbage_bytes[idx] = req->handle->volume_desc->soft_superindex->epoch;
				segment->garbage_bytes[idx+1] = segment->garbage_bytes[previous_idx+1];
				//printf("[%s:%s:%d] garbage bytes now in block  %llu are %llu\n",__FILE__,__func__,__LINE__,(LLU)block,(LLU)block->garbage_bytes[idx+1]);
			}
			assert(idx+1 >= 0 && idx+1 < (2*MAX_COUNTER_VERSIONS));
			segment->garbage_bytes[idx+1] +=  *(uint32_t *)index_key_buf +  *(uint32_t *)(index_key_buf+sizeof(uint32_t)+*(uint32_t *)index_key_buf) + (2*sizeof(uint32_t));
#endif
			break;
		}
		else if(ret < 0){
		up_leaf_1:
			start_idx = middle+1;
			if(start_idx > end_idx)
			{
				middle++;
				addr = (void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(middle * sizeof(uint64_t)));
				dest_addr = (void *)(uint64_t)addr + sizeof(uint64_t);

				num_of_bytes = (leaf->numberOfEntriesInNode - middle) * sizeof(uint64_t);
				memmove(dest_addr, addr, num_of_bytes);
				memmove((void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t) )+ (middle * PREFIX_SIZE) + PREFIX_SIZE),
					(void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t))+(middle*PREFIX_SIZE)),
					(leaf->numberOfEntriesInNode - middle) * PREFIX_SIZE);
				break;
			}
		}
		else if(ret > 0){
		up_leaf_2:
			end_idx = middle-1;
			if(start_idx > end_idx)
			{
				addr = (void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(middle * sizeof(uint64_t)));
				dest_addr = (void *)(uint64_t)addr + sizeof(uint64_t);

				num_of_bytes = (leaf->numberOfEntriesInNode - middle) * sizeof(uint64_t);
				memmove(dest_addr, addr, num_of_bytes);
				memmove((void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE) + PREFIX_SIZE),
					(void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE)),
					(leaf->numberOfEntriesInNode - middle) * PREFIX_SIZE);
				break;
			}
		}
	}
	/*setup the pointer*/
	if(key_format == KV_FORMAT){
		*(uint64_t *)addr = (uint64_t)key_buf - MAPPED;
		void * tmp_addr = (void *)(MAPPED + *(uint64_t *)addr);
		assert(*(uint32_t *)tmp_addr <= 24 &&  *(uint32_t *)(tmp_addr+*(uint32_t *)tmp_addr+4)<=1100);
	} else {
		//up_leaf_3:
		*(uint64_t *)addr = (*(uint64_t*)(key_buf+PREFIX_SIZE+HASH_SIZE))-MAPPED;
		//req->handle->db_desc->last_spilled_leaf = leaf;
		//req->handle->db_desc->last_spilled_position = middle;
	}
	/*setup the prefix*/
	/*assert_leaf_node(leaf);*/
	memcpy((void *)((uint64_t)leaf + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE)), key_buf_prefix, PREFIX_SIZE);
	return ret;
}


void assert_leaf_node(node_header * leaf)
{
	void * prev;
	void * curr;
	void * addr;
	int64_t ret;
	int i;
	if(leaf->numberOfEntriesInNode == 1)
	{
		return;
	}
	addr = (void *)(uint64_t)leaf + sizeof(node_header);
	curr = (void *)*(uint64_t *)addr+MAPPED;

	for(i=1;i<leaf->numberOfEntriesInNode;i++)
	{
		addr += 8;
		prev = curr;
		curr = (void *)*(uint64_t *)addr+MAPPED;
		ret = _tucana_key_cmp(prev, curr, KV_FORMAT, KV_FORMAT);
		if(ret > 0)
		{
			printf("[%s:%s:%d] FATAL corrupted leaf index at index %d total entries %d\n",__FILE__, __func__,__LINE__, i, leaf->numberOfEntriesInNode);
			printf("previous key is: %s\n", (char *)prev+sizeof(int32_t));
			printf("curr key is: %s\n", (char *)curr+sizeof(int32_t));
			raise(SIGINT);
			exit(-1);
		}
	}
}
#ifdef DEBUG_TUCANA_2
#endif

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

	for(i=0;i<req->node->numberOfEntriesInNode;i++)
	{
		if(i < req->node->numberOfEntriesInNode/2)
			tmp_index = rep->left_child;
		else
			tmp_index = rep->right_child;

		left_child = (node_header *) (MAPPED + *(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
#ifndef FIXED_SIZE_KEYS
		key_buf = (void *)(MAPPED + *(uint64_t *)full_addr);
#else
		key_buf = (void *) *(uint64_t *)full_addr;
#endif
		full_addr += sizeof(uint64_t);
		right_child = (node_header *)(MAPPED + *(uint64_t *)full_addr);
		if(i == req->node->numberOfEntriesInNode/2){
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
int insertKVAtLeaf(insertKV_request *req, node_header * leaf, char allocation_code){

	void * key_addr = NULL;
	/*added at 18/10/2016 to replace the useless leaf->first_kv_block, leaf->last_kv_block, and leaf->log_size*/
	int ret;
	/*where are we now, read global log for this tree from its root
	 * Reminder: We do not perform a COW check before updating root_w
	 *	of the tree because by construction(see snapshot function the allocator)
	 * a non null root_w is always in non immutable state
	 */
	if((req->insert_flags&0x00FF0000) == APPEND_TO_LOG){
		printf("[%s:%s:%d] FATAL APPEND_TO_LOG at insertKVAtLeaf unsuppported\n",__FILE__,__func__,__LINE__);
		exit(EXIT_FAILURE);
	}

	if(req->key_format == KV_FORMAT && (req->insert_flags&0xFF000000) == INSERT_TO_L0_INDEX){
		key_addr = req->key_value_buf;
	}
	/*kv pair already in KVlog,part of spill request, format should be KV_PREFIX*/
	if(req->key_format == KV_PREFIX && (req->insert_flags&0xFF000000) == INSERT_TO_L1_INDEX){
		key_addr = req->key_value_buf;
	}
	if(__update_leaf_index(req, leaf, key_addr, req->key_format) != 0){

		leaf->numberOfEntriesInNode++;
		__sync_fetch_and_add(&req->handle->db_desc->total_keys[req->level_id],1);
		ret = 1;
	}
	else{ /*if key already present at the leaf, must be an update or an append*/
		leaf->fragmentation++;
		ret = 0;
	}
	return ret;
}


int split_leaf(split_request * req, split_reply *rep){

	node_header* node_copy;
	void * addr;
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

		for(i=0;i<req->node->numberOfEntriesInNode;i++){
			key_addresses[i] = MAPPED + *(uint64_t *)addr;
			/*let the 4KB page fault happen without locking the db, for level-0*/
			data_addresses[i] =  key_addresses[i]+sizeof(uint32_t)+*(uint32_t *)key_addresses[i];
			addr += sizeof(uint64_t);
		}
		//lock db
		MUTEX_LOCK(&(insert_req.handle->db_desc->write_lock));
		/* pthread_mutex_lock(&(insert_req.handle->db_desc->write_lock)); */
		req->node->v1++;//lamport counter
		for(i=0;i<req->node->numberOfEntriesInNode;i++){
			insert_req.key_buf = (void *)key_addresses[i];
			insert_req.data_buf = (void *)data_addresses[i];
			insertKVAtLeaf(&insert_req,req->node, REORGANIZATION);
		}
		//unlock db
		req->node->v2++;//lamport counter
		MUTEX_UNLOCK(&(insert_req.handle->db_desc->write_lock));
		/* pthread_mutex_unlock(&(insert_req.handle->db_desc->write_lock)); */
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

	addr = (void *)(uint64_t)req->node + sizeof(node_header)+ ((req->node->numberOfEntriesInNode / 2) * sizeof(uint64_t));
#ifndef FIXED_SIZE_KEYS
	rep->middle_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
#else
	rep->middle_key_buf = (void *)*(uint64_t *)(MAPPED + *(uint64_t *)addr+sizeof(uint32_t));
	printf("[%s:%s:%d] middle key of split leaf is %llu\n",__FILE__,__func__,__LINE__,(LLU)rep->middle_key_buf);
#endif

	/*pointers*/
	memcpy((void *)((uint64_t)rep->right_child + sizeof(node_header)),(void *)(uint64_t)req->node+sizeof(node_header)+((req->node->numberOfEntriesInNode/2)*sizeof(uint64_t)), ((req->node->numberOfEntriesInNode / 2) + (req->node->numberOfEntriesInNode % 2)) * sizeof(uint64_t));
	/*prefixes*/
	memcpy((void *)(uint64_t)rep->right_child+sizeof(node_header)+(leaf_order*sizeof(uint64_t)),
	       (void *)(uint64_t)req->node+sizeof(node_header)+(leaf_order*sizeof(uint64_t))+((req->node->numberOfEntriesInNode/2)*PREFIX_SIZE),
	       ((req->node->numberOfEntriesInNode / 2) + (req->node->numberOfEntriesInNode % 2))*PREFIX_SIZE);

	rep->right_child->numberOfEntriesInNode = (req->node->numberOfEntriesInNode/2)+(req->node->numberOfEntriesInNode%2);
	rep->right_child->type = leafNode;

	rep->right_child->height = req->node->height;
	/*left leaf*/
	rep->left_child->height = req->node->height;
	rep->left_child->numberOfEntriesInNode = req->node->numberOfEntriesInNode/2;

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
void * _index_node_binary_search(node_header * node, void *key_buf, char query_key_format)
{
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->numberOfEntriesInNode-1;
	int32_t num_entries = node->numberOfEntriesInNode;

	while(num_entries > 0)
	{
		middle = (start_idx + end_idx)/2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return NULL;

		addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) + sizeof(uint64_t)+(uint64_t)(middle*2*sizeof(uint64_t));
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if(ret > 0)
		{
			end_idx = middle - 1;
			if(start_idx > end_idx)
			{
				middle--;
				addr -= sizeof(uint64_t);
				break;
			}
		}
		else if(ret == 0)
		{
			addr += sizeof(uint64_t);
			break;
		}
		else
		{
			start_idx = middle+1;
			if(start_idx > end_idx)
			{
				middle++;
				addr += sizeof(uint64_t);
				break;
			}
		}
	}

	if(middle < 0)
		addr = (void *)(uint64_t)node + sizeof(node_header);
	else if(middle >= node->numberOfEntriesInNode)
		addr = (void *)(uint64_t)node + sizeof(node_header)+(2*sizeof(uint64_t)*node->numberOfEntriesInNode);

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
	IN_log_header * bh;
	//printf("[%s:%s:%d] level id %d\n",__FILE__,__func__,__LINE__,allocator_desc->level_id);
	ptr = (node_header *)(*allocator_desc->allocate_space)(allocator_desc->handle, NODE_SIZE, allocator_desc->level_id,allocation_code);
	ptr->type = type;
	ptr->epoch = handle->volume_desc->soft_superindex->epoch;
	ptr->numberOfEntriesInNode = 0;
	ptr->fragmentation  =  0;
	ptr->v1=0;
	ptr->v2=0;

	if(type == leafNode || type == leafRootNode){
		ptr->first_IN_log_header = NULL;/*unused field in leaves*/
		ptr->last_IN_log_header  = NULL;/*unused field in leaves*/
		ptr->key_log_size = 0;/*unused also*/
		ptr->height = 0;
#ifdef SCAN_REORGANIZATION
		if(allocator_desc->level_id >= NUM_OF_TREES_PER_LEVEL) {
			ptr->leaf_id = ++handle->db_desc->leaf_id;
		}
#endif
	}
	else{/*internal or root node(s)*/
		/*private key log for index nodes*/
		bh = (IN_log_header *)(*allocator_desc->allocate_space)(allocator_desc->handle, KEY_BLOCK_SIZE, allocator_desc->level_id,KEY_LOG_EXPANSION);
		bh->next = (void *)NULL;
		ptr->first_IN_log_header  = (IN_log_header *)((uint64_t)bh - MAPPED);
		ptr->last_IN_log_header =  ptr->first_IN_log_header;
		ptr->key_log_size = sizeof(uint64_t);
	}

	if(type == rootNode)/*increase node height by 1*/
		ptr->height = handle->db_desc->root_w[allocator_desc->level_id]->height + 1;
	return (void *)ptr;
}



void spill_buffer(void * _spill_req)
{
	spill_request *spill_req = (spill_request *)_spill_req;
	db_descriptor *db_desc;
	level_scanner * level_sc;
	int32_t local_spilled_keys = 0;
	int i, rc = 100;

	DPRINT("spill worker started\n");
	assert(spill_req->dst_tree_id > 0 && spill_req->dst_tree_id < 255);

	/*Initialize a scan object*/
	db_desc = spill_req->db_desc;
	db_handle handle;
	handle.db_desc = spill_req->db_desc;
	handle.volume_desc = spill_req->volume_desc;

	level_sc = _init_spill_buffer_scanner(&handle, spill_req->src_root,spill_req->start_key);
  assert(level_sc != NULL);
  kv_location location;
	int32_t num_of_keys = (SPILL_BUFFER_SIZE-(2*sizeof(uint32_t)))/(PREFIX_SIZE + sizeof(uint64_t));
	
	do{
		while(handle.volume_desc->snap_preemption == SNAP_INTERRUPT_ENABLE)
			usleep(50000);

		db_desc->dirty = 0x01;
		if(handle.db_desc->db_mode == DB_IS_CLOSING){
			DPRINT("db is closing bye bye from spiller\n");
			__sync_fetch_and_sub(&db_desc->count_active_spillers,1);
			return;
		}

  for(i = 0; i < num_of_keys; i++){
			location.kv_addr = level_sc->keyValue;
			location.log_offset = 0;/*unused*/
			_insert_index_entry(&handle, &location, INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (spill_req->dst_tree_id << 8) | SPILL_OPERATION);

			++local_spilled_keys;
			//_sync_fetch_and_add(&db_desc->spilled_keys,1);
			rc = _get_next_KV(level_sc);
			if(rc == END_OF_DATABASE)
				break;
			if (spill_req->end_key !=NULL &&_tucana_key_cmp(level_sc->keyValue,spill_req->end_key,KV_PREFIX,KV_FORMAT) >= 0) {
				DPRINT("STOP KEY REACHED %s\n",(char *)spill_req->end_key+4);
				goto finish_spill;
			}
		}
	}while(rc != END_OF_DATABASE);
finish_spill:/*Unused label*/

	_close_spill_buffer_scanner(level_sc, spill_req->src_root);
	/*sanity check
	  if(spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
	  printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
	  exit(EXIT_FAILURE);
	  }*/
	DPRINT("local spilled keys %d\n", local_spilled_keys);
	/*Clean up code, Free the buffer tree was occupying. free_block() used intentionally*/
	__sync_fetch_and_sub(&db_desc->count_active_spillers,1);
	if(db_desc->count_active_spillers == 0){
		printf("[%s:%s:%d] last spiller cleaning up level 0 remains\n",__FILE__,__func__,__LINE__);
		level_scanner * sc = _init_spill_buffer_scanner(&handle,spill_req->src_root, NULL);

		_close_spill_buffer_scanner(sc,spill_req->src_root);
		void * free_addr;
		uint64_t size;
		free_addr = (void *)db_desc->segments[spill_req->src_tree_id*3];
		size = db_desc->segments[(spill_req->src_tree_id*3)+1];
		while(1){
			if(size != BUFFER_SEGMENT_SIZE){
				fprintf(stderr, "[%s:%s:%d] FATAL corrupted segment size %llu should be %llu\n",__FILE__,__func__,__LINE__,(LLU)size,(LLU)BUFFER_SEGMENT_SIZE);
				exit(EXIT_FAILURE);
			}
			uint64_t s_id = ((uint64_t)free_addr - (uint64_t)handle.volume_desc->bitmap_end)/BUFFER_SEGMENT_SIZE;
			//printf("[%s:%s:%d] freeing %llu size %llu s_id %llu freed pages %llu\n",__FILE__,__func__,__LINE__,(LLU)free_addr,(LLU)size,(LLU)s_id,(LLU)handle->volume_desc->segment_utilization_vector[s_id]);
			if(handle.volume_desc->segment_utilization_vector[s_id]!= 0 && handle.volume_desc->segment_utilization_vector[s_id] < SEGMENT_MEMORY_THREASHOLD){

				//printf("[%s:%s:%d] last segment remains\n",__FILE__,__func__,__LINE__);
				/*dimap hook, release dram frame*/
				/*if(dmap_dontneed(FD, ((uint64_t)free_addr-MAPPED)/PAGE_SIZE, BUFFER_SEGMENT_SIZE/PAGE_SIZE)!=0){
				  printf("[%s:%s:%d] fatal ioctl failed\n",__FILE__,__func__,__LINE__);
				  exit(-1);
				  }
				  __sync_fetch_and_sub(&(handle->db_desc->zero_level_memory_size), (unsigned long long)handle->volume_desc->segment_utilization_vector[s_id]*4096);
				*/
				handle.volume_desc->segment_utilization_vector[s_id] = 0;
			}
			free_block(handle.volume_desc, free_addr, size, -1);
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
		db_desc->L0_start_log_offset = spill_req->l0_end;

	}
	free(spill_req);
	DPRINT("spill finished\n");
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
	for(k=0;k<node->numberOfEntriesInNode;k++){
		/*check child type*/
		child = (node_header *)(MAPPED + *(uint64_t *)addr);
		if(child->type!=rootNode && child->type!=internalNode && child->type != leafNode && child->type != leafRootNode)
		{
			printf("[%s:%s:%d] FATAL corrupted child at index for child %llu type is %d\n",__FILE__,__func__,__LINE__, (LLU)(uint64_t)child-MAPPED, child->type);
			exit(-1);
		}
		//printf("\tpointer to child %llu\n", (LLU)child-MAPPED);

		addr+=sizeof(uint64_t);
#ifndef FIXED_SIZE_KEYS
		key_tmp = (void *)MAPPED + *(uint64_t *)addr;
		/* printf("\tkey %s\n",(char *)key_tmp+sizeof(int32_t)); */
#else
		key_tmp = addr;
#endif

		if(key_tmp_prev != NULL)
		{
#ifndef FIXED_SIZE_KEYS
			if(_tucana_key_cmp(key_tmp_prev, key_tmp, KV_FORMAT, KV_FORMAT) >=0 )
#else
				if(memcmp(key_tmp_prev,key_tmp,sizeof(uint64_t)) >= 0)
#endif
				{
					/* printf("[%s:%s:%d] FATAL: corrupted index %s something else %s\n",__FILE__,__func__,__LINE__,key_tmp_prev+4,key_tmp+4); */
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
	printf("total entries = %d\n",node->numberOfEntriesInNode);
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


uint64_t hash(uint64_t x) 
{
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table * _find_position(lock_table** table,node_header* node){

	unsigned long position;
	lock_table * return_value;

	if(node->height>MAX_HEIGHT){
		printf("[%s:%s:%d] FATAL ERROR: MAX_HEIGHT exceeded rearrange values in size_per_height array\n",__FILE__,__func__,__LINE__);
		BREAKPOINT
		exit(EXIT_FAILURE);
	}

	position=hash((uint64_t)node)%size_per_height[node->height];
	return_value=table[node->height];
	return &return_value[position];
}


void _unlock_upper_levels(lock_table * node[],unsigned size,unsigned release){

	unsigned i;
	for(i=release;i<size;++i){
		if(RWLOCK_UNLOCK(&node[i]->rx_lock)!=0){
			printf("[%s:%s:%d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
	}
}

uint8_t _concurrent_insert(insertKV_request * req)
{

	lock_table * upper_level_nodes[MAX_HEIGHT];/*The array with the locks that belong to this thread from upper levels*/
	lock_table * lock;
	void * next_addr;
	superindex * soft_superindex;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	split_request split_req;
	split_reply split_rep;
	node_header * new_node;
	node_header * node_copy;
	node_header * father;
	node_header * son;
	uint64_t addr;
	int64_t ret;
	unsigned size;/*Size of upper_level_nodes*/
	unsigned release;/*Counter to know the position that releasing should begin */
	uint32_t order;
	int init = 0;

	// remove some warnings here
	(void)ret;
	(void)addr;
	volume_desc = req->handle->volume_desc;
	db_desc = req->handle->db_desc;
	release = 0;
	size = 0;
	/*guard lock already aquired*/
	upper_level_nodes[size++] = req->guard_of_level;

retry:
	father = NULL;
	if(init == 1){
		_unlock_upper_levels(upper_level_nodes,size,release);
		size=0;
		release=0;
		/*Extra lock in order to get a valid root node*/
		if(RWLOCK_WRLOCK(&req->guard_of_level->rx_lock) !=0){
			printf("[%s:%s:%d] ERROR locking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
		/*refresh info for level-0 after a retry*/
		if(req->level_id < NUM_OF_TREES_PER_LEVEL){
			req->level_id=db_desc->active_tree;
			req->allocator_desc.level_id = db_desc->active_tree;
		}
		upper_level_nodes[size++]=req->guard_of_level;
	}
	init = 1;
	soft_superindex = req->handle->volume_desc->soft_superindex;

	if(db_desc->root_w[req->level_id] == NULL){/*cow logic follows*/
		if(db_desc->root_r[req->level_id] != NULL){
			node_header *t = (*req->allocator_desc.allocate_space)(req->allocator_desc.handle,NODE_SIZE,req->allocator_desc.level_id,COW_FOR_INDEX);
			memcpy(t, db_desc->root_r[req->level_id], NODE_SIZE);
			t->epoch = req->handle->volume_desc->soft_superindex->epoch;
			db_desc->root_w[req->level_id] = t;
		} else {
			/*we are allocating a new tree*/
			if(req->level_id < NUM_OF_TREES_PER_LEVEL)
				allocate_segment(req->handle,BUFFER_SEGMENT_SIZE,req->level_id,NEW_LEVEL_0_TREE);
			else
				allocate_segment(req->handle,BUFFER_SEGMENT_SIZE,req->level_id,NEW_LEVEL_1_TREE);

			db_desc->root_w[req->level_id] = (node_header *)createEmptyNode(&(req->allocator_desc), req->handle, leafRootNode, NEW_ROOT);
		}
	}
	/*acquiring lock of the current root*/
        lock = _find_position(req->level_lock_table,db_desc->root_w[req->level_id]);
	if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){
		printf("[%s:%s:%d] ERROR locking\n",__func__,__FILE__,__LINE__);
                 exit(-1);
        }
        upper_level_nodes[size++]=lock;
	son = db_desc->root_w[req->level_id];

	while(1){
		if(son->type == leafNode || son->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;
		/*Check if father is safe it should be*/
		if(father){
			unsigned int father_order;
			if(father->type == leafNode || father->type == leafRootNode)
				father_order=leaf_order;
			else
				father_order=index_order;
			assert(father->epoch > volume_desc->dev_superindex->epoch);
			assert(father->numberOfEntriesInNode < father_order);
		}
		if(son->numberOfEntriesInNode >= order){/*Overflow split*/
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
				free_logical_node(&(req->allocator_desc),son);/*node has splitted, free it*/
				son->v2++;
			}else{
				son->v1++;
				split_leaf(&split_req, &split_rep);
				son->v2++;
			}
			/*Insert pivot at father*/
			if(father!=NULL){

				father->v1++;/*lamport counter*/
				/* printf("[%s:%s%d]Key is %d %s\n",__FILE__,__FUNCTION__,__LINE__,*(uint32_t*)split_rep.middle_key_buf,split_rep.middle_key_buf+4); */
				insertKeyAtIndex(&(req->allocator_desc),father,split_rep.left_child,split_rep.right_child,split_rep.middle_key_buf,KEY_LOG_EXPANSION);
				father->v2++;/*lamport counter*/
			}else{
				/*Root was splitted*/
				new_node = createEmptyNode(&(req->allocator_desc),req->handle, rootNode, NEW_ROOT);

				new_node->v1++;/*lamport counter*/
				son->v1++;
				insertKeyAtIndex(&(req->allocator_desc),new_node,split_rep.left_child,split_rep.right_child,split_rep.middle_key_buf,KEY_LOG_EXPANSION);
				new_node->v2++;/*lamport counter*/
				son->v2++;
				db_desc->root_w[req->level_id] = new_node; /*new write root of the tree*/
			}
			//__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}else if(son->epoch <= volume_desc->dev_superindex->epoch){ /*Cow*/

			node_copy = (*req->allocator_desc.allocate_space)((void *)req->allocator_desc.handle, NODE_SIZE, req->allocator_desc.level_id, NEW_ROOT);
			memcpy(node_copy, son, NODE_SIZE);
			node_copy->epoch = soft_superindex->epoch;
			node_copy->v1=0;
			node_copy->v2=0;
			/*Update father's pointer*/
			if(father!=NULL){
				father->v1++;/*lamport counter*/
				*(uint64_t *)next_addr = (uint64_t)node_copy-MAPPED;
				father->v2++;/*lamport counter*/
			}else{/*We COWED the root*/
				db_desc->root_w[req->level_id]=node_copy;
			}
			/*Free the node*/
			(*req->allocator_desc.free_space)((void *)req->allocator_desc.handle,son,NODE_SIZE,req->allocator_desc.level_id);
			//__sync_fetch_and_sub(writers_counter,1);
			goto retry;
		}

		if(son->height == 0)
			break;
		/*Finding the next node to traverse*/
		next_addr = _index_node_binary_search(son, req->key_value_buf, req->key_format);
		father = son;
		/*Taking the lock of the next node before its traversal*/
		lock=_find_position(req->level_lock_table,(node_header *) (MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++]=lock;
		if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){
			printf("[%s %s %d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
		/*Node acquired */
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);
		if(son->type == leafNode || son->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;
		/*if the node is not safe hold its ancestor's lock else release locks from ancestors */
		if(!(son->epoch <= volume_desc->dev_superindex->epoch||son->numberOfEntriesInNode >= order)){
			_unlock_upper_levels(upper_level_nodes,size-1,release);
			release=size-1;
		}
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if(son->type!=leafRootNode)
		assert((size-1)-release==0);

	if(son->height!=0){
		printf("[%s:%s:%d] FATAL son corrupted\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	son->v1++;/*lamport counter*/
	ret = insertKVAtLeaf(req,son,KV_LOG_EXPANSION);
	son->v2++;/*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes,size,release);
	//__sync_fetch_and_sub(writers_counter,1);
	return SUCCESS;
}


uint8_t _writers_join_as_readers(insertKV_request * req){

	lock_table * upper_level_nodes[MAX_HEIGHT];/*The array with the locks that belong to this thread from upper levels*/
	void * next_addr;
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
	node_header * son;
	lock_table * lock;

	uint64_t addr;
	int64_t ret;
	unsigned size;/*Size of upper_level_nodes*/
	unsigned release;/*Counter to know the position that releasing should begin */
	uint32_t order;

	//remove some warnings here
	(void)ret;
	(void)addr;
	volume_desc = req->handle->volume_desc;
	db_desc = req->handle->db_desc;
	size = 0;
	release = 0;

	/* db guard lock should be taken prior calling _writers_join_as_readers */
	upper_level_nodes[size++]=req->guard_of_level;
	if(db_desc->root_w[req->level_id] == NULL || db_desc->root_w[req->level_id]->type == leafRootNode){
		_unlock_upper_levels(upper_level_nodes,size,release);
		return FAILURE;
	 }

	/*acquiring lock of the current root*/
	lock = _find_position(req->level_lock_table,db_desc->root_w[req->level_id]);
	upper_level_nodes[size++]=lock;
	if(RWLOCK_RDLOCK(&lock->rx_lock)!=0){
		printf("[%s:%s:%d] ERROR locking\n",__func__,__FILE__,__LINE__);
		exit(-1);
	}
	son = db_desc->root_w[req->level_id];
	while(1){
		if(son->type == leafNode || son->type == leafRootNode)
			order=leaf_order;
		else
			order=index_order;
		if(son->numberOfEntriesInNode >= order){
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes,size,release);
			return FAILURE;
		}
		else if(son->epoch <= volume_desc->dev_superindex->epoch){
			/*failed needs COW*/
			_unlock_upper_levels(upper_level_nodes,size,release);
			return FAILURE;
		}

		/*Finding the next node to traverse*/
		next_addr = _index_node_binary_search(son, req->key_value_buf, req->key_format);
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);
		if(son->height == 0)
			break;
		/*Taking the lock of the next node before its traversal*/
		lock=_find_position(req->level_lock_table,(node_header *) (MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++]=lock;
		if(RWLOCK_RDLOCK(&lock->rx_lock)!=0){
			printf("[%s %s %d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
			exit(-1);
		}
		/*Node acquired */
		_unlock_upper_levels(upper_level_nodes,size-1,release);
		release=size-1;
	}

	lock=_find_position(req->level_lock_table,(node_header *) (MAPPED + *(uint64_t *)next_addr));
	upper_level_nodes[size++]=lock;
	if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){
		printf("[%s %s %d] ERROR unlocking\n",__func__,__FILE__,__LINE__);
		exit(-1);
	}

	if(son->numberOfEntriesInNode >= leaf_order || son->epoch <= volume_desc->dev_superindex->epoch){
		_unlock_upper_levels(upper_level_nodes,size,release);
		return FAILURE;
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if(son->height!=0){
		printf("[%s:%s:%d] FATAL son corrupted\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	son->v1++;/*lamport counter*/
	ret = insertKVAtLeaf(req,son,KV_LOG_EXPANSION);
	son->v2++;/*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes,size,release);
	return SUCCESS;
}
