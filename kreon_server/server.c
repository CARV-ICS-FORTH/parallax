/**
 * tucana_server.h
 *  Tucana server
 * Created by Pilar Gonzalez-Ferez on 28/07/16.
 * Copyright (c) 2016 Pilar Gonzalez-Ferez <pilar@ics.forth.gr>.
 **/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <alloca.h>

#include "regions.h"
#include "messages.h"
#include "prototype.h"
#include "storage_devices.h"
#include "globals.h"
#include "../kreon_lib/btree/btree.h"
#include "zk_server.h"
#include "../kreon_rdma/memory_regions.h"
#include "../kreon_rdma/rdma.h"
#include "../kreon_rdma/memory_regions.h"
#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_lib/btree/conf.h"
#include "../utilities/queue.h"
#include "../utilities/min_max_heap.h"
#include "stats.h"

#ifdef CHECKSUM_DATA_MESSAGES
#include "djb2.h"
#endif


#define TIERING_MAX_CAPACITY 8
#define LOG_SEGMENT_CHUNK  32*1024

#define RECVFROM 1
#if RECVFROM
#define MAX_THREADS 1
#else
#define MAX_THREADS 2
#endif

#define GREATER 5
#define GREATER_OR_EQUAL 6

#define  MY_MAX_THREADS 2048


extern char * DB_NO_SPILLING;


typedef struct prefix_table{
	char prefix[PREFIX_SIZE];
}prefix_table;

typedef struct spill_task_descriptor
{
	pthread_t spill_worker_context;
	volatile spill_request spill_req;
	/*XXX TODO XXX, add appropriate fields*/
	work_task task;
	struct  _tucana_region_S * region;
	int standalone;
	volatile work_task_status spill_task_status;
}spill_task_descriptor;


#ifdef TIERING
typedef struct replica_tiering_compaction_request
{
	pthread_t tiering_compaction_context;
	_tucana_region_S * region;
	int level_id;
}tiering_compaction_request;
void tiering_compaction_worker(void *);
#endif

	/*re-implementation of distributed kreonR put, in order not to mess with Kreon local library*/
void append_and_insert_kv_pair(_tucana_region_S* S_tu_region, tu_data_message_s *data_message,
		connection_rdma *rdma_conn, 
		kv_location * location,
		work_task *task, 
		int wait);

/*functions for building index at replicas*/
void _calculate_btree_index_nodes(_tucana_region_S* region, uint64_t num_of_keys);
void append_entry_to_leaf_node(_tucana_region_S *region,void * pointer_to_kv_pair, void *prefix, int32_t tree_id);
struct node_header *_create_tree_node(struct _tucana_region_S *region, int tree_id, int node_height, int type);
void _append_pivot_to_index(_tucana_region_S* region, node_header * left_brother, void * pivot, 
		node_header * right_brother, int tree_id, int node_height);

pthread_mutex_t reg_lock;/*Lock for the conn_list*/

extern _tuzk_server tuzk_S;
extern _RegionsSe regions_S;
extern tu_storage_device  storage_dev;


char* Device_name = NULL;
uint64_t Device_size = 0;

#define FAKE_TUCANA 0
/*
 * protocol that threads use to inform the system that they perform
 * a region operation (insert,get,delete). Crucial for the case where
 * regions are destroyed due to failures of another server or
 * some elastic operation
 * */
#define ENTERED_REGION 0x02
#define EXITED_REGION 0x03
#define THROTTLE 2048
static inline char __ENTER_REGION(_tucana_region_S * region)
{
	return ENTERED_REGION;
	long ret_value;
	long value;
	do{
		value = region->active_region_threads;
		//printf("[%s:%s:%d] trying to enter region active %llu\n",__FILE__,__func__,__LINE__,value);
		if(value > THROTTLE)
			return DB_IS_CLOSING;
		ret_value = __sync_val_compare_and_swap(&region->active_region_threads, value, value+1);
		if(ret_value > THROTTLE)
			return DB_IS_CLOSING;
	}while(ret_value != value);
	return ENTERED_REGION;
}



static inline char __EXIT_REGION(_tucana_region_S *region)
{
	return ENTERED_REGION;
	long ret_value;
	long value;
	do{
		value = region->active_region_threads;
		//printf("[%s:%s:%d] trying to exit region active %llu\n",__FILE__,__func__,__LINE__,value);
		ret_value = __sync_val_compare_and_swap(&region->active_region_threads, value, value-1);
	}while(ret_value != value);
	return EXITED_REGION;
}

void server_receiving_messages_blocking_RDMA(void *args);
struct tu_data_message* handle_scan_request(struct tu_data_message* data_message, void* connection);
struct tu_data_message *Server_Handling_Received_Message( struct tu_data_message *data_message , int reg_num, int next_mail );
int handle_put_request(tu_data_message_s *data_message, connection_rdma *rdma_conn);
// struct tu_data_message *Server_FlushVolume_RDMA( struct tu_data_message *data_message, struct connection_rdma *rdma_conn ); // FIXME Never used



_tucana_region_S * get_region(void *key, int key_len)
{
	//_tucana_region_S * region = (_tucana_region_S *)find_region_min_key_on_rbtree( &regions_S.tree, key, key_len);
	_tucana_region_S *region = find_region(key, key_len);
	if(region == NULL){
		DPRINT("FATAL region not found\n");
		exit(EXIT_FAILURE);
	}
	return region;
}

/* 
 * these two functions should be used for spills only for kreonR
 * This function creates a spill task descriptor and sets a new L0 tree
 * as active. It DOES NOT spawn a spiller thread
 * 
 * */
spill_task_descriptor * kreonR_spill_check(_tucana_region_S * region)
{
	db_handle *handle = region->db;
	spill_task_descriptor * desc = NULL;
	int to_spill_tree_id;
	int i;
	//DPRINT("L0 current size %llu max %llu tree status %d flag %d\n",
	//		(LLU)handle->db_desc->zero_level_memory_size, (LLU)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD,*(uint32_t *)handle->db_desc->tree_status,*(uint32_t*)DB_NO_SPILLING);
	if(handle->db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
			memcmp(handle->db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0){

		//#if LOG_WITH_MUTEX
		//		MUTEX_LOCK(&handle->db_desc->lock_log);
		//#else
		//		SPIN_LOCK(&handle->db_desc->lock_log);
		//#endif


		/*wait for L0 writers to complete*/
		spin_loop(&handle->db_desc->count_writers_level_0,0);
		
		/*Acquire guard lock*/
		if(RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock) !=0){
			DPRINT("ERROR locking guard\n");
			exit(EXIT_FAILURE);
		}
		/*double check*/
		if(handle->db_desc->zero_level_memory_size >=  (uint64_t)ZERO_LEVEL_MEMORY_SPILL_THREASHOLD &&
				memcmp(handle->db_desc->tree_status,DB_NO_SPILLING,NUM_OF_TREES_PER_LEVEL) == 0){

			DPRINT("MASTER: Yeahp time for a spill!\n");
			/******   let's create the spill task   *******/
			for(i=0;i<NUM_OF_TREES_PER_LEVEL;i++){

				if(i!= handle->db_desc->active_tree && handle->db_desc->tree_status[i] == NO_SPILLING){

					desc = (spill_task_descriptor *)malloc(sizeof(spill_task_descriptor));
					to_spill_tree_id = handle->db_desc->active_tree;
					handle->db_desc->tree_status[to_spill_tree_id] = SPILLING_IN_PROGRESS;
					handle->db_desc->active_tree = i;
					assert(handle->db_desc->root_w[i] == NULL && handle->db_desc->root_w[i] == NULL);
					/*initialize spill task descriptor*/
					desc->spill_req.db_desc = handle->db_desc;
					desc->spill_req.volume_desc = handle->volume_desc;

					if(handle->db_desc->root_w[to_spill_tree_id]!=NULL){
						desc->spill_req.src_root = handle->db_desc->root_w[to_spill_tree_id];
					}
					else{
						desc->spill_req.src_root = handle->db_desc->root_r[to_spill_tree_id];
					}
					desc->spill_req.src_tree_id = to_spill_tree_id;
					desc->spill_req.dst_tree_id = NUM_OF_TREES_PER_LEVEL;
					desc->spill_req.l0_start = handle->db_desc->L0_start_log_offset;
					desc->spill_req.l0_end = handle->db_desc->L0_end_log_offset;
					desc->spill_req.start_key = NULL;
					desc->spill_req.end_key = NULL;
					desc->spill_req.db_desc = NULL;
					desc->spill_req.volume_desc = NULL;
					desc->standalone = 0;
					desc->region = NULL;
					handle->db_desc->count_active_spillers = 1;
					region->status = REGION_IN_TRANSITION;
					/*note for the line above region will be ok after replica has send SPIL_INIT_ACK*/
					DPRINT("Spilling tree id %d to dest tree id %d\n",desc->spill_req.src_tree_id,desc->spill_req.dst_tree_id);
					break;
				}
			}
			/*this means that we did not find an empty tree in L0, FATAL*/
			assert(desc != NULL);
			goto unlock;
		}
		else{
			/*someone else triggered it already*/
			goto unlock;
		}
	}
	else{
		/*no spill needed*/
		return NULL;
	}

unlock:
	//#if LOG_WITH_MUTEX
	//	MUTEX_UNLOCK(&handle->db_desc->lock_log);
	//#else
	//	SPIN_UNLOCK(&handle->db_desc->lock_log);
	//#endif
	/*unlock guard*/
	if(RWLOCK_UNLOCK(&handle->db_desc->guard_level_0.rx_lock) !=0){
		DPRINT("ERROR locking\n");
		exit(EXIT_FAILURE);
	}
	return desc;
}



void kreonR_spill_worker(void * _spill_task_desc)
{
	kv_location location;
	spill_task_descriptor * spill_task_desc = (spill_task_descriptor *)_spill_task_desc;
	tu_data_message_s *msg = NULL;
	tu_data_message_s *spill_buffer_msg = NULL;
	void *spill_buffer;
	uint64_t log_addr;
	tu_data_message_s *reply = NULL;
	level_scanner * level_sc = NULL;

	void * free_addr;
	uint64_t size;
	void * addr;
	uint32_t region_key_len;
	uint32_t keys_batch_to_spill;
	uint32_t num_of_spilled_keys;
	int i;
	int rc;

	while(1){

		switch (spill_task_desc->spill_task_status){

			case SEND_SPILL_INIT:

				assert(spill_task_desc->standalone == 0);
				DPRINT("MASTER: Sending spill init to replica\n");

				region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;
				msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con, 28 + region_key_len, SPILL_INIT,ASYNCHRONOUS, 0, &spill_task_desc->task);
				if(spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS){
					DPRINT("allocation rollback\n");
					if(pthread_yield()!= 0){
						DPRINT("FATAL yield failed\n");
					}
					break;
				}
				/*reset the status flag for subsequent operations*/
				spill_task_desc->task.allocation_status = ALLOCATION_START;

				addr = msg->data;
				/*command */
				*(uint32_t *)addr = region_key_len;
				addr += sizeof(int32_t);
				/*region key for replica to locate the corresponding region*/
				memcpy(addr, spill_task_desc->region->ID_region.minimum_range+sizeof(uint32_t),region_key_len);
				addr += region_key_len;
				/*L0 start*/
				*(uint64_t *)addr = spill_task_desc->spill_req.l0_start;
				addr += sizeof(uint64_t);
				/*L0 end*/
				*(uint64_t *)addr =spill_task_desc->spill_req.l0_end;
				addr += sizeof(uint64_t);
				/*total keys to spill*/
				DPRINT("keys from L0 tree with id: %d to spill are are %llu\n",spill_task_desc->spill_req.src_tree_id, 
						(LLU)spill_task_desc->region->db->db_desc->total_keys[spill_task_desc->spill_req.src_tree_id]);
				*(uint64_t *)addr = spill_task_desc->region->db->db_desc->total_keys[spill_task_desc->spill_req.src_tree_id];
				addr += sizeof(uint64_t);
				msg->next = addr;
				msg->request_message_local_addr = msg;/*info to spinning thread to wake us up on reply*/
				msg->reply_message = NULL;
				if(send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) != KREON_SUCCESS){
					DPRINT("FATAL failed message\n");
					exit(EXIT_FAILURE);
				}
				DPRINT("Sent spill init command to replica to region: %s payload len %u waiting for reply...\n",
						spill_task_desc->region->ID_region.minimum_range+4, 24 + region_key_len);
				spill_task_desc->spill_task_status = WAIT_FOR_SPILL_INIT_REPLY;
				break;

			case WAIT_FOR_SPILL_INIT_REPLY:

				if(msg->reply_message == NULL){
					if(pthread_yield()!= 0){
						DPRINT("FATAL yield failed\n");
					}
					break;
				}
				reply = (tu_data_message_s *)msg->reply_message;

				if(reply->error_code == KREON_OK){
					DPRINT("MASTER: Replica ready to participate in spill :-)\n");
				}
				else if(reply->error_code == REPLICA_PENDING_SPILL){
					DPRINT("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
					exit(EXIT_FAILURE);	
				} else {
					DPRINT("FATAL Unknown code\n");
					raise(SIGINT);
					exit(EXIT_FAILURE);
				}
				free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
				spill_task_desc->spill_task_status = INIT_SPILL_BUFFER_SCANNER;
				DPRINT("MASTER: got SPILL_INIT reply!\n");
				break;

			case INIT_SPILL_BUFFER_SCANNER:

				DPRINT("MASTER: INIT_SPILL_BUFFER_SCANNER!\n");
				level_sc = _init_spill_buffer_scanner(spill_task_desc->region->db, 
						spill_task_desc->spill_req.src_root,spill_task_desc->spill_req.start_key);

				assert(level_sc != NULL);
				keys_batch_to_spill = (SPILL_BUFFER_SIZE-(2*sizeof(uint32_t)))/(PREFIX_SIZE + sizeof(uint64_t));
				spill_task_desc->spill_task_status = SPILL_BUFFER_REQ;
				break;

			case SPILL_BUFFER_REQ:

				if(!spill_task_desc->standalone){
					/*allocate buffer*/
					spill_buffer_msg= __allocate_rdma_message(spill_task_desc->region->replica_next_control_con, SPILL_BUFFER_SIZE, SPILL_BUFFER_REQUEST,ASYNCHRONOUS, 0, &spill_task_desc->task);
					if(spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS){
						if(pthread_yield()!= 0){
							DPRINT("FATAL yield failed\n");
						}
						break;
					}
					spill_buffer = spill_buffer_msg->data;
					spill_buffer += sizeof(uint32_t);/*keep 4 bytes for num of entries*/
					/*reset the status flag for subsequent operations*/
					spill_task_desc->task.allocation_status = ALLOCATION_START;
				}
				num_of_spilled_keys = 0;
				for(i = 0; i < keys_batch_to_spill; i++){
					location.kv_addr = level_sc->keyValue;
					location.log_offset = 0;/*unused*/

					_insert_index_entry(spill_task_desc->region->db, &location, INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (spill_task_desc->spill_req.dst_tree_id << 8) | SPILL_OPERATION);

					if(!spill_task_desc->standalone){
						/*for the replica prefix*/
						memcpy(spill_buffer,  level_sc->keyValue, PREFIX_SIZE);
						spill_buffer += PREFIX_SIZE;
						/*relative log address*/
						log_addr = (*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE)) - MAPPED;
						memcpy(spill_buffer,&log_addr, sizeof(uint64_t));
						spill_buffer += sizeof(uint64_t);
						++num_of_spilled_keys;
					}

					rc = _get_next_KV(level_sc);
					if(rc == END_OF_DATABASE){
						if(!spill_task_desc->standalone){
							spill_task_desc->spill_task_status = SEND_SPILL_COMPLETE;
							break;
						}
						else {
							spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
							break;
						}
					}
				}

				if(!spill_task_desc->standalone){
					*(uint32_t *)spill_buffer_msg->data = num_of_spilled_keys;
					if(send_rdma_message(spill_task_desc->region->replica_next_control_con, spill_buffer_msg) != KREON_SUCCESS){
						DPRINT("FATAL failed message\n");
						exit(EXIT_FAILURE);
					} else {
						//DPRINT("MASTER: Just send buffer for spill with keys %d\n",num_of_spilled_keys);
					}
				}

				break;

			case CLOSE_SPILL_BUFFER:

				_close_spill_buffer_scanner(level_sc, spill_task_desc->spill_req.src_root);
				/*sanity check
					if(spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
					printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
					exit(EXIT_FAILURE);
					}
					*/

				/*Clean up code, Free the buffer tree was occupying. free_block() used intentionally*/
				__sync_fetch_and_sub(&spill_task_desc->region->db->db_desc->count_active_spillers,1);
				assert(spill_task_desc->region->db->db_desc->count_active_spillers == 0);
				if(spill_task_desc->region->db->db_desc->count_active_spillers == 0){

					DPRINT("MASTER: spill completed freeing up level 0\n");
					free_addr = (void *)spill_task_desc->region->db->db_desc->segments[spill_task_desc->spill_req.src_tree_id*3];
					size = spill_task_desc->region->db->db_desc->segments[(spill_task_desc->spill_req.src_tree_id*3)+1];
					while(1){
						if(size != BUFFER_SEGMENT_SIZE){
							DPRINT("FATAL corrupted segment size %llu should be %llu\n",(LLU)size,(LLU)BUFFER_SEGMENT_SIZE);
							exit(EXIT_FAILURE);
						}
						uint64_t s_id = ((uint64_t)free_addr - (uint64_t)spill_task_desc->region->db->volume_desc->bitmap_end)/BUFFER_SEGMENT_SIZE;
						//printf("[%s:%s:%d] freeing %llu size %llu s_id %llu freed pages %llu\n",__FILE__,__func__,__LINE__,(LLU)free_addr,(LLU)size,(LLU)s_id,(LLU)handle->volume_desc->segment_utilization_vector[s_id]);
						if(spill_task_desc->region->db->volume_desc->segment_utilization_vector[s_id]!= 0 && 
								spill_task_desc->region->db->volume_desc->segment_utilization_vector[s_id] < SEGMENT_MEMORY_THREASHOLD){

							//printf("[%s:%s:%d] last segment remains\n",__FILE__,__func__,__LINE__);
							/*dimap hook, release dram frame*/
							/*if(dmap_dontneed(FD, ((uint64_t)free_addr-MAPPED)/PAGE_SIZE, BUFFER_SEGMENT_SIZE/PAGE_SIZE)!=0){
								printf("[%s:%s:%d] fatal ioctl failed\n",__FILE__,__func__,__LINE__);
								exit(-1);
								}
								__sync_fetch_and_sub(&(handle->db_desc->zero_level_memory_size), (unsigned long long)handle->volume_desc->segment_utilization_vector[s_id]*4096);
								*/
							spill_task_desc->region->db->volume_desc->segment_utilization_vector[s_id] = 0;
						}
						free_block(spill_task_desc->region->db->volume_desc, free_addr, size, -1);
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
					spill_task_desc->region->db->db_desc->total_keys[spill_task_desc->spill_req.src_tree_id] = 0;
					spill_task_desc->region->db->db_desc->segments[spill_task_desc->spill_req.src_tree_id*3] = 0;
					spill_task_desc->region->db->db_desc->segments[(spill_task_desc->spill_req.src_tree_id*3)+1] = 0;
					spill_task_desc->region->db->db_desc->segments[(spill_task_desc->spill_req.src_tree_id*3)+2] = 0;
					spill_task_desc->region->db->db_desc->root_r[spill_task_desc->spill_req.src_tree_id] = NULL;
					spill_task_desc->region->db->db_desc->root_w[spill_task_desc->spill_req.src_tree_id] = NULL;
					//db_desc->spilled_keys=0;
					/*XXX TODO XXX REMOVE*/
					spill_task_desc->region->db->db_desc->zero_level_memory_size=0;
					spill_task_desc->region->db->db_desc->tree_status[spill_task_desc->spill_req.src_tree_id] = NO_SPILLING;
					spill_task_desc->region->db->db_desc->L0_start_log_offset = spill_task_desc->spill_req.l0_end;
				}
				free(spill_task_desc);
				DPRINT("MASTER spill finished and cleaned L0 remains\n");
				return;

			case SEND_SPILL_COMPLETE:
				assert(spill_task_desc->region->replica_next_control_con != NULL);

				region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;

				msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con, 20 + region_key_len, SPILL_COMPLETE,ASYNCHRONOUS, 0, &spill_task_desc->task);
				if(spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS){
					if(pthread_yield()!= 0){
						DPRINT("FATAL yield failed\n");
					}
					break;
				}

				DPRINT("MASTER: Sending SPILL_COMPLETE message to REPLICA\n");
				spill_task_desc->task.allocation_status = ALLOCATION_START;

				addr = msg->data;
				*(uint32_t *)addr = region_key_len;
				addr += sizeof(int32_t);
				memcpy(addr,spill_task_desc->region->ID_region.minimum_range+sizeof(uint32_t),region_key_len);
				addr += region_key_len;
				*(uint64_t *)addr = spill_task_desc->spill_req.l0_start;
				addr += sizeof(uint64_t);
				*(uint64_t *)addr = spill_task_desc->spill_req.l0_end;
				addr += sizeof(uint64_t);
				msg->next = addr;
				msg->request_message_local_addr = msg;
				msg->reply_message = NULL;
				if(send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) != KREON_SUCCESS){
					DPRINT("FATAL to send spill complete message\n");
					exit(EXIT_FAILURE);
				}
				spill_task_desc->spill_task_status = WAIT_FOR_SPILL_COMPLETE_REPLY;
				break;

			case WAIT_FOR_SPILL_COMPLETE_REPLY:
				//DPRINT("MASTER: Waiting for SPILL_COMPLETE reply\n");
				if(msg->reply_message == NULL){
					if(pthread_yield()!= 0){
						DPRINT("FATAL yield failed\n");
					}
					break;
				}
				reply = (tu_data_message_s *)msg->reply_message;

				if(reply == NULL){
					DPRINT("FATAL reply to spill buffer request is NULL\n");
					exit(EXIT_FAILURE);
				}

				if(reply->error_code == KREON_OK){
					DPRINT("Replica completed remote spill\n");
					free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
					spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
					/*DO THE CLEANINING HERE, and exit thread*/
					DPRINT("Master: Replica informed that it finished its spill\n");
					break;
				}
				else if(reply->error_code == REPLICA_PENDING_SPILL){
					DPRINT("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
					exit(EXIT_FAILURE);
				}
				else{
					DPRINT("Unknown spill completion code\n");
					exit(EXIT_FAILURE);
				}
			default:
				DPRINT("FATAL unkown state for spill task\n");
				exit(EXIT_FAILURE);
		}
	}
}



#ifdef TIERING
void tiering_compaction_check(_tucana_region_S* region, int level_id)
{
	tiering_compaction_request * request;
	db_descriptor * db_desc = region->db->db_desc;
	int level_max_capacity = 4;
	int level_size = 0;
	int i;

	/*check if level 1 capacity is full*/
	for(i=0;i<level_max_capacity;i++){
		if(db_desc->replica_forest.tree_roots[(level_id * level_max_capacity)+i]!= NULL){
			++level_size;
		}
	}

	if(level_size >= level_max_capacity){
		request = (tiering_compaction_request *)malloc(sizeof(tiering_compaction_request));
		request->region = region;
		request->level_id = 0;
		DPRINT("REPLICA: Time for a tiering compaction\n");
		db_desc->db_mode = BACKUP_DB_TIERING_COMPACTION;   
		pthread_setname_np(request->tiering_compaction_context,"replica_tiering_worker");
		if(pthread_create(&request->tiering_compaction_context,NULL,(void *)tiering_compaction_worker, (void *)request)!=0){
			DPRINT("FATAL: error spawning tiering compaction worker\n");
			exit(EXIT_FAILURE);
		}
	}
}




void tiering_compaction_worker(void * _tiering_request)
{
	
	tiering_compaction_request *request;
	min_heap * heap = create_and_initialize_heap(TIERING_MAX_CAPACITY);
	min_heap_node node;
	uint64_t total_keys_to_compact; 
	uint64_t actual_compacted_keys;
	int destination_tree_id;
	int i;
	int rc;
	int scanner_id;
	int empty_scanners_num = 0;

	request = (tiering_compaction_request *)_tiering_request;

	level_scanner ** scanners = (level_scanner **)alloca(sizeof(level_scanner *)*TIERING_MAX_CAPACITY);
	total_keys_to_compact = 0;
	actual_compacted_keys = 0;

	for(i=0;i<TIERING_MAX_CAPACITY;i++){
		total_keys_to_compact += 
			request->region->db->db_desc->replica_forest.total_keys_per_tree[(request->level_id * TIERING_MAX_CAPACITY)+i];
				scanners[i] = _init_spill_buffer_scanner(request->region->db, 
						request->region->db->db_desc->replica_forest.tree_roots[(request->level_id * TIERING_MAX_CAPACITY)+i],NULL);
				add_to_min_heap(heap, scanners[i]->keyValue,KV_PREFIX,(request->level_id * TIERING_MAX_CAPACITY)+i);
	}
	/*now find an available tree in the id+1 level*/
	destination_tree_id = -1;
	for(i=0;i<TIERING_MAX_CAPACITY;i++){
		if(request->region->db->db_desc->replica_forest.tree_roots[((request->level_id+1) * TIERING_MAX_CAPACITY)+i] == NULL){
			destination_tree_id = ((request->level_id+1) * TIERING_MAX_CAPACITY)+i;
			break;
		}
	}
	assert(destination_tree_id != -1);
	
	DPRINT("REPLICA: Tiering compaction from level %d to level %d number of keys to compact = %"PRIu64"\n",
			request->level_id, request->level_id+1,total_keys_to_compact);
	_calculate_btree_index_nodes(request->region, total_keys_to_compact);

	while(empty_scanners_num > 0){

		node = pop_min(heap);
		++actual_compacted_keys;
		append_entry_to_leaf_node(request->region,node.keyValue+PREFIX_SIZE, node.keyValue,destination_tree_id);
		scanner_id = node.tree_id - (request->level_id * TIERING_MAX_CAPACITY);
		rc = _get_next_KV(scanners[scanner_id]);
		if(rc == END_OF_DATABASE){
			scanners[scanner_id] = NULL;
			++empty_scanners_num;
		}
	}
	assert(actual_compacted_keys == total_keys_to_compact);
	request->region->db->db_desc->replica_forest.tree_status[destination_tree_id] = READY_TO_PERSIST;
	DPRINT("REPLICA: Tiering compaction from level to level maybe a snapshot now? XXX TODO XXX\n");
	request->region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;

	tiering_compaction_check(request->region, request->level_id+1);
	free(_tiering_request);
}
#endif


int _init_replica_rdma_connections(struct _tucana_region_S *S_tu_region)
{
	


	if(S_tu_region->n_replicas > 1 && S_tu_region->replica_next_data_con == NULL){

		if(S_tu_region->db->db_desc->db_mode != PRIMARY_DB){
			DPRINT("\n\t\t\tNot the primary let the primary init the connections\n");
			return KREON_SUCCESS;
		}
		if(!S_tu_region->replica_next_net){
			DPRINT("FATAL uninitialized _server_tu_network_data structure for region %u\n",S_tu_region->ID_region.ID);
			exit(EXIT_FAILURE);
		}

		if(!S_tu_region->replica_next_net->IPs) {
			DPRINT("Uninitialized replica_next_net->IPs field\n");
		}

		DPRINT("MASTER: Creating replica connections for region range %s\n", S_tu_region->ID_region.minimum_range+4);

		S_tu_region->replica_next_data_con = crdma_client_create_connection_list_hosts(regions_S.channel,S_tu_region->replica_next_net->IPs, 
				S_tu_region->replica_next_net->num_NICs, MASTER_TO_REPLICA_CONNECTION);
		S_tu_region->replica_next_data_con->priority = HIGH_PRIORITY;
		S_tu_region->db->db_desc->data_conn = &S_tu_region->replica_next_data_con; 
		DPRINT("MASTER: replica data connection created successfuly = %llu\n", (LLU)S_tu_region->replica_next_data_con);

		DPRINT("MASTER: Creating control connection for region range %s\n", S_tu_region->ID_region.minimum_range+4);
		S_tu_region->replica_next_control_con = crdma_client_create_connection_list_hosts(regions_S.channel,
				S_tu_region->replica_next_net->IPs, S_tu_region->replica_next_net->num_NICs, MASTER_TO_REPLICA_CONNECTION);
		S_tu_region->replica_next_control_con->priority = HIGH_PRIORITY;
		DPRINT("MASTER: replica control connection created successfuly = %llu\n",(LLU)S_tu_region->replica_next_control_con);
		/*allocate remote log buffer*/
		DPRINT("MASTER: Allocating and initializing remote log buffer\n");
		//S_tu_region->db->db_desc->log_buffer = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, BUFFER_SEGMENT_SIZE+4096, FLUSH_SEGMENT); 
		S_tu_region->db->db_desc->log_buffer = S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer;

		tu_data_message_s * tmp = (tu_data_message_s *)S_tu_region->db->db_desc->log_buffer;

		/*init message*/
		tmp->pay_len = 4096+BUFFER_SEGMENT_SIZE; 
		tmp->padding_and_tail = RDMA_LOG_BUFFER_PADDING+TU_TAIL_SIZE;//???
		DPRINT("TOTAL LOG BUFFER SIZE %d Padding %d\n", RDMA_TOTAL_LOG_BUFFER_SIZE, RDMA_LOG_BUFFER_PADDING);
		tmp->data = (void *)((uint64_t)tmp + TU_HEADER_SIZE);
		tmp->next = tmp->data;
		tmp->receive = TU_RDMA_REGULAR_MSG;
		/*set the tail to the proper value*/
		*(uint32_t *)((uint64_t)tmp + TU_HEADER_SIZE + 4096 + BUFFER_SEGMENT_SIZE + RDMA_LOG_BUFFER_PADDING) = TU_RDMA_REGULAR_MSG;
		tmp->type =	FLUSH_SEGMENT;
		tmp->flags = SERVER_CATEGORY;

		tmp->local_offset = 0;
		tmp->remote_offset = 0;

		tmp->ack_arrived = REPLY_PENDING;
		tmp->callback_function = NULL;
		tmp->request_message_local_addr = NULL;
		__sync_fetch_and_add(&S_tu_region->replica_next_data_con->pending_sent_messages,1);
		/*set connection propeties with the replica
		 *	1. pin data and control conn to high priority
		 *	2. Reduce memory for control conn
		 */
		/*
			 DPRINT("Setting connection properties with the Replica");
			 set_connection_property_req * req;
			 tu_data_message_s * data_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST); 
			 req = (set_connection_property_req *)data_conn_req->data;
			 req->desired_priority_level = HIGH_PRIORITY;
			 req->desired_RDMA_memory_size = DEFAULT_MEMORY_SIZE_OPTION;
			 data_conn_req->request_message_local_addr = (void *)data_conn_req;	
			 send_rdma_message(*S_tu_region->db->db_desc->data_conn, data_conn_req);
			 int i = 0;
			 while(data_conn_req->ack_arrived != REPLY_ARRIVED){
			 if(++i%100000 == 0){
			 DPRINT("Waiting for the remote side to pin my connection\n");
			 }
			 }

			 tu_data_message_s * control_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST); 
			 req = (set_connection_property_req *)control_conn_req->data;
			 req->desired_priority_level = HIGH_PRIORITY;
			 req->desired_RDMA_memory_size = CONTROL_CONNECTION_MEMORY_SIZE;

			 control_conn_req->request_message_local_addr = (void *)control_conn_req;	
			 send_rdma_message(*S_tu_region->db->db_desc->data_conn, control_conn_req);
			 i = 0;
			 while(control_conn_req->ack_arrived != REPLY_ARRIVED){
			 if(++i%100000 == 0){
			 DPRINT("Waiting for the remote side to pin my connection\n");
			 }
			 }
			 DPRINT("Setting connection properties with the Replica ... DONE");
			 */
	} 
	else
		S_tu_region->db->db_desc->data_conn = NULL;
	return KREON_SUCCESS;
}



/*
 * This functions handle PUT_QUERY requests which contain a single key value
 * put operation task states that this function must handle
 INITIAL_STATE
 WAIT_FOR_REPLICA_TO_FLUSH_REGION
 WAIT_FOR_REPLICA_CONNECTION_TO_RESET
 CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK
 CHECK_FOR_REPLICA_RESET_BUFFER_ACK
 APPEND_SUCCESS
 */
void append_and_insert_kv_pair(_tucana_region_S* S_tu_region, tu_data_message_s *data_message,
		connection_rdma *rdma_conn, 
		kv_location * location,
		work_task *task, 
		int wait)
{

	tu_data_message_s * tmp;
	spill_task_descriptor * desc;
	char *key;
	segment_header * s_header;
	void *key_addr;/*address at the device*/
	//void *data_addr;/*address at the device*/
	void * key_addr_in_log_buffer = NULL;
	//void * data_addr_in_log_buffer;
	void * addr;
	uint32_t key_length;
	uint32_t value_length;
	uint32_t kv_size;
	uint32_t available_space_in_log;
	uint32_t allocated_space;
	uint32_t position_in_the_segment;
	uint64_t rdma_source_offset;
	void * rdma_source;
	uint32_t rdma_length;
	int tries;
	int spill_check = 0;
	/**/

	key = data_message->data;
	key_length = *(uint32_t*)key;	

	value_length = *(uint32_t *)(key+sizeof(uint32_t)+key_length);
	kv_size = (2*sizeof(uint32_t)) + key_length + value_length;
	location->rdma_key = rdma_conn->rdma_memory_regions->remote_memory_region->lkey;


	/*check here for returning fast (optimization)*/
	if(task->kreon_operation_status == APPEND_START && S_tu_region->status != REGION_OK){
		//DPRINT("Back off %d for region %s task %llu\n",S_tu_region->status, S_tu_region->db->db_desc->db_name,(LLU)task);
		return;
	}

#if LOG_WITH_MUTEX
	MUTEX_LOCK(&S_tu_region->db->db_desc->lock_log);
#else
	SPIN_LOCK(&S_tu_regtion->db->db_desc->lock_log);
#endif

	/*double check*/
	if(task->kreon_operation_status == APPEND_START && S_tu_region->status != REGION_OK){
		//DPRINT("Back off %d for region %s task %llu \n",S_tu_region->status, S_tu_region->db->db_desc->db_name, (LLU)task);
#if LOG_WITH_MUTEX
		MUTEX_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#else
		SPIN_UNLOCK(&S_tu_regtion->db->db_desc->lock_log);
#endif
		return;
	}

	/*############## fsm state logic follows ###################*/
	while(1){
		switch(task->kreon_operation_status){
			case APPEND_START:

				if(S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0)
					available_space_in_log = BUFFER_SEGMENT_SIZE-(S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
				else
					available_space_in_log = 0;

				/*do we have enough space in  the current segment?*/
				if(available_space_in_log < kv_size){

					/*pad with zeroes remaining bytes in segment*/
					key_addr = (void*)((uint64_t)S_tu_region->db->db_desc->KV_log_last_segment+(S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
					memset(key_addr,0x00,available_space_in_log);

					if (S_tu_region->replica_next_data_con != NULL){

						key_addr_in_log_buffer = S_tu_region->db->db_desc->log_buffer + 4096 + (S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
						memset(key_addr_in_log_buffer,0x00,available_space_in_log);
						S_tu_region->status = REGION_IN_TRANSITION;
						/*some things to keep before changing segment*/
						position_in_the_segment = S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0
							?S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE:BUFFER_SEGMENT_SIZE;

						assert(S_tu_region->db->db_desc->latest_proposal_start_segment_offset <= position_in_the_segment); 

						/*1. RDMA possible remains to the remote side, does not block*/
						rdma_kv_entry_to_replica(S_tu_region->replica_next_data_con, 
								S_tu_region->db->db_desc->log_buffer,
								S_tu_region->db->db_desc->latest_proposal_start_segment_offset,
								S_tu_region->db->db_desc->log_buffer + 4096 + S_tu_region->db->db_desc->latest_proposal_start_segment_offset,
								position_in_the_segment - S_tu_region->db->db_desc->latest_proposal_start_segment_offset,
								S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_region->lkey);
						/*
							 DPRINT("Sending remains latest proposal %llu position in the segment %llu size %llu\n",
							 (LLU)handle->db_desc->latest_proposal_start_segment_offset, (LLU)position_in_the_segment,
							 (LLU)position_in_the_segment - handle->db_desc->latest_proposal_start_segment_offset);
							 */
						addr = ((tu_data_message_s *)S_tu_region->db->db_desc->log_buffer)->data;
						/*first 4KB are segment metadata*/
						*(uint64_t *)addr = (uint64_t)S_tu_region->db->db_desc->KV_log_last_segment-MAPPED;
						//DPRINT(master current log segment = %llu\n",(uint64_t)handle->db_desc->KV_log_last_segment-MAPPED);
						*(uint64_t *)(addr + sizeof(uint64_t)) =  S_tu_region->db->db_desc->KV_log_size + available_space_in_log;
						//DPRINT("end of log = %llu\n",handle->db_desc->KV_log_size + available_space_in_log);
						*(uint64_t *)(addr + (2*sizeof(uint64_t))) = available_space_in_log;

						*(uint64_t *)(addr + (3*sizeof(uint64_t))) = S_tu_region->db->db_desc->KV_log_last_segment->segment_id;
						//DPRINT("segment id = %llu for db %s\n", (LLU)S_tu_region->db->db_desc->KV_log_last_segment->segment_id, S_tu_region->db->db_desc->db_name);
						/*base region key*/
						memcpy(addr + (4*sizeof(uint64_t)), S_tu_region->db->db_desc->region_min_key, 4+*(uint32_t *)S_tu_region->db->db_desc->region_min_key);	

						/*wake up replica, count the FLUSH_SEGMENT MSG*/
						++S_tu_region->replica_next_data_con->FLUSH_SEGMENT_requests_sent;
						/*Do we need to send a FLUSH_SEGMENT OR a FLUSH_SEGMENT_AND_RESET?*/
						if( S_tu_region->replica_next_data_con->rdma_memory_regions->memory_region_length 
								- (uint64_t)S_tu_region->replica_next_data_con->offset < 2*RDMA_TOTAL_LOG_BUFFER_SIZE){
							//DPRINT("Master: not enough space REPLICA flush and reset please recv set to %d\n",((tu_data_message_s *)S_tu_region->db->db_desc->log_buffer)->receive);
							((tu_data_message_s *)S_tu_region->db->db_desc->log_buffer)->type = FLUSH_SEGMENT_AND_RESET;
						} else {
							//DPRINT("Master: not enough space REPLICA JUST flush\n");
							((tu_data_message_s *)S_tu_region->db->db_desc->log_buffer)->type = FLUSH_SEGMENT;
						}
						wake_up_replica_to_flush_segment(S_tu_region->replica_next_data_con, S_tu_region->db->db_desc->log_buffer, wait);


						/*done waking up replica*/		
						S_tu_region->db->db_desc->latest_proposal_start_segment_offset = 0; 

						if(wait == WAIT_REPLICA_TO_COMMIT){
							/*mark regions in waiting state for others*/
							task->flush_segment_request = S_tu_region->db->db_desc->log_buffer;
							S_tu_region->db->db_desc->log_buffer = NULL;
							task->kreon_operation_status = CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK;
						} else {	
							/*allocate new log buffer*/
							task->kreon_operation_status = ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA;
							task->allocation_status = ALLOCATION_START; 
						}
					}  else {
						/*standalone mode, it will check if a spill is needed and then spawn the spiler*/
						task->kreon_operation_status = PERFORM_SPILL_CHECK;
						task->allocation_status = ALLOCATION_START; 
					}
					/*allocate new segment got the log*/
					allocated_space = kv_size + sizeof(segment_header);
					allocated_space +=  BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
					/*this allocate() is left intentionally. KV log allocates space only from allocator*/
					s_header = (segment_header *)allocate_segment(S_tu_region->db,allocated_space,KV_LOG_ID, KV_LOG_EXPANSION);
					memset(s_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
					s_header->next_segment = NULL;
					s_header->prev_segment = (segment_header *)((uint64_t)S_tu_region->db->db_desc->KV_log_last_segment - MAPPED);
					S_tu_region->db->db_desc->KV_log_last_segment->next_segment = (void *)((uint64_t)s_header - MAPPED);
					S_tu_region->db->db_desc->KV_log_size += (available_space_in_log + sizeof(segment_header)); /* position the log to the newly added block */

					s_header->segment_id = S_tu_region->db->db_desc->KV_log_size/BUFFER_SEGMENT_SIZE;

					assert(s_header->segment_id == (S_tu_region->db->db_desc->KV_log_last_segment->segment_id+1));
					S_tu_region->db->db_desc->KV_log_last_segment = s_header;

					break;/*To the appropriate fsm state*/
				}
				/* always in this path, PRIMARY_L0_INSERT */
				__sync_fetch_and_add(&S_tu_region->db->db_desc->count_writers_level_0, 1);
				location->log_offset = S_tu_region->db->db_desc->KV_log_size;

				key_addr = (void*)((uint64_t)S_tu_region->db->db_desc->KV_log_last_segment+(S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE));
				//data_addr = (void *)((uint64_t)key_addr + sizeof(uint32_t) + key_length);

				if(S_tu_region->replica_next_data_con != NULL){
					key_addr_in_log_buffer = S_tu_region->db->db_desc->log_buffer + 4096 + (S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE);
					/*put in the log buffer for sending to the replicas*/
					memcpy(key_addr_in_log_buffer,key, kv_size);
				}

				S_tu_region->db->db_desc->KV_log_size += kv_size;

				if(S_tu_region->replica_next_data_con != NULL){

					/*is log_segment_chunk full? Actual RDMA happens in the lines below not here!*/
					position_in_the_segment = S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE != 0
						?S_tu_region->db->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE :BUFFER_SEGMENT_SIZE;

					assert(S_tu_region->db->db_desc->latest_proposal_start_segment_offset <= position_in_the_segment); 

					if(position_in_the_segment - S_tu_region->db->db_desc->latest_proposal_start_segment_offset >= LOG_SEGMENT_CHUNK){
						/*Time to sent a proposal to the replica*/
						rdma_source_offset = S_tu_region->db->db_desc->latest_proposal_start_segment_offset;
						rdma_source = S_tu_region->db->db_desc->log_buffer + 4096 + S_tu_region->db->db_desc->latest_proposal_start_segment_offset;
						rdma_length = position_in_the_segment - S_tu_region->db->db_desc->latest_proposal_start_segment_offset;
						S_tu_region->db->db_desc->latest_proposal_start_segment_offset = position_in_the_segment; 
						
						//DPRINT("Time to RDMA proposal %llu position in the segment %llu size %llu\n",
						//		(LLU)rdma_source_offset, (LLU)rdma_source%BUFFER_SEGMENT_SIZE,(LLU)rdma_length);
						rdma_kv_entry_to_replica(S_tu_region->replica_next_data_con,
								S_tu_region->db->db_desc->log_buffer,
								rdma_source_offset,
								rdma_source,
								rdma_length,
								S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_region->lkey);
					}
				}

#if LOG_WITH_MUTEX
				MUTEX_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#else
				SPIN_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#endif

#if !OMMIT_IO_IN_THE_INSERT_PATH
				/*In the device now*/
				memcpy(key_addr,key, kv_size);
				location->kv_addr = key_addr;
				/*insert to primary's index*/
				_insert_index_entry(S_tu_region->db, location, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG  | PRIMARY_L0_INSERT);
#endif
				task->kreon_operation_status = APPEND_COMPLETE;
				return;

				/*XXX TODO XXX this case has not yet tested by any tests*/
			case CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK:
				tries = 0;
				while(task->flush_segment_request->ack_arrived != 1){
					if(++tries >= NUM_OF_TRIES){
#if LOG_WITH_MUTEX
						MUTEX_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#else
						SPIN_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#endif
						return;
					}
				}
				task->kreon_operation_status = ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA;
				break;

			case ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA:

				/*old buffer that we ve already sent in the previous state*/
				tmp = (tu_data_message_s *)S_tu_region->db->db_desc->log_buffer;

				if(tmp->type == FLUSH_SEGMENT){
					//DPRINT("MASTER: no need to wait double buffering style Flush Commands sent %"PRIu64" Flush acks received %"PRIu64"\n",
					//		S_tu_region->replica_next_data_con->FLUSH_SEGMENT_requests_sent,S_tu_region->replica_next_data_con->FLUSH_SEGMENT_acks_received);
					/*No need to wait, double buffering style*/

					S_tu_region->replica_next_data_con->offset += RDMA_TOTAL_LOG_BUFFER_SIZE;

					S_tu_region->db->db_desc->log_buffer = (void *)((uint64_t)S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer 
							+S_tu_region->replica_next_data_con->offset);
					spill_check = 0;
				} 
				else if(tmp->type == FLUSH_SEGMENT_AND_RESET){
					spill_check = 1;
					tries = 0;
					while(S_tu_region->replica_next_data_con->FLUSH_SEGMENT_requests_sent != 
							S_tu_region->replica_next_data_con->FLUSH_SEGMENT_acks_received){

						if(++tries >= NUM_OF_TRIES){
#if LOG_WITH_MUTEX
							MUTEX_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#else
							SPIN_UNLOCK(&S_tu_regtion->db->db_desc->lock_log);
#endif
							return;
						}

					}
					S_tu_region->replica_next_data_con->offset = 0;
					S_tu_region->db->db_desc->log_buffer = (void *)S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer;
				}
				else{
					DPRINT("Unknown type FATAL");
					assert(0);
				}

				/*new buffer initialization*/
				tmp = (tu_data_message_s *)S_tu_region->db->db_desc->log_buffer;
				/*init message*/

				tmp->pay_len = 4096+BUFFER_SEGMENT_SIZE; 
				tmp->padding_and_tail = RDMA_LOG_BUFFER_PADDING+TU_TAIL_SIZE;//???
				tmp->data = (void *)((uint64_t)tmp + TU_HEADER_SIZE);
				tmp->next = tmp->data;
				tmp->receive = TU_RDMA_REGULAR_MSG;
				/*set the tail to the proper value*/
				*(uint32_t *)((uint64_t)tmp + TU_HEADER_SIZE + 4096 + BUFFER_SEGMENT_SIZE + RDMA_LOG_BUFFER_PADDING) = TU_RDMA_REGULAR_MSG;

				tmp->flags = SERVER_CATEGORY;

				tmp->local_offset = S_tu_region->replica_next_data_con->offset;
				tmp->remote_offset = S_tu_region->replica_next_data_con->offset;
				tmp->ack_arrived = REPLY_PENDING;
				tmp->callback_function = NULL;
				tmp->request_message_local_addr = NULL;
				__sync_fetch_and_add(&S_tu_region->replica_next_data_con->pending_sent_messages,1);
				if(spill_check){
					task->kreon_operation_status = PERFORM_SPILL_CHECK;
				}
				else{
					task->kreon_operation_status = APPEND_START;
					S_tu_region->status = REGION_OK;
				}
				task->allocation_status = ALLOCATION_START;
				break;

			case PERFORM_SPILL_CHECK:
				/*Finally, do we need a spill operation? returns !NULL if we need to spawn a spill worker*/
				desc = NULL;
				desc = kreonR_spill_check((_tucana_region_S *)task->region);
				if(desc != NULL){
					/*
					 * fill in appropriated fields, watch out spill_ckeck has already filled the encapsulated spill_request fields,
					 * wee need to fill the rest
					 * */
					desc->task.allocation_status = ALLOCATION_START;
					desc->region = task->region;
					if(desc->region->replica_next_control_con == NULL){
						DPRINT("Master Warning no Backup servers, just a local L0 spill :-)\n");
						desc->standalone = 1;
						desc->spill_task_status = INIT_SPILL_BUFFER_SCANNER;
					}
					else {

						desc->spill_task_status = SEND_SPILL_INIT;
						desc->standalone = 0;
					}

					if(pthread_create(&desc->spill_worker_context,NULL,(void *)kreonR_spill_worker, (void *)desc)!=0){
						DPRINT("FATAL: error creating spiller thread\n");
						exit(EXIT_FAILURE);
					}
					task->kreon_operation_status = WAIT_FOR_SPILL_START;
					task->intermediate_buffer = desc;
					break;
				} 
				else{
					S_tu_region->status = REGION_OK;
					task->kreon_operation_status = APPEND_START;
					break;
				}

			case WAIT_FOR_SPILL_START:
				tries = 0;
				desc = (spill_task_descriptor *)task->intermediate_buffer;
				while(desc->spill_task_status == SEND_SPILL_INIT || 
						desc->spill_task_status == WAIT_FOR_SPILL_INIT_REPLY){
					if(++tries > NUM_OF_TRIES){
#if LOG_WITH_MUTEX
						MUTEX_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#else
						SPIN_UNLOCK(&S_tu_region->db->db_desc->lock_log);
#endif
						return;
					}
				}
				S_tu_region->status = REGION_OK;
				task->kreon_operation_status = APPEND_START;
				break;

			case APPEND_COMPLETE:
			case ALLOCATION_START:
			case CHECK_FOR_RESET_BUFFER_ACK:
			case CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE:
			case	ALLOCATION_SUCCESS:
			case TASK_START:
			case TASK_COMPLETED:
			default:
				DPRINT("FATAL Ended up in faulty state\n");
				assert(0);
				return;
		}
	}
}



/*####################################################*/
/*functions for building efficiently index at replicas*/
void * _get_space_for_tree(_tucana_region_S *region, int32_t tree_id, int32_t size)
{
	void * addr; 
	segment_header * new_segment;
	uint64_t available_space; 
	assert(size % DEVICE_BLOCK_SIZE == 0 && size <= (BUFFER_SEGMENT_SIZE - sizeof(segment_header)));

	if(region->db->db_desc->replica_forest.tree_segment_list[tree_id] == NULL){
		region->db->db_desc->replica_forest.tree_segment_list[tree_id] = allocate(region->db->volume_desc, BUFFER_SEGMENT_SIZE, -1,  NEW_REPLICA_FOREST_TREE);
		region->db->db_desc->replica_forest.end_of_log[tree_id] = sizeof(segment_header);
		region->db->db_desc->replica_forest.tree_segment_list[tree_id]->next_segment = NULL;
		region->db->db_desc->replica_forest.tree_segment_list[tree_id]->prev_segment = NULL;
		DPRINT("Initialized new tree in the forest with id %d\n", tree_id);
	}

	/*check if we have enough space within the current segment*/
	if(region->db->db_desc->replica_forest.end_of_log[tree_id]%BUFFER_SEGMENT_SIZE == 0){
		available_space = 0;
	} else {
		available_space = BUFFER_SEGMENT_SIZE - (region->db->db_desc->replica_forest.end_of_log[tree_id]%BUFFER_SEGMENT_SIZE); 
	}

	if(available_space >= size){
		addr =  (void *)(uint64_t)region->db->db_desc->replica_forest.tree_segment_list[tree_id] + (region->db->db_desc->replica_forest.end_of_log[tree_id]%BUFFER_SEGMENT_SIZE);
		region->db->db_desc->replica_forest.end_of_log[tree_id]+=size;
	} else {
		//DPRINT("new segment needed for the tree\n");

		/*pad remaining remaining space*/
		region->db->db_desc->replica_forest.end_of_log[tree_id]+= (BUFFER_SEGMENT_SIZE - region->db->db_desc->replica_forest.end_of_log[tree_id]%BUFFER_SEGMENT_SIZE); 
		new_segment = (segment_header *)allocate(region->db->volume_desc, BUFFER_SEGMENT_SIZE, -1, SPACE_FOR_FOREST_TREE);
		region->db->db_desc->replica_forest.end_of_log[tree_id] += sizeof(segment_header);
		new_segment->next_segment = region->db->db_desc->replica_forest.tree_segment_list[tree_id];
		new_segment->prev_segment = NULL;
		region->db->db_desc->replica_forest.tree_segment_list[tree_id] = new_segment;
		addr =  (void *)(uint64_t)region->db->db_desc->replica_forest.tree_segment_list[tree_id] + (region->db->db_desc->replica_forest.end_of_log[tree_id]%BUFFER_SEGMENT_SIZE);
		region->db->db_desc->replica_forest.end_of_log[tree_id]+=size;
	}
	return addr; 
}  



node_header *_create_tree_node(_tucana_region_S *region, int tree_id, int node_height, int type)
{
	node_header * node = NULL;
	if(type == leafNode){
		node = (node_header *)_get_space_for_tree(region, tree_id, DEVICE_BLOCK_SIZE);
		node->type = leafNode;
		node->epoch = region->db->volume_desc->soft_superindex->epoch;
		node->numberOfEntriesInNode = 0;
		node->fragmentation = 0;
		node->v1 = 0;
		node->v2 = 0;
		node->first_IN_log_header = NULL;
		node->last_IN_log_header = NULL;
		node->key_log_size = 0;
		node->height = node_height;
	} else {
		node = (node_header *)_get_space_for_tree(region, tree_id, DEVICE_BLOCK_SIZE);
		node->type = internalNode;
		node->epoch = region->db->volume_desc->soft_superindex->epoch;
		node->numberOfEntriesInNode = 0;
		node->fragmentation = 0;
		node->v1 = 0;
		node->v2 = 0;
		node->first_IN_log_header = (IN_log_header *) ((uint64_t)_get_space_for_tree(region, tree_id, KEY_BLOCK_SIZE) - MAPPED);
		node->last_IN_log_header = node->first_IN_log_header;
		node->key_log_size = sizeof(IN_log_header);
		node->height = node_height;
	}
	return node;
}

void append_entry_to_leaf_node(_tucana_region_S *region,void * pointer_to_kv_pair, void *prefix, int32_t tree_id)
{
	node_header * new_node = NULL;
	uint64_t * pointers_to_kv_pairs;
	prefix_table * table;
	int entries_limit = leaf_order;

	/*debugging staff*/
	//if(*(uint32_t *)pointer_to_kv_pair > 30 || *(uint32_t *)pointer_to_kv_pair == 0){
	//	DPRINT("Faulty pointer size %"PRIu32"\n",*(uint32_t *)pointer_to_kv_pair);
	//	raise(SIGINT);
	//	exit(EXIT_FAILURE);
	//}

	if(region->cur_nodes_per_level[0] == 0 &&
			region->last_node_per_level[0] == NULL){

		region->last_node_per_level[0] =  _create_tree_node(region,tree_id,0,leafNode);
		++region->cur_nodes_per_level[0];
	}

	else if(region->num_of_nodes_per_level[0] > 1 && 
			(region->cur_nodes_per_level[0] == region->num_of_nodes_per_level[0] - 1)){
		entries_limit = region->entries_in_semilast_node[0];
	}

	else if(region->num_of_nodes_per_level[0] > 1 &&
			(region->cur_nodes_per_level[0] == region->num_of_nodes_per_level[0])){
		entries_limit = region->entries_in_last_node[0];
	}

	if(region->last_node_per_level[0]->numberOfEntriesInNode == entries_limit){

		new_node =  _create_tree_node(region,tree_id,0,leafNode);
		/*add pivot to index node*/
		_append_pivot_to_index(region, region->last_node_per_level[0],pointer_to_kv_pair,new_node, tree_id, 1);
		region->last_node_per_level[0] = new_node;
	} 

	/*add_entry_to_btree_node*/
	pointers_to_kv_pairs = (uint64_t *)((uint64_t)region->last_node_per_level[0] + sizeof(node_header));
	table = (prefix_table *)((uint64_t)region->last_node_per_level[0] + sizeof(node_header) + (leaf_order*sizeof(uint64_t)));

	pointers_to_kv_pairs[region->last_node_per_level[0]->numberOfEntriesInNode] = (uint64_t)pointer_to_kv_pair - MAPPED;
	table[region->last_node_per_level[0]->numberOfEntriesInNode] = *(prefix_table *)prefix;
	++region->last_node_per_level[0]->numberOfEntriesInNode;

	return;
}

void _append_pivot_to_index(_tucana_region_S* region, node_header * left_brother, void * pivot, 
		node_header * right_brother, int tree_id, int node_height)
{

	node_header * new_node = NULL;
	IN_log_header * last_d_header = NULL;
	IN_log_header * d_header = NULL;
	void * pivot_for_the_upper_level;
	int entries_limit = index_order;
	uint32_t key_len;
	void * key_addr = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;




	if(region->cur_nodes_per_level[node_height] == 0 &&
			region->last_node_per_level[node_height] == NULL){


		region->last_node_per_level[node_height] =  _create_tree_node(region,tree_id,node_height,internalNode);
		++region->cur_nodes_per_level[node_height];
	}

	else if(region->cur_nodes_per_level[node_height] == region->num_of_nodes_per_level[node_height]-1){
		entries_limit = region->entries_in_semilast_node[node_height];
	}

	else if(region->cur_nodes_per_level[node_height] == region->num_of_nodes_per_level[node_height]){
		entries_limit = region->entries_in_last_node[node_height];
	}


	if(region->last_node_per_level[node_height]->numberOfEntriesInNode == entries_limit){
		new_node =  _create_tree_node(region,tree_id,node_height, internalNode);
		/*add pivot to index node, right rotate*/
		pivot_for_the_upper_level = (void *)(uint64_t)region->last_node_per_level[node_height] + sizeof(node_header) + 
			((region->last_node_per_level[node_height]->numberOfEntriesInNode-1) * 2 * sizeof(uint64_t)) + sizeof(uint64_t);
		pivot_for_the_upper_level = (void *) MAPPED + *(uint64_t *)pivot_for_the_upper_level;  

		_append_pivot_to_index(region, region->last_node_per_level[node_height],pivot_for_the_upper_level, new_node, tree_id, node_height+1);

		--region->last_node_per_level[node_height]->numberOfEntriesInNode;
		region->last_node_per_level[node_height] = new_node;
	} 


	/*append the pivot  to the private key log and add the addr*/
	key_len = *(uint32_t *)pivot;
	if(region->last_node_per_level[node_height]->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - ( region->last_node_per_level[node_height]->key_log_size % (int32_t)KEY_BLOCK_SIZE );

	req_space = (key_len + sizeof(uint32_t));
	if(avail_space < req_space){/*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space+sizeof(node_header))/KEY_BLOCK_SIZE;
		if((req_space+sizeof(node_header))%KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space = allocated_space *  KEY_BLOCK_SIZE;

		d_header = _get_space_for_tree(region, tree_id, allocated_space);
		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)region->last_node_per_level[node_height]->last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		region->last_node_per_level[node_height]->last_IN_log_header = last_d_header->next;
		region->last_node_per_level[node_height]->key_log_size += (avail_space +  sizeof(uint64_t));/* position the log to the newly added block*/
		assert(region->last_node_per_level[node_height]->key_log_size < 9000);
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)region->last_node_per_level[node_height]->last_IN_log_header + 
		(uint64_t)(region->last_node_per_level[node_height]->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, pivot, sizeof(uint32_t) + key_len);/*key length */
	region->last_node_per_level[node_height]->key_log_size += sizeof(uint32_t) + key_len;

	/*finally add the pivot entry*/ 
	void *addr = (void *)((uint64_t)region->last_node_per_level[node_height] + sizeof(node_header) + 
			region->last_node_per_level[node_height]->numberOfEntriesInNode*2*sizeof(uint64_t)); 
	*(uint64_t *)addr = (uint64_t)left_brother - MAPPED;
	*(uint64_t *)(addr+sizeof(uint64_t)) = (uint64_t)key_addr - MAPPED;
	*(uint64_t *)(addr+(2*sizeof(uint64_t))) = (uint64_t)right_brother - MAPPED;

	++region->last_node_per_level[node_height]->numberOfEntriesInNode;
	return;
}

void _calculate_btree_index_nodes(_tucana_region_S* region, uint64_t num_of_keys)
{
	int level_id = 0;
	memset(region->num_of_nodes_per_level,0x00, sizeof(region->num_of_nodes_per_level));
	memset(region->cur_nodes_per_level,0x00, sizeof(region->cur_nodes_per_level));
	memset(region->entries_in_semilast_node,0x00, sizeof(region->entries_in_semilast_node));
	memset(region->entries_in_last_node,0x00, sizeof(region->entries_in_last_node));
	memset(region->last_node_per_level,0x00,sizeof(region->last_node_per_level));	

	/*first calculate leaves needed*/
	region->num_of_nodes_per_level[level_id] = num_of_keys/leaf_order;
	if(region->num_of_nodes_per_level[level_id] > 1 ||
			(region->num_of_nodes_per_level[level_id] == 1 && num_of_keys%leaf_order > 0)){
		if(num_of_keys%leaf_order !=0){
			/*borrow from left to have at least leaf_order/2 from left brother*/
			++region->num_of_nodes_per_level[level_id];
			if(num_of_keys%leaf_order < (leaf_order/2)){
				region->entries_in_semilast_node[level_id] = leaf_order - ((leaf_order/2) - (num_of_keys % leaf_order)); 
				region->entries_in_last_node[level_id] = leaf_order/2;
			}
			else {
				region->entries_in_semilast_node[level_id] = leaf_order; 
				region->entries_in_last_node[level_id] = num_of_keys % leaf_order; 
			}
		} else {
			region->entries_in_semilast_node[level_id] = leaf_order;
			region->entries_in_last_node[level_id] = leaf_order;
		}
	} else{ 
		region->entries_in_semilast_node[level_id] = 0; 
		region->entries_in_last_node[level_id] = num_of_keys;
		DPRINT("What ? num of nodes for level %d = %llu\n",level_id, (LLU)region->num_of_nodes_per_level[level_id]);
		return;
	}

	level_id = 1;
	while(level_id < MAX_TREE_HEIGHT){

		if(region->num_of_nodes_per_level[level_id-1]%index_order != 0){
			region->num_of_nodes_per_level[level_id] = region->num_of_nodes_per_level[level_id - 1]/index_order;
			++region->num_of_nodes_per_level[level_id];

			region->entries_in_last_node[level_id] = region->num_of_nodes_per_level[level_id-1] % index_order;

			if(region->entries_in_last_node[level_id] < index_order/2){
				region->entries_in_semilast_node[level_id] = index_order - ((index_order/2) - region->entries_in_last_node[level_id]);
				region->entries_in_last_node[level_id] = index_order/2;
			} else {
				region->entries_in_semilast_node[level_id] = index_order;
				region->entries_in_last_node[level_id] = num_of_keys % index_order;
			}

		} else {
			region->num_of_nodes_per_level[level_id] = region->num_of_nodes_per_level[level_id - 1]/index_order;
			region->entries_in_semilast_node[level_id] = index_order; 
			region->entries_in_last_node[level_id] = index_order;
		}

		if(region->num_of_nodes_per_level[level_id] == 1){
			region->entries_in_semilast_node[level_id] = 0; 
			region->entries_in_last_node[level_id] = region->num_of_nodes_per_level[level_id-1];
			/*done we are ready*/
			break;
		}
		++level_id;
	}

	assert(level_id != MAX_TREE_HEIGHT -1);
#if 0
	level_id = 0;
	while(level_id < MAX_TREE_HEIGHT){

		if(region->num_of_nodes_per_level[level_id] == 0){
			DPRINT("calculation end\n");
			break;
		}
		DPRINT("\t\t Level %d num_of_nodes %llu semilast has %llu last has %llu index_order %d leaf_order %d\n",level_id,(LLU)region->num_of_nodes_per_level[level_id],
				(LLU)region->entries_in_semilast_node[level_id], (LLU)region->entries_in_last_node[level_id], index_order, leaf_order);
		++level_id;
	}
#endif

	return;
}

/*####################################################*/


//<<<<<<< HEAD
struct tu_data_message* Server_Scan_MulipleRegions_RDMA(tu_data_message_s* data_message, void* connection)
	//=======
	//struct tu_data_message* handle_scan_request(struct tu_data_message* data_message, void* connection)
	//>>>>>>> 24a32ec7ad53b7a8345c33120e1034aa734c8b79
{
	/* TODO implement scans
	 * Use the current GET implentation as a baseline on how to get data from kreon.
	 * The client will always send a start key, stop key and the max number of kv pairs
	 * they want to receive from the server.
	 * Subsequent scan messages for the same scan will just have a different start key(the 
	 * last key they received from the server)
	 * Scanner API for the btree is in ../kreon/scanner/scanner.h
	 * XXX What about scans across regions???
	 * XXX Need to fix consistency model; the server should inform the client of the persistent tree
	 *     branch it used to answer its first query for this scan and the client will add that
	 *     info in each subsequent request for the same scan.
	 */
	/*Buffer format: <get_count, start_key_len, start_key, stop_key_len, stop_key>*/
	uint32_t kv_get_count = *(uint32_t*)data_message->data;
	void* start_key_buff = data_message->data + sizeof(uint32_t);
	void* stop_key_buff = start_key_buff + sizeof(uint32_t) + *(uint32_t*)start_key_buff;
	_tucana_region_S *S_tu_region;
	struct tu_data_message* reply_data_message;
	void* kv_buffer;
	uint32_t kv_buffer_len;
	char seek_mode = (data_message->value)?GREATER_OR_EQUAL:GREATER;

	/*DPRINT("Requested %"PRId32" kv pairs\n", kv_get_count);*/
	/*DPRINT("Start Key %s:%"PRId32"\n", (char*)(start_key_buff + sizeof(uint32_t)), *(uint32_t*)start_key_buff);*/
	/*DPRINT("Stop Key %s:%"PRId32"\n", (char*)(stop_key_buff + sizeof(uint32_t)), *(uint32_t*)stop_key_buff);*/
	/*fflush(stdout);*/

	S_tu_region = find_region(start_key_buff + sizeof(uint32_t), *(uint32_t*)start_key_buff);
	if(S_tu_region == NULL) {
		DPRINT("ERROR: Region not found for key %s\n", start_key_buff + sizeof(uint32_t));
		return NULL;
	}

	//Buffer format: kv_buffer = [total_kv_pairs, (key_length, key, value_length, value)*]
	//FIXME there should be an upper limit to the kv_buffer_len
	kv_buffer_len = multiget_calc_kv_size(S_tu_region->db, start_key_buff, stop_key_buff, kv_get_count, seek_mode);
	reply_data_message = allocate_rdma_message((struct connection_rdma*)connection, kv_buffer_len, SCAN_REQUEST);
	kv_buffer = reply_data_message->data;
	int rc = multi_get(S_tu_region->db, start_key_buff, stop_key_buff, kv_buffer, kv_buffer_len, kv_get_count, seek_mode);
	reply_data_message->value = rc;
	/*DPRINT("Keys Retrieved = %u\n", *(uint32_t*)kv_buffer);*/
	return reply_data_message;
}

#if 0 // FIXME never used
struct tu_data_message *Server_FlushVolume_RDMA( struct tu_data_message *data_message, struct connection_rdma *rdma_conn )
{
	struct tu_data_message *reply_data_message;
	_tucana_region_S *S_tu_region;

	S_tu_region = get_first_region();
	DPRINT("flushing volume for region %s min_range %s max_range %s\n",S_tu_region->ID_region.IDstr,S_tu_region->ID_region.minimum_range+4,S_tu_region->ID_region.maximum_range+4);
	flush_volume(S_tu_region->db->volume_desc, SPILL_ALL_DBS_IMMEDIATELY);
	printf("\n******[%s:%s:%d] Flushed Volume successfully ******\n",__FILE__,__func__,__LINE__);
	reply_data_message = tdm_Alloc_Flush_Volume_Reply_Message_WithMR( rdma_conn, data_message );
	return reply_data_message;
}
#endif



/*
 * KreonR main processing function of networkrequests.
 * Each network processing request must be resumable. For each message type KreonR process it via 
 * a specific data path. We treat all taks related to network  as paths that may fail, that we can resume later. The idea 
 * behind this 
 * */
void handle_task(void * __task)
{
	work_task * task = (work_task *)__task;
	kv_location location;
	struct connection_rdma *rdma_conn;

	_tucana_region_S * S_tu_region;
	int tries;
	void *region_key;
	//leave it for later
	void * addr;
	uint64_t log_address;
	void * master_segment;
	void * local_log_addr;
	int32_t num_entries;

	void *key = NULL;
	void *value;
	uint32_t key_length = 0 ;

	/*unboxing the arguments*/
	S_tu_region = NULL;
	task->reply_msg = NULL;
	rdma_conn = task->conn;

	if(task->msg == NULL){
		DPRINT("FATAL NULL msg in request\n");
		exit(EXIT_FAILURE);
	}



	stats_update(task->thread_id);
	switch(task->msg->type){
		case SPILL_INIT:

			task->reply_msg = __allocate_rdma_message(task->conn, 0, SPILL_INIT_ACK, ASYNCHRONOUS, 0, task);
			if(task->allocation_status != ALLOCATION_SUCCESS){
				return;
			}	
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

			region_key = task->msg->data;
			S_tu_region = find_region(region_key+sizeof(uint32_t), *(uint32_t *)region_key);

			assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB && 
					S_tu_region->db->db_desc->db_mode == BACKUP_DB_NO_PENDING_SPILL);
			assert(task->conn->pending_received_messages == 1 && 
					rdma_conn->pending_sent_messages == 1);

			DPRINT("REPLICA: Master requests a remote spill  for region %s\n",region_key+sizeof(uint32_t));
			S_tu_region->db->db_desc->db_mode = BACKUP_DB_PENDING_SPILL;
			S_tu_region->db->db_desc->spill_segment_table = S_tu_region->db->db_desc->backup_segment_table;
			S_tu_region->db->db_desc->backup_segment_table = NULL;
			map_entry *s = (map_entry *)malloc(sizeof(map_entry));
			s->key = (uint64_t)S_tu_region->db->db_desc->last_master_segment;
			s->value = (uint64_t)S_tu_region->db->db_desc->last_local_mapping;
			HASH_ADD_PTR(S_tu_region->db->db_desc->backup_segment_table,key,s);

			/*finally find an empty tree in the forest to insert the new spill*/
			S_tu_region->current_active_tree_in_the_forest =  -1;
			int i;
			for(i=0;i<MAX_FOREST_SIZE;i++){
				if(S_tu_region->db->db_desc->replica_forest.tree_status[i] == NOT_USED){
					DPRINT("REPLICA: Initiating remote spill for tree_id %d in the forest\n",i);
					S_tu_region->db->db_desc->replica_forest.tree_status[i] = IN_TRANSIT_DIRTY;
					S_tu_region->current_active_tree_in_the_forest = i;
					break;
				}
			}
			_calculate_btree_index_nodes(S_tu_region, *(uint64_t *)(task->msg->data + (task->msg->pay_len - sizeof(uint64_t))));
			if(S_tu_region->current_active_tree_in_the_forest == -1){
				DPRINT("REPLICA: Time for compaction forest is full XXX TODO XXX\n");
				exit(EXIT_FAILURE);
			}
			task->kreon_operation_status = SPILL_INIT_END;
			task->overall_status = TASK_COMPLETED;
			task->reply_msg->error_code = KREON_OK;
			free_rdma_received_message(task->conn, task->msg);
			break;	

		case SPILL_COMPLETE:  

			task->reply_msg = __allocate_rdma_message(task->conn, 0, SPILL_COMPLETE_ACK, ASYNCHRONOUS, 0, task);
			if(task->allocation_status != ALLOCATION_SUCCESS){
				return;
			}	
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

			region_key = task->msg->data;
			S_tu_region = find_region(region_key+sizeof(uint32_t), *(uint32_t *)region_key);
			assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB);
			/*clear all mappings*/
			map_entry *current, *tmp;
			HASH_ITER(hh, S_tu_region->db->db_desc->spill_segment_table,current,tmp) {
				HASH_DEL(S_tu_region->db->db_desc->spill_segment_table, current);  /* delete it (users advances to next) */
				free(current);/* free it */
			}

			task->reply_msg->error_code = KREON_OK;
			DPRINT("REPLICA: completed remote spill snapshotting volume, ommiting CAUTION\n");
			//snapshot(S_tu_region->db->volume_desc);
			S_tu_region->db->db_desc->L0_end_log_offset = *(uint64_t *)task->msg->data;
			S_tu_region->db->db_desc->L0_start_log_offset = *(uint64_t *)task->msg->data;
			int j;
			for(j=MAX_TREE_HEIGHT-1;j>=0;j--){
				if(S_tu_region->last_node_per_level[j]!=NULL){
					S_tu_region->last_node_per_level[j]->type = rootNode;
					S_tu_region->db->db_desc->replica_forest.tree_roots[S_tu_region->current_active_tree_in_the_forest] = S_tu_region->last_node_per_level[j];
					break;
				}
			}/*snapshot maybe?, snapshot is for replica thus does not include network communication*/
			S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] = READY_TO_PERSIST;
			DPRINT("REPLICA: Spill complete maybe a snapshot now? XXX TODO XXX\n");
			S_tu_region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
			task->kreon_operation_status = SPILL_COMPLETE_END;
			task->overall_status = TASK_COMPLETED;
			free_rdma_received_message(task->conn, task->msg);
			break;

		case SPILL_BUFFER_REQUEST:


			/*Nothing to do here for suspend/resume because in this version
				it does not send a reply to the client*/
			region_key = task->msg->data+sizeof(uint32_t);
			S_tu_region = find_region(region_key, PREFIX_SIZE);
			assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB && S_tu_region->db->db_desc->db_mode == BACKUP_DB_PENDING_SPILL);
			/*iterate values*/
			addr = task->msg->data;
			num_entries = *(uint32_t *)(addr);
			addr+=sizeof(uint32_t);
			//DPRINT("\tREPLICA: applying remote spill buffer at replica num entries %d\n",num_entries);
			S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] = IN_TRANSIT_DIRTY;
			for(i=0;i<num_entries;i++) {
				/*rewrite mapping, PREFIX stays the same*/
				log_address = (*(uint64_t *)(addr + PREFIX_SIZE));
				master_segment = (void *) log_address - ((uint64_t)log_address % BUFFER_SEGMENT_SIZE);
				//local_log_addr = (void *) clht_get(handle->db_desc->backup_segment_table->ht, (clht_addr_t) master_segment);
				map_entry *s;
				SPIN_LOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
				HASH_FIND_PTR(S_tu_region->db->db_desc->spill_segment_table,&master_segment,s);
				if(s == NULL){
					DPRINT("REPLICA: FATAL mapping is missing for master segment %llu\n",(LLU)master_segment);
					raise(SIGINT);
					exit(EXIT_FAILURE);
				}
				SPIN_UNLOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
				/*add the offset*/
				local_log_addr = (void *) MAPPED + s->value  +(log_address % BUFFER_SEGMENT_SIZE);
				*(uint64_t *)(addr+PREFIX_SIZE) = (uint64_t)local_log_addr;

				//DPRINT("mapping remote log segment: %llu local segment : %llu local full address in log %llu\n",
				//	(LLU)master_segment,(LLU)s->value, (LLU)local_log_addr);
				//if( *(uint32_t *)local_log_addr > 30 || *(uint32_t *)local_log_addr == 0){
				//	DPRINT("mapping remote log segment: %llu local segment : %llu local full address in log %llu\n",
				//			(LLU)master_segment,(LLU)s->value, (LLU)local_log_addr);
				//	DPRINT("Faulty pointer size %"PRIu32" i is %d\n",*(uint32_t *)local_log_addr,i);
				//	raise(SIGINT);
				//	exit(EXIT_FAILURE);
				//}

#if LEVELING
				location.kv_addr = addr;
				/*insert to local L1*/
				//DEBUGGING
				//if(memcmp(addr, local_log_addr+4,PREFIX_SIZE) != 0){
				//  DPRINT("boom corrupted log remote key %s, local key %s\n",(char *)addr, (char *)local_log_addr+4);
				//  raise(SIGINT);
				//}
				_insert_index_entry(s_tu_region->db, &location, INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (4 << 8) | BACKUP_OPERATION);
#else    
				/*tiering*/
				append_entry_to_leaf_node(S_tu_region,(void *)(*(uint64_t *)(addr+PREFIX_SIZE)), addr, S_tu_region->current_active_tree_in_the_forest);
#endif
				addr +=(PREFIX_SIZE+sizeof(uint64_t));
			}
			free_rdma_received_message(task->conn, task->msg);
			task->overall_status = TASK_COMPLETED;
			break;


#if 0	
		case SCAN_REQUEST:
			task->reply_msg = Server_Scan_MulipleRegions_RDMA(task->msg, rdma_conn);
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			break;

			/*
			 * Kind reminder, SPILL_INIT, SPILL_BUFFER_REQUEST, and SPILL_COMPLETE are handled by the server 
			 * which has backup role for the given region
			 */

#endif
		case RESET_BUFFER:
			//DPRINT("Got reset buffer request pending received messages are %llu\n", (LLU)task->conn->pending_received_messages);
			if(task->kreon_operation_status == RESET_BUFFER_START){
				/*Have all requests been completed for this connection?*/
				tries = 0;
				while(task->conn->pending_received_messages != 0){
					if(++tries >= NUM_OF_TRIES){
						//DPRINT("\tWaiting for processing of received messages to send RESET_BUFFER_ACK pending messages %llu\n",(LLU)task->conn->pending_received_messages);
						return;
					}
				}
			}
			_send_reset_buffer_ack(task->conn);
			task->kreon_operation_status = RESET_BUFFER_COMPLETE;
			_zero_rendezvous_locations(task->msg);
			_update_rendezvous_location(task->conn, 0);/*"0" indicates RESET*/
			task->overall_status = TASK_COMPLETED;
			break;
		case PUT_REQUEST:
		case TU_UPDATE:
			/* *
			 * retrieve region handle for the corresponding key, find_region
			 * initiates internally rdma connections if needed
			 * */

			key = task->msg->data;
			key_length = *(uint32_t*)key;	
			assert(key_length != 0);
			S_tu_region = find_region(key+sizeof(uint32_t),*(uint32_t *)key);
			if(S_tu_region == NULL){
				DPRINT("FATAL:  Region not found for key size %u:%s\n", key_length, key + sizeof(uint32_t));
				exit(EXIT_FAILURE);
			}
			task->region = (void *)S_tu_region;


			if(task->kreon_operation_status != APPEND_COMPLETE){
				append_and_insert_kv_pair(S_tu_region, task->msg, 
						task->conn, 
						&location,
						task, 
						DO_NOT_WAIT_REPLICA_TO_COMMIT);

				if(task->kreon_operation_status == APPEND_COMPLETE){
					task->allocation_status = ALLOCATION_START;
					//free_rdma_received_message(task->conn, task->msg);
				} else {
					return;
				}
			}

			task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer + (uint64_t)task->msg->reply);
			/*initialize message*/
			if(task->msg->reply_length >= TU_HEADER_SIZE){
				task->reply_msg->pay_len = 0;
				task->reply_msg->padding_and_tail = 0;
				task->reply_msg->data = NULL;
				task->reply_msg->next = NULL;


				task->reply_msg->type = PUT_REPLY;
				task->reply_msg->flags = CLIENT_CATEGORY;
				task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
				task->reply_msg->tail = NULL; /*to be deleted field*/
				task->reply_msg->local_offset = (uint64_t)task->msg->reply;
				task->reply_msg->remote_offset = (uint64_t)task->msg->reply;

				//DPRINT("\t Sending to remote offset %llu\n", msg->remote_offset);
				task->reply_msg->ack_arrived = REPLY_PENDING;
				task->reply_msg->callback_function = NULL;
				task->reply_msg->request_message_local_addr = NULL;

			}else{
				DPRINT("SERVER: FATAL mr CLIENT reply space not enough  size %"PRIu32" FIX XXX TODO XXX\n",task->msg->reply_length);
				exit(EXIT_FAILURE);
			}

			/*piggyback info for use with the client*/
			task->reply_msg->request_message_local_addr = task->notification_addr;
			task->overall_status = TASK_COMPLETED;
			//DPRINT("\t reply to msg data_message->request_message_local_addr %llu pending received %d\n", 
			//	data_message->request_message_local_addr,rdma_conn->pending_received_messages);
			return;

		case MULTI_PUT:
			DPRINT("FATAL MULTI_PUT request is deprecated\n");
			exit(EXIT_FAILURE);
			break;

		case TU_GET_QUERY:
			value = NULL;
			/*kreon phase*/
			if(task->kreon_operation_status == GET_START){
				key = (char*)task->msg->data;
				key_length = *(uint32_t *)key;
				S_tu_region = find_region(key+sizeof(uint32_t),key_length);

				if(S_tu_region == NULL){
					DPRINT("ERROR: Region not found for key %s\n",key);
					assert(0);
					return;
				}
//#if !OMMIT_IO_IN_THE_INSERT_PATH
				//value  = find_key(S_tu_region->db, key+sizeof(uint32_t), key_length);
//#else
				value = (void *)alloca(1024);
				*(uint32_t *)value = 1020;
//#endif
				
				if(value == NULL) {
					DPRINT(" FATAL key not found key %s : length %u region min_key %s max key %s\n",
                            key+sizeof(uint32_t),key_length, S_tu_region->ID_region.minimum_range+sizeof(int),S_tu_region->ID_region.maximum_range+sizeof(int));
					exit(EXIT_FAILURE);
				}
				//task->kreon_operation_status = GET_COMPLETE;
				task->intermediate_buffer = NULL;
			}
			/*allocate rdma message and reply to client phase*/
			if(task->intermediate_buffer == NULL){
				task->reply_msg = __allocate_rdma_message(task->conn, *(uint32_t *)value+sizeof(uint32_t), TU_GET_REPLY, ASYNCHRONOUS, 0,task);
			} 
			else{
				task->reply_msg = __allocate_rdma_message(task->conn, *(uint32_t *)task->intermediate_buffer+sizeof(uint32_t), TU_GET_REPLY, ASYNCHRONOUS, 0, task);
			}

			if(task->allocation_status != ALLOCATION_SUCCESS){
				//DPRINT("Retry allocating RDMA buffer for GET reply\n");
				if(task->intermediate_buffer == NULL){
					/*store intermediate result*/
					//task->intermediate_buffer = malloc(*(uint32_t *)value+sizeof(uint32_t));
					//memcpy(task->intermediate_buffer,value,*(uint32_t *)value+sizeof(uint32_t));
				}
				return;
			}

			if(task->intermediate_buffer == NULL){
				*(uint32_t *)task->reply_msg->data = *(uint32_t *)value;
				if(push_buffer_in_tu_data_message(task->reply_msg, value+sizeof(uint32_t), *(uint32_t *)value) != KREON_SUCCESS){
					DPRINT("FATAL push buffer failed\n");
					exit(EXIT_FAILURE);
				}
			} 
			else {
				*(uint32_t *)task->reply_msg->data = *(uint32_t *)task->intermediate_buffer;
				if(push_buffer_in_tu_data_message(task->reply_msg, task->intermediate_buffer+sizeof(uint32_t), *(uint32_t *)task->intermediate_buffer) != KREON_SUCCESS){
					DPRINT("FATAL push buffer failed\n");
					exit(EXIT_FAILURE);
				}
				free(task->intermediate_buffer);
			}
			/*piggyback info for use with the client*/
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			free_rdma_received_message(task->conn, task->msg);
			task->overall_status = TASK_COMPLETED;
			break;
		case TEST_REQUEST:
			task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer + (uint64_t)task->msg->reply);
			/*initialize message*/
			if(task->msg->reply_length >= TU_HEADER_SIZE){
				task->reply_msg->pay_len = 0;
				task->reply_msg->padding_and_tail = 0;
				task->reply_msg->data = NULL;
				task->reply_msg->next = NULL;


				task->reply_msg->type = TEST_REPLY;
				task->reply_msg->flags = CLIENT_CATEGORY;
				task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
				task->reply_msg->tail = NULL; /*to be deleted field*/
				task->reply_msg->local_offset = (uint64_t)task->msg->reply;
				task->reply_msg->remote_offset = (uint64_t)task->msg->reply;

				task->reply_msg->ack_arrived = REPLY_PENDING;
				task->reply_msg->callback_function = NULL;
				task->reply_msg->request_message_local_addr = NULL;
				task->overall_status = TASK_COMPLETED;
			} else {
				DPRINT("SERVER: FATAL mr CLIENT reply space not enough  size %"PRIu32" FIX XXX TODO XXX\n",task->msg->reply_length);
				exit(EXIT_FAILURE);
			}
			/*piggyback info for use with the client*/
			task->reply_msg->request_message_local_addr = task->notification_addr;
			break;

		case TEST_REQUEST_FETCH_PAYLOAD:
			task->reply_msg = __allocate_rdma_message(task->conn, 1024, TEST_REPLY_FETCH_PAYLOAD, ASYNCHRONOUS, 0,task);
			if(task->allocation_status != ALLOCATION_SUCCESS){
				return;
			}
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			task->overall_status = TASK_COMPLETED;
			break;
#if 0	
		case TU_FLUSH_VOLUME_QUERY:
			reply_data_message = Server_FlushVolume_RDMA( data_message, rdma_conn);	
			break;
		case TU_UPDATE:
			if(handle_update_request(data_message, rdma_conn)!= KREON_SUCCESS){
				DPRINT("Warning update failed :-(\n");
			}
			reply_data_message = allocate_rdma_message(rdma_conn, 0, TU_UPDATE_REPLY);
			/*piggyback info for use with the client*/
			reply_data_message->request_message_local_addr = data_message->request_message_local_addr;
			break;
#endif
		case FLUSH_SEGMENT:
		case FLUSH_SEGMENT_AND_RESET:
			if(task->kreon_operation_status == FLUSH_SEGMENT_START){
				//DPRINT("**** Ordered from master to perform a flush ****\n");
				/*ommit header find the corresponding region*/
				region_key = (void *)(task->msg->data + 32);
				_tucana_region_S * s_tu_region = find_region(region_key+sizeof(uint32_t), *(uint32_t *)region_key);

				if(s_tu_region == NULL){
					DPRINT("FATAL region with min key %s not found\n",region_key);	
					exit(EXIT_FAILURE);
				}
				if(s_tu_region->db->db_desc->db_mode == PRIMARY_DB){
					DPRINT("FATAL flushing primary db?\n");
					raise(SIGINT);
					exit(EXIT_FAILURE);
				}

#if !OMMIT_IO_IN_THE_INSERT_PATH
				void * master_segment = (void *)*(uint64_t *)((uint64_t)task->msg->data);
				uint64_t end_of_log = *(uint64_t *)((uint64_t)task->msg->data+(sizeof(uint64_t)));
				uint64_t bytes_to_pad = *(uint64_t *)((uint64_t)task->msg->data+ (2*sizeof(uint64_t)));
				uint64_t segment_id = *(uint64_t *)((uint64_t)task->msg->data + (3*sizeof(uint64_t)));

				void *buffer = task->msg->data + 4096;
				//DPRINT("REPLICA: master segment %llu end of log %llu bytes to pad %llu segment_id %llu\n",(LLU)master_segment,(LLU)end_of_log,(LLU)bytes_to_pad,(LLU)segment_id);
				flush_replica_log_buffer(s_tu_region->db, (segment_header *)master_segment, buffer, end_of_log, bytes_to_pad, segment_id);
#endif
				free_rdma_received_message(task->conn, task->msg);
				task->kreon_operation_status = FLUSH_SEGMENT_COMPLETE;
			}

			/*Since reply message is of fixed size we allocate it first*/

			task->reply_msg = (tu_data_message_s *)(task->conn->rdma_memory_regions->local_memory_buffer + task->conn->offset);
			/*init message*/
			task->reply_msg->pay_len = 0;
			task->reply_msg->padding_and_tail = 0;
			task->reply_msg->data = NULL;
			task->reply_msg->next = task->reply_msg->data;
			task->reply_msg->receive = TU_RDMA_REGULAR_MSG;	
			task->reply_msg->flags = SERVER_CATEGORY;


			task->reply_msg->local_offset = task->conn->offset;
			task->reply_msg->remote_offset = task->conn->offset;
			task->reply_msg->ack_arrived = REPLY_PENDING;
			task->reply_msg->callback_function = NULL;
			task->reply_msg->request_message_local_addr = NULL;	

			if(task->msg->type == FLUSH_SEGMENT){
				task->reply_msg->type = FLUSH_SEGMENT_ACK;
				task->conn->offset += MESSAGE_SEGMENT_SIZE;
			}else{
				task->reply_msg->type = FLUSH_SEGMENT_ACK_AND_RESET;
				task->conn->offset = 0;
			}
			//task->reply_msg = __allocate_rdma_message(task->conn, 0, FLUSH_SEGMENT_ACK, ASYNCHRONOUS, 0, task);
			//if(task->allocation_status != ALLOCATION_SUCCESS){
			//	return;
			//}
			task->reply_msg->request_message_local_addr = task->notification_addr;
			__sync_fetch_and_add(&task->conn->pending_sent_messages, 1);
			//DPRINT("* Everything ok sending FLUSH_SEGMENT_ACK pending sent for con are %llu\n",(LLU)task->conn->pending_sent_messages);
			task->overall_status = TASK_COMPLETED;
			break;
		default:
			DPRINT("FATAL unknown operation %d\n", task->msg->type);
			exit(EXIT_FAILURE);
	}
	//free_rdma_received_message(rdma_conn, data_message);
	//assert(reply_data_message->request_message_local_addr);
	return;
}



#ifndef TESTS
/*helper functions*/
void _str_split(char* a_str, const char a_delim, uint64_t ** core_vector, uint32_t * num_of_cores)
{
	//DPRINT("%s\n",a_str); 
	char * tmp = alloca(128);
	char** result    = 0;
	size_t count     = 0;

	char* last_comma = 0;

	char delim[2];
	int i;

	strcpy(tmp, a_str);
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp){
		if(a_delim == *tmp){
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);
	count++;
	/* Add space for terminating null string so caller
		 knows where the list of returned strings ends. */

	result = malloc(sizeof(char*) * count);

	*num_of_cores = count-1; 
	*core_vector = (uint64_t *)malloc(sizeof(uint64_t)*count);
	i = 0;

	if (result){
		size_t idx  = 0;
		char* token = strtok(a_str, delim);

		while (token){
			assert(idx < count);
			*(result + idx++) = strdup(token);
			if(*token != 0x00){
				(*core_vector)[i] = strtol(token, (char **)NULL, 10);
				//DPRINT("Core id %d = %llu\n",i,(LLU)(*core_vector)[i]);
				++i;
			}
			token = strtok(0, delim);
		}
		assert(idx == count - 1);
		*(result + idx) = 0;
		free(result);
	}
	return;
}


sem_t exit_main;
static void tu_ec_sig_handler(int signo)
{
	/*pid_t tid = syscall(__NR_gettid);*/
	DPRINT("caught signal closing server\n");
	stats_notify_stop_reporter_thread();
	sem_post(&exit_main);
}

int main(int argc, char *argv[])
{
	int i;
	uint32_t aux_len=100;
    globals_set_zk_host(zookeeper_host_port);
	RDMA_LOG_BUFFER_PADDING = 0;
	RDMA_TOTAL_LOG_BUFFER_SIZE = TU_HEADER_SIZE + BUFFER_SEGMENT_SIZE + 4096 + TU_TAIL_SIZE;

	if(RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE != 0){
		/*need to pad */
		RDMA_LOG_BUFFER_PADDING = (MESSAGE_SEGMENT_SIZE - (RDMA_TOTAL_LOG_BUFFER_SIZE%MESSAGE_SEGMENT_SIZE));
		RDMA_TOTAL_LOG_BUFFER_SIZE += RDMA_LOG_BUFFER_PADDING;
		assert(RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE == 0);
	}

	if (argc == 6) {
		int rdma_port = strtol(argv[1], NULL, 10);
        globals_set_RDMA_connection_port(rdma_port);
		Device_name = argv[2];
		Device_size = strtol(argv[3], NULL, 10) * 1024 * 1024 * 1024;

		_str_split(argv[4],',', &spinning_threads_core_ids, &num_of_spinning_threads);
		_str_split(argv[5],',', &worker_threads_core_ids, &num_of_worker_threads);
	} else {
		DPRINT("Error: usage: ./tucanaserver <port number> <device name> <device size in GB> <spinning thread core ids>  <working thread core ids>\n");
		exit(EXIT_FAILURE);
	}


	for(i=0;i<num_of_spinning_threads;i++){
		DPRINT(" spinning thread core[%d] = %llu\n",i,(LLU)spinning_threads_core_ids[i]);
	}
	for(i=0;i<num_of_worker_threads;i++){
		DPRINT(" worker thread core[%d] = %llu\n",i,(LLU)worker_threads_core_ids[i]);
	}
	assert(num_of_worker_threads % num_of_spinning_threads == 0);
	WORKER_THREADS_PER_SPINNING_THREAD = (num_of_worker_threads/num_of_spinning_threads);

	DPRINT("Set pool size for each spinning thread to %u\n",WORKER_THREADS_PER_SPINNING_THREAD);
	struct sigaction sa;
	sa.sa_handler = tu_ec_sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	int ret = sigaction(SIGINT, &sa, NULL);
	assert(ret == 0);

	srand(time(NULL));
	pthread_mutex_init( &reg_lock, NULL);

	//i = ibv_fork_init();
	//if(i){
	//	DPRINT("FATAL call failed reason follows-->\n");
	//	perror("Reason: ");
	//	exit(EXIT_FAILURE);
	//}



	DPRINT("initializing storage device:%s\n",Device_name);
	Init_Storage_Device(&storage_dev, Device_name, (uint64_t)Device_size);
	DPRINT("initializing zookeeper server\n");
	Init_tuzk_server( &tuzk_S );
	DPRINT("initializing regionse?\n");
	Init_RegionsSe();
#if TU_RDMA
	Set_OnConnection_Create_Function( regions_S.channel, handle_task);
	DPRINT("initialized RDMA\n");
#endif
	DPRINT("initializing data server\n");
	Init_Data_Server_from_ZK();
	stats_init(num_of_worker_threads);
	sem_init(&exit_main, 0, 0);
	sem_wait(&exit_main);

	DPRINT("kreonR server exiting\n");
	Free_RegionsSe();
	return 0;
}
#endif
