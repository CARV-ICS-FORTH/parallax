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
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#include "regions.h"
#include "messages.h"
#include "prototype.h"
#include "storage_devices.h"
#include "globals.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/btree/segment_allocator.h"
#include "zk_server.h"
#include "replica_utilities.h"
#include "../kreon_rdma/rdma.h"

#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_lib/btree/conf.h"
#include "../utilities/queue.h"
#include "../utilities/min_max_heap.h"
#include "../build/external-deps/log/src/log.h"
#include "stats.h"

#ifdef CHECKSUM_DATA_MESSAGES
#include "djb2.h"
#endif

#define TIERING_MAX_CAPACITY 8
#define LOG_SEGMENT_CHUNK 32 * 1024
#define MY_MAX_THREADS 2048

extern char *DB_NO_SPILLING;

typedef struct prefix_table {
	char prefix[PREFIX_SIZE];
} prefix_table;

typedef struct spill_task_descriptor {
	pthread_t spill_worker_context;
	bt_spill_request *spill_req;
	/*XXX TODO XXX, add appropriate fields*/
	work_task task;
	struct _tucana_region_S *region;
	int standalone;
	volatile work_task_status spill_task_status;
} spill_task_descriptor;

#ifdef TIERING
typedef struct replica_tiering_compaction_request {
	pthread_t tiering_compaction_context;
	_tucana_region_S *region;
	int level_id;
} tiering_compaction_request;
void tiering_compaction_worker(void *);
#endif

/*inserts to Kreon and implements the replication logic*/
void insert_kv_pair(_tucana_region_S *S_tu_region, tu_data_message *data_message, connection_rdma *rdma_conn,
		    kv_location *location, work_task *task, int wait);

/*functions for building index at replicas*/
void _calculate_btree_index_nodes(_tucana_region_S *region, uint64_t num_of_keys);
void append_entry_to_leaf_node(_tucana_region_S *region, void *pointer_to_kv_pair, void *prefix, int32_t tree_id);
struct node_header *_create_tree_node(struct _tucana_region_S *region, int tree_id, int node_height, int type);
void _append_pivot_to_index(_tucana_region_S *region, node_header *left_brother, void *pivot,
			    node_header *right_brother, int tree_id, int node_height);

pthread_mutex_t reg_lock; /*Lock for the conn_list*/

extern _tuzk_server tuzk_S;
extern _RegionsSe regions_S;
extern tu_storage_device storage_dev;

char *Device_name = NULL;
uint64_t Device_size = 0;

/*
 * protocol that threads use to inform the system that they perform
 * a region operation (insert,get,delete). Crucial for the case where
 * regions are destroyed due to failures of another server or
 * some elastic operation
 * */
#define ENTERED_REGION 0x02
#define EXITED_REGION 0x03
#define THROTTLE 2048
static inline char __ENTER_REGION(_tucana_region_S *region)
{
	return ENTERED_REGION;
	long ret_value;
	long value;
	do {
		value = region->active_region_threads;
		//printf("[%s:%s:%d] trying to enter region active %llu\n",__FILE__,__func__,__LINE__,value);
		if (value > THROTTLE)
			return DB_IS_CLOSING;
		ret_value = __sync_val_compare_and_swap(&region->active_region_threads, value, value + 1);
		if (ret_value > THROTTLE)
			return DB_IS_CLOSING;
	} while (ret_value != value);
	return ENTERED_REGION;
}

static inline char __EXIT_REGION(_tucana_region_S *region)
{
	return ENTERED_REGION;
	long ret_value;
	long value;
	do {
		value = region->active_region_threads;
		//printf("[%s:%s:%d] trying to exit region active %llu\n",__FILE__,__func__,__LINE__,value);
		ret_value = __sync_val_compare_and_swap(&region->active_region_threads, value, value - 1);
	} while (ret_value != value);
	return EXITED_REGION;
}

struct tu_data_message *handle_scan_request(struct tu_data_message *data_message, void *connection);
struct tu_data_message *Server_Handling_Received_Message(struct tu_data_message *data_message, int reg_num,
							 int next_mail);
int handle_put_request(tu_data_message *data_message, connection_rdma *rdma_conn);
// struct tu_data_message *Server_FlushVolume_RDMA( struct tu_data_message *data_message, struct connection_rdma *rdma_conn ); // FIXME Never used

_tucana_region_S *get_region(void *key, int key_len)
{
	//_tucana_region_S * region = (_tucana_region_S *)find_region_min_key_on_rbtree( &regions_S.tree, key, key_len);
	_tucana_region_S *region = find_region(key, key_len);
	if (region == NULL) {
		DPRINT("FATAL region not found\n");
		exit(EXIT_FAILURE);
	}
	return region;
}

static void kreonR_spill_worker(void *_spill_task_desc)
{
//gesalous leave it for later
#if 0
	kv_location location;
	spill_task_descriptor *spill_task_desc = (spill_task_descriptor *)_spill_task_desc;
	bt_spill_request *spill_req = spill_task_desc->spill_req;
	tu_data_message *msg = NULL;
	tu_data_message *spill_buffer_msg = NULL;
	void *spill_buffer;
	uint64_t log_addr;
	tu_data_message *reply = NULL;
	level_scanner *level_sc = NULL;

	void *free_addr;
	uint64_t size;
	void *addr;
	uint32_t region_key_len;
	uint32_t keys_batch_to_spill;
	uint32_t num_of_spilled_keys;
	int i;
	int rc;

	while (1) {
		switch (spill_task_desc->spill_task_status) {
		case SEND_SPILL_INIT:

			assert(spill_task_desc->standalone == 0);
			log_info("MASTER: Sending spill init to replica\n");

			region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;
			msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
						      28 + region_key_len, SPILL_INIT, ASYNCHRONOUS, 0,
						      &spill_task_desc->task);
			if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
				DPRINT("allocation rollback\n");
				if (pthread_yield() != 0) {
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
			memcpy(addr, spill_task_desc->region->ID_region.minimum_range + sizeof(uint32_t),
			       region_key_len);
			addr += region_key_len;
			/*L0 start*/
			*(uint64_t *)addr = spill_task_desc->spill_req->l0_start;
			addr += sizeof(uint64_t);
			/*L0 end*/
			*(uint64_t *)addr = spill_task_desc->spill_req->l0_end;
			addr += sizeof(uint64_t);
			/*total keys to spill*/
			log_info("keys from level:%u tree:%u to spill are are %llu\n", spill_req->src_level,
				 spill_req->src_tree,
				 spill_req->db_desc->levels[spill_req->src_tree].total_keys[spill_req->src_tree]);
			*(uint64_t *)addr =
				spill_req->db_desc->levels[spill_req->src_level].total_keys[spill_req->src_tree];
			addr += sizeof(uint64_t);
			msg->next = addr;
			msg->request_message_local_addr = msg; /*info to spinning thread to wake us up on reply*/
			msg->reply_message = NULL;
			if (send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) !=
			    KREON_SUCCESS) {
				log_info("failed to send message\n");
				exit(EXIT_FAILURE);
			}
			log_info(
				"Sent spill init command to replica to region: %s payload len %u waiting for reply...\n",
				spill_task_desc->region->ID_region.minimum_range + 4, 24 + region_key_len);
			spill_task_desc->spill_task_status = WAIT_FOR_SPILL_INIT_REPLY;
			break;

		case WAIT_FOR_SPILL_INIT_REPLY:

			if (msg->reply_message == NULL) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}
			reply = (tu_data_message *)msg->reply_message;

			if (reply->error_code == KREON_OK) {
				log_info("MASTER: Replica ready to participate in spill :-)\n");
			} else if (reply->error_code == REPLICA_PENDING_SPILL) {
				log_info("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
				exit(EXIT_FAILURE);
			} else {
				log_info("FATAL Unknown code\n");
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
			free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
			spill_task_desc->spill_task_status = INIT_SPILL_BUFFER_SCANNER;
			log_info("MASTER: got SPILL_INIT reply!\n");
			break;

		case INIT_SPILL_BUFFER_SCANNER:

			DPRINT("MASTER: INIT_SPILL_BUFFER_SCANNER!\n");
			level_sc = _init_spill_buffer_scanner(spill_task_desc->region->db, spill_req->src_root,
							      spill_req->start_key);

			assert(level_sc != NULL);
			keys_batch_to_spill =
				(SPILL_BUFFER_SIZE - (2 * sizeof(uint32_t))) / (PREFIX_SIZE + sizeof(uint64_t));
			spill_task_desc->spill_task_status = SPILL_BUFFER_REQ;
			break;

		case SPILL_BUFFER_REQ:

			if (!spill_task_desc->standalone) {
				/*allocate buffer*/
				spill_buffer_msg =
					__allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
								SPILL_BUFFER_SIZE, SPILL_BUFFER_REQUEST, ASYNCHRONOUS,
								0, &spill_task_desc->task);
				if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
					if (pthread_yield() != 0) {
						DPRINT("FATAL yield failed\n");
					}
					break;
				}
				spill_buffer = spill_buffer_msg->data;
				spill_buffer += sizeof(uint32_t); /*keep 4 bytes for num of entries*/
				/*reset the status flag for subsequent operations*/
				spill_task_desc->task.allocation_status = ALLOCATION_START;
			}
			num_of_spilled_keys = 0;
			bt_insert_req req;
			for (i = 0; i < keys_batch_to_spill; i++) {
				location.kv_addr = level_sc->keyValue;
				location.log_offset = 0; /*unused*/
				req.handle = spill_task_desc->region->db;
				req.key_value_buf = level_sc->keyValue;
				req.level_id = spill_req->dst_level;
				req.tree_id = spill_req->dst_tree;
				req.key_format = KV_PREFIX;
				req.append_to_log = 0;
				req.gc_request = 0;
				req.recovery_request = 0;
				_insert_key_value(&req);

				if (!spill_task_desc->standalone) {
					/*for the replica prefix*/
					memcpy(spill_buffer, level_sc->keyValue, PREFIX_SIZE);
					spill_buffer += PREFIX_SIZE;
					/*relative log address*/
					log_addr = (*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE)) - MAPPED;
					memcpy(spill_buffer, &log_addr, sizeof(uint64_t));
					spill_buffer += sizeof(uint64_t);
					++num_of_spilled_keys;
				}

				rc = _get_next_KV(level_sc);
				if (rc == END_OF_DATABASE) {
					if (!spill_task_desc->standalone) {
						spill_task_desc->spill_task_status = SEND_SPILL_COMPLETE;
						break;
					} else {
						spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
						break;
					}
				}
			}

			if (!spill_task_desc->standalone) {
				*(uint32_t *)spill_buffer_msg->data = num_of_spilled_keys;
				if (send_rdma_message(spill_task_desc->region->replica_next_control_con,
						      spill_buffer_msg) != KREON_SUCCESS) {
					DPRINT("FATAL failed message\n");
					exit(EXIT_FAILURE);
				} else {
					//DPRINT("MASTER: Just send buffer for spill with keys %d\n",num_of_spilled_keys);
				}
			}

			break;

		case CLOSE_SPILL_BUFFER:

			_close_spill_buffer_scanner(level_sc, spill_task_desc->spill_req->src_root);
			/*sanity check
					if(spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
					printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
					exit(EXIT_FAILURE);
					}
					*/

			/*Clean up code, Free the buffer tree was occupying. free_block() used intentionally*/
			__sync_fetch_and_sub(&spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
						      .outstanding_spill_ops,
					     1);
			assert(spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
				       .outstanding_spill_ops == 0);

			if (spill_task_desc->region->db->db_desc->levels[spill_req->src_level].outstanding_spill_ops ==
			    0) {
				seg_free_level(spill_task_desc->region->db, spill_req->src_level, spill_req->src_tree);
				if (spill_req->src_level == 0) {
					spill_task_desc->region->db->db_desc->levels[0].level_size = 0;
					spill_task_desc->region->db->db_desc->L0_start_log_offset = spill_req->l0_end;
				}
				spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
					.tree_status[spill_req->src_tree] = NO_SPILLING;
			}
			free(spill_task_desc);
			log_info("MASTER spill finished and cleaned remains\n");
			return;

		case SEND_SPILL_COMPLETE:
			assert(spill_task_desc->region->replica_next_control_con != NULL);

			region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;

			msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
						      20 + region_key_len, SPILL_COMPLETE, ASYNCHRONOUS, 0,
						      &spill_task_desc->task);
			if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}

			DPRINT("MASTER: Sending SPILL_COMPLETE message to REPLICA\n");
			spill_task_desc->task.allocation_status = ALLOCATION_START;

			addr = msg->data;
			*(uint32_t *)addr = region_key_len;
			addr += sizeof(int32_t);
			memcpy(addr, spill_task_desc->region->ID_region.minimum_range + sizeof(uint32_t),
			       region_key_len);
			addr += region_key_len;
			*(uint64_t *)addr = spill_task_desc->spill_req.l0_start;
			addr += sizeof(uint64_t);
			*(uint64_t *)addr = spill_task_desc->spill_req.l0_end;
			addr += sizeof(uint64_t);
			msg->next = addr;
			msg->request_message_local_addr = msg;
			msg->reply_message = NULL;
			if (send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) !=
			    KREON_SUCCESS) {
				DPRINT("FATAL to send spill complete message\n");
				exit(EXIT_FAILURE);
			}
			spill_task_desc->spill_task_status = WAIT_FOR_SPILL_COMPLETE_REPLY;
			break;

		case WAIT_FOR_SPILL_COMPLETE_REPLY:
			//DPRINT("MASTER: Waiting for SPILL_COMPLETE reply\n");
			if (msg->reply_message == NULL) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}
			reply = (tu_data_message *)msg->reply_message;

			if (reply == NULL) {
				DPRINT("FATAL reply to spill buffer request is NULL\n");
				exit(EXIT_FAILURE);
			}

			if (reply->error_code == KREON_OK) {
				DPRINT("Replica completed remote spill\n");
				free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
				spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
				/*DO THE CLEANINING HERE, and exit thread*/
				DPRINT("Master: Replica informed that it finished its spill\n");
				break;
			} else if (reply->error_code == REPLICA_PENDING_SPILL) {
				DPRINT("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
				exit(EXIT_FAILURE);
			} else {
				DPRINT("Unknown spill completion code\n");
				exit(EXIT_FAILURE);
			}
		default:
			DPRINT("FATAL unkown state for spill task\n");
			exit(EXIT_FAILURE);
		}
	}
#endif
}

#ifdef TIERING
void tiering_compaction_check(_tucana_region_S *region, int level_id)
{
	tiering_compaction_request *request;
	db_descriptor *db_desc = region->db->db_desc;
	int level_max_capacity = 4;
	int level_size = 0;
	int i;

	/*check if level 1 capacity is full*/
	for (i = 0; i < level_max_capacity; i++) {
		if (db_desc->replica_forest.tree_roots[(level_id * level_max_capacity) + i] != NULL) {
			++level_size;
		}
	}

	if (level_size >= level_max_capacity) {
		request = (tiering_compaction_request *)malloc(sizeof(tiering_compaction_request));
		request->region = region;
		request->level_id = 0;
		DPRINT("REPLICA: Time for a tiering compaction\n");
		db_desc->db_mode = BACKUP_DB_TIERING_COMPACTION;
		pthread_setname_np(request->tiering_compaction_context, "replica_tiering_worker");
		if (pthread_create(&request->tiering_compaction_context, NULL, (void *)tiering_compaction_worker,
				   (void *)request) != 0) {
			DPRINT("FATAL: error spawning tiering compaction worker\n");
			exit(EXIT_FAILURE);
		}
	}
}

void tiering_compaction_worker(void *_tiering_request)
{
	tiering_compaction_request *request;
	min_heap *heap = create_and_initialize_heap(TIERING_MAX_CAPACITY);
	min_heap_node node;
	uint64_t total_keys_to_compact;
	uint64_t actual_compacted_keys;
	int destination_tree_id;
	int i;
	int rc;
	int scanner_id;
	int empty_scanners_num = 0;

	request = (tiering_compaction_request *)_tiering_request;

	level_scanner **scanners = (level_scanner **)alloca(sizeof(level_scanner *) * TIERING_MAX_CAPACITY);
	total_keys_to_compact = 0;
	actual_compacted_keys = 0;

	for (i = 0; i < TIERING_MAX_CAPACITY; i++) {
		total_keys_to_compact += request->region->db->db_desc->replica_forest
						 .total_keys_per_tree[(request->level_id * TIERING_MAX_CAPACITY) + i];
		scanners[i] =
			_init_spill_buffer_scanner(request->region->db,
						   request->region->db->db_desc->replica_forest
							   .tree_roots[(request->level_id * TIERING_MAX_CAPACITY) + i],
						   NULL);
		add_to_min_heap(heap, scanners[i]->keyValue, KV_PREFIX, (request->level_id * TIERING_MAX_CAPACITY) + i);
	}
	/*now find an available tree in the id+1 level*/
	destination_tree_id = -1;
	for (i = 0; i < TIERING_MAX_CAPACITY; i++) {
		if (request->region->db->db_desc->replica_forest
			    .tree_roots[((request->level_id + 1) * TIERING_MAX_CAPACITY) + i] == NULL) {
			destination_tree_id = ((request->level_id + 1) * TIERING_MAX_CAPACITY) + i;
			break;
		}
	}
	assert(destination_tree_id != -1);

	DPRINT("REPLICA: Tiering compaction from level %d to level %d number of keys to compact = %" PRIu64 "\n",
	       request->level_id, request->level_id + 1, total_keys_to_compact);
	_calculate_btree_index_nodes(request->region, total_keys_to_compact);

	while (empty_scanners_num > 0) {
		node = pop_min(heap);
		++actual_compacted_keys;
		append_entry_to_leaf_node(request->region, node.keyValue + PREFIX_SIZE, node.keyValue,
					  destination_tree_id);
		scanner_id = node.tree_id - (request->level_id * TIERING_MAX_CAPACITY);
		rc = _get_next_KV(scanners[scanner_id]);
		if (rc == END_OF_DATABASE) {
			scanners[scanner_id] = NULL;
			++empty_scanners_num;
		}
	}
	assert(actual_compacted_keys == total_keys_to_compact);
	request->region->db->db_desc->replica_forest.tree_status[destination_tree_id] = READY_TO_PERSIST;
	DPRINT("REPLICA: Tiering compaction from level to level maybe a snapshot now? XXX TODO XXX\n");
	request->region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;

	tiering_compaction_check(request->region, request->level_id + 1);
	free(_tiering_request);
}
#endif

int _init_replica_rdma_connections(struct _tucana_region_S *S_tu_region)
{
	if (S_tu_region->n_replicas > 1 && S_tu_region->replica_next_data_con == NULL) {
		if (S_tu_region->db->db_desc->db_mode != PRIMARY_DB) {
			//Not the primary let the primary init the connections;
			return KREON_SUCCESS;
		}
		if (!S_tu_region->replica_next_net) {
			log_fatal("uninitialized network structure for region %u\n", S_tu_region->ID_region.ID);
			exit(EXIT_FAILURE);
		}

		if (!S_tu_region->replica_next_net->IPs) {
			log_info("Uninitialized replica_next_net->IPs field");
		}

		log_info("MASTER: Creating replica connections for region range %s",
			 S_tu_region->ID_region.minimum_range + 4);

		if (SE_REPLICA_NUM_SEGMENTS <= 0) {
			log_fatal("Cannot set SE_REPLICA_NUM_SEGMENTS to a value less than 1!");
			exit(EXIT_FAILURE);
		}
		S_tu_region->replica_next_data_con =
			crdma_client_create_connection_list_hosts(regions_S.channel, S_tu_region->replica_next_net->IPs,
								  S_tu_region->replica_next_net->num_NICs,
								  MASTER_TO_REPLICA_DATA_CONNECTION);

		/*fix replica buffer staff*/
		S_tu_region->master_rep_buf = (se_replica_log_buffer *)malloc(sizeof(se_replica_log_buffer));
		/*valid range for start-end log offset this segment covers*/
		S_tu_region->master_rep_buf->bounds[0].start =
			S_tu_region->db->db_desc->KV_log_size - (S_tu_region->db->db_desc->KV_log_size % SEGMENT_SIZE);
		S_tu_region->master_rep_buf->bounds[0].end =
			S_tu_region->master_rep_buf->bounds[0].start + SEGMENT_SIZE;
		/*bytes written in this segment*/
		S_tu_region->master_rep_buf->seg_bufs[0].bytes_wr_per_seg = 0;

		S_tu_region->master_rep_buf->seg_bufs[0].rdma_local_buf =
			(se_rdma_buffer *)S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer;
		S_tu_region->master_rep_buf->seg_bufs[0].rdma_local_buf =
			(se_rdma_buffer *)S_tu_region->replica_next_data_con->rdma_memory_regions->remote_memory_buffer;

		int32_t i;
		for (i = 1; i < SE_REPLICA_NUM_SEGMENTS; i++) {
			S_tu_region->master_rep_buf->bounds[i].start = 0;
			S_tu_region->master_rep_buf->bounds[i].end = 0;
			S_tu_region->master_rep_buf->seg_bufs[i].bytes_wr_per_seg = 0;
			S_tu_region->master_rep_buf->seg_bufs[i].rdma_local_buf =
				(se_rdma_buffer *)((uint64_t)S_tu_region->master_rep_buf->seg_bufs[i - 1].rdma_local_buf +
						   sizeof(se_rdma_buffer));
			S_tu_region->master_rep_buf->seg_bufs[i].rdma_remote_buf =
				(se_rdma_buffer *)((uint64_t)S_tu_region->master_rep_buf->seg_bufs[i - 1].rdma_local_buf +
						   sizeof(se_rdma_buffer));
		}
		S_tu_region->replica_next_data_con->priority = HIGH_PRIORITY;

		log_info("MASTER: replica data connection created successfuly = %llu\n",
			 (LLU)S_tu_region->replica_next_data_con);

		log_info("MASTER: Creating control connection for region range %s\n",
			 S_tu_region->ID_region.minimum_range + 4);
		S_tu_region->replica_next_control_con =
			crdma_client_create_connection_list_hosts(regions_S.channel, S_tu_region->replica_next_net->IPs,
								  S_tu_region->replica_next_net->num_NICs,
								  MASTER_TO_REPLICA_DATA_CONNECTION);
		S_tu_region->replica_next_control_con->priority = HIGH_PRIORITY;
		log_info("MASTER: replica control connection created successfuly = %llu",
			 (LLU)S_tu_region->replica_next_control_con);
		/*allocate remote log buffer*/
		log_info("MASTER: Allocating and initializing remote log buffer");

		//S_tu_region->db->db_desc->log_buffer =
		//	S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer;

		tu_data_message *tmp =
			(tu_data_message *)
				S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_buffer;

		/*init message*/
		tmp->pay_len = 4096 + BUFFER_SEGMENT_SIZE;
		tmp->padding_and_tail = RDMA_LOG_BUFFER_PADDING + TU_TAIL_SIZE; //???
		DPRINT("TOTAL LOG BUFFER SIZE %d Padding %d\n", RDMA_TOTAL_LOG_BUFFER_SIZE, RDMA_LOG_BUFFER_PADDING);
		tmp->data = (void *)((uint64_t)tmp + TU_HEADER_SIZE);
		tmp->next = tmp->data;
		tmp->receive = TU_RDMA_REGULAR_MSG;
		/*set the tail to the proper value*/
		*(uint32_t *)((uint64_t)tmp + TU_HEADER_SIZE + 4096 + BUFFER_SEGMENT_SIZE + RDMA_LOG_BUFFER_PADDING) =
			TU_RDMA_REGULAR_MSG;
		tmp->type = FLUSH_SEGMENT;
		tmp->flags = SERVER_CATEGORY;

		tmp->local_offset = 0;
		tmp->remote_offset = 0;

		tmp->ack_arrived = KR_REP_PENDING;
		tmp->callback_function = NULL;
		tmp->request_message_local_addr = NULL;
		__sync_fetch_and_add(&S_tu_region->replica_next_data_con->pending_sent_messages, 1);
		/*set connection propeties with the replica
		 *	1. pin data and control conn to high priority
		 *	2. Reduce memory for control conn
		 */
		/*
			 DPRINT("Setting connection properties with the Replica");
			 set_connection_property_req * req;
			 tu_data_message * data_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST); 
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

			 tu_data_message * control_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST); 
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
void insert_kv_pair(_tucana_region_S *S_tu_region, tu_data_message *data_message, connection_rdma *rdma_conn,
		    kv_location *location, work_task *task, int wait)
{
	char *key;
	se_replica_log_segment *curr_seg;
	uint32_t key_length;
	uint32_t value_length;
	uint32_t kv_size;

	int32_t seg_id = -1;
	int32_t i = 0;

	void *rdma_src;
	void *rdma_dst;
	key = data_message->data;
	key_length = *(uint32_t *)key;

	value_length = *(uint32_t *)(key + sizeof(uint32_t) + key_length);
	kv_size = (2 * sizeof(uint32_t)) + key_length + value_length;
	location->rdma_key = rdma_conn->rdma_memory_regions->remote_memory_region->lkey;

	bt_insert_req req;

	/*############## fsm state logic follows ###################*/
	while (1) {
		switch (task->kreon_operation_status) {
		case APPEND_START:

			req.handle = S_tu_region->db;
			req.kv_size = kv_size;
			req.key_value_buf = data_message->data;
			req.level_id = 0;
			req.key_format = KV_FORMAT;
			req.append_to_log = 1;
			req.gc_request = 0;
			req.recovery_request = 0;
			req.segment_full_event = 0;
			_insert_key_value(&req);
			if (S_tu_region->replica_next_data_con != NULL) {
				/*We have a replica to feed*/
				if (req.segment_full_event) {
					/*find the log segment that corresponds to this full event*/
					seg_id = -1;
					for (i = 0; i < SE_REPLICA_NUM_SEGMENTS; i++) {
						if (S_tu_region->master_rep_buf->bounds[i].start <=
							    req.log_offset_full_event &&
						    S_tu_region->master_rep_buf->bounds[i].end >
							    req.log_offset_full_event) {
							seg_id = i;
							break;
						}
					}
					if (seg_id == -1) {
						log_fatal("Corrupted replica log buffer");
						exit(EXIT_FAILURE);
					}
					uint32_t next_buffer;
					uint8_t msg_type;
					if (seg_id == SE_REPLICA_NUM_SEGMENTS - 1) {
						next_buffer = 0;
						msg_type = FLUSH_SEGMENT_AND_RESET;
					} else {
						next_buffer = seg_id + 1;
						msg_type = FLUSH_SEGMENT;
					}

					/*Now,wait until next buffer is available, server spinning thread updates this field*/
					curr_seg = &S_tu_region->master_rep_buf->seg_bufs[next_buffer];
					spin_loop(&curr_seg->buffer_free, 1);
					/*mark it now as in use*/
					curr_seg->buffer_free = 0;
					/*fix its new boundaries*/
					S_tu_region->master_rep_buf->bounds[next_buffer].start =
						req.segment_id * SEGMENT_SIZE;
					S_tu_region->master_rep_buf->bounds[next_buffer].end =
						S_tu_region->master_rep_buf->bounds[next_buffer].start + SEGMENT_SIZE;

					/*ok others are ready to proceed, now let's wake up replica*/
					curr_seg = &S_tu_region->master_rep_buf->seg_bufs[seg_id];
					uint32_t bytes_threashold =
						SEGMENT_SIZE - (sizeof(segment_header) + req.log_padding);
					/*wait until all bytes of segment are written*/
					spin_loop(&curr_seg->bytes_wr_per_seg, bytes_threashold);
					/*prepare segment metadata for replica*/
					curr_seg->rdma_local_buf->metadata.master_segment = req.log_segment_addr;
					curr_seg->rdma_local_buf->metadata.end_of_log = req.end_of_log;
					curr_seg->rdma_local_buf->metadata.log_padding = req.log_padding;
					curr_seg->rdma_local_buf->metadata.segment_id = req.segment_id;
					strcpy(curr_seg->rdma_local_buf->metadata.region_key,
					       S_tu_region->ID_region.minimum_range);

					curr_seg->rdma_local_buf->msg.type = msg_type;
					curr_seg->rdma_local_buf->msg.receive = TU_RDMA_REGULAR_MSG;

					rdma_src = (void *)&curr_seg->rdma_local_buf->metadata;
					rdma_dst = (void *)&curr_seg->rdma_remote_buf->metadata;
					/*send metadata to replica*/
					if (rdma_post_write(S_tu_region->replica_next_data_con->rdma_cm_id, rdma_src,
							    rdma_src, sizeof(se_seg_metadata),
							    S_tu_region->replica_next_data_con->rdma_memory_regions
								    ->local_memory_region,
							    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
							    S_tu_region->replica_next_data_con->peer_mr->rkey) != 0) {
						log_fatal("Writing metadata of segment to replica failed!");
						exit(EXIT_FAILURE);
					}
					/*finally wake up replica*/
					rdma_src = (void *)&curr_seg->rdma_local_buf->msg;
					rdma_dst = (void *)&curr_seg->rdma_remote_buf->msg;
					if (rdma_post_write(S_tu_region->replica_next_data_con->rdma_cm_id, rdma_src,
							    rdma_src, sizeof(struct tu_data_message),
							    S_tu_region->replica_next_data_con->rdma_memory_regions
								    ->local_memory_region,
							    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
							    S_tu_region->replica_next_data_con->peer_mr->rkey) != 0) {
						log_fatal("Waking up replica failed!");
						exit(EXIT_FAILURE);
					}
				}

				/*Common ins path, find the log segment that corresponds to this full event*/
				seg_id = -1;
				i = 0;
				while (1) {
					if (S_tu_region->master_rep_buf->bounds[i].start <= req.log_offset &&
					    S_tu_region->master_rep_buf->bounds[i].end > req.log_offset) {
						seg_id = i;
						break;
					}
					if (++i == SE_REPLICA_NUM_SEGMENTS)
						i = 0;
				}

				curr_seg = &S_tu_region->master_rep_buf->seg_bufs[seg_id];
				rdma_src = (void *)&curr_seg->rdma_local_buf->seg[req.log_offset % SEGMENT_SIZE];

				rdma_dst = (void *)&curr_seg->rdma_remote_buf->seg[req.log_offset % SEGMENT_SIZE];
				memcpy(rdma_src, req.key_value_buf, req.kv_size);
				/*now next step to the remote*/
				if (rdma_post_write(
					    S_tu_region->replica_next_data_con->rdma_cm_id, rdma_src, rdma_src,
					    req.kv_size,
					    S_tu_region->replica_next_data_con->rdma_memory_regions->local_memory_region,
					    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
					    S_tu_region->replica_next_data_con->peer_mr->rkey) != 0) {
					log_fatal("Writing to replica failed!");
					exit(EXIT_FAILURE);
				}
				/* ok add the bytes*/
				__sync_fetch_and_add(&curr_seg->bytes_wr_per_seg, req.kv_size);
			}
			task->kreon_operation_status = APPEND_COMPLETE;
			return;
		case CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK:
			log_fatal("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA:
			log_fatal("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case PERFORM_SPILL_CHECK:
		case WAIT_FOR_SPILL_START:
			log_warn("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case APPEND_COMPLETE:
		case ALLOCATION_START:
		case CHECK_FOR_RESET_BUFFER_ACK:
		case CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE:
		case ALLOCATION_SUCCESS:
		case TASK_START:
		case TASK_COMPLETED:
		default:
			DPRINT("FATAL Ended up in faulty state\n");
			assert(0);
			return;
		}
	}
}

//<<<<<<< HEAD
struct tu_data_message *Server_Scan_MulipleRegions_RDMA(tu_data_message *data_message, void *connection)
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
	uint32_t kv_get_count = *(uint32_t *)data_message->data;
	void *start_key_buff = data_message->data + sizeof(uint32_t);
	void *stop_key_buff = start_key_buff + sizeof(uint32_t) + *(uint32_t *)start_key_buff;
	_tucana_region_S *S_tu_region;
	struct tu_data_message *reply_data_message;
	void *kv_buffer;
	uint32_t kv_buffer_len;
	char seek_mode = (data_message->value) ? GREATER_OR_EQUAL : GREATER;

	/*DPRINT("Requested %"PRId32" kv pairs\n", kv_get_count);*/
	/*DPRINT("Start Key %s:%"PRId32"\n", (char*)(start_key_buff + sizeof(uint32_t)), *(uint32_t*)start_key_buff);*/
	/*DPRINT("Stop Key %s:%"PRId32"\n", (char*)(stop_key_buff + sizeof(uint32_t)), *(uint32_t*)stop_key_buff);*/
	/*fflush(stdout);*/

	S_tu_region = find_region(start_key_buff + sizeof(uint32_t), *(uint32_t *)start_key_buff);
	if (S_tu_region == NULL) {
		DPRINT("ERROR: Region not found for key %s\n", start_key_buff + sizeof(uint32_t));
		return NULL;
	}

	//Buffer format: kv_buffer = [total_kv_pairs, (key_length, key, value_length, value)*]
	//FIXME there should be an upper limit to the kv_buffer_len
	kv_buffer_len = multiget_calc_kv_size(S_tu_region->db, start_key_buff, stop_key_buff, kv_get_count, seek_mode);
	reply_data_message = allocate_rdma_message((struct connection_rdma *)connection, kv_buffer_len, SCAN_REQUEST);
	kv_buffer = reply_data_message->data;
	int rc = multi_get(S_tu_region->db, start_key_buff, stop_key_buff, kv_buffer, kv_buffer_len, kv_get_count,
			   seek_mode);
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
void handle_task(void *__task)
{
	work_task *task = (work_task *)__task;
	kv_location location;
	struct connection_rdma *rdma_conn;

	_tucana_region_S *S_tu_region;
	int tries;
	void *region_key;
	//leave it for later
	void *addr;
	uint64_t log_address;
	void *master_segment;
	void *local_log_addr;
	int32_t num_entries;

	void *key = NULL;
	void *value;
	uint32_t key_length = 0;

	/*unboxing the arguments*/
	S_tu_region = NULL;
	task->reply_msg = NULL;
	rdma_conn = task->conn;

	if (task->msg == NULL) {
		DPRINT("FATAL NULL msg in request\n");
		exit(EXIT_FAILURE);
	}

	stats_update(task->thread_id);
	switch (task->msg->type) {
	//gesalous leave it for later
#if 0
	case SPILL_INIT:

		task->reply_msg = __allocate_rdma_message(task->conn, 0, SPILL_INIT_ACK, ASYNCHRONOUS, 0, task);
		if (task->allocation_status != ALLOCATION_SUCCESS) {
			return;
		}
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

		region_key = task->msg->data;
		S_tu_region = find_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);

		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB &&
		       S_tu_region->db->db_desc->db_mode == BACKUP_DB_NO_PENDING_SPILL);
		assert(task->conn->pending_received_messages == 1 && rdma_conn->pending_sent_messages == 1);

		DPRINT("REPLICA: Master requests a remote spill  for region %s\n", region_key + sizeof(uint32_t));
		S_tu_region->db->db_desc->db_mode = BACKUP_DB_PENDING_SPILL;
		S_tu_region->db->db_desc->spill_segment_table = S_tu_region->db->db_desc->backup_segment_table;
		S_tu_region->db->db_desc->backup_segment_table = NULL;
		map_entry *s = (map_entry *)malloc(sizeof(map_entry));
		s->key = (uint64_t)S_tu_region->db->db_desc->last_master_segment;
		s->value = (uint64_t)S_tu_region->db->db_desc->last_local_mapping;
		HASH_ADD_PTR(S_tu_region->db->db_desc->backup_segment_table, key, s);

		/*finally find an empty tree in the forest to insert the new spill*/
		S_tu_region->current_active_tree_in_the_forest = -1;
		int i;
		for (i = 0; i < MAX_FOREST_SIZE; i++) {
			if (S_tu_region->db->db_desc->replica_forest.tree_status[i] == NOT_USED) {
				DPRINT("REPLICA: Initiating remote spill for tree_id %d in the forest\n", i);
				S_tu_region->db->db_desc->replica_forest.tree_status[i] = IN_TRANSIT_DIRTY;
				S_tu_region->current_active_tree_in_the_forest = i;
				break;
			}
		}
		_calculate_btree_index_nodes(S_tu_region,
					     *(uint64_t *)(task->msg->data + (task->msg->pay_len - sizeof(uint64_t))));
		if (S_tu_region->current_active_tree_in_the_forest == -1) {
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
		if (task->allocation_status != ALLOCATION_SUCCESS) {
			return;
		}
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

		region_key = task->msg->data;
		S_tu_region = find_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);
		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB);
		/*clear all mappings*/
		map_entry *current, *tmp;
		HASH_ITER(hh, S_tu_region->db->db_desc->spill_segment_table, current, tmp)
		{
			HASH_DEL(S_tu_region->db->db_desc->spill_segment_table,
				 current); /* delete it (users advances to next) */
			free(current); /* free it */
		}

		task->reply_msg->error_code = KREON_OK;
		DPRINT("REPLICA: completed remote spill snapshotting volume, ommiting CAUTION\n");
		//snapshot(S_tu_region->db->volume_desc);
		S_tu_region->db->db_desc->L0_end_log_offset = *(uint64_t *)task->msg->data;
		S_tu_region->db->db_desc->L0_start_log_offset = *(uint64_t *)task->msg->data;
		int j;
		for (j = MAX_TREE_HEIGHT - 1; j >= 0; j--) {
			if (S_tu_region->last_node_per_level[j] != NULL) {
				S_tu_region->last_node_per_level[j]->type = rootNode;
				S_tu_region->db->db_desc->replica_forest
					.tree_roots[S_tu_region->current_active_tree_in_the_forest] =
					S_tu_region->last_node_per_level[j];
				break;
			}
		} /*snapshot maybe?, snapshot is for replica thus does not include network communication*/
		S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] =
			READY_TO_PERSIST;
		DPRINT("REPLICA: Spill complete maybe a snapshot now? XXX TODO XXX\n");
		S_tu_region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		task->kreon_operation_status = SPILL_COMPLETE_END;
		task->overall_status = TASK_COMPLETED;
		free_rdma_received_message(task->conn, task->msg);
		break;

	case SPILL_BUFFER_REQUEST:

		/*Nothing to do here for suspend/resume because in this version
				it does not send a reply to the client*/
		region_key = task->msg->data + sizeof(uint32_t);
		S_tu_region = find_region(region_key, PREFIX_SIZE);
		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB &&
		       S_tu_region->db->db_desc->db_mode == BACKUP_DB_PENDING_SPILL);
		/*iterate values*/
		addr = task->msg->data;
		num_entries = *(uint32_t *)(addr);
		addr += sizeof(uint32_t);
		//DPRINT("\tREPLICA: applying remote spill buffer at replica num entries %d\n",num_entries);
		S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] =
			IN_TRANSIT_DIRTY;
		for (i = 0; i < num_entries; i++) {
			/*rewrite mapping, PREFIX stays the same*/
			log_address = (*(uint64_t *)(addr + PREFIX_SIZE));
			master_segment = (void *)log_address - ((uint64_t)log_address % BUFFER_SEGMENT_SIZE);
			//local_log_addr = (void *) clht_get(handle->db_desc->backup_segment_table->ht, (clht_addr_t) master_segment);
			map_entry *s;
			SPIN_LOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
			HASH_FIND_PTR(S_tu_region->db->db_desc->spill_segment_table, &master_segment, s);
			if (s == NULL) {
				DPRINT("REPLICA: FATAL mapping is missing for master segment %llu\n",
				       (LLU)master_segment);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
			SPIN_UNLOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
			/*add the offset*/
			local_log_addr = (void *)MAPPED + s->value + (log_address % BUFFER_SEGMENT_SIZE);
			*(uint64_t *)(addr + PREFIX_SIZE) = (uint64_t)local_log_addr;

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
			_insert_index_entry(s_tu_region->db, &location,
					    INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (4 << 8) | BACKUP_OPERATION);
#else
			/*tiering*/
			append_entry_to_leaf_node(S_tu_region, (void *)(*(uint64_t *)(addr + PREFIX_SIZE)), addr,
						  S_tu_region->current_active_tree_in_the_forest);
#endif
			addr += (PREFIX_SIZE + sizeof(uint64_t));
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
#endif
	case RESET_BUFFER:
		//DPRINT("Got reset buffer request pending received messages are %llu\n", (LLU)task->conn->pending_received_messages);
		if (task->kreon_operation_status == RESET_BUFFER_START) {
			/*Have all requests been completed for this connection?*/
			tries = 0;
			while (task->conn->pending_received_messages != 0) {
				if (++tries >= NUM_OF_TRIES) {
					//DPRINT("\tWaiting for processing of received messages to send RESET_BUFFER_ACK pending messages %llu\n",(LLU)task->conn->pending_received_messages);
					return;
				}
			}
		}
		_send_reset_buffer_ack(task->conn);
		task->kreon_operation_status = RESET_BUFFER_COMPLETE;
		_zero_rendezvous_locations(task->msg);
		_update_rendezvous_location(task->conn, 0); /*"0" indicates RESET*/
		task->overall_status = TASK_COMPLETED;
		break;
	case PUT_REQUEST:
	case TU_UPDATE:
		/* *
			 * retrieve region handle for the corresponding key, find_region
			 * initiates internally rdma connections if needed
			 * */

		key = task->msg->data;
		key_length = *(uint32_t *)key;
		assert(key_length != 0);
		S_tu_region = find_region(key + sizeof(uint32_t), *(uint32_t *)key);
		if (S_tu_region == NULL) {
			DPRINT("FATAL:  Region not found for key size %u:%s\n", key_length, key + sizeof(uint32_t));
			exit(EXIT_FAILURE);
		}
		task->region = (void *)S_tu_region;

		if (task->kreon_operation_status != APPEND_COMPLETE) {
			insert_kv_pair(S_tu_region, task->msg, task->conn, &location, task,
				       DO_NOT_WAIT_REPLICA_TO_COMMIT);

			if (task->kreon_operation_status == APPEND_COMPLETE) {
				task->allocation_status = ALLOCATION_START;
				//free_rdma_received_message(task->conn, task->msg);
			} else {
				return;
			}
		}

		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/
		if (task->msg->reply_length >= TU_HEADER_SIZE) {
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
			task->reply_msg->ack_arrived = KR_REP_PENDING;
			task->reply_msg->callback_function = NULL;
			task->reply_msg->request_message_local_addr = NULL;

		} else {
			DPRINT("SERVER: FATAL mr CLIENT reply space not enough  size %" PRIu32 " FIX XXX TODO XXX\n",
			       task->msg->reply_length);
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
		if (task->kreon_operation_status == GET_START) {
			key = (char *)task->msg->data;
			key_length = *(uint32_t *)key;
			S_tu_region = find_region(key + sizeof(uint32_t), key_length);

			if (S_tu_region == NULL) {
				DPRINT("ERROR: Region not found for key %s\n", key);
				assert(0);
				return;
			}
			//#if !OMMIT_IO_IN_THE_INSERT_PATH
			//value  = find_key(S_tu_region->db, key+sizeof(uint32_t), key_length);
			//#else
			value = (void *)alloca(1024);
			*(uint32_t *)value = 1020;
			//#endif

			if (value == NULL) {
				DPRINT(" FATAL key not found key %s : length %u region min_key %s max key %s\n",
				       key + sizeof(uint32_t), key_length,
				       S_tu_region->ID_region.minimum_range + sizeof(int),
				       S_tu_region->ID_region.maximum_range + sizeof(int));
				exit(EXIT_FAILURE);
			}
			//task->kreon_operation_status = GET_COMPLETE;
			task->intermediate_buffer = NULL;
		}
		/*allocate rdma message and reply to client phase*/
		if (task->intermediate_buffer == NULL) {
			task->reply_msg = __allocate_rdma_message(task->conn, *(uint32_t *)value + sizeof(uint32_t),
								  TU_GET_REPLY, ASYNCHRONOUS, 0, task);
		} else {
			task->reply_msg =
				__allocate_rdma_message(task->conn,
							*(uint32_t *)task->intermediate_buffer + sizeof(uint32_t),
							TU_GET_REPLY, ASYNCHRONOUS, 0, task);
		}

		if (task->allocation_status != ALLOCATION_SUCCESS) {
			//DPRINT("Retry allocating RDMA buffer for GET reply\n");
			if (task->intermediate_buffer == NULL) {
				/*store intermediate result*/
				//task->intermediate_buffer = malloc(*(uint32_t *)value+sizeof(uint32_t));
				//memcpy(task->intermediate_buffer,value,*(uint32_t *)value+sizeof(uint32_t));
			}
			return;
		}

		if (task->intermediate_buffer == NULL) {
			*(uint32_t *)task->reply_msg->data = *(uint32_t *)value;
			if (push_buffer_in_tu_data_message(task->reply_msg, value + sizeof(uint32_t),
							   *(uint32_t *)value) != KREON_SUCCESS) {
				DPRINT("FATAL push buffer failed\n");
				exit(EXIT_FAILURE);
			}
		} else {
			*(uint32_t *)task->reply_msg->data = *(uint32_t *)task->intermediate_buffer;
			if (push_buffer_in_tu_data_message(task->reply_msg,
							   task->intermediate_buffer + sizeof(uint32_t),
							   *(uint32_t *)task->intermediate_buffer) != KREON_SUCCESS) {
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
		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/
		if (task->msg->reply_length >= TU_HEADER_SIZE) {
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

			task->reply_msg->ack_arrived = KR_REP_PENDING;
			task->reply_msg->callback_function = NULL;
			task->reply_msg->request_message_local_addr = NULL;
			task->overall_status = TASK_COMPLETED;
		} else {
			DPRINT("SERVER: FATAL mr CLIENT reply space not enough  size %" PRIu32 " FIX XXX TODO XXX\n",
			       task->msg->reply_length);
			exit(EXIT_FAILURE);
		}
		/*piggyback info for use with the client*/
		task->reply_msg->request_message_local_addr = task->notification_addr;
		break;

	case TEST_REQUEST_FETCH_PAYLOAD:
		task->reply_msg =
			__allocate_rdma_message(task->conn, 1024, TEST_REPLY_FETCH_PAYLOAD, ASYNCHRONOUS, 0, task);
		if (task->allocation_status != ALLOCATION_SUCCESS) {
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
		if (task->kreon_operation_status == FLUSH_SEGMENT_START) {
			//DPRINT("**** Ordered from master to perform a flush ****\n");
			/*ommit header find the corresponding region*/
			region_key = (void *)(task->msg->data + 32);
			_tucana_region_S *s_tu_region =
				find_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);

			if (s_tu_region == NULL) {
				DPRINT("FATAL region with min key %s not found\n", region_key);
				exit(EXIT_FAILURE);
			}
			if (s_tu_region->db->db_desc->db_mode == PRIMARY_DB) {
				DPRINT("FATAL flushing primary db?\n");
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}

#if !OMMIT_IO_IN_THE_INSERT_PATH
			void *master_segment = (void *)*(uint64_t *)((uint64_t)task->msg->data);
			uint64_t end_of_log = *(uint64_t *)((uint64_t)task->msg->data + (sizeof(uint64_t)));
			uint64_t bytes_to_pad = *(uint64_t *)((uint64_t)task->msg->data + (2 * sizeof(uint64_t)));
			uint64_t segment_id = *(uint64_t *)((uint64_t)task->msg->data + (3 * sizeof(uint64_t)));

			void *buffer = task->msg->data + 4096;
			//DPRINT("REPLICA: master segment %llu end of log %llu bytes to pad %llu segment_id %llu\n",(LLU)master_segment,(LLU)end_of_log,(LLU)bytes_to_pad,(LLU)segment_id);
			flush_replica_log_buffer(s_tu_region->db, (segment_header *)master_segment, buffer, end_of_log,
						 bytes_to_pad, segment_id);
#endif
			free_rdma_received_message(task->conn, task->msg);
			task->kreon_operation_status = FLUSH_SEGMENT_COMPLETE;
		}

		/*Since reply message is of fixed size we allocate it first*/

		task->reply_msg = (tu_data_message *)(task->conn->rdma_memory_regions->local_memory_buffer +
							task->conn->offset);
		/*init message*/
		task->reply_msg->pay_len = 0;
		task->reply_msg->padding_and_tail = 0;
		task->reply_msg->data = NULL;
		task->reply_msg->next = task->reply_msg->data;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->flags = SERVER_CATEGORY;

		task->reply_msg->local_offset = task->conn->offset;
		task->reply_msg->remote_offset = task->conn->offset;
		task->reply_msg->ack_arrived = KR_REP_PENDING;
		task->reply_msg->callback_function = NULL;
		task->reply_msg->request_message_local_addr = NULL;

		if (task->msg->type == FLUSH_SEGMENT) {
			task->reply_msg->type = FLUSH_SEGMENT_ACK;
			task->conn->offset += MESSAGE_SEGMENT_SIZE;
		} else {
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
void _str_split(char *a_str, const char a_delim, uint64_t **core_vector, uint32_t *num_of_cores)
{
	//DPRINT("%s\n",a_str);
	char *tmp = alloca(128);
	char **result = 0;
	size_t count = 0;

	char *last_comma = 0;

	char delim[2];
	int i;

	strcpy(tmp, a_str);
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp) {
		if (a_delim == *tmp) {
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

	result = malloc(sizeof(char *) * count);

	*num_of_cores = count - 1;
	*core_vector = (uint64_t *)malloc(sizeof(uint64_t) * count);
	i = 0;

	if (result) {
		size_t idx = 0;
		char *token = strtok(a_str, delim);

		while (token) {
			assert(idx < count);
			*(result + idx++) = strdup(token);
			if (*token != 0x00) {
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
	globals_set_zk_host(zookeeper_host_port);
	RDMA_LOG_BUFFER_PADDING = 0;
	RDMA_TOTAL_LOG_BUFFER_SIZE = TU_HEADER_SIZE + BUFFER_SEGMENT_SIZE + 4096 + TU_TAIL_SIZE;

	if (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE != 0) {
		/*need to pad */
		RDMA_LOG_BUFFER_PADDING = (MESSAGE_SEGMENT_SIZE - (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE));
		RDMA_TOTAL_LOG_BUFFER_SIZE += RDMA_LOG_BUFFER_PADDING;
		assert(RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE == 0);
	}

	if (argc == 6) {
		int rdma_port = strtol(argv[1], NULL, 10);
		globals_set_RDMA_connection_port(rdma_port);
		Device_name = argv[2];
		Device_size = strtol(argv[3], NULL, 10) * 1024 * 1024 * 1024;

		_str_split(argv[4], ',', &spinning_threads_core_ids, &num_of_spinning_threads);
		_str_split(argv[5], ',', &worker_threads_core_ids, &num_of_worker_threads);
	} else {
		DPRINT("Error: usage: ./tucanaserver <port number> <device name> <device size in GB> <spinning thread core ids>  <working thread core ids>\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_of_spinning_threads; i++) {
		DPRINT(" spinning thread core[%d] = %llu\n", i, (LLU)spinning_threads_core_ids[i]);
	}
	for (i = 0; i < num_of_worker_threads; i++) {
		DPRINT(" worker thread core[%d] = %llu\n", i, (LLU)worker_threads_core_ids[i]);
	}
	assert(num_of_worker_threads % num_of_spinning_threads == 0);
	WORKER_THREADS_PER_SPINNING_THREAD = (num_of_worker_threads / num_of_spinning_threads);

	DPRINT("Set pool size for each spinning thread to %u\n", WORKER_THREADS_PER_SPINNING_THREAD);
	struct sigaction sa;
	sa.sa_handler = tu_ec_sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	int ret = sigaction(SIGINT, &sa, NULL);
	assert(ret == 0);

	srand(time(NULL));
	pthread_mutex_init(&reg_lock, NULL);

	//i = ibv_fork_init();
	//if(i){
	//	DPRINT("FATAL call failed reason follows-->\n");
	//	perror("Reason: ");
	//	exit(EXIT_FAILURE);
	//}

	DPRINT("initializing storage device:%s\n", Device_name);
	Init_Storage_Device(&storage_dev, Device_name, (uint64_t)Device_size);
	DPRINT("initializing zookeeper server\n");
	Init_tuzk_server(&tuzk_S);
	DPRINT("initializing regionse?\n");
	Init_RegionsSe();
#if TU_RDMA
	Set_OnConnection_Create_Function(regions_S.channel, handle_task);
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
