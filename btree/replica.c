#include <math.h>
#include <sys/syscall.h>

//#include "../CLHT/include/clht.h"
//#include "../CLHT/external/include/ssmem.h"
#include "../allocator/allocator.h"


#define NUM_BUCKETS 1024
#define SIZE(x) *(uint32_t *)x
#define SE floor(log2(BUFFER_SEGMENT_SIZE) + 1);
#define LEVEL_1 4


uint64_t segment_mask = 0;
uint64_t spill_epoch = 0;
uint32_t current_segment_key = 0;


void init_backup_db_segment_table(db_handle * handle){
	int max_bits;
	if(handle->db_desc->db_mode != PRIMARY_DB){
		/*handle->db_desc->backup_segment_table = clht_create(NUM_BUCKETS);*/
		handle->db_desc->backup_segment_table = NULL;
		if(segment_mask == 0){
			segment_mask = 0xFFFFFFFFFFFFFFFF;
			max_bits = floor(log2(BUFFER_SEGMENT_SIZE) + 1);
			segment_mask = ((segment_mask >> max_bits)<<max_bits);
		}
	} else
		handle->db_desc->backup_segment_table = NULL;
	return;
}


/*void register_thread(db_handle * handle, int thread_id){
	if(handle != NULL && handle->db_desc->db_mode != PRIMARY_DB){
		if(handle == NULL){
			printf("[%s:%s:%d null handle?\n",__FILE__,__func__,__LINE__);
			return;
		}
		clht_gc_thread_init(handle->db_desc->backup_segment_table, thread_id);
		thread_local_id = thread_id;
	}
	return;
}*/


int apply_proposal(db_handle *handle, void * kv_proposal, char KEY_VALUE_FORMAT, void * master_log_segment){
#if 0
	void * addr;
	block_header * current_log_segment;
	//extract address
	//uint32_t key_size;
	//uint32_t val_size;
	if(handle->db_desc->db_mode != PRIMARY_DB){
		//key_size = SIZE(kv_proposal);
		//addr = kv_proposal + sizeof(uint32_t) + key_size;

		//val_size = SIZE(addr);
		//pthread_mutex_lock(&(handle->db_desc->lock_log));
		/*check if there is need to re-register, false positives may be present
		if(thread_local_spill_epoch != spill_epoch){
			thread_local_spill_epoch = spill_epoch;
			clht_gc_thread_init(handle->db_desc->backup_segment_table, thread_local_id);
		}
		*/
		/*has log segment of master changed?*/
		current_log_segment = (handle->db_desc->g_last_kv_log);
		handle->db_desc->dirty = 0x01;
		addr = append_key_value_to_log(handle, kv_proposal,KEY_VALUE_FORMAT);
		//pthread_mutex_unlock(&(handle->db_desc->lock_log));

		/*segment ok, add the mapping*/
		if( current_log_segment == handle->db_desc->g_first_kv_log || current_log_segment != handle->db_desc->g_last_kv_log){
			//printf("[%s:%s:%d] segment changed!\n",__FILE__,__func__,__LINE__);
			current_log_segment = handle->db_desc->g_last_kv_log;
			master_log_segment  = master_log_segment - ((uint64_t)master_log_segment % BUFFER_SEGMENT_SIZE);
			//clht_put(handle->db_desc->backup_segment_table,(uint64_t)master_log_segment, (clht_val_t )((uint64_t)current_log_segment-MAPPED));
			 map_entry *s = (map_entry *)malloc(sizeof(map_entry));
			s->key = (uint64_t)master_log_segment;
			HASH_ADD_INT(handle->db_desc->backup_segment_table,key,s);
			s->value = (uint64_t)current_log_segment - MAPPED;
			printf("[%s:%s:%d] adding address mapping master: %llu current_log_segment = %llu\n",__FILE__,__func__,__LINE__,(LLU)master_log_segment, (LLU)current_log_segment-MAPPED);
		}
	}
#endif
	return KREON_OK;
}



void apply_spill_buffer(db_handle *handle, void * buffer){
#if 0
	/*iterate values*/
	uint64_t log_address;
	void * master_segment;
	//void * local_log_addr;
	void * addr;
	uint32_t buffer_size;

	addr = buffer + sizeof(uint32_t);
	buffer_size = SIZE(buffer);
	if(handle->db_desc->db_mode != PRIMARY_DB){
		int i=0;
		/*check if there is need to re-register, false positives may be present
		if(thread_local_spill_epoch != spill_epoch){
			thread_local_spill_epoch = spill_epoch;
			clht_gc_thread_init(handle->db_desc->backup_segment_table, thread_local_id);
		}*/

		for(i=0;i<buffer_size;i++){
			/*rewrite mapping, PREFIX stays the same*/
			log_address = (*(uint64_t *)(addr + PREFIX_SIZE));
			master_segment = (void *) log_address - ((uint64_t)log_address % BUFFER_SEGMENT_SIZE);
			//local_log_addr = (void *) clht_get(handle->db_desc->backup_segment_table->ht, (clht_addr_t) master_segment);
			map_entry *s;
			HASH_FIND_INT(handle->db_desc->backup_segment_table,&master_segment,s);
			if(s == NULL){
				printf("[%s:%s:%d] FATAL mapping is missing for master segment %llu\n",__FILE__,__func__,__LINE__,(LLU)master_segment);
				exit(EXIT_FAILURE);
			}
			printf("[%s:%s:%d] mapping remote log segment: %llu local: %llu\n",__FILE__,__func__,__LINE__,(LLU)master_segment,(LLU)local_log_addr);
			/*add the offset*/
			//local_log_addr += (log_address % BUFFER_SEGMENT_SIZE);
			*(uint64_t *)(addr+PREFIX_SIZE) = MAPPED + (uint64_t)local_log_addr;
			/*insert to local L1*/
			//printf("[%s:%s:%d] Local entry %d buffer_size %u key is %d:%s\n",__FILE__,__func__,__LINE__,i,buffer_size, *(int32_t *)(MAPPED+(uint64_t)log_address), (char *) (MAPPED+log_address+sizeof(uint32_t)));
			//printf("[%s:%s:%d] Replica entry %d buffer_size %u key is %u:%s\n",__FILE__,__func__,__LINE__,i,buffer_size, *(uint32_t *)(*(uint64_t *)(addr+PREFIX_SIZE)), (char *) (*(uint64_t *)(addr+PREFIX_SIZE))+sizeof(uint32_t));
			 _insert_key_value(handle, addr, LEVEL_1);
			 /*find the mapping*/
			addr += (PREFIX_SIZE+sizeof(uint64_t));
		}
	}
#endif
}

void init_remote_spill(db_handle *handle){
	if(handle->db_desc->db_mode != PRIMARY_DB){
		printf("[%s:%s:%d] initiating spill\n",__FILE__,__func__,__LINE__);
		handle->db_desc->db_mode = BACKUP_DB_PENDING_SPILL;
		handle->db_desc->g_first_backup_kv_log = handle->db_desc->g_first_kv_log;
		handle->db_desc->g_last_backup_kv_log = handle->db_desc->g_last_kv_log;
		handle->db_desc->g_backup_kv_log_size = handle->db_desc->g_kv_log_size;
	}
}

void complete_remote_spill(db_handle *handle){
	if(handle->db_desc->db_mode != PRIMARY_DB){
		/*destroy clht with the mappings*/
		//clht_gc_destroy(handle->db_desc->backup_segment_table);
		//handle->db_desc->backup_segment_table = clht_create(NUM_BUCKETS);
		//__sync_fetch_and_add(&spill_epoch, 1);
		/*clear all mappings*/
		map_entry *current, *tmp;
		HASH_ITER(hh,handle->db_desc->backup_segment_table,current,tmp) {
			HASH_DEL(handle->db_desc->backup_segment_table, current);  /* delete it (users advances to next) */
			free(current);/* free it */
		}
		handle->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		printf("[%s:%s:%d] completing spill snapshotting volume\n",__FILE__,__func__,__LINE__);
		snapshot(handle->volume_desc);
	}
	return;
}

