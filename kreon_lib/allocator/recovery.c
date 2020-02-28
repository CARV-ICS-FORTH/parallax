#define TRUE 0x01
#define FALSE 0x00
#include <signal.h>
#include <assert.h>
#include "allocator.h"
#include "dmap-ioctl.h"
#define KEY_SIZE(x)  *(uint32_t *)x

void recovery_worker(void * args){

	db_handle handle;
	kv_location location;
	recovery_request * recover_req = (recovery_request *)args;
	db_descriptor *db_desc = recover_req->db_desc;
	segment_header * current_log_segment;
	uint64_t remaining_bytes_in_segment;
	void * kv_addr;
	uint64_t log_offset;
	uint64_t bit_idx;/*unused only for compatibility*/

	handle.volume_desc = recover_req->volume_desc;
	handle.db_desc = recover_req->db_desc;
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle.db_desc->lock_log);
#else
	SPIN_LOCK(&handle.db_desc->lock_log);
#endif

	if(recover_req->db_desc->commit_log->kv_log_size < recover_req->db_desc->KV_log_size){
		printf("[%s:%s:%d] warning commit log should be larger than g_kv_log\n",__FILE__,__func__,__LINE__);
	}
	printf("[%s:%s:%d] starting recovery for db %s first KV log segment %llu last KV log last segment %llu\n", __FILE__,__func__,__LINE__, 
	       recover_req->db_desc->db_name, (LLU)recover_req->db_desc->KV_log_first_segment, (LLU)recover_req->db_desc->KV_log_last_segment);


	/*first, we need to check the L0_start_offset to which segment points to*/
	uint64_t segment_id = recover_req->recovery_start_log_offset/BUFFER_SEGMENT_SIZE;
	printf("[%s:%s:%d] L0 start offset %llu maps to segment id %llu\n",__FILE__,__func__,__LINE__,(LLU)recover_req->db_desc->L0_start_log_offset,(LLU)segment_id);
	current_log_segment = (segment_header *)(MAPPED + (uint64_t)recover_req->db_desc->commit_log->last_kv_log);
	uint64_t previous_segment_id = 0;
	while(current_log_segment->segment_id != segment_id){
		previous_segment_id = current_log_segment->segment_id;
		current_log_segment = (segment_header *)(MAPPED + (uint64_t)current_log_segment->prev_segment);
		if(previous_segment_id != current_log_segment->segment_id + 1){
			printf("[%s:%s:%d] FATAL corrupted segments, segment ids are not sequential previous = %llu current = %llu\n",__FILE__,__func__,__LINE__,(LLU)previous_segment_id,(LLU)current_log_segment->segment_id);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		if(current_log_segment->segment_id < segment_id){
			printf("[%s:%s:%d] FATAL KV log corrupted segment id %llu not found\n",__FILE__,__func__,__LINE__,(LLU)segment_id);
			exit(EXIT_FAILURE);
		}
	}
	printf("[%s:%s:%d] starting segment %llu of L0 found starting recovery procedure\n",__FILE__,__func__,__LINE__,(LLU)segment_id);

	log_offset = recover_req->recovery_start_log_offset;
	while(log_offset < db_desc->commit_log->kv_log_size){
		if(log_offset == 0){
			/*ommit segment header*/
			log_offset += sizeof(segment_header);
			continue;
		}
		if(log_offset % BUFFER_SEGMENT_SIZE == 0){
			if(current_log_segment->next_segment == NULL)
				break;
			segment_id = current_log_segment->segment_id;
			current_log_segment = (segment_header *)(MAPPED + (uint64_t)current_log_segment->next_segment);
			printf("[%s:%s:%d] recovering segment = %llu of db %s padded space = %llu log offset %llu commit log offset %llu\n",
			       __FILE__,__func__,__LINE__,(LLU)current_log_segment->segment_id, recover_req->db_desc->db_name,
			       (LLU)(BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE)),(LLU)log_offset,(LLU)db_desc->commit_log->kv_log_size);
			assert(segment_id +1 == current_log_segment->segment_id);
			log_offset += sizeof(segment_header);
			continue;
		}

		kv_addr = (void*)((uint64_t)current_log_segment+(log_offset % BUFFER_SEGMENT_SIZE));
		  //apply kv_addr....
		  if(KEY_SIZE(kv_addr) > 0){
			//printf("[%s:%s:%d] key size %lu\n",__FILE__,__func__,__LINE__,(long unsigned int)KEY_SIZE(kv_addr));
			//printf("[%s:%s:%d] value size %lu\n",__FILE__,__func__,__LINE__, *(uint32_t*)(kv_addr + sizeof(uint32_t)+*(uint32_t *)kv_addr));
			assert(KEY_SIZE(kv_addr) < 23);
			assert(*(uint32_t *)(kv_addr + sizeof(uint32_t)+KEY_SIZE(kv_addr)) < 1120);
			location.kv_addr = kv_addr;
			location.log_offset = 0;
			 _insert_index_entry(&handle, &location, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG | RECOVERY_OPERATION);

			log_offset += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			kv_addr += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			log_offset += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			remaining_bytes_in_segment = BUFFER_SEGMENT_SIZE-(log_offset % BUFFER_SEGMENT_SIZE);

			if(remaining_bytes_in_segment <= sizeof(uint32_t)){
				segment_id = current_log_segment->segment_id;
				current_log_segment = (segment_header *)(MAPPED + (uint64_t)current_log_segment->next_segment);
				assert(segment_id +1 == current_log_segment->segment_id);
				log_offset += sizeof(segment_header);
				printf("[%s:%s:%d] recovering segment = %llu of db %s padded space = %llu log offset %llu commit log offset %llu\n",
			       __FILE__,__func__,__LINE__,(LLU)current_log_segment->segment_id, recover_req->db_desc->db_name,
			       (LLU)(BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE)),(LLU)log_offset,(LLU)db_desc->commit_log->kv_log_size);

				/*mark it as reserved. Due to restart, allocation info has not survived*/
				mark_block(handle.volume_desc, (void *)current_log_segment, BUFFER_SEGMENT_SIZE, 0x00, &bit_idx);
				log_offset += remaining_bytes_in_segment;
				printf("[%s:%s:%d] recovering segment %llu\n",__FILE__,__func__,__LINE__,(LLU)current_log_segment->segment_id);
			}
		} else if(KEY_SIZE(kv_addr) == 0){/*padded space*/
			printf("[%s:%s:%d] End of segment id %llu padded space is  %llu\n",__FILE__,__func__,__LINE__,(LLU)current_log_segment->segment_id,(LLU)(BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE)));
			log_offset += (BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE));
			if(log_offset >= db_desc->commit_log->kv_log_size)
				break;
			segment_id = current_log_segment->segment_id;
			if(current_log_segment->next_segment == NULL){
				break;
			}
			current_log_segment = (segment_header *)(MAPPED + (uint64_t)current_log_segment->next_segment);
			log_offset += sizeof(segment_header);
			printf("[%s:%s:%d] now recovering segment = %llu of db %s log offset %llu commit log offset %llu\n",
				__FILE__,__func__,__LINE__,(LLU)current_log_segment->segment_id, recover_req->db_desc->db_name,(LLU)log_offset,(LLU)db_desc->commit_log->kv_log_size);
			assert(segment_id +1 == current_log_segment->segment_id);

			/*mark it as reserved. Due to restart allocation info has not survived*/
			mark_block(handle.volume_desc, (void *)current_log_segment, BUFFER_SEGMENT_SIZE, 0x00, &bit_idx);
		}
	}
	printf("[%s:%s:%d] finished recovery for db %s log offset = %llu commit log offset = %llu\n", __FILE__,__func__,__LINE__,recover_req->db_desc->db_name,(LLU)log_offset,(LLU)db_desc->commit_log->kv_log_size);
	assert(log_offset == (LLU)db_desc->commit_log->kv_log_size);
	log_offset = recover_req->db_desc->KV_log_size;
#if LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle.db_desc->lock_log);
#else
	SPIN_UNLOCK(&handle.db_desc->lock_log);
#endif
}
