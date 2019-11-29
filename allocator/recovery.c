#define TRUE 0x01
#define FALSE 0x00
#include "allocator.h"
#include "dmap-ioctl.h"

void recovery_worker(void * args){

	db_handle handle;
	recovery_request * recover_req = (recovery_request *)args;
	db_descriptor *db_desc = recover_req->db_desc;
	block_header * current_log_segment;
	uint64_t remaining_bytes_in_segment;
	void * kv_addr;
	uint64_t log_offset;
	uint64_t bit_idx;/*unused only for compatibility*/


	handle.volume_desc = recover_req->volume_desc;
	handle.db_desc = recover_req->db_desc;
	if(recover_req->db_desc->commit_log->kv_log_size < recover_req->db_desc->g_kv_log_size){
		printf("[%s:%s:%d] warning commit log should be larger than g_kv_log\n",__FILE__,__func__,__LINE__);
	}

	log_offset = recover_req->db_desc->g_kv_log_size;
	/*this should be ok already reserved in the allocator, otherwise error*/
	current_log_segment = recover_req->db_desc->g_last_kv_log;
	if(current_log_segment == NULL)/*happens for a newly initialized db*/
		current_log_segment = (void *)((uint64_t)db_desc->commit_log->first_kv_log +MAPPED);

	while(log_offset < db_desc->commit_log->kv_log_size){
		  kv_addr = (void*)((uint64_t)current_log_segment+sizeof(block_header)+(log_offset % BUFFER_SEGMENT_SIZE));
		  //apply kv_addr....
		  if(KEY_SIZE(kv_addr) > 0){

			/*apply kv_addr*/
			printf("[%s:%s:%d] key size %lu\n",__FILE__,__func__,__LINE__,(long unsigned int)KEY_SIZE(kv_addr));
			_insert_key_value(&handle, kv_addr, INSERT_TO_L0_INDEX | DO_NOT_APPEND_TO_LOG);

			log_offset += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			kv_addr += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			//printf("[%s:%s:%d] value size %lu\n",__FILE__,__func__,__LINE__,(long unsigned int)KEY_SIZE(kv_addr));
			log_offset += sizeof(uint32_t)+KEY_SIZE(kv_addr);
			remaining_bytes_in_segment = BUFFER_SEGMENT_SIZE-(log_offset % BUFFER_SEGMENT_SIZE);
			if(remaining_bytes_in_segment < sizeof(uint32_t)){
				//printf("[%s:%s:%d] remaining %llu\n",__FILE__,__func__,__LINE__,(LLU)remaining_bytes_in_segment);
				current_log_segment = (block_header *)(MAPPED + (uint64_t)current_log_segment->next_block);
				/*mark it as reserved. Due to restart allocation info has not survived*/
				mark_block(handle.volume_desc, (void *)current_log_segment, BUFFER_SEGMENT_SIZE, 0x00, &bit_idx);
				log_offset += remaining_bytes_in_segment+sizeof(block_header);
			}
		} else if(KEY_SIZE(kv_addr) == 0){/*padded space*/
			//printf("[%s:%s:%d] padded space = %llu\n",__FILE__,__func__,__LINE__,(LLU)(BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE)));
			log_offset += (BUFFER_SEGMENT_SIZE - (log_offset%BUFFER_SEGMENT_SIZE));
			current_log_segment = (block_header *)(MAPPED + (uint64_t)current_log_segment->next_block);
			/*mark it as reserved. Due to restart allocation info has not survived*/
			mark_block(handle.volume_desc, (void *)current_log_segment, BUFFER_SEGMENT_SIZE, 0x00, &bit_idx);
			log_offset+= sizeof(block_header);
		  }
	}
}
