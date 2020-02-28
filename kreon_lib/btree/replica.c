#ifdef KREONR
#include <math.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
//#include "../CLHT/include/clht.h"
//#include "../CLHT/external/include/ssmem.h"
#include "conf.h"
#include "../allocator/allocator.h"
#include "../../kreon_server/conf.h"
#include "../../kreon_server/messages.h"


#define NUM_BUCKETS 1024
#define SIZE(x) *(uint32_t *)x
#define SE floor(log2(BUFFER_SEGMENT_SIZE) + 1);
#define LEVEL_1 4

//int counter = 0;



void _append_pivot_to_index(_tucana_region_S* region, node_header * left_brother, void * pivot, 
    node_header * right_brother, int tree_id, int node_height);

void init_backup_db_segment_table(db_handle * handle)
{
	handle->db_desc->backup_segment_table = NULL;
	handle->db_desc->spill_segment_table  = NULL;
	return;
}



int flush_replica_log_buffer(db_handle * handle, segment_header * master_log_segment, void * buffer, uint64_t end_of_log, uint64_t bytes_to_pad, uint64_t segment_id)
{
	segment_header * s_header;
	segment_header * disk_segment_header;
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
	if( handle->db_desc->KV_log_size == 0 || (handle->db_desc->KV_log_size > 0 && handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE == 0)){
		buffer_offset = 0;
	} else {
		buffer_offset = handle->db_desc->KV_log_size % BUFFER_SEGMENT_SIZE;
	}

	buffer_bytes_to_write = end_of_log - handle->db_desc->KV_log_size;
	assert(buffer_bytes_to_write == BUFFER_SEGMENT_SIZE || buffer_bytes_to_write == bytes_to_pad);
	if(bytes_to_pad > 0){
		memset((buffer + buffer_offset+buffer_bytes_to_write) - bytes_to_pad, 0x00, bytes_to_pad);
	}
	s_header = (segment_header *)buffer;

	/****************** assert check *********************/
	if(handle->db_desc->KV_log_last_segment != NULL &&  handle->db_desc->KV_log_last_segment->segment_id != segment_id){
		if(handle->db_desc->KV_log_last_segment->segment_id+1 != segment_id){
			DPRINT(" No sequential segment ids last %llu current %llu db %s\n",
					(LLU)handle->db_desc->KV_log_last_segment->segment_id,(LLU)segment_id,handle->db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		//DPRINT("Sequential segment ids last %llu current %llu db %s\n",
		//		(LLU)handle->db_desc->KV_log_last_segment->segment_id,(LLU)segment_id,handle->db_desc->db_name);
	}

	/****************************************************/
	if(handle->db_desc->KV_log_last_segment == NULL || handle->db_desc->KV_log_last_segment->segment_id < segment_id){
		memset(s_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
		s_header->segment_id = segment_id;
		s_header->next_segment = NULL;
		if(handle->db_desc->KV_log_last_segment != NULL){
			s_header->prev_segment = (segment_header *)((uint64_t)handle->db_desc->KV_log_last_segment - MAPPED);
		}
		else{
			s_header->prev_segment = NULL;
		}
		
		disk_segment_header = (segment_header *)allocate_segment(handle, BUFFER_SEGMENT_SIZE,KV_LOG_ID,KV_LOG_EXPANSION);
		
		if(handle->db_desc->KV_log_last_segment != NULL){
			handle->db_desc->KV_log_last_segment->next_segment = (segment_header*)((uint64_t)disk_segment_header - MAPPED);
		}
		
		handle->db_desc->KV_log_last_segment = disk_segment_header;
		
		if(handle->db_desc->KV_log_first_segment == NULL){
			DPRINT("initializing first segment for db %s\n",handle->db_desc->db_name);
			handle->db_desc->KV_log_first_segment = handle->db_desc->KV_log_last_segment;
		}

		/*add the mapping as well*/
		map_entry *s = (map_entry *)malloc(sizeof(map_entry));
		s->key = (uint64_t)master_log_segment;
		s->value = (uint64_t)disk_segment_header - MAPPED;
		//DPRINT("Mappings adding entry remote %llu to local %llu\n", master_log_segment, s->value);
		HASH_ADD_PTR(handle->db_desc->backup_segment_table,key,s);
		handle->db_desc->last_master_segment = s->key;
		handle->db_desc->last_local_mapping = s->value;
	}
	else if(handle->db_desc->KV_log_last_segment->segment_id == segment_id){
		disk_segment_header = handle->db_desc->KV_log_last_segment;
	} else{
		DPRINT("FATAL id out of range\n");
		exit(EXIT_FAILURE);
	}

	handle->db_desc->KV_log_size = end_of_log;

#ifdef EXPLICIT_IO
	int64_t offset = (uint64_t)disk_segment_header - MAPPED;
	offset += buffer_offset;
	if(lseek(FD, offset, SEEK_SET) < offset){
		DPRINT("FATAL seek failed\n");
		exit(EXIT_FAILURE);
	}
	int64_t bytes_written = 0;
	int64_t total_bytes_written = 0;
	do{
		bytes_written = write(FD, buffer+buffer_offset+total_bytes_written, buffer_bytes_to_write-total_bytes_written);
		if(bytes_written < 0){
			DPRINT("FATAL ERROR:failed to write log buffer\n");
			perror("Error is :");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}while(total_bytes_written < buffer_bytes_to_write);
#else
	memcpy((void *)((uint64_t)disk_segment_header+buffer_offset), buffer+buffer_offset, buffer_bytes_to_write);
	if(handle->db_desc->KV_log_last_segment->segment_id != segment_id){
		DPRINT("FATAL buffer offset  %llu\n buffer bytes to write %llu\n", (LLU)buffer_offset, (LLU)buffer_bytes_to_write);
		assert(0);
	}
	memset(s_header->garbage_bytes,0x00,2*MAX_COUNTER_VERSIONS*sizeof(uint64_t));
#if 0
	//test code that checks the contents of the log buffer, useful for debugging
	uint64_t i = 0;
	void *addr = buffer+buffer_offset + 4096;
	while(i < buffer_bytes_to_write){
		DPRINT("key %d:%s  i %"PRIu64" buffer_bytes_to_write %"PRIu64"\n",*(uint32_t *)addr, addr+sizeof(uint32_t), i, buffer_bytes_to_write);
		addr+= (*(uint32_t *)addr + sizeof(uint32_t));
		i+= (*(uint32_t *)addr + sizeof(uint32_t));//key
		addr+= (*(uint32_t *)addr + sizeof(uint32_t));
		i+= (*(uint32_t *)addr + sizeof(uint32_t));//key
		DPRINT("value %d\n",*(uint32_t *)addr);
		if(*(uint32_t *)addr == 0)
			break;
	}
	DPRINT("Padding was %"PRIu64" bytes to write %"PRIu64" i %"PRIu64"\n",buffer_bytes_to_write - i, buffer_bytes_to_write, i);
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



int commit_kv_log_metadata(db_handle * handle)
{
	/*write log info*/
	if(handle->db_desc->KV_log_first_segment != NULL)
		handle->db_desc->commit_log->first_kv_log = (segment_header *)((uint64_t)handle->db_desc->KV_log_first_segment - MAPPED);
	else
		handle->db_desc->commit_log->first_kv_log = NULL;
	if(handle->db_desc->KV_log_last_segment != NULL)
		handle->db_desc->commit_log->last_kv_log = (segment_header *)((uint64_t)handle->db_desc->KV_log_last_segment - MAPPED);
	else
		handle->db_desc->commit_log->last_kv_log = NULL;
	handle->db_desc->commit_log->kv_log_size = handle->db_desc->KV_log_size;

	//if(msync(handle->db_desc->commit_log,sizeof(commit_log_info),MS_SYNC) == -1){
	//	DPRINT("FATAL msync failed\n");
	//	exit(EXIT_FAILURE);
	//}

	return KREON_OK;
}
#endif
