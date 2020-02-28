/* memory_region_pool.h
 * Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created on: Thu Aug 1 2019
 */

#ifndef _MEMORY_REGION_POOL_H
#define _MEMORY_REGION_POOL_H

#include <infiniband/verbs.h>
#include <stddef.h>
//#include "tu_rdma.h"
#include "../utilities/list.h"
//typedef struct mrpool memory_region_pool_s;
//typedef struct memory_region memory_region_s;

typedef enum pool_type{
	DYNAMIC = 123,
	PREALLOCATED
}pool_type;

typedef struct memory_region_pool{
	// FIXME LIST is not thread-safe; need to add at least a coarse-grained lock
	LIST* free_mrs; // Free list for each priority level
	size_t max_allocated_memory; // Maximum amount of memory allocated in bytes
	size_t allocated_memory; // Currently allocated memory in bytes
	struct ibv_pd* pd; // The protection domain in which all new memory regions will be pinned
	pool_type type;
	size_t default_allocation_size;/*used only for dynamic currently*/
}memory_region_pool;



typedef struct memory_region {
	memory_region_pool* mrpool; // The memory pool where this mr was allocated
	size_t memory_region_length;
	struct ibv_mr* local_memory_region; // memory region struct as returned by ibv_reg_mr
	char* local_memory_buffer; // the malloced buffer for the above mr
	struct ibv_mr* remote_memory_region; // memory region struct as returned by ibv_reg_mr
	char* remote_memory_buffer; // the malloced buffer for the above mr
}memory_region;

memory_region_pool* mrpool_create(struct ibv_pd* pd, size_t max_allocated_memory, pool_type type, size_t allocation_size);
memory_region* mrpool_allocate_memory_region(memory_region_pool* pool);
void mrpool_free_memory_region(memory_region** mr);

/*for client connections*/
extern const size_t MEM_REGION_BASE_SIZE;
extern const size_t MR_PREALLOCATE_COUNT;
extern const size_t REPLICA_BUFFER_SIZE;


#endif //_MEMORY_REGION_POOL_H
