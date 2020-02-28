/* memory_region_pool.c
 * Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created on: Thu Aug 1 2019
 */

#define _POSIX_C_SOURCE 200112L // required for posix_memalign
#include <assert.h>
#include <infiniband/verbs.h>
#include <stdlib.h>

#include "memory_region_pool.h"
#include "../utilities/list.h"
#include "../utilities/macros.h"
#include "../kreon_server/conf.h" // FIXME only included for the priority macros


/*for client connections*/
const size_t MEM_REGION_BASE_SIZE = 512 * 1024;
const size_t MR_PREALLOCATE_COUNT = 1024;
const size_t REPLICA_BUFFER_SIZE = 8 * 1024 * 1024;


static int _mrpool_preallocate_mr(memory_region_pool*);
static void _mrpool_initialize_mem_region(memory_region*, struct ibv_pd*, size_t);
static void _mrpool_destroy_mr(struct NODE*);

/**
 * Initialize a memory region pool. The mrpool struct is allocated by the caller 
 * and not in this function
 * @param pd The protection domain where the allocated memory buffers will be registered
 * @return Returns the newly allocated memory region pool or NULL if the allocation failed
 */
memory_region_pool* mrpool_create(struct ibv_pd* pd, size_t max_allocated_memory,pool_type type,size_t allocation_size){
	assert(pd);
	memory_region_pool* pool = (memory_region_pool*) malloc(sizeof(memory_region_pool));
	if (!pool) {
		ERRPRINT("Allocation of new memory region pool failed\n");
		return NULL;
	}
	pool->max_allocated_memory = max_allocated_memory;
	pool->allocated_memory = 0;
	pool->pd = pd;

	pool->type = type;
	if (pool->type == PREALLOCATED){
		pool->free_mrs = init_list(_mrpool_destroy_mr);
		_mrpool_preallocate_mr(pool);
		pool->default_allocation_size = MEM_REGION_BASE_SIZE;
	}
	else if(pool->type == DYNAMIC){
		pool->free_mrs = NULL;
		pool->default_allocation_size = allocation_size;
	} else {
		ERRPRINT("Bad pool type\n");
		exit(EXIT_FAILURE);
	}
	return pool;
}

/**
 * Allocate a new memory pool with a given priority. The memory region is 
 * retrieved from the free list if it's not empty, otherwise a new one is 
 * created.
 * @param pool The memory region pool to use for this allocation
 * @param priority The priority level desired for the memory region to be 
 *                 allocated
 * @return The newly allocated memory region
 */
memory_region* mrpool_allocate_memory_region(memory_region_pool* pool){

	/* TODO We could have a preallocation policy for cases where the free list is 
	 * empty. Properly implementing it is tricky since we wouldn't want this 
	 * allocate call to take too long and we wouldn't want to allocate 
	 * significantly more memory than we'll be using.
	 *
	 * Perhaps we could asign the preallocation as a task to a worker
	 */
	LIST* freelist;
	NODE* freelist_node;
	memory_region* mr = NULL;                    	

	if(pool->type == PREALLOCATED){
		freelist = pool->free_mrs;
		freelist_node = remove_first(freelist);
		if (freelist_node) {
			mr = (memory_region*)freelist_node->data;
		}
	} 
	else if(pool->type == DYNAMIC){
		mr = (memory_region*) malloc(sizeof(memory_region));
		if(!mr){
			ERRPRINT("Allocation of new memory region failed\n");
			return NULL;
		}
		_mrpool_initialize_mem_region(mr, pool->pd,pool->default_allocation_size);
		mr->mrpool = pool;
	}
	return mr;
}

/**
 * Free an allocated memory region. This means that it's added to the 
 * corresponding free list of its memory pool for future use.
 * @param mr The memory region to be freed
 */
void mrpool_free_memory_region(memory_region** mr){
	memory_region_pool* pool = (*mr)->mrpool;

	if(pool->type == PREALLOCATED){
		memset((*mr)->local_memory_buffer, 0xFF, (*mr)->memory_region_length);
		memset((*mr)->remote_memory_buffer, 0xFF, (*mr)->memory_region_length);
		add_first(pool->free_mrs, *mr, NULL);
		// FIXME decrement allocated memory
		*mr = NULL;
	} 
	else {
		if (ibv_dereg_mr((*mr)->local_memory_region)) {
			ERRPRINT("ibv_dereg_mr failed: %s\n", strerror(errno));
		}
		if (ibv_dereg_mr((*mr)->remote_memory_region)) {
			DPRINT("ERROR: ibv_dereg_mr failed: %s\n", strerror(errno));
		}
		free((*mr)->local_memory_buffer);
		free((*mr)->remote_memory_buffer);
		free(*mr);
	}
}

/**
 * Allocate memory regions for a given priority level and add them to the free 
 * list of memory region pool
 * @param pool The memory region pool where the new memory regions will be added
 * @param max_allocated_memory The amount of memory the memory region pool is
 *                             allowed to allocate
 * @param count The number of memory regions to be created
 */
static int _mrpool_preallocate_mr(memory_region_pool* pool) {
	LIST* freelist = pool->free_mrs;
	size_t i;
	// size_t count = max_allocated_memory / MEM_REGION_BASE_SIZE;
	size_t count = MR_PREALLOCATE_COUNT; // FIXME only added this for experiments
	pool->allocated_memory += count * MEM_REGION_BASE_SIZE;
	// assert (pool->allocated_memory <= pool->max_allocated_memory);
	for (i = 0; i < count;i++) {
		memory_region* mr = (memory_region*) malloc(sizeof(memory_region));
		if (!mr) {
			ERRPRINT("Preallocation of new memory region failed\n");
			return 1;
		}
		_mrpool_initialize_mem_region(mr, pool->pd, MEM_REGION_BASE_SIZE);
		mr->mrpool = pool;
		add_first(freelist, mr, NULL);
	}
	return 0;
}

/**
 * Initialize a new memory region. The memory_region_s is allocated by the 
 * caller. A memory buffer is created for the local and remote memory regions and
 * both are registered by calling ibv_reg_mr.
 * @param mr The memory region struct to be initialized
 * @param priority The priority level for the memory region to be initialized
 * @param pd The protection domain to be used for registering the newly allocated
 *           memory regions
 */
static void _mrpool_initialize_mem_region(memory_region* mr, struct ibv_pd* pd, size_t memory_region_size){

	mr->memory_region_length = memory_region_size;	
	if(posix_memalign((void **)&mr->local_memory_buffer, 4096, mr->memory_region_length)!=0){
		ERRPRINT("FATAL Allocation for local memory region failed\n");
		exit(EXIT_FAILURE);
	}
	memset(mr->local_memory_buffer, 0xBB, mr->memory_region_length);
	// mr->local_memory_region = ibv_reg_mr(pd, mr->local_memory_buffer, mr->memory_region_length, IBV_ACCESS_LOCAL_WRITE);
	// if(!mr->local_memory_buffer){
	// 	ERRPRINT("FATAL Registering local rdma memory failed: %s\n", strerror(errno));
	// 	exit(EXIT_FAILURE);
	// }	

	if(posix_memalign((void **)&mr->remote_memory_buffer, 4096, mr->memory_region_length)!=0){
		ERRPRINT("FATAL Allocation for remote memory region failed\n");
		exit(EXIT_FAILURE);
	}
	memset(mr->remote_memory_buffer, 0xBB, mr->memory_region_length);
	// mr->remote_memory_region = ibv_reg_mr(pd, mr->remote_memory_buffer, mr->memory_region_length, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE); 
	// if(!mr->remote_memory_region){
	// 	ERRPRINT("FATAL Registering remote rdma memory failed: %s\n", strerror(errno));
	// 	exit(EXIT_FAILURE);
	// }
}

/**
 * Free list node destructor. De-register a memory region and free its memory.
 * @param node The list node to be freed
 */
static void _mrpool_destroy_mr(struct NODE* node) {
	memory_region* mr = (memory_region*) node->data;
	if (ibv_dereg_mr(mr->local_memory_region)) {
		DPRINT("ERROR: ibv_dereg_mr failed: %s\n", strerror(errno));
	}
	if (ibv_dereg_mr(mr->remote_memory_region)) {
		DPRINT("ERROR: ibv_dereg_mr failed: %s\n", strerror(errno));
	}
	free(mr->local_memory_buffer);
	free(mr->remote_memory_buffer);
	free(mr);
}

