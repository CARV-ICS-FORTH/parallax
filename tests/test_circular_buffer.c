#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "../utilities/circular_buffer.h"
#include "../utilities/macros.h"

#define MEMORY_SIZE 32*1024*1024
#define SEGMENT_SIZE 256
#define NUM_OF_ALLOCATIONS 4000000



typedef struct space_descriptor{
	char * addr;
	uint32_t size;
}space_descriptor;


int main()
{
	space_descriptor * allocations;
	char * last_allocation = NULL;
	uint32_t last_size = 0;
	char * addr;
	char * memory_region;
	circular_buffer *c;
	uint32_t size;
	int i;
	int n;
	int idx = 0;
	circular_buffer_op_status op_code;

	memory_region = (char *)malloc(MEMORY_SIZE);
	allocations = (space_descriptor *)malloc(NUM_OF_ALLOCATIONS * sizeof(space_descriptor));
	memset(allocations, 0x00, NUM_OF_ALLOCATIONS * sizeof(space_descriptor));
	c = create_and_init_circular_buffer(memory_region, MEMORY_SIZE, SEGMENT_SIZE, SEND_BUFFER);
	i = 0;
	while(i < NUM_OF_ALLOCATIONS){
		n = rand() % 100 + 1;
		size = n * SEGMENT_SIZE;
		op_code = allocate_space_from_circular_buffer(c,n* SEGMENT_SIZE, &addr);
		if(op_code == ALLOCATION_IS_SUCCESSFULL){
			++i;
			//DPRINT("Got space address %llu\n",(long long unsigned)addr);
			assert(addr == last_allocation + last_size || addr == memory_region);
			last_allocation = addr;
			last_size = size;

			idx = rand() % NUM_OF_ALLOCATIONS;
			if(allocations[idx].addr!= NULL){
				free_space_from_circular_buffer(c,allocations[idx].addr,allocations[idx].size);
			}
			allocations[idx].addr = last_allocation;
			allocations[idx].size = size;
		}
		else if(op_code == NOT_ENOUGH_SPACE_AT_THE_END){
			DPRINT("Not enough space at the tail allocation number %d size %lu resetting buffer\n",i,(long unsigned)size);
			reset_circular_buffer(c);
		}
		else if(op_code == SPACE_NOT_READY_YET){
			DPRINT("Space at the tail not freed yet allocation number %d size %lu \n",i,(long unsigned)size);
			//idx = rand() % NUM_OF_ALLOCATIONS;
			for(i=0;i<NUM_OF_ALLOCATIONS;i++){
				if(allocations[i].addr!= NULL){
					free_space_from_circular_buffer(c,allocations[i].addr,allocations[i].size);
				}
			}
		}
	}	
	DPRINT("Test 1 successfull!\n");
	free(c);
	free(memory_region);
	free(allocations);

	memory_region = (char *)malloc(MEMORY_SIZE);
	allocations = (space_descriptor *)malloc(NUM_OF_ALLOCATIONS * sizeof(space_descriptor));
	memset(allocations, 0x00, NUM_OF_ALLOCATIONS * sizeof(space_descriptor));
	c = create_and_init_circular_buffer(memory_region, MEMORY_SIZE, SEGMENT_SIZE, SEND_BUFFER);
	i = 0;
	while(i < NUM_OF_ALLOCATIONS){
		n = 1;
		size = n * SEGMENT_SIZE;
		op_code = allocate_space_from_circular_buffer(c,n* SEGMENT_SIZE, &addr);
		if(op_code == ALLOCATION_IS_SUCCESSFULL){
			++i;
			//DPRINT("Got space address %llu\n",(long long unsigned)addr);
			assert(addr == last_allocation + last_size || addr == memory_region);
			last_allocation = addr;
			last_size = size;

			idx = rand() % NUM_OF_ALLOCATIONS;
			if(allocations[idx].addr!= NULL){
				free_space_from_circular_buffer(c,allocations[idx].addr,allocations[idx].size);
			}
			allocations[idx].addr = last_allocation;
			allocations[idx].size = size;
		}
		else if(op_code == NOT_ENOUGH_SPACE_AT_THE_END){
			DPRINT("Not enough space at the tail allocation number %d size %lu resetting buffer\n",i,(long unsigned)size);
			reset_circular_buffer(c);
		}
		else if(op_code == SPACE_NOT_READY_YET){
			DPRINT("Space at the tail not freed yet allocation number %d size %lu \n",i,(long unsigned)size);
			//idx = rand() % NUM_OF_ALLOCATIONS;
			for(i=0;i<NUM_OF_ALLOCATIONS;i++){
				if(allocations[i].addr!= NULL){
					free_space_from_circular_buffer(c,allocations[i].addr,allocations[i].size);
				}
			}
		}
	}	

	DPRINT("Test 2 successfull!\n");
	free(c);
	free(memory_region);
	free(allocations);
}

