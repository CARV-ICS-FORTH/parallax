#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include "macros.h"
#include "circular_buffer.h"
#define BITS_PER_BITMAP_WORD 32

static void mark_used_space_in_bitmap(circular_buffer *c, char * address, uint32_t size);
static int check_if_space_is_free(circular_buffer * c, char * addr, uint32_t size);
static circular_buffer_op_status __allocate_space_from_send_circular_buffer(circular_buffer * c, uint32_t size, char ** addr);
static circular_buffer_op_status __allocate_space_from_recv_circular_buffer(circular_buffer * c, uint32_t size, char ** addr);
/*Note bit 1 unit free, 0 unit in use*/

circular_buffer *create_and_init_circular_buffer(char * memory_region, uint32_t memory_region_size, uint32_t memory_size_represented_per_bit,circular_buffer_type type)
{
	assert(memory_region_size % (BITS_PER_BITMAP_WORD * memory_size_represented_per_bit) == 0);
	int bitmap_size;
	bitmap_size = (memory_region_size/memory_size_represented_per_bit);
	assert(bitmap_size%BITS_PER_BITMAP_WORD == 0);
	bitmap_size = bitmap_size/BITS_PER_BITMAP_WORD;
	circular_buffer * c = (circular_buffer *)malloc(sizeof(circular_buffer)+ (bitmap_size*sizeof(int)));
	c->bitmap_size = bitmap_size;
	c->total_memory_size = memory_region_size;
	c->remaining_space = memory_region_size;
	c->memory_size_represented_per_bit = memory_size_represented_per_bit;
	c->memory_region = memory_region;
	c->last_addr = memory_region;
	c->bitmap = (int *)((uint64_t)c + sizeof(circular_buffer));
	c->type = type;
	memset(c->bitmap,0xFF, c->bitmap_size*sizeof(int));
	if(type == RECEIVE_BUFFER){
		c->bitmap[c->bitmap_size-1] = 0x7FFFFFFF;
	}
	return c;
}


circular_buffer_op_status allocate_space_from_circular_buffer(circular_buffer * c, uint32_t size, char ** addr)
{
	if(c->type == SEND_BUFFER){
		return __allocate_space_from_send_circular_buffer(c,size,addr);
	} else {
		return __allocate_space_from_recv_circular_buffer(c,size,addr);
	}
}



static circular_buffer_op_status __allocate_space_from_send_circular_buffer(circular_buffer * c, uint32_t size, char ** addr)
{
	assert(size % c->memory_size_represented_per_bit == 0);
	assert(size <= c->total_memory_size);
	
	if(c->remaining_space == 0){
		/*silently reset the buffer*/
		c->remaining_space = c->total_memory_size;
		c->last_addr = c->memory_region;
		*addr = NULL;
	}

	if(c->remaining_space >= size){

		if(check_if_space_is_free(c, c->last_addr,size)){
			mark_used_space_in_bitmap(c, c->last_addr,size);
			*addr = c->last_addr;
			c->remaining_space -= size;
			c->last_addr += size;
			return ALLOCATION_IS_SUCCESSFULL;
		} else {
			/*space not freed yet*/
			return SPACE_NOT_READY_YET;
		}
	} else{
		/*
		 * space not enough, however for correctness we need to check if remaining space
		 * (although not sufficient) is free 
		 */
		if(check_if_space_is_free(c, c->last_addr, c->remaining_space)){
			*addr = NULL;
			DPRINT("bitmap[0] = %x\n",c->bitmap[0]);
			return NOT_ENOUGH_SPACE_AT_THE_END;
		}
		else{
			return SPACE_NOT_READY_YET;
		}
	}
}



static circular_buffer_op_status __allocate_space_from_recv_circular_buffer(circular_buffer * c, uint32_t size, char ** addr)
{
	assert(size % c->memory_size_represented_per_bit == 0);
	assert(size <= c->total_memory_size);
	
	if(c->remaining_space == c->memory_size_represented_per_bit){
		/*silently reset the buffer*/
		//DPRINT("Silent RESET\n");
		c->remaining_space = c->total_memory_size;
		c->last_addr = c->memory_region;
		*addr = NULL;
	}

	if(c->remaining_space-c->memory_size_represented_per_bit >= size){

		if(check_if_space_is_free(c, c->last_addr,size)){

			mark_used_space_in_bitmap(c, c->last_addr,size);
			*addr = c->last_addr;
			c->remaining_space -= size;

			c->last_addr += size;
			return ALLOCATION_IS_SUCCESSFULL;
		} else {
			/*space not freed yet*/
			DPRINT("Space not ready size requested %d remaining %d\n", size, c->remaining_space);
			return SPACE_NOT_READY_YET;
		}
	}else{
		/*
		 * space not enough, however for correctness we need to check if remaining space
		 * (although not sufficient) is free 
		 */
		if(check_if_space_is_free(c, c->last_addr, c->remaining_space-c->memory_size_represented_per_bit)){
			*addr = c->last_addr;
			DPRINT("bitmap[0] = %x\n",c->bitmap[0]);
			return NOT_ENOUGH_SPACE_AT_THE_END;
		} else{
			return SPACE_NOT_READY_YET;
		}
	}
}



static int check_if_space_is_free(circular_buffer * c, char * address, uint32_t size)
{
	char * end;
	char * addr;

	uint32_t word_id;
	uint32_t bit_inside_word; 
	uint32_t mask;

	if(size == 0){
		return 1;
	}
	addr = address;
	end = address + size;

	while(addr < end){
		mask = 0x00000001;
		word_id = ((addr-c->memory_region)/c->memory_size_represented_per_bit)/BITS_PER_BITMAP_WORD;
		bit_inside_word = ((addr-c->memory_region)/c->memory_size_represented_per_bit)%BITS_PER_BITMAP_WORD;

		mask = mask << bit_inside_word;
		mask = mask & c->bitmap[word_id];
		if(mask == 0){
			return 0;
		}
		addr += c->memory_size_represented_per_bit;
	}
	return 1;
}



void free_space_from_circular_buffer(circular_buffer * c, char * address, uint32_t size)
{
	char  * start;
	char * end;
	char * addr;
	uint32_t word_id;
	uint32_t bit_inside_word;
	uint32_t mask ;
	uint32_t old_val;
	uint32_t new_val;

	assert(size % c->memory_size_represented_per_bit == 0);
	assert(address >= c->memory_region && address < c->memory_region + c->total_memory_size);
	start = address;
	end = address + size;
	addr = start;

	while(addr < end){
		mask = 0x00000001;
		word_id = ((addr-c->memory_region)/c->memory_size_represented_per_bit)/BITS_PER_BITMAP_WORD;
		bit_inside_word = ((addr-c->memory_region)/c->memory_size_represented_per_bit)%BITS_PER_BITMAP_WORD;

		mask = mask << bit_inside_word;
		old_val = c->bitmap[word_id];
		new_val = old_val | mask; 
		if(__sync_bool_compare_and_swap(&(c->bitmap[word_id]), old_val, new_val)){
			addr +=c->memory_size_represented_per_bit;
		}
		//uint32_t i = 0;
		//for(i = 0;i<c->bitmap_size;i++){
		//	DPRINT("After free old bitmap[%d] = %x  new val bitmap[%d] = %x for circ %x\n",i,old_val, i,new_val,c);
		//}
	}
}



void mark_used_space_in_bitmap(circular_buffer * c, char * address, uint32_t size)
{

	char  * start;
	char * end;
	char * addr;

	uint32_t word_id;
	uint32_t bit_inside_word;
	uint32_t mask;
	uint32_t old_val;
	uint32_t new_val;
	assert(size % c->memory_size_represented_per_bit == 0);
	start = address;
	end = address + size;
	addr = start;

	while(addr < end){

		mask = 0x00000001;
		word_id = ((addr-c->memory_region)/c->memory_size_represented_per_bit)/BITS_PER_BITMAP_WORD;
		bit_inside_word = ((addr-c->memory_region)/c->memory_size_represented_per_bit)%BITS_PER_BITMAP_WORD;

		mask = mask << bit_inside_word;
		mask = ~mask;
		old_val = c->bitmap[word_id];
		new_val = old_val & mask;

		if(__sync_bool_compare_and_swap (&(c->bitmap[word_id]), old_val, new_val)){
			addr +=c->memory_size_represented_per_bit;
		}
		//uint32_t i;
		//for(i = 0;i<c->bitmap_size;i++){
		//	DPRINT("After mark old bitmap[%d] = %x  new val bitmap[%d] = %x word_id %d bit inside %d for circ %x\n",i,old_val, i,new_val,word_id,bit_inside_word,c);
		//}
	}
}



void reset_circular_buffer(circular_buffer *c){
	c->remaining_space = c->total_memory_size;
	c->last_addr = c->memory_region;
}

