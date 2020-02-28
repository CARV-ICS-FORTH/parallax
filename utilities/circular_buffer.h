#include <stdint.h>
#ifndef __CIRCULAR_BUFFER_H__
#define __CIRCULAR_BUFFER_H__
#define BITS_PER_BITMAP_WORD 32
typedef enum circular_buffer_op_status{
	BITMAP_RESET = 0x00,
	ALLOCATION_IS_SUCCESSFULL,
	NOT_ENOUGH_SPACE_AT_THE_END,
	SPACE_NOT_READY_YET
}circular_buffer_op_status;

typedef enum circular_buffer_type{
	SEND_BUFFER = 0x00,
	RECEIVE_BUFFER
}circular_buffer_type;

typedef struct circular_buffer{

	uint32_t total_memory_size;
	volatile uint32_t remaining_space;
	uint32_t memory_size_represented_per_bit;
	uint32_t bitmap_size;
	circular_buffer_type type; /*send or receive*/
	char * last_addr;
	char * memory_region;
	int *bitmap;
}circular_buffer;




circular_buffer *create_and_init_circular_buffer(char * memory_region, uint32_t memory_region_size, uint32_t memory_size_represented_per_bit,circular_buffer_type type);
circular_buffer_op_status allocate_space_from_circular_buffer(circular_buffer * c, uint32_t size, char ** addr);
void free_space_from_circular_buffer(circular_buffer * c, char * address, uint32_t size);
void reset_circular_buffer(circular_buffer *c);
#endif
