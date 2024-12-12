#include <stdio.h>
#define _GNU_SOURCE
#include "buddy_allocator.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#define BA_DEBUG

struct ba_allocation_header {
	uint64_t allocation_size;
	struct ba_allocation_header *next;
	struct ba_allocation_header *prev;
};

/*Since we do not have a malloc() we create vm_areas that host the metadata of
* the allocator: 1)Bitmap per allocation list which informs us if a buddy is
* present in the list 2)Root allocator metadata*/
static void *ba_mmap_allocate(size_t size)
{
	size_t padding = BA_PAGE_SIZE - (size % BA_PAGE_SIZE);
	size_t mmap_size = size + padding;

	void *memory = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	if (MAP_FAILED == memory) {
		fprintf(stderr, "MMAP failed reason follows size was %ld\n", mmap_size);
		perror("Reason for mmap");
		_exit(EXIT_FAILURE);
	}
	return memory;
}

/*We use this function to destory dynamic vm_areas that we have created for the
* buddy allocator*/
static void ba_mmap_free(void *memory, size_t size)
{
	size_t padding = BA_PAGE_SIZE - (size % BA_PAGE_SIZE);
	size_t mmap_size = size + padding;

	if (munmap(memory, mmap_size)) {
		printf("MUNMAP failed reason follows\n");
		perror("Reason for mmap");
		_exit(EXIT_FAILURE);
	}
}

/*Marks ownership of buddies in the corresponding list*/
static void ba_mark_used_space_in_list(buddy_allocator_t *allocator, int list_id, void *memory_addr)
{
	uint64_t offset = (uint64_t)memory_addr - (uint64_t)allocator->raw_memory;
	uint32_t num_bits = offset / allocator->allocation_list[list_id].memory_size;
	uint32_t bitmap_id = num_bits / BA_BITS_PER_BITMAP_ID;
	uint32_t bitmap_bit = num_bits % BA_BITS_PER_BITMAP_ID;

#ifdef BA_DEBUG
	fprintf(stderr, "Marking  used space for list: %d and bitmap_id %u and bitmap bit %u\n", list_id, bitmap_id,
		bitmap_bit);
#endif
	BA_SET_BIT(&allocator->allocation_list[list_id].bitmap[bitmap_id], bitmap_bit);
}

/*Marks non-ownership of buddies that are removed from the corresponding list*/
static void ba_mark_free_space_in_list(buddy_allocator_t *allocator, int list_id, void *memory_addr)
{
	uint64_t offset = (uint64_t)memory_addr - (uint64_t)allocator->raw_memory;
	uint32_t num_bits = offset / allocator->allocation_list[list_id].memory_size;
	uint32_t bitmap_id = num_bits / BA_BITS_PER_BITMAP_ID;
	uint32_t bitmap_bit = num_bits % BA_BITS_PER_BITMAP_ID;

#ifdef BA_DEBUG
	fprintf(stderr, "Marking free space for list: %d and bitmap_id %u and bitmap bit %u\n", list_id, bitmap_id,
		bitmap_bit);
#endif
	BA_CLEAR_BIT(&allocator->allocation_list[list_id].bitmap[bitmap_id], bitmap_bit);
}

/*Inserts free memory chunks in the allocation list*/
static void ba_insert_free_space_in_list(buddy_allocator_t *allocator, int list_id, void *memory_addr)
{
	struct ba_allocation_header *new_free_node = (struct ba_allocation_header *)memory_addr;
	/*insert into free list of list*/
	struct ba_allocation_list *list = &allocator->allocation_list[list_id];
	new_free_node->next = list->list_head;

	if (list->list_head)
		list->list_head->prev = new_free_node;

	new_free_node->prev = NULL;
	list->list_head = new_free_node;
	ba_mark_used_space_in_list(allocator, list_id, memory_addr);
}

static int ba_is_power_of_two(size_t n)
{
	if (n == 0)
		return 0;
	while (n != 1) {
		if (n % 2 != 0)
			return 0;
		n = n / 2;
	}
	return 1;
}

/**Creates and initializes all allocator's metadata: the root structure and the
 * bitmaps per allocation list for all possible allocation sizes from
 * 2^BA_MIN_SIZE_POW to 2^BA_MAX_SIZE_POW. Initially only the list
 * 2^BA_MAX_SIZE_POW has the entire memory size
 */
buddy_allocator_t *buddy_create(void *raw_memory, size_t raw_memory_size)
{
	/*Check if the memory size is 1)power of 2 and 2) smaller or equal to 2^BA_MAX_SIZE_POW*/
	if (!ba_is_power_of_two(raw_memory_size)) {
		fprintf(stderr, "Memory size: %ld not a power of two\n", raw_memory_size);
		return NULL;
	}

	if (raw_memory_size < BA_MIN_ALLOCATION_SIZE) {
		fprintf(stderr, "Memory size: %ld too small minumum: %ld\n", raw_memory_size, BA_MIN_ALLOCATION_SIZE);
		return NULL;
	}

	/*Find out in which list should we asign the initial free space*/
	size_t max_allocation_unit = 0;
	/*Fine the largest allocation size that this memory size can hold*/
	if (raw_memory_size > BA_MAX_ALLOCATION_SIZE)
		max_allocation_unit = BA_MAX_ALLOCATION_SIZE;
	else
		max_allocation_unit = raw_memory_size;

	/*Initialize buddy allocator metadata*/
	buddy_allocator_t *allocator = ba_mmap_allocate(sizeof(buddy_allocator_t));
	uint64_t allocation_size = BA_MIN_ALLOCATION_SIZE;

#ifdef BA_DEBUG
	fprintf(stderr, "Num allocation lists are %d\n", BA_NUM_ALLOCATION_LISTS);
#endif

	int initial_list_id = 0;

	for (int i = 0; i < BA_NUM_ALLOCATION_LISTS; ++i) {
		allocator->allocation_list[i].memory_size = allocation_size << i;
		fprintf(stderr, "[%s:%s:%d] memmory_size = %lu\n", __FILE__, __func__, __LINE__,
			allocator->allocation_list[i].memory_size);

		/*Find the id of the list where we are going to place the initial free space*/
		if (allocator->allocation_list[i].memory_size == max_allocation_unit)
			initial_list_id = i;

		allocator->allocation_list[i].list_head = NULL;
		/*number of bits needed*/
		uint64_t num_bits = raw_memory_size / allocator->allocation_list[i].memory_size;
		/*how many logs does this bits map to?*/
		uint64_t pad_byte = num_bits % BA_BITS_PER_BITMAP_ID ? 1 : 0;
		uint64_t bitmap_size = (num_bits / BA_BITS_PER_BITMAP_ID) + pad_byte;
		allocator->allocation_list[i].bitmap_size = bitmap_size;
#ifdef BA_DEBUG
		fprintf(stderr, "bitmap size for list[%u] =  %lu is %lu\n", i,
			allocator->allocation_list[i].memory_size, allocator->allocation_list[i].bitmap_size);
#endif
		allocator->allocation_list[i].bitmap = ba_mmap_allocate(bitmap_size * sizeof(long int));
		/*all reserved except the last*/
		memset(allocator->allocation_list[i].bitmap, 0x00, allocator->allocation_list[i].bitmap_size);

		allocator->allocation_list[i].list_head = NULL;
	}

	allocator->raw_memory = raw_memory;
	char *memory = raw_memory;
	size_t offset = 0;
	while (offset < raw_memory_size) {
		ba_insert_free_space_in_list(allocator, initial_list_id, &memory[offset]);
		offset += max_allocation_unit;
	}

	return (buddy_allocator_t *)allocator;
}

static void *ba_remove_list_head(buddy_allocator_t *allocator, int list_id)
{
	struct ba_allocation_list *list = &allocator->allocation_list[list_id];

	if (NULL == list->list_head) {
		return NULL;
	}
	struct ba_allocation_header *new_list_head = list->list_head->next;

	if (new_list_head)
		new_list_head->prev = NULL;

	void *memory = list->list_head;
	ba_mark_free_space_in_list(allocator, list_id, memory);
	list->list_head = new_list_head;
	return memory;
}

/*Allocates space from the corresponding list. If list does not have space it
* borrows from the next list and keeps the one half for it and with the other
* one it satifies the allocation request*/
static void *ba_allocate_from_list(buddy_allocator_t *allocator, int list_id)
{
	if (list_id >= BA_NUM_ALLOCATION_LISTS)
		return NULL;

	char *memory = ba_remove_list_head(allocator, list_id);
	if (memory)
		return memory;

	char *memory_addr = ba_allocate_from_list(allocator, list_id + 1);
	if (memory_addr) {
		ba_insert_free_space_in_list(allocator, list_id, memory_addr);

#ifdef BA_DEBUG
		fprintf(stderr, "returning offset is %lu for list %u\n",
			&memory_addr[allocator->allocation_list[list_id].memory_size] - allocator->raw_memory, list_id);
#endif
		return &memory_addr[allocator->allocation_list[list_id].memory_size];
	}
	return NULL;
}

/*The allocation function of our allocator*/
void *buddy_allocator_alloc(buddy_allocator_t *allocator, size_t size)
{
	size_t actual_size = size + sizeof(struct ba_allocation_header);
	int responsible_list = -1;
	fprintf(stderr, "[%s:%s:%d] user requested size %lu rounded up to %lu\n", __FILE__, __func__, __LINE__, size,
		actual_size);
	/*find appropriate list*/
	for (int i = 0; i < BA_NUM_ALLOCATION_LISTS - 1; ++i) {
		if (0 == i && actual_size <= allocator->allocation_list[i].memory_size) {
			responsible_list = i;
			break;
		}

		if (actual_size > allocator->allocation_list[i].memory_size &&
		    actual_size <= allocator->allocation_list[i + 1].memory_size) {
			responsible_list = i + 1;
			break;
		}
	}

#ifdef BA_DEBUG
	fprintf(stderr, "responsible_list is %d actual size %ld\n", responsible_list, actual_size);
#endif
	if (-1 == responsible_list) {
		fprintf(stderr, "Too large memory %ld requested cannot serve\n", size);
		_exit(EXIT_FAILURE);

		return NULL;
	}

	char *alloc_memory = ba_allocate_from_list(allocator, responsible_list);

	if (alloc_memory) {
		struct ba_allocation_header *memory_header = (struct ba_allocation_header *)alloc_memory;
		memory_header->allocation_size = allocator->allocation_list[responsible_list].memory_size;
		return &alloc_memory[sizeof(struct ba_allocation_header)];
	}
	return NULL;
}

/*This function recursively checks if a buddy is present in the list. If it is,
* it removes the buddy merges the two buddies and proceeds to the next
* allocation list*/
static void ba_check_buddy(buddy_allocator_t *allocator, int list_id, void *memory_addr)
{
	if (list_id >= BA_NUM_ALLOCATION_LISTS)
		return;
	void *buddy_memory_addr = NULL;
	void *merged_memory_addr = NULL;
	uint64_t offset = (uint64_t)memory_addr - (uint64_t)allocator->raw_memory;

#ifdef BA_DEBUG
	if (offset >= allocator->raw_memory_size) {
		fprintf(stderr, "offset %lu memory size %lu out of range\n", offset, allocator->raw_memory_size);
	}
#endif
	uint32_t num_bits = offset / allocator->allocation_list[list_id].memory_size;
	uint32_t bitmap_id = num_bits / BA_BITS_PER_BITMAP_ID;
	uint32_t bitmap_bit = num_bits % BA_BITS_PER_BITMAP_ID;

	/*Check buddy, odd buddy case*/
	uint32_t buddy_bit = 0;
	uint8_t buddy_bit_value = 0;
	if (bitmap_bit % 2) {
		buddy_bit = bitmap_bit - 1;
		buddy_bit_value = BA_GET_BIT(allocator->allocation_list[list_id].bitmap[bitmap_id], buddy_bit);
		buddy_memory_addr = (void *)((uint64_t)memory_addr - allocator->allocation_list[list_id].memory_size);
		merged_memory_addr = buddy_memory_addr;
	} else { /*even buddy case*/
		buddy_bit = buddy_bit + 1;
		buddy_bit_value = BA_GET_BIT(allocator->allocation_list[list_id].bitmap[bitmap_id], buddy_bit);
		buddy_memory_addr = (void *)((uint64_t)memory_addr + allocator->allocation_list[list_id].memory_size);
		merged_memory_addr = memory_addr;
	}

	if (!buddy_bit_value) {
#ifdef BA_DEBUG
		fprintf(stderr, "Buddy is not free for list id %d and addr %p\n", list_id, memory_addr);
#endif
		ba_insert_free_space_in_list(allocator, list_id, memory_addr);
		return;
	}

#ifdef BA_DEBUG
	fprintf(stderr, "Buddy is  free for list id %d and addr %p\n", list_id, memory_addr);
#endif
	/*Remove buddy pair from list*/
	struct ba_allocation_header *buddy_node = buddy_memory_addr;
	if (NULL == buddy_node->prev) {
		/*this is the head*/
		allocator->allocation_list[list_id].list_head = buddy_node->next;

#ifdef BA_DEBUG
		fprintf(stderr, "Removed head of list %d\n", list_id);
#endif
	} else
		buddy_node->prev->next = buddy_node->next;

	if (buddy_node->next)
		buddy_node->next->prev = buddy_node->prev;

	BA_CLEAR_BIT(&allocator->allocation_list[list_id].bitmap[bitmap_id], bitmap_bit);
	BA_CLEAR_BIT(&allocator->allocation_list[list_id].bitmap[bitmap_id], buddy_bit);
	/*Remove buddy from list*/

	ba_check_buddy(allocator, list_id + 1, merged_memory_addr);
}

/**
  * API's free function
*/
void buddy_allocator_free(buddy_allocator_t *allocator, void *ptr)
{
	struct ba_allocation_header *allocation_header =
		(struct ba_allocation_header *)((uint64_t)ptr - sizeof(struct ba_allocation_header));

	int list_id = ffsl(allocation_header->allocation_size) - (BA_MIN_SIZE_POW + 1);
	if (list_id < 0 || list_id >= BA_NUM_ALLOCATION_LISTS) {
		fprintf(stderr, "Corrupted allocator metadata\n");
		_exit(EXIT_FAILURE);
	}
	ba_check_buddy(allocator, list_id, (void *)allocation_header);
}

/**
  * API's destroy function
  */
void buddy_allocator_destroy(buddy_allocator_t *allocator)
{
	for (int i = 0; i < BA_NUM_ALLOCATION_LISTS; ++i) {
		ba_mmap_free(allocator->allocation_list[i].bitmap, allocator->allocation_list[i].bitmap_size);
	}
	free(allocator->raw_memory);
	ba_mmap_free(allocator, sizeof(buddy_allocator_t));
}

#define BA_MAGIC_NUMBER 666

/**
 * Our test in each loop allocates all memory using the corresponding
 * allocation unit, writes the allocation unit with a magic number, checks if
 * this magic number is there in case of corruption. Then, it frees it and proceeds
 * to the next allocation unit.
 */
/*int main(void)
{
	uint64_t raw_memory_size = BA_MAX_ALLOCATION_SIZE;
	char *raw_memory = malloc(raw_memory_size);
	memset(raw_memory, 0x00, raw_memory_size);

	buddy_allocator_t *allocator = buddy_create(raw_memory, raw_memory_size);

	for (uint32_t i = 0; i < BA_NUM_ALLOCATION_LISTS; ++i) {
		char *memory = NULL;
		uint32_t allocation_size =
			allocator->allocation_list[i].memory_size - sizeof(struct ba_allocation_header);
		uint64_t total_allocations = raw_memory_size / allocator->allocation_list[i].memory_size;

		for (uint64_t j = 0; j < total_allocations; ++j) {
#ifdef BA_DEBUG
			fprintf(stderr, "Trying to allocate size %u list memory size %lu\n", allocation_size,
				allocator->allocation_list[i].memory_size);
#endif
			memory = buddy_allocator_alloc(allocator, allocation_size);

#ifdef BA_DEBUG
			fprintf(stderr,
				"Got offset at alloc %lu allocation no %lu out of total %lu "
				"memory size %lu\n",
				memory - allocator->raw_memory, j, total_allocations,
				allocator->allocation_list[i].memory_size);
#endif
			*(uint32_t *)memory = BA_MAGIC_NUMBER;
		}

		memory = buddy_allocator_alloc(allocator, allocation_size);
		if (memory) {
			fprintf(stderr,
				"This allocation should have been NULL! for allocation list %lu "
				"total alloations %lu\n",
				allocator->allocation_list[i].memory_size, total_allocations);
			_exit(EXIT_FAILURE);
		}

		for (uint64_t j = 0; j < total_allocations; ++j) {
			struct ba_magic_number {
				struct ba_allocation_header header;
				uint32_t number;
			};
			struct ba_magic_number *magic_number =
				(struct ba_magic_number *)&allocator
					->raw_memory[j * allocator->allocation_list[i].memory_size];
			if (magic_number->number != BA_MAGIC_NUMBER) {
				fprintf(stderr,
					"Faulty allocation no %lu out of a total of %lu at list[%u] = "
					"%lu magic number is %u\n",
					j, total_allocations, i, allocator->allocation_list[i].memory_size,
					magic_number->number);
				_exit(EXIT_FAILURE);
			}
		}
#if BA_DEBUG
		fprintf(stderr, "Before free state is as follows\n");
		for (int list_id = 0; list_id < BA_NUM_ALLOCATION_LISTS; ++list_id) {
			fprintf(stderr, "Head of list %d is %lu\n", list_id,
				allocator->allocation_list[list_id].list_head);
		}
		fprintf(stderr, "Freeing now for allocation list with memory size %lu total_free %lu\n",
			allocator->allocation_list[i].memory_size, total_allocations);
#endif
		for (uint64_t j = 0; j < total_allocations; ++j) {
			char *free_addr = &raw_memory[(j * allocator->allocation_list[i].memory_size) +
						      sizeof(struct ba_allocation_header)];
			buddy_allocator_free(allocator, free_addr);
		}
#if BA_DEBUG
		fprintf(stderr, "After free state is as follows\n");
		for (int list_id = 0; list_id < BA_NUM_ALLOCATION_LISTS; ++list_id) {
			fprintf(stderr, "Head of list %d is %lu\n", list_id,
				allocator->allocation_list[list_id].list_head);
		}

		fprintf(stderr, "Freeing now for allocation list with memory size %lu SUCCESS\n",
			allocator->allocation_list[i].memory_size);
#endif
	}
	fprintf(stderr, "Test passed\n");
	buddy_allocator_destroy(allocator);
	return 0;
}*/
