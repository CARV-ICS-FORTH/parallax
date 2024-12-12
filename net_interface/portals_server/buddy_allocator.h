#include <stdint.h>
#include <stdio.h>

#define BA_PAGE_SIZE (4096)
#define BA_BITS_PER_BYTE (8)
#define BA_BITS_PER_BITMAP_ID (sizeof(long int) * BA_BITS_PER_BYTE)
#define BA_MAX_SIZE_POW (16)
#define BA_MIN_SIZE_POW (5) // 32 B
#define BA_MAX_ALLOCATION_SIZE (1L << BA_MAX_SIZE_POW) // 16GB
#define BA_MIN_ALLOCATION_SIZE (1L << BA_MIN_SIZE_POW)
#define BA_NUM_ALLOCATION_LISTS ((BA_MAX_SIZE_POW - BA_MIN_SIZE_POW) + 1)
#define BA_BIT_MASK(X) (1L << X)
#define BA_INV_BIT_MASK(X) (~BA_BIT_MASK(X))
#define BA_SET_BIT(X, Y) (*X = *X | BA_BIT_MASK(Y))
#define BA_CLEAR_BIT(X, Y) (*X = *X & BA_INV_BIT_MASK(Y))
#define BA_GET_BIT(X, Y) ((X & (1L << Y)) >> Y)

struct ba_allocation_list {
	uint64_t memory_size;
	uint64_t bitmap_size;
	struct ba_allocation_header *list_head;
	long int *bitmap;
};

typedef struct {
	struct ba_allocation_list allocation_list[BA_NUM_ALLOCATION_LISTS];
	size_t raw_memory_size;
	char *raw_memory;
} buddy_allocator_t;

buddy_allocator_t *buddy_create(void *raw_memory, size_t raw_memory_size);
void *buddy_allocator_alloc(buddy_allocator_t *allocator, size_t size);
void buddy_allocator_free(buddy_allocator_t *allocator, void *ptr);
void buddy_allocator_destroy(buddy_allocator_t *allocator);
