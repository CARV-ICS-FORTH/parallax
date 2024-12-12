#include "buddy_allocator.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Constants for testing
#define TEST_MEMORY_SIZE (1024 * 1024) // 1MB
#define TEST_ALLOCATION_SIZE_SMALL 32
#define TEST_ALLOCATION_SIZE_MEDIUM 128
#define TEST_ALLOCATION_SIZE_LARGE (BA_MAX_ALLOCATION_SIZE / 2)
#define MAX_ALLOCATIONS 100
#define MAX_ALLOCATION_SIZE 256
#define TEST_ITERATIONS 1000

void test_random_allocations(void)
{
	printf("Testing random allocations and frees...\n");

	// Allocate raw memory for the allocator
	void *raw_memory = NULL;
	posix_memalign(&raw_memory, 4096, TEST_MEMORY_SIZE);
	assert(raw_memory != NULL);

	// Create the allocator
	buddy_allocator_t *allocator = buddy_create(raw_memory, TEST_MEMORY_SIZE);
	assert(allocator != NULL);
	printf("Allocator created with %u bytes of memory.\n", TEST_MEMORY_SIZE);

	// Array to keep track of allocated pointers
	void *allocated[MAX_ALLOCATIONS] = { NULL };

	// Seed random number generator
	srand((unsigned int)time(NULL));

	// Perform random allocations, frees, and memsets
	for (int iter = 0; iter < TEST_ITERATIONS; iter++) {
		int action = rand() % 2; // Randomly choose to allocate, free, or memset

		if (action == 0) { // Allocate
			// Find a free slot in the allocated array
			int slot = -1;
			for (int i = 0; i < MAX_ALLOCATIONS; i++) {
				if (allocated[i] == NULL) {
					slot = i;
					break;
				}
			}

			if (slot != -1) {
				size_t size = (rand() % MAX_ALLOCATION_SIZE) + 1;
				void *ptr = buddy_allocator_alloc(allocator, size);
				if (ptr != NULL) {
					allocated[slot] = ptr;
					memset(ptr, rand() % 256, size); // Fill memory with random data
					printf("Allocated %zu bytes at %p\n", size, ptr);
				}
			}
		} else { // Free
			// Find a random allocated slot to free
			int slot = rand() % MAX_ALLOCATIONS;
			if (allocated[slot] != NULL) {
				printf("Freeing memory at %p\n", allocated[slot]);
				buddy_allocator_free(allocator, allocated[slot]);
				allocated[slot] = NULL;
			}
		}
	}
	// Free all remaining allocations
	for (int i = 0; i < MAX_ALLOCATIONS; i++) {
		if (allocated[i] != NULL) {
			printf("Freeing remaining memory at %p\n", allocated[i]);
			buddy_allocator_free(allocator, allocated[i]);
			allocated[i] = NULL;
		}
	}

	// Destroy the allocator
	buddy_allocator_destroy(allocator);
	printf("Allocator destroyed.\n");

	printf("Random allocation and free test passed!\n");
}

void test_buddy_allocator(void)
{
	// Allocate raw memory for the allocator
	void *raw_memory = NULL;
	posix_memalign(&raw_memory, 4096, TEST_MEMORY_SIZE);
	assert(raw_memory != NULL);

	// Create the allocator
	buddy_allocator_t *allocator = buddy_create(raw_memory, TEST_MEMORY_SIZE);
	assert(allocator != NULL);

	// Test small allocation
	void *ptr1 = buddy_allocator_alloc(allocator, TEST_ALLOCATION_SIZE_SMALL);
	assert(ptr1 != NULL);
	memset(ptr1, 0xAA, TEST_ALLOCATION_SIZE_SMALL); // Test write access

	// Test large allocation
	void *ptr2 = buddy_allocator_alloc(allocator, TEST_ALLOCATION_SIZE_LARGE);
	assert(ptr2 != NULL);
	memset(ptr2, 0xBB, TEST_ALLOCATION_SIZE_LARGE); // Test write access

	// Free allocations
	buddy_allocator_free(allocator, ptr1);
	buddy_allocator_free(allocator, ptr2);

	// Attempt out-of-bound allocation

	// Test multiple small allocations
	void *ptrs[100];
	for (int i = 0; i < 100; i++) {
		ptrs[i] = buddy_allocator_alloc(allocator, TEST_ALLOCATION_SIZE_SMALL);
		assert(ptrs[i] != NULL);
	}

	// Free all allocations
	for (int i = 0; i < 100; i++) {
		buddy_allocator_free(allocator, ptrs[i]);
	}

	// Stress test with variable sizes
	for (int i = 1; i <= 10; i++) {
		size_t size = TEST_ALLOCATION_SIZE_SMALL * i;
		void *ptr = buddy_allocator_alloc(allocator, size);
		assert(ptr != NULL);
		memset(ptr, 0xDD, size); // Test write access
		buddy_allocator_free(allocator, ptr);
	}

	// Allocate minimum possible size
	void *ptr5 = buddy_allocator_alloc(allocator, BA_MIN_ALLOCATION_SIZE);
	assert(ptr5 != NULL);
	memset(ptr5, 0xEE, BA_MIN_ALLOCATION_SIZE);
	buddy_allocator_free(allocator, ptr5);

	// Allocate with size not power of two
	void *ptr6 = buddy_allocator_alloc(allocator, TEST_ALLOCATION_SIZE_MEDIUM + 1);
	assert(ptr6 != NULL);
	memset(ptr6, 0xFF, TEST_ALLOCATION_SIZE_MEDIUM + 1);
	buddy_allocator_free(allocator, ptr6);

	// Destroy the allocator
	buddy_allocator_destroy(allocator);

	// Free raw memory
	//free(raw_memory);

	printf("All tests passed!\n");
}

int main(void)
{
	test_buddy_allocator();
	test_random_allocations();
	return 0;
}
