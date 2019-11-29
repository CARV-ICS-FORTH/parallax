#include <stdint.h>
#define EMPTY_MIN_HEAP 4
#define GOT_MIN_HEAP 5
#define HEAP_SIZE 8

typedef struct heap_node {
	void *data;
  uint8_t level_id;
	uint8_t duplicate;
} heap_node;

typedef struct minHeap {
  heap_node elem[HEAP_SIZE];
	int size;
	int active_tree;
} minHeap;

void initMinHeap(minHeap *heap, int active_tree);
void insertheap_node(minHeap *hp, heap_node * nd);
uint8_t getMinAndRemove(minHeap *hp, heap_node *node);
