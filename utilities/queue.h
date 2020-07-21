#ifndef UTILS_QUEUE_HEADER
#define UTILS_QUEUE_HEADER
#include <stddef.h>
#include <stdint.h>

#define CONF_CACHE_LINE 64

/*watch out this is the vanilla value*/
#define UTILS_QUEUE_CAPACITY 1024 //512

#ifdef __cplusplus
extern "C" {
#endif /* ifdef __cplusplus */

/**
 * Internal structure of queue.
 */
struct queue {
	/** Push here  */
	volatile uint16_t bottom __attribute__((aligned(CONF_CACHE_LINE)));

	/** Pop here */
	volatile uint16_t top __attribute__((aligned(CONF_CACHE_LINE)));

	/** Pointers to data. */
	void *entries[UTILS_QUEUE_CAPACITY];
} __attribute__((aligned(CONF_CACHE_LINE)));

typedef struct queue utils_queue_s;

/**
 * Initialize a queue at the memory pointed by buff.
 *
 * @param buff Allocated buffer.
 * @return queue instance.NULL on failure.
 */
utils_queue_s *utils_queue_init(void *buff);

/**
 * Return number of used slots in the queue.
 *
 * NOTE: Since this is a concurrent queue the value returned by this
 * function may not always reflect the true state of the queue
 *
 * @param q Valid queue instance pointer.
 * @return Number of used slots in queue.
 */
unsigned int utils_queue_used_slots(utils_queue_s *q);

/**
 * Add data to an queue
 *
 * @param q Valid queue instance pointer.
 * @param data Non NULL pointer to data.
 * @return Equal to data, NULL on failure.
 */
void *utils_queue_push(utils_queue_s *q, void *data);

/**
 * Pop data from queue.
 *
 * @param q Valid queue instance pointer.
 * @return Data pointer, NULL on failure.
 */
void *utils_queue_pop(utils_queue_s *q);

/**
 * Peek first element from queue if any
 *
 * @param q Valid queue instance pointer.
 * @return Data pointer, NULL on failure.
 */
void *utils_queue_peek(utils_queue_s *q);
#ifdef __cplusplus
}
#endif /* ifdef __cplusplus */

#endif /* ifndef UTILS_QUEUE_HEADER */
