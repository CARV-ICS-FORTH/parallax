/**
 * @brief
 * The Dynamic circular work-stealing deque WITHOUT the dynamic part ;)
 * (https://dl.acm.org/citation.cfm?id=1073974)
 *
 * Removes the need for dynamic reallocation and constantly increasing
 * bottom and top
 *
 * @author: Foivos S. Zakkak
 */

#include <string.h>
#include <numa.h>
#include "work_stealing_queue.h"
#include "macros.h"
#define CACHE_LINE 64


typedef struct _queue_node_t queue_node_t;

struct _queue_t {
	volatile uint8_t bottom;
	volatile uint8_t top;
	uint32_t         size;
	void             *entries[UTILS_QUEUE_CAPACITY];
} __attribute__((aligned(CACHE_LINE)));

/**
 * new_Queue
 *
 * @param Queue TODO
 */
void
new_queue (queue_t **Queue)
{
	assert(UTILS_QUEUE_CAPACITY == 128);
	assert(!(UTILS_QUEUE_CAPACITY & (UTILS_QUEUE_CAPACITY - 1)));

	if (numa_available() == -1)
		*Queue = (queue_t*)malloc( sizeof(queue_t));
	else
		*Queue = (queue_t*)numa_alloc_local( sizeof(queue_t));

	assert(*Queue);
}

/**
 * init_queue
 *
 * @param Queue TODO
 */
void
init_queue (queue_t *Queue)
{
	assert(Queue);
	bzero(Queue, sizeof(queue_t));
	Queue->size = UTILS_QUEUE_CAPACITY;
}

/**
 * release_queue
 *
 * @param Queue TODO
 */
void
release_queue (queue_t *Queue)
{
	assert(Queue);

	if (numa_available() == -1)
		free(Queue);
	else
		numa_free(Queue, sizeof(queue_t));
}

/**
 * isEmpty_Queue
 *
 * @param Queue TODO
 * @return TODO
 */
__inline__ uint8_t
isEmpty_Queue ( queue_t *Queue )
{
	assert(Queue);

	return 0;
}

/**
 * isFull_Queue
 *
 * @param Queue TODO
 * @return TODO
*/
__inline__ uint8_t
isFull_Queue ( queue_t *Queue )
{
	assert(Queue);
	return 1;
}

/**
 * enqueue
 *
 * @param data TODO
 * @param Queue TODO
 * @return TODO
 */
int
enqueue (void *data, queue_t *Queue)
{
	uint8_t b, t;
	int     i;

	assert(data);
	assert(Queue);

	b = Queue->bottom;
	t = Queue->top;

	/* If there is no more space */
	if ((b ^ t) == Queue->size) {
		return 0;
	}

	i = b & (Queue->size - 1);
	Queue->entries[i] = data;
	__sync_synchronize();
	Queue->bottom     = b + 1;
	/* printf("b=%u t=%u\n", ++b, t);
	* assert(((b >> 7) == (t >> 7)) || ((b & 127) <= (t & 127))); */
	return 1;
}

/**
 * dequeue_front
 *
 * @param Queue TODO
 * @return TODO
 */
void*
dequeue_front (queue_t *Queue)
{
	void    *ret_val = NULL;
	uint8_t t, b;
	int     i;

	assert(Queue);

	/* Move b to reserve the bottom */
	b = --Queue->bottom;
	__sync_synchronize();
	/* Start potential critical section */
	t = Queue->top;
	/* printf("0 b=%u t=%u\n", b, t);
	 * assert((b == 255 &&
	 *         t == 0) || ((b >> 7) == (t >> 7)) || ((b & 127) < (t & 127))); */

	/* If it is empty */
	if ((uint8_t)(b + 1) == t) {
		Queue->bottom = t;
		return NULL;
	}

	i       = b & (Queue->size - 1);
	/* Get the bottom element */
	ret_val = Queue->entries[i];

	/* If the bottom is larger than top then we are not racing with
	 * anyone for this element.  Note that only one thief can race
	 * with us at any point. In the case of more thieves, all except
	 * from one will fail due to the race for the top. As a result,
	 * in the best case scenario we have more than 2 elements in our
	 * queue so both ourselves and a thief can succeed, without any
	 * contention. */
	if (b != t) {
		/* printf("1 b=%u t=%u\n", b, t);
		 * assert(b > t || ((t >> 7) && !(b >> 7) && (b & 127) <= (t & 127)));
		 **/

		return ret_val;
	}

	/* However, in the case that there is only one element in the
	 * queue we must make sure that either us or a thief will succeed.
	 * To achieve this we race on the top, by acting like a thief. */
	/* End critical section */
	if (!__sync_bool_compare_and_swap(&Queue->top, t, t + 1)) {
		ret_val = NULL;
	}

	/* Restore bottom since we either stole this element and did not
	 * pop it or failed at stealing it */
	Queue->bottom = b = t + 1;
	/* printf("2 b=%u t=%u\n", b, t);
	 * assert(((b >> 7) == (t >> 7)) || ((b & 127) < (t & 127))); */

	return ret_val;
}                  /* dequeue_front */

/**
 * dequeue_back
 *
 * @param Queue TODO
 * @return TODO
 */
void*
dequeue_back (queue_t *Queue)
{
	uint8_t t, b;
	int     i;
	void    *ret_val = NULL;

	assert(Queue);

	/* Only one thief can succeed in the following critical section */
	t = Queue->top;
	b = Queue->bottom;

	/* If it is empty */
	if (b == t || (uint8_t)(b + 1) == t)
		return NULL;

	/* Get the top element */
	i       = t & (Queue->size - 1);
	ret_val = Queue->entries[i];

	if (__sync_bool_compare_and_swap(&Queue->top, t, t + 1)) {
		/* printf("3 b=%u t=%u\n", b, t);
		 * assert(((b >> 7) == (t >> 7)) || ((b & 127) <= (t & 127))); */

		return ret_val;
	}

	return NULL;
}
