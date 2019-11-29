#include "locks.h"
#include <stdio.h>
#include <assert.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")

void membar() {
  asm volatile("": : :"memory");
  __sync_synchronize();
};

void acquire(lock_queue_t *L, qnode_t *I) {
  assert(I);

  // set this node's status to waiting and get predecessor
  I->next = NULL;
  I->locked = 1;
  membar();

  qnode_t *predecessor = __sync_lock_test_and_set(L, I); // note: this works like a fetch_and_set

  if (predecessor) {
    predecessor->next = I; // set self to next
    while (I->locked); //spin
  }

  membar();
}

void release(lock_queue_t *L, qnode_t *I) {
  membar();

  if (I->next == NULL) { // no known successor
    if (__sync_bool_compare_and_swap(L, I, NULL)) {// are we still head?
      return;
    }

    while (I->next == NULL); // wait for new node to change next
  }

  I->next->locked = 0; // unlock the new node
}

#pragma GCC pop_options
