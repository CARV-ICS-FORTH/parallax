/*
 *          File: stack.h
 *        Author: Robert I. Pitts <rip@cs.bu.edu>
 * Last Modified: March 7, 2000
 *         Topic: Stack - Array Implementation
 * ----------------------------------------------------------------
 *
 * This is the interface for a stack of characters.
 */
#pragma once
#include <stdint.h>

#include "../btree/conf.h"
#include "../btree/btree.h"

/*
 * Type: stackElementT
 * -------------------
 * This is the type of the objects entered in the stack.
 * Edit it to change the type of things to be placed in
 * the stack.
 */

typedef struct stackElementT {
	node_header *node;
	uint32_t idx;
	uint8_t leftmost;
	uint8_t rightmost;
	uint8_t guard;
} stackElementT;

/*
 * Type: stackT
 * --------------
 * This is the type for a stack, i.e., it is a type that
 * holds the information necessary to keep track of a stack.
 * It has a pointer `contents' to a dynamically-allocated
 * array (used to hold the contents of the stack), an integer
 * `maxSize' that holds the size of this array (i.e., the
 * maximum number of things that can be held in the stack),
 * and another integer `top,' which stores the array index of
 * the element at the top of the stack.
 */

typedef struct {
	stackElementT contents[MAX_SIZE];
	int maxSize;
	int top;
} stackT;
/*
 * Function: StackInit
 * Usage: StackInit(&stack, maxSize);
 * -------------------------
 * A new stack variable is initialized.  The initialized
 * stack is made empty.  MaxSize is used to determine the
 * maximum number of character that can be held in the
 * stack.
 */

void stack_init(stackT *stackP);

/* Function: StackDestroy
 * Usage: StackDestroy(&stack);
 * -----------------------
 * This function frees all memory associated with the stack.
 * The `stack' variable may not be used again unless
 * StackInit(&stack, maxSize) is first called on the stack.
 */

void stack_destroy(stackT *stackP);

/*
 * Functions: StackPush, StackPop
 * Usage: StackPush(&stack, element); element = StackPop(&stack);
 * --------------------------------------------
 * These are the fundamental stack operations that add an element to
 * the top of the stack and remove an element from the top of the stack.
 * A call to StackPop on an empty stack or to StackPush on a full stack
 * is an error.  Make use of StackIsEmpty()/StackIsFull() (see below)
 * to avoid these errors.
 */

void stack_push(stackT *stackP, stackElementT element);
stackElementT stack_pop(stackT *stackP);

/*
 * Functions: StackIsEmpty, StackIsFull
 * Usage: if (StackIsEmpty(&stack)) ...
 * -----------------------------------
 * These return a true value if the stack is empty
 * or full (respectively).
 */
void stack_reset(stackT *stackP);

int stack_is_empty(stackT *stackP);
int stack_is_full(stackT *stackP);
