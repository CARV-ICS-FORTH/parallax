/*
 *          File: stack.c
 *        Author: Robert I. Pitts <rip@cs.bu.edu>
 * Last Modified: March 7, 2000
 *         Topic: Stack - Array Implementation
 * Modified by Giorgos Saloustros, renamed functions due to conflict 13/04/2016
 * ----------------------------------------------------------------
 *
 * This is an array implementation of a character stack.
 */

#include <stdio.h>
#include <stdlib.h> /* for dynamic allocation */
#include <assert.h>
#include <log.h>
#include "stack.h"

/************************ Function Definitions **********************/

void stack_init(stackT *stackP)
{
	stackP->maxSize = MAX_SIZE;
	stackP->top = -1; /* I.e., empty */
}

void stack_reset(stackT *stackP)
{
	stackP->top = -1;
}
void stack_destroy(stackT *stackP)
{
	stackP->maxSize = 0;
	stackP->top = -1; /* I.e., empty */
}

void stack_push(stackT *stackP, stackElementT element)
{
	if (stack_is_full(stackP)) {
		log_fatal("Can't push element on stack: stack is full");
		assert(0);
		exit(EXIT_FAILURE); /* Exit, returning error code. */
	}

	/* Put information in array; update top. */

	stackP->contents[++stackP->top] = element;
}

stackElementT stack_pop(stackT *stackP)
{
	if (stack_is_empty(stackP)) {
		stackElementT guard = { .node = NULL, .idx = 0, .leftmost = 0, .rightmost = 0, .guard = 1 };
		return guard;
	}
	return stackP->contents[stackP->top--];
}

int stack_is_empty(stackT *stackP)
{
	return stackP->top < 0;
}

int stack_is_full(stackT *stackP)
{
	return stackP->top >= stackP->maxSize - 1;
}
