// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "stack.h"
#include <assert.h>
#include <log.h>
#include <stdlib.h>

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
		_Exit(EXIT_FAILURE); /* Exit, returning error code. */
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
