#define _GNU_SOURCE
#include "common.h"
#include <execinfo.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#define TRACE_SIZE 32

/** Prints the stack trace for the last \ref TRACE_SIZE functions on the call_stack.  */
void stack_trace(void)
{
	void *trace[TRACE_SIZE];
	char **messages = (char **)NULL;

	int trace_size = backtrace(trace, TRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);

	log_fatal("<<<<<<<<<[stack trace starts here]>>>>>>>>>");

	//Start index from 2 to ignore stack_trace() and BUG_ON() calls.
	for (int i = 2; i < trace_size; i++)
		log_fatal("%s", messages[i]);

	log_fatal("<<<<<<<<<[stack trace ends here]>>>>>>>>>");

	free(messages);
}

__attribute__((noreturn)) void print_stack_trace(void)
{
	stack_trace();
	_Exit(EXIT_FAILURE);
}

/** Prints a stack trace and terminates program execution.
 *  It returns void * to suppress compiler warnings in the future this function will return void.
 */
__attribute__((noreturn)) void *BUG_ON(void)
{
	print_stack_trace();
}

__attribute__((noreturn)) uint32_t BUG_ON_UINT32T(void)
{
	print_stack_trace();
}
