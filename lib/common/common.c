#include "common.h"
#include <execinfo.h>
#include <log.h>
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

	for (int i = 0; i < trace_size; i++)
		log_fatal("%s", messages[i]);

	log_fatal("<<<<<<<<<[stack trace ends here]>>>>>>>>>");

	free(messages);
}

/** Prints a stack trace and terminates program execution.
 *  It returns void * to suppress compiler warnings in the future this function will return void.*/
__attribute__((noreturn)) void *BUG_ON(void)
{
	stack_trace();
	_Exit(EXIT_FAILURE);
}

__attribute__((noreturn)) uint32_t CALC_PIVOT_SIZE_OF_NULL_POINTER_BUG(void)
{
	stack_trace();
	_Exit(EXIT_FAILURE);
}
