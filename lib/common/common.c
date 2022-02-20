#include "common.h"
#include <execinfo.h>
#include <log.h>
#include <stdlib.h>

#define TRACE_SIZE 32
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

_Noreturn void *BUG_ON(void)
{
	stack_trace();
	_Exit(EXIT_FAILURE);
}
