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

void *BUG_ON(const char *file, unsigned line, const char *function)
{
	log_fatal("Fatal BUG: File %s: line %u: function %s", file, line, function);
	stack_trace();
	_Exit(EXIT_FAILURE);
}
