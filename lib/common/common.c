#define _GNU_SOURCE
#include "common.h"
#include <assert.h>
#include <execinfo.h>
#include <log.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#define TRACE_SIZE 32

/** Prints the stack trace for the last \ref TRACE_SIZE functions on the call_stack.  */
void stack_trace(void)
{
	void *trace[TRACE_SIZE];
	char **messages = (char **)NULL;

	int trace_size = backtrace(trace, TRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);
	assert(0);
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

/**
 * @brief It prints the stack trace of the process using gdb. Compared to print_stack_trace, this function is more portable and produces
 * human readable output consistently. https://neugierig.org/software/blog/2012/06/backtraces.html
 *
 * @param signal
 */
void print_stack_trace_with_gdb(int signal)
{
	(void)signal;
	pid_t dying_pid = getpid();
	pid_t child_pid = fork();
	FILE *fp = fopen("gdb_commands.txt", "w");
	if (fp == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	fprintf(fp, "set pagination off\n"
		    "bt full\n"
		    "python\n"
		    "import gdb\n"
		    "frame = gdb.newest_frame()\n"
		    "while frame is not None:\n"
		    "    gdb.execute('frame ' + str(frame.level()))\n"
		    "    try:\n"
		    "        gdb.execute('list')\n"
		    "    except gdb.error:\n"
		    "        print('No source available for this frame.')\n"
		    "    frame = frame.older()\n"
		    "end\n"
		    "quit\n");
	fclose(fp);

	if (child_pid < 0) {
		perror("fork() while collecting backtrace:");
	} else if (child_pid == 0) {
		char command[1024];
		snprintf(command, sizeof(command), "gdb -p %d -batch -x /tmp/gdb_commands.txt", dying_pid);
		const char *argv[] = { "sh", "-c", command, NULL };
		execve("/bin/sh", (char **)argv, NULL);
		_exit(1);
	} else {
		waitpid(child_pid, NULL, 0);
	}
	_exit(1);
}

void backtrace_on_sigsegv(void)
{
	struct sigaction action = { 0 };
	action.sa_handler = print_stack_trace_with_gdb;
	if (sigaction(SIGSEGV, &action, NULL) < 0) {
		perror("sigaction(SEGV)");
	}
}

/** Prints a stack trace and terminates program execution.
 *  It returns void * to suppress compiler warnings in the future this function will return void.
 */
__attribute__((noreturn)) void *BUG_ON(void)
{
	raise(SIGSEGV);
	_exit(EXIT_FAILURE);
}