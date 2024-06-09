// cppcheck-suppress-file [unreachableCode]
#define _GNU_SOURCE
#include "common.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
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
		snprintf(command, sizeof(command), "gdb -p %d -batch -x gdb_commands.txt", dying_pid);
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
	backtrace_on_sigsegv();
	raise(SIGSEGV);
	_exit(1);
}
