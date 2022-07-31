#ifndef COMMON_MACROS_H_
#define COMMON_MACROS_H_

#include <assert.h>
#define SAFE_FREE_PTR(ptr) \
	assert(ptr);       \
	free(ptr);         \
	ptr = NULL;

#endif // COMMON_MACROS_H_
