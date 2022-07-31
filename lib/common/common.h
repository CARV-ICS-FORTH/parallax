#ifndef COMMON_H_
#define COMMON_H_
#include <stdint.h>

#if defined(__GNUC__) && !defined(__clang__)
#define CHECK_PRINTF_FORMATTING __attribute__((format(printf, 2, 3)))
#elif defined(__clang__)
#define CHECK_PRINTF_FORMATTING __attribute__((__format__(__printf__, 2, 3)))
#else
#define CHECK_PRINTF_FORMATTING
#pragma message "Unknown compiler no checking for format arguments!\n"
#endif

__attribute__((noreturn)) void *BUG_ON(void);
__attribute__((noreturn)) uint32_t BUG_ON_UINT32T(void);

CHECK_PRINTF_FORMATTING void create_error_message(char **error_message, const char *fmt, ...);

#endif // COMMON_H_
