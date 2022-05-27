#ifndef COMMON_H_
#define COMMON_H_
#include <stdint.h>
__attribute__((noreturn)) void *BUG_ON(void);
__attribute__((noreturn)) uint32_t BUG_ON_UINT32T(void);
#endif // COMMON_H_
