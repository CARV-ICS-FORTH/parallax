#ifndef COMMON_H_
#define COMMON_H_
#include <stdint.h>
__attribute__((noreturn)) void *BUG_ON(void);
__attribute__((noreturn)) uint32_t CALC_PIVOT_SIZE_OF_NULL_POINTER_BUG(void);
#endif // COMMON_H_
