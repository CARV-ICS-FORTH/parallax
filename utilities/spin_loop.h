#include <stdio.h>
#include <stdint.h>

void spin_loop(volatile int64_t *counter, int64_t threashold);
void wait_for_value(volatile uint32_t *value_addr, uint32_t value);
