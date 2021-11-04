#include <stdint.h>

uint32_t read_value(volatile uint32_t *value_addr)
{
	return *value_addr;
}

int64_t get_counter(volatile int64_t *counter)
{
	return *counter;
}

void spin_loop(volatile int64_t *counter, int64_t threashold)
{
	while (get_counter(counter) > threashold)
		;
}

void wait_for_value(volatile uint32_t *value_addr, uint32_t value)
{
	while (read_value(value_addr) != value)
		;
}
