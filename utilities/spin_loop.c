#include <stdio.h>
#include <stdint.h>

int64_t get_counter(int64_t *counter);
uint32_t _read_value(uint32_t *value_addr);

void spin_loop(int64_t *counter, int64_t threashold)
{
	while (get_counter(counter) > threashold) {
	}
	return;
}

void wait_for_value(uint32_t *value_addr, uint32_t value)
{
	while (_read_value(value_addr) != value) {
	}
}

uint32_t _read_value(uint32_t *value_addr)
{
	return *value_addr;
}

int64_t get_counter(int64_t *counter)
{
	return *counter;
}
