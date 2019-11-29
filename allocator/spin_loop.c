#include <stdio.h>
#include <stdint.h>
int64_t get_counter(int64_t * counter);


void spin_loop(int64_t * counter, uint64_t threashold){
	while(get_counter(counter) > threashold){}
	return;
}


int64_t get_counter(int64_t * counter){
	return *counter;
}
