#if !DISABLE_LOGGING
#include <stdio.h>
#endif

#include <stdint.h>

int main(void)
{
	uint64_t x = 0;
	(void)x;
#if !DISABLE_LOGGING
	printf("Disable Logging is not working\n");
#endif
	return 0;
}
