#include <stdlib.h>

int main(void)
{
	char *a = malloc(sizeof(char));
	(void)a;
	//cppcheck-suppress memleak
	return 0;
}
