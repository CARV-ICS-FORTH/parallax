#include <log.h>
#include <parallax/parallax.h>
#include <parallax/structures.h>
#include <stdlib.h>

int main(void)
{
	const char *error_message = NULL;
	if (get_kv_category(5, 15, insertOp, &error_message) != SMALL_INPLACE) {
		log_fatal("A small sized key is not labeled as SMALL_INPLACE");
		exit(EXIT_FAILURE);
	}
	if (get_kv_category(5, 150, insertOp, &error_message) != MEDIUM_INPLACE) {
		log_fatal("A medium sized key is not labeled as MEDIUM_INPLACE");
		exit(EXIT_FAILURE);
	}
	if (get_kv_category(5, 1500, insertOp, &error_message) != BIG_INLOG) {
		log_fatal("A large sized key is not labeled as BIG_INLOG");
		exit(EXIT_FAILURE);
	}
	return 0;
}
