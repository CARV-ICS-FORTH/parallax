#include <stdio.h>
#include "parallax.h"

int main() {
    par_db_options db_options = { .volume_name = (char *)"/tmp/par",
				      .db_name = "test_db",
				      .create_flag = PAR_CREATE_DB,
				      .options = par_get_default_options() };
	db_options.options[LEVEL0_SIZE].value = 8;
	db_options.options[GROWTH_FACTOR].value = 8;
	db_options.options[PRIMARY_MODE].value = 1;
	db_options.options[ENABLE_BLOOM_FILTERS].value = 1;

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);

    if (error_message) {
		printf("Parallax says: %s\n", error_message);
	}

	if (handle == NULL && error_message) {
		printf("Error upon opening the DB, error %s\n", error_message);
	}

    return 0;
}
