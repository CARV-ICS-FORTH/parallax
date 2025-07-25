#include "parallax.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
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

	const char *keyStr = "test";
	const char *valueStr = "data";

	struct par_value value = {
		.val_buffer_size = strlen(valueStr) + 1,
		.val_size = strlen(valueStr) + 1,
		.val_buffer = malloc(strlen(valueStr) + 1),
	};
	if (!value.val_buffer) {
		fprintf(stderr, "Memory allocation failed\n");
		return 1;
	}
	memcpy(value.val_buffer, valueStr, value.val_size);
	struct par_key_value kv = {
		.k = {
			.size = strlen(keyStr) + 1,
			.data = keyStr,
		},
		.v = value,
	};
	const char *error_msg = NULL;
	par_put(handle, &kv, &error_msg);

	struct par_key key = {
		.size = strlen(keyStr) + 1,
		.data = keyStr,
	};
	struct par_value getValue;
	par_get(handle, &key, &getValue, &error_msg);

	free(value.val_buffer);

	par_close(handle);

	return 0;
}
