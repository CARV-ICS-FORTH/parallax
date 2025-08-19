#include "parallax.h"
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_DB_PATH "/tmp/root/parallax/default"
#define TEST_DB_NAME "test_db"
#define TEST_KEY "key"
#define TEST_VALUE "value"
#define LARGE_VALUE_SIZE 16990

static void cleanup_and_exit(par_handle handle, void *buf1, void *buf2)
{
	if (buf1)
		free(buf1);
	if (buf2)
		free(buf2);
	if (handle)
		par_close(handle);
	exit(EXIT_FAILURE);
}

int main(void)
{
	log_info("Starting Parallax IB API test...");

	par_db_options db_options = { .volume_name = (char *)TEST_DB_PATH,
				      .db_name = TEST_DB_NAME,
				      .create_flag = PAR_CREATE_DB,
				      .options = par_get_default_options() };
	db_options.options[LEVEL0_SIZE].value = 8;
	db_options.options[GROWTH_FACTOR].value = 8;
	db_options.options[PRIMARY_MODE].value = 1;
	db_options.options[ENABLE_BLOOM_FILTERS].value = 1;

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);
	if (error_message) {
		log_debug("Parallax says: %s", error_message);
	}
	if (handle == NULL && error_message) {
		log_debug("Error upon opening the DB, error %s", error_message);
	}
	log_info("Database opened successfully.");

	log_info("Testing small put operation...");
	struct par_value value = {
		.val_buffer_size = strlen(TEST_VALUE) + 1,
		.val_size = strlen(TEST_VALUE) + 1,
		.val_buffer = malloc(strlen(TEST_VALUE) + 1),
	};
	if (!value.val_buffer) {
		log_debug("Memory allocation failed for value");
		cleanup_and_exit(handle, NULL, NULL);
	}
	memcpy(value.val_buffer, TEST_VALUE, value.val_size);
	struct par_key_value kv = {
		.k = { .size = strlen(TEST_KEY) + 1, .data = TEST_KEY },
		.v = value,
	};
	const char *error_msg = NULL;
	if (par_put(handle, &kv, &error_msg), error_msg) {
		log_debug("Error during put: %s", error_msg);
		cleanup_and_exit(handle, value.val_buffer, NULL);
	}
	log_info("Small put operation successful.");

	log_info("Testing large put operation...");
	char *large_value = malloc(LARGE_VALUE_SIZE + 1);
	if (!large_value) {
		log_debug("Memory allocation failed for large value");
		cleanup_and_exit(handle, value.val_buffer, NULL);
	}
	memset(large_value, 'd', LARGE_VALUE_SIZE);
	large_value[LARGE_VALUE_SIZE] = '\0';
	struct par_value largeValue = {
		.val_buffer_size = LARGE_VALUE_SIZE + 1,
		.val_size = LARGE_VALUE_SIZE,
		.val_buffer = large_value,
	};
	struct par_key_value largekv = {
		.k = { .size = strlen(TEST_KEY) + 1, .data = TEST_KEY },
		.v = largeValue,
	};
	if (par_put(handle, &largekv, &error_msg), error_msg) {
		log_debug("Error during large put: %s", error_msg);
		cleanup_and_exit(handle, value.val_buffer, large_value);
	}
	log_info("Large put operation successful.");

	log_info("Testing get operation for small value...");
	struct par_key key = { .size = strlen(TEST_KEY) + 1, .data = TEST_KEY };
	struct par_value getValue = { 0 };
	par_get(handle, &key, &getValue, &error_msg);
	if (error_msg) {
		log_debug("Error during get: %s", error_msg);
		cleanup_and_exit(handle, value.val_buffer, large_value);
	} else {
		log_info("Get operation successful for key '%s'.", TEST_KEY);
	}

	log_info("Testing get operation for large value...");
	struct par_value getLargeValue = { 0 };
	par_get(handle, &key, &getLargeValue, &error_msg);
	if (error_msg) {
		log_debug("Error during get (large value): %s", error_msg);
		cleanup_and_exit(handle, value.val_buffer, large_value);
	} else {
		log_info("Get operation successful for large value, key '%s'.", TEST_KEY);
	}

	log_info("Testing get operation for non-existing key...");
	const char *nfKeyStr = "nfKey";
	struct par_key nfKey = { .size = strlen(nfKeyStr) + 1, .data = nfKeyStr };
	struct par_value nfGetValue = { 0 };
	par_get(handle, &nfKey, &nfGetValue, &error_msg);
	if (error_msg) {
		log_debug("Expected error for non-existing key: %s", error_msg);
	} else {
		log_info("Unexpectedly found value for non-existing key.");
	}

	free(large_value);
	free(value.val_buffer);
	par_close(handle);

	log_info("All tests completed successfully.");
	return 0;
}
