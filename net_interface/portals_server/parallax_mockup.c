#include "../allocator/kv_format.h"
#include "../btree/btree.h"
#include "../btree/set_options.h"
#include "../include/parallax/parallax.h"
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Dump implementation of the functions
char *par_format(char *device_name, uint32_t max_regions_num)
{
	log_debug("Called par_format with device_name: %s, max_regions_num: %u", device_name, max_regions_num);
	return kvf_init_parallax(device_name, max_regions_num);
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
#ifdef LOG_LEVEL_RELEASE
	log_set_level(2);
#endif
	log_debug("Called par_open with create_flag: %d", db_options->create_flag);
	if (db_options->create_flag == PAR_CREATE_DB || db_options->create_flag == PAR_DONOT_CREATE_DB) {
		return (par_handle)db_open(db_options, error_message);
	}

	*error_message = "Unknown create flag provided.";
	return NULL;
}

const char *par_close(par_handle handle)
{
	log_debug("Called par_close with handle: %p", handle);
	return NULL; // No actual closing of database
}

char *par_get_db_name(par_handle handle, const char **error_message)
{
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_get_db_name with handle: %p", handle);
	return "dummy_db_name"; // Return a dummy name
}

enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message)
{
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called get_kv_category with key_size: %d, value_size: %d, operation: %d", key_size, value_size,
		  operation);
	return BIG_INLOG; // Dummy return value
}

struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_put with handle: %p, key_size: %d, value_size: %d", handle, key_value->k.size,
		  key_value->v.val_size);
	struct par_put_metadata dummy_metadata = { 0 }; // Return dummy metadata
	return dummy_metadata;
}

struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction)
{
	(void)serialized_key_value; // Suppress unused parameter warning
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_put_serialized with handle: %p, append_to_log: %d, abort_on_compaction: %d", handle,
		  append_to_log, abort_on_compaction);
	struct par_put_metadata dummy_metadata = { 0 }; // Return dummy metadata
	return dummy_metadata;
}

void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_get with handle: %p, key_size: %d", handle, key->size);
	// Simulate a successful fetch
	value->val_size = 0;
	value->val_buffer = NULL;
}

void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message)
{
	(void)key_serialized; // Suppress unused parameter warning
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_get_serialized with handle: %p", handle);
	value->val_size = 0;
	value->val_buffer = NULL;
}

par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	log_debug("Called par_exists with handle: %p, key_size: %d", handle, key->size);
	return PAR_KEY_NOT_FOUND; // Simulate that the key does not exist
}

uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat)
{
	(void)buf; // Suppress unused parameter warning
	(void)buf_size; // Suppress unused parameter warning
	log_debug("Called par_flush_segment_in_log with handle: %p, IO_size: %u, log_cat: %d", handle, IO_size,
		  log_cat);
	return 0; // Simulate no operation
}

void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_delete with handle: %p, key_size: %d", handle, key->size);
}

par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
	(void)key; // Suppress unused parameter warning
	(void)error_message; // Suppress unused parameter warning
	log_debug("Called par_init_scanner with handle: %p, mode: %d", handle, mode);
	return NULL; // Simulate scanner initialization
}

void par_close_scanner(par_scanner sc)
{
	log_debug("Called par_close_scanner with scanner: %p", sc);
}

int par_get_next(par_scanner sc)
{
	log_debug("Called par_get_next with scanner: %p", sc);
	return 0; // Simulate no next item
}

int par_is_valid(par_scanner sc)
{
	log_debug("Called par_is_valid with scanner: %p", sc);
	return 0; // Simulate invalid scanner
}

struct par_key par_get_key(par_scanner sc)
{
	log_debug("Called par_get_key with scanner: %p", sc);
	struct par_key dummy_key = { 0 }; // Return dummy key
	return dummy_key;
}

struct par_value par_get_value(par_scanner sc)
{
	log_debug("Called par_get_value with scanner: %p", sc);
	struct par_value dummy_value = { 0 }; // Return dummy value
	return dummy_value;
}

par_ret_code par_sync(par_handle handle)
{
	log_debug("Called par_sync with handle: %p", handle);
	return PAR_SUCCESS; // Simulate success
}

struct par_options_desc *par_get_default_options(void)
{
	struct par_options_desc *default_db_options =
		(struct par_options_desc *)calloc(NUM_OF_CONFIGURATION_OPTIONS, sizeof(struct par_options_desc));

	// parse the options from options.yml config file
	struct lib_option *dboptions = NULL;
	parse_options(&dboptions);

	struct lib_option *option = NULL;
	/*get the default db option values */
	check_option(dboptions, "level0_size", &option);
	uint64_t level0_size = MB(option->value.count);

	check_option(dboptions, "growth_factor", &option);
	uint64_t growth_factor = option->value.count;

	check_option(dboptions, "level_medium_inplace", &option);
	uint64_t level_medium_inplace = option->value.count;

	check_option(dboptions, "medium_log_LRU_cache_size", &option);
	uint64_t LRU_cache_size = MB(option->value.count);

	check_option(dboptions, "gc_interval", &option);
	uint64_t gc_interval = option->value.count;

	check_option(dboptions, "primary_mode", &option);
	uint64_t primary_mode = option->value.count;

	check_option(dboptions, "replica_mode", &option);
	uint64_t replica_mode = option->value.count;

	check_option(dboptions, "replica_build_index", &option);
	uint64_t replica_build_index = option->value.count;

	check_option(dboptions, "replica_send_index", &option);
	uint64_t replica_send_index = option->value.count;

	check_option(dboptions, "enable_bloom_filters", &option);
	uint64_t enable_bloom_filters = option->value.count;

	check_option(dboptions, "enable_compaction_double_buffering", &option);
	uint64_t enable_compaction_double_buffering = option->value.count;

	check_option(dboptions, "number_of_replicas", &option);
	uint64_t number_of_replicas = option->value.count;

	//fill default_db_options based on the default values
	default_db_options[LEVEL0_SIZE].value = level0_size;
	default_db_options[GROWTH_FACTOR].value = growth_factor;
	default_db_options[LEVEL_MEDIUM_INPLACE].value = level_medium_inplace;
	default_db_options[MEDIUM_LOG_LRU_CACHE_SIZE].value = LRU_cache_size;
	default_db_options[GC_INTERVAL].value = gc_interval;
	default_db_options[PRIMARY_MODE].value = primary_mode;
	default_db_options[REPLICA_MODE].value = replica_mode;
	default_db_options[ENABLE_BLOOM_FILTERS].value = enable_bloom_filters;
	default_db_options[ENABLE_COMPACTION_DOUBLE_BUFFERING].value = enable_compaction_double_buffering;
	default_db_options[NUMBER_OF_REPLICAS].value = number_of_replicas;
	default_db_options[REPLICA_BUILD_INDEX].value = replica_build_index;
	default_db_options[REPLICA_SEND_INDEX].value = replica_send_index;
	default_db_options[WCURSOR_SPIN_FOR_FLUSH_REPLIES].value = 0;

	return default_db_options;
}
