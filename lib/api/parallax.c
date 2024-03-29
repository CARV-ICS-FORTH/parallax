// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "../include/parallax/parallax.h"
#include "../allocator/kv_format.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/index_node.h"
#include "../btree/kv_pairs.h"
#include "../btree/set_options.h"
#include "../scanner/scanner.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256
#define NUM_OF_OPTIONS 5

char *par_format(char *device_name, uint32_t max_regions_num)
{
	return kvf_init_parallax(device_name, max_regions_num);
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
	if (db_options->create_flag == PAR_CREATE_DB || db_options->create_flag == PAR_DONOT_CREATE_DB) {
		return (par_handle)db_open(db_options, error_message);
	}

	*error_message = "Unknown create flag provided.";
	return NULL;
}

const char *par_close(par_handle handle)
{
	return db_close((db_handle *)handle);
}

enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message)
{
	if (paddingOp == operation || unknownOp == operation) {
		*error_message = "Unknown operation provided %d";
		return BIG_INLOG;
	}

	return calculate_KV_category(key_size, value_size, operation);
}

struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	return insert_key_value((db_handle *)handle, (char *)key_value->k.data, (char *)key_value->v.val_buffer,
				key_value->k.size, key_value->v.val_size, insertOp, *error_message);
}

/**
 * Execute a put request of the key given a kv_formated key_value
 * @param handle, the db handle that we initiated with db open
 * @param serialized_key_value, the kv_formated key to be inserted
 * @param error_message, possible error message upon a failure in the insert path
 * */
struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message)
{
	return serialized_insert_key_value((db_handle *)handle, serialized_key_value, *error_message);
}

static inline int par_serialize_to_key_format(struct par_key *key, char **buf, int32_t buf_size)
{
	int ret = 0;
	int32_t key_size_with_metadata = sizeof(key->size) + key->size;
	int32_t get_op_payload_size = key_size_with_metadata;
	if (get_op_payload_size > buf_size) {
		*buf = malloc(get_op_payload_size);
		ret = 1;
	}
	struct key_splice *kv_buf = (struct key_splice *)*buf;
	set_key_size_of_key_splice(kv_buf, key->size);
	set_key_splice_key_offset(kv_buf, (char *)key->data);
	return ret;
}

void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
	if (value == NULL) {
		*error_message = "value cannot be NULL";
		return;
	}

	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *key_buf = buf;
	int malloced = par_serialize_to_key_format(key, &key_buf, PAR_MAX_PREALLOCATED_SIZE);

	struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_buf = key_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 0,
					   .found = 0,
					   .tombstone = 0,
					   .retrieve = 1 };

	get_op.buffer_to_pack_kv = (char *)value->val_buffer;
	get_op.size = value->val_buffer_size;

	find_key(&get_op);
	if (malloced)
		free(key_buf);

	if (!get_op.found)
		*error_message = "key not found";

	if (get_op.buffer_overflow)
		*error_message = "not enough buffer space";

	value->val_buffer = get_op.buffer_to_pack_kv;
	value->val_size = get_op.size;
}

void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message)
{
	if (value == NULL) {
		*error_message = "value cannot be NULL";
		return;
	}

	struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_buf = (char *)key_serialized,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 0,
					   .found = 0,
					   .tombstone = 0,
					   .retrieve = 1 };

	get_op.buffer_to_pack_kv = (char *)value->val_buffer;
	get_op.size = value->val_buffer_size;

	find_key(&get_op);

	if (!get_op.found)
		*error_message = "key not found";

	if (get_op.buffer_overflow)
		*error_message = "not enough buffer space";

	value->val_buffer = get_op.buffer_to_pack_kv;
	value->val_size = get_op.size;
}

par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *key_buf = buf;
	int malloced = par_serialize_to_key_format(key, &key_buf, PAR_MAX_PREALLOCATED_SIZE);

	struct db_handle *hd = (struct db_handle *)handle;
	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_buf = key_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 1,
					   .found = 0,
					   .retrieve = 0 };

	find_key(&get_op);
	if (malloced)
		free(key_buf);

	if (!get_op.found)
		return PAR_KEY_NOT_FOUND;

	return PAR_SUCCESS;
}

void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	struct db_handle *hd = (struct db_handle *)handle;
	insert_key_value(hd, (void *)key->data, "empty", key->size, 0, deleteOp, *error_message);
}

/*scanner staff*/

struct par_scanner {
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	struct scannerHandle *sc;
	uint32_t buf_size;
	uint16_t allocated;
	uint16_t valid;
	char *kv_buf;
};

par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
	if (key && key->size + sizeof(key->size) > PAR_MAX_PREALLOCATED_SIZE) {
		*error_message = "Can serialize key buffer, buffer to small";
		return NULL;
	}

	char seek_key_buffer[PAR_MAX_PREALLOCATED_SIZE];

	struct key_splice *seek_key = (struct key_splice *)seek_key_buffer;

	enum SEEK_SCANNER_MODE scanner_mode = 0;
	switch (mode) {
	case PAR_GREATER:
		scanner_mode = GREATER;
		seek_key->key_size = key->size;
		memcpy(seek_key->data, key->data, key->size);
		break;
	case PAR_GREATER_OR_EQUAL:
		seek_key->key_size = key->size;
		memcpy(seek_key->data, key->data, key->size);
		scanner_mode = GREATER_OR_EQUAL;
		break;
	case PAR_FETCH_FIRST:
		scanner_mode = GREATER_OR_EQUAL;
		fill_smallest_possible_pivot(seek_key_buffer, PAR_MAX_PREALLOCATED_SIZE);
		break;
	default:
		*error_message = "Unknown seek scanner mode";
		return NULL;
	}

	struct scannerHandle *scanner = (struct scannerHandle *)calloc(1, sizeof(struct scannerHandle));
	struct par_scanner *p_scanner = (struct par_scanner *)calloc(1, sizeof(struct par_scanner));

	struct db_handle *internal_db_handle = (struct db_handle *)handle;
	scanner->type_of_scanner = FORWARD_SCANNER;
	init_dirty_scanner(scanner, internal_db_handle, seek_key, scanner_mode);
	p_scanner->sc = scanner;
	p_scanner->allocated = 0;
	p_scanner->buf_size = PAR_MAX_PREALLOCATED_SIZE;
	p_scanner->kv_buf = p_scanner->buf;

	p_scanner->valid = 1;
	if (scanner->keyValue == NULL) {
		p_scanner->valid = 0;
		return p_scanner;
	}

	struct bt_kv_log_address log_address = { .addr = scanner->keyValue, .tail_id = UINT8_MAX, .in_tail = 0 };
	if (!scanner->kv_level_id && BIG_INLOG == scanner->kv_cat)
		log_address =
			bt_get_kv_log_address(&scanner->db->db_desc->big_log, ABSOLUTE_ADDRESS(scanner->keyValue));

	uint32_t kv_size = get_kv_size((struct kv_splice *)log_address.addr);
	if (kv_size > p_scanner->buf_size) {
		//log_info("Space not enougn needing %u got %u", kv_size, par_s->buf_size);
		if (p_scanner->allocated)
			free(p_scanner->kv_buf);
		p_scanner->buf_size = kv_size;
		p_scanner->allocated = 1;
		p_scanner->kv_buf = calloc(1, p_scanner->buf_size);
	}
	memcpy(p_scanner->kv_buf, log_address.addr, kv_size);
	if (log_address.in_tail)
		bt_done_with_value_log_address(&scanner->db->db_desc->big_log, &log_address);

	return p_scanner;
}

void par_close_scanner(par_scanner sc)
{
	assert(sc);
	struct par_scanner *par_s = (struct par_scanner *)sc;
	close_scanner((struct scannerHandle *)par_s->sc);
	if (par_s->allocated)
		free(par_s->kv_buf);

	free(par_s);
}

int par_get_next(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct scannerHandle *scanner_hd = par_s->sc;
	if (!get_next(scanner_hd)) {
		par_s->valid = 0;
		return 0;
	}

	struct bt_kv_log_address log_address = { .addr = scanner_hd->keyValue, .tail_id = UINT8_MAX, .in_tail = 0 };
	if (!scanner_hd->kv_level_id && BIG_INLOG == scanner_hd->kv_cat)
		log_address = bt_get_kv_log_address(&scanner_hd->db->db_desc->big_log,
						    ABSOLUTE_ADDRESS(scanner_hd->keyValue));

	uint32_t kv_size = get_kv_size((struct kv_splice *)log_address.addr);
	if (kv_size > par_s->buf_size) {
		//log_info("Space not enough needing %u got %u", kv_size, par_s->buf_size);
		if (par_s->allocated)
			free(par_s->kv_buf);

		par_s->buf_size = kv_size;
		par_s->allocated = 1;
		par_s->kv_buf = calloc(1, par_s->buf_size);
	}
	memcpy(par_s->kv_buf, log_address.addr, kv_size);
	if (log_address.in_tail)
		bt_done_with_value_log_address(&scanner_hd->db->db_desc->big_log, &log_address);
	return 1;
}

int par_is_valid(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	return NULL == par_s ? 0 : par_s->valid;
}

struct par_key par_get_key(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct kv_splice *kv_buf = (struct kv_splice *)par_s->kv_buf;
	struct par_key key = { .size = get_key_size(kv_buf), .data = get_key_offset_in_kv(kv_buf) };
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct kv_splice *kv_buf = (struct kv_splice *)par_s->kv_buf;
	struct par_value val = { .val_size = get_value_size(kv_buf),
				 .val_buffer = get_value_offset_in_kv(kv_buf, get_key_size(kv_buf)),
				 .val_buffer_size = get_value_size(kv_buf) };

	return val;
}

// cppcheck-suppress unusedFunction
par_ret_code par_sync(par_handle handle)
{
	log_fatal("Currently developing persistency..");
	(void)handle;
	//_Exit(EXIT_FAILURE);
	return PAR_FAILURE;
}

/**
 * Create, populate and return a buffer containing the default db_options values from option.yml file. Callers can modify the buffer at will.
 * @retval Array with NUM_OF_OPTIONS sizeo of struct options_desc
 */
struct par_options_desc *par_get_default_options(void)
{
	struct par_options_desc *default_db_options =
		(struct par_options_desc *)calloc(NUM_OF_OPTIONS, sizeof(struct par_options_desc));

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

	//fill default_db_options based on the default values
	default_db_options[LEVEL0_SIZE].value = level0_size;
	default_db_options[GROWTH_FACTOR].value = growth_factor;
	default_db_options[LEVEL_MEDIUM_INPLACE].value = level_medium_inplace;
	default_db_options[MEDIUM_LOG_LRU_CACHE_SIZE].value = LRU_cache_size;
	default_db_options[GC_INTERVAL].value = gc_interval;

	return default_db_options;
}
