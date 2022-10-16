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
#include "../btree/set_options.h"
#include "../common/common_functions.h"
#include "../scanner/scanner.h"
#include <log.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256
#define NUM_OF_OPTIONS 5

/*
 * Frees an error message, it is a runtime check if the pointer is not NULL.
 * @param error_message A pointer to the error message.
 */
static void free_error_message(char **error_message)
{
	if (*error_message)
		free(*error_message);
}
char *par_format(char *device_name, uint32_t max_regions_num)
{
	return kvf_init_parallax(device_name, max_regions_num);
}

par_handle par_open(par_db_options *db_options, char **error_message)
{
	if (db_options->create_flag == PAR_CREATE_DB || db_options->create_flag == PAR_DONOT_CREATE_DB) {
		return (par_handle)db_open(db_options, error_message);
	}

	create_error_message(error_message, "Unknown create flag provided.");
	return NULL;
}

char *par_close(par_handle handle)
{
	return db_close((db_handle *)handle);
}

enum kv_category get_kv_category(uint32_t key_size, uint32_t value_size, request_type operation, char **error_message)
{
	free_error_message(error_message);
	if (paddingOp == operation || unknownOp == operation) {
		create_error_message(error_message, "Unknown operation provided %d", operation);
		return BIG_INLOG;
	}

	return calculate_KV_category(key_size, value_size, operation);
}

void par_put(par_handle handle, struct par_key_value *key_value, char **error_message)
{
	free_error_message(error_message);

	insert_key_value((db_handle *)handle, (char *)key_value->k.data, (char *)key_value->v.val_buffer,
			 key_value->k.size, key_value->v.val_size, insertOp, *error_message);
}

/**
 * Execute a put request of the key given a kv_formated key_value
 * @param handle, the db handle that we initiated with db open
 * @param serialized_key_value, the kv_formated key to be inserted
 * @param error_message, possible error message uppon a failure in the insert path
 * */
void par_put_serialized(par_handle handle, char *serialized_key_value, char **error_message)
{
	free_error_message(error_message);
	serialized_insert_key_value((db_handle *)handle, serialized_key_value, *error_message);
}

static inline int par_serialize_to_kv_format(struct par_key *key, char **buf, uint32_t buf_size)
{
	int ret = 0;
	uint32_t key_size = sizeof(uint32_t) + key->size;
	uint32_t value_size = UINT32_MAX;
	uint32_t get_op_payload_size = key_size + sizeof(uint32_t);
	if (get_op_payload_size > buf_size) {
		*buf = malloc(get_op_payload_size);
		ret = 1;
	}
	char *kv_buf = *buf;
	// key_size
	memcpy(&kv_buf[0], &key->size, sizeof(uint32_t));
	// value size
	memcpy(&kv_buf[sizeof(uint32_t)], &value_size, sizeof(uint32_t));
	// key payload
	memcpy(&kv_buf[sizeof(uint32_t) + sizeof(uint32_t)], key->data, key->size);
	return ret;
}

void par_get(par_handle handle, struct par_key *key, struct par_value *value, char **error_message)
{
	free_error_message(error_message);
	if (value == NULL) {
		create_error_message(error_message, "value cannot be NULL");
	}

	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *kv_buf = buf;
	int malloced = par_serialize_to_kv_format(key, &kv_buf, PAR_MAX_PREALLOCATED_SIZE);

	struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .kv_buf = kv_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 0,
					   .found = 0,
					   .tombstone = 0,
					   .retrieve = 1 };

	if (value->val_buffer != NULL) {
		get_op.buffer_to_pack_kv = (char *)value->val_buffer;
		get_op.size = value->val_buffer_size;
	}

	find_key(&get_op);
	if (malloced)
		free(kv_buf);

	if (!get_op.found)
		create_error_message(error_message, "key not found");

	if (get_op.buffer_overflow)
		create_error_message(error_message, "not enough buffer space");

	value->val_buffer = get_op.buffer_to_pack_kv;
	value->val_size = get_op.size;
}

par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *kv_buf = buf;
	int malloced = par_serialize_to_kv_format(key, &kv_buf, PAR_MAX_PREALLOCATED_SIZE);

	memcpy(&kv_buf[0], &key->size, sizeof(uint32_t));
	memcpy(&kv_buf[sizeof(uint32_t)], key->data, key->size);

	struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .kv_buf = kv_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 1,
					   .found = 0,
					   .retrieve = 0 };

	find_key(&get_op);
	if (malloced)
		free(kv_buf);

	if (!get_op.found)
		return PAR_KEY_NOT_FOUND;

	return PAR_SUCCESS;
}

void par_delete(par_handle handle, struct par_key *key, char **error_message)
{
	free_error_message(error_message);
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

#define SMALLEST_KEY_BUFFER_SIZE (8)
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode)
{
	char tmp[PAR_MAX_PREALLOCATED_SIZE];
	struct db_handle *hd = (struct db_handle *)handle;
	struct par_seek_key {
		uint32_t key_size;
		char key[];
	};
	char smallest_key[SMALLEST_KEY_BUFFER_SIZE] = { 0 };
	struct scannerHandle *sc = NULL;
	struct par_scanner *par_s = NULL;
	struct par_seek_key *seek_key = NULL;
	char free_seek_key = 0;

	enum SEEK_SCANNER_MODE scanner_mode = 0;
	switch (mode) {
	case PAR_GREATER:
		scanner_mode = GREATER;
		goto init_seek_key;
	case PAR_GREATER_OR_EQUAL:
		scanner_mode = GREATER_OR_EQUAL;
		goto init_seek_key;
	case PAR_FETCH_FIRST: {
		scanner_mode = GREATER_OR_EQUAL;
		uint32_t *size = (uint32_t *)smallest_key;
		*size = 0;
		//fill the seek_key with the smallest key of the region
		seek_key = (struct par_seek_key *)tmp;
		seek_key->key_size = *size;
		memcpy(seek_key->key, smallest_key, *size);
		goto init_scanner;
	}
	default:
		log_fatal("Unknown seek scanner mode");
		return NULL;
	}
init_seek_key:
	if (key->size + sizeof(uint32_t) > PAR_MAX_PREALLOCATED_SIZE) {
		seek_key = (struct par_seek_key *)calloc(1, sizeof(struct par_seek_key) + key->size);
		free_seek_key = 1;
	} else
		seek_key = (struct par_seek_key *)tmp;

	seek_key->key_size = key->size;
	memcpy(seek_key->key, key->data, key->size);

init_scanner:
	sc = (struct scannerHandle *)calloc(1, sizeof(struct scannerHandle));

	if (!sc) {
		log_fatal("Calloc did not return memory!");
		return NULL;
	}

	par_s = (struct par_scanner *)calloc(1, sizeof(struct par_scanner));
	if (!par_s) {
		log_fatal("Calloc did not return memory!");
		return NULL;
	}

	sc->type_of_scanner = FORWARD_SCANNER;
	init_dirty_scanner(sc, hd, seek_key, scanner_mode);
	par_s->sc = sc;
	par_s->allocated = 0;
	par_s->buf_size = PAR_MAX_PREALLOCATED_SIZE;
	par_s->kv_buf = par_s->buf;

	// Now check what we got
	if (sc->keyValue == NULL)
		par_s->valid = 0;
	else {
		par_s->valid = 1;

		struct bt_kv_log_address log_address = { .addr = sc->keyValue, .tail_id = UINT8_MAX, .in_tail = 0 };
		if (!sc->kv_level_id && BIG_INLOG == sc->kv_cat)
			log_address = bt_get_kv_log_address(&sc->db->db_desc->big_log, ABSOLUTE_ADDRESS(sc->keyValue));

		uint32_t kv_size = get_kv_size((struct splice *)log_address.addr);
		if (kv_size > par_s->buf_size) {
			//log_info("Space not enougn needing %u got %u", kv_size, par_s->buf_size);
			if (par_s->allocated)
				free(par_s->kv_buf);
			par_s->buf_size = kv_size;
			par_s->allocated = 1;
			par_s->kv_buf = calloc(1, par_s->buf_size);
		}
		memcpy(par_s->kv_buf, log_address.addr, kv_size);
		if (log_address.in_tail)
			bt_done_with_value_log_address(&sc->db->db_desc->big_log, &log_address);
	}

	if (free_seek_key)
		free(seek_key);
	return (par_scanner)par_s;
}

void par_close_scanner(par_scanner sc)
{
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

	uint32_t kv_size = get_kv_size((struct splice *)log_address.addr);
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
	return par_s->valid;
}

struct par_key par_get_key(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct splice *kv_buf = (struct splice *)par_s->kv_buf;
	struct par_key key = { .size = get_key_size(kv_buf), .data = get_key_offset_in_kv(kv_buf) };
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct splice *kv_buf = (struct splice *)par_s->kv_buf;
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
