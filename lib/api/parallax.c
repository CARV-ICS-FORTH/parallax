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
#include "../scanner/scanner.h"
#include <log.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256

char *par_format(char *device_name, uint32_t max_regions_num)
{
	return kvf_init_parallax(device_name, max_regions_num);
}

par_handle par_open(par_db_options *db_options, char **error_message)
{
	if (db_options->create_flag == PAR_CREATE_DB || db_options->create_flag == PAR_DONOT_CREATE_DB) {
		return (par_handle)db_open(db_options->volume_name, (char *)db_options->db_name,
					   db_options->create_flag, error_message);
	}

	create_error_message(error_message, "Unknown create flag provided.");
	return NULL;
}

char *par_close(par_handle handle)
{
	return db_close((db_handle *)handle);
}

void par_put(par_handle handle, struct par_key_value *key_value, char **error_message)
{
	if (*error_message) {
		free(*error_message);
	}

	*error_message = insert_key_value((db_handle *)handle, (char *)key_value->k.data,
					  (char *)key_value->v.val_buffer, key_value->k.size, key_value->v.val_size,
					  insertOp);
}

void par_put_serialized(par_handle handle, char *serialized_key_value, char **error_message)
{
	if (*error_message) {
		free(*error_message);
	}

	*error_message = serialized_insert_key_value((db_handle *)handle, serialized_key_value);
}

static inline int par_serialize_to_kv_format(struct par_key *key, char **buf, uint32_t buf_size)
{
	int ret = 0;
	uint32_t key_size = sizeof(uint32_t) + key->size;
	if (key_size > buf_size) {
		*buf = malloc(key_size);
		ret = 1;
	}
	char *kv_buf = *buf;
	memcpy(&kv_buf[0], &key->size, sizeof(uint32_t));
	memcpy(&kv_buf[sizeof(uint32_t)], key->data, key->size);
	return ret;
}

par_ret_code par_get(par_handle handle, struct par_key *key, struct par_value *value)
{
	if (value == NULL) {
		log_warn("value cannot be NULL");
		return PAR_FAILURE;
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
		return PAR_KEY_NOT_FOUND;

	if (get_op.buffer_overflow)
		return PAR_GET_NOT_ENOUGH_BUFFER_SPACE;

	value->val_buffer = get_op.buffer_to_pack_kv;
	value->val_size = get_op.size;
	return PAR_SUCCESS;
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
	if (*error_message) {
		free(error_message);
	}

	struct db_handle *hd = (struct db_handle *)handle;
	*error_message = insert_key_value(hd, (void *)key->data, "empty", key->size, 0, deleteOp);
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

		uint32_t kv_size = KEY_SIZE(log_address.addr) + sizeof(struct kv_format);
		struct kv_format *v = (struct kv_format *)((uint64_t)log_address.addr + kv_size);
		kv_size += (v->key_size + sizeof(struct kv_format));
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

	uint32_t kv_size = KEY_SIZE(log_address.addr) + sizeof(struct kv_format);
	struct kv_format *v = (struct kv_format *)((uint64_t)log_address.addr + kv_size);
	kv_size += v->key_size + sizeof(struct kv_format);
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
	struct par_key key = { .size = *(uint32_t *)par_s->kv_buf, .data = par_s->kv_buf + sizeof(uint32_t) };
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	char *value = par_s->kv_buf + *(uint32_t *)par_s->kv_buf + sizeof(uint32_t);
	struct par_value val = { .val_size = *(uint32_t *)value,
				 .val_buffer = value + sizeof(uint32_t),
				 .val_buffer_size = *(uint32_t *)value };

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
