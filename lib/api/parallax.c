// Copyright [2020] [FORTH-ICS]
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

#include "../include/parallax.h"
#include <log.h>
#include <stdlib.h>
#include "../btree/btree.h"
#include "../scanner/scanner.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256

par_handle par_open(par_db_options *options)
{
	switch (options->create_flag) {
	case PAR_CREATE_DB:
		return (par_handle)db_open(options->volume_name, options->volume_start, options->volume_size,
					   (char *)options->db_name, CREATE_DB);
	case PAR_DONOT_CREATE_DB:
		return (par_handle)db_open(options->volume_name, options->volume_start, options->volume_size,
					   (char *)options->db_name, DONOT_CREATE_DB);
	default:
		printf("Unknown open option flag\n");
		return NULL;
	}
}

void par_close(par_handle handle)
{
	(void)handle;
	/* db_close((db_handle *)handle); */
}

par_ret_code par_put(par_handle handle, struct par_key_value *key_value)
{
	int ret = insert_key_value((db_handle *)handle, (char *)key_value->k.data, (char *)key_value->v.val_buffer,
				   key_value->k.size, key_value->v.val_size);
	if (ret == SUCCESS)
		return PAR_SUCCESS;

	return PAR_FAILURE;
}

par_ret_code par_get(par_handle handle, struct par_key *key, struct par_value *value)
{
	struct val {
		uint32_t size;
		char val[];
	};

	if (value == NULL) {
		log_warn("value cannot be NULL");
		return PAR_FAILURE;
	}

	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *kv_buf = buf;
	int malloced = 0;
	if (key->size > PAR_MAX_PREALLOCATED_SIZE) {
		malloced = 1;
		kv_buf = calloc(1, key->size + sizeof(uint32_t));
	}
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
	value->val_buffer = get_op.buffer_to_pack_kv;
	value->val_size = get_op.size;
	return PAR_SUCCESS;
}

par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	char *kv_buf = buf;
	int malloced = 0;
	if (key->size > PAR_MAX_PREALLOCATED_SIZE) {
		malloced = 1;
		kv_buf = calloc(1, key->size + sizeof(uint32_t));
	}
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

par_ret_code par_delete(par_handle handle, struct par_key *key)
{
	log_fatal("Parallax doesn't support deletes right now. Will be implemented soon");
	(void)handle;
	(void)key;
	exit(EXIT_FAILURE);
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

par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode)
{
	char tmp[PAR_MAX_PREALLOCATED_SIZE];
	struct db_handle *hd = (struct db_handle *)handle;
	struct par_seek_key {
		uint32_t key_size;
		char key[];
	};
	char smallest_key[4] = { '\0' };
	struct scannerHandle *sc = NULL;
	struct par_scanner *par_s = NULL;
	struct par_seek_key *seek_key = NULL;
	char free_seek_key = 0;

	enum SEEK_SCANNER_MODE native_mode = 0;
	switch (mode) {
	case PAR_GREATER:
		native_mode = GREATER;
		goto init_seek_key;
	case PAR_GREATER_OR_EQUAL:
		native_mode = GREATER_OR_EQUAL;
		goto init_seek_key;
	case PAR_FETCH_FIRST: {
		uint32_t *size = (uint32_t *)smallest_key;
		*size = 1;
		//fill the seek_key with the smallest key of the region
		seek_key = (struct par_seek_key *)tmp;
		seek_key->key_size = *size;
		memcpy(seek_key->key, smallest_key, *size);
		goto init_scanner;
	}
	default:
		printf("Unknown seek scanner mode");
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
	par_s = (struct par_scanner *)calloc(1, sizeof(struct par_scanner));
	sc->type_of_scanner = FORWARD_SCANNER;
	init_dirty_scanner(sc, hd, seek_key, native_mode);
	par_s->sc = sc;
	par_s->allocated = 0;
	par_s->buf_size = PAR_MAX_PREALLOCATED_SIZE;
	par_s->kv_buf = par_s->buf;

	// Now check what we got
	if (sc->keyValue == NULL)
		par_s->valid = 0;
	else {
		par_s->valid = 1;
		uint32_t kv_size = get_key_size(sc) + sizeof(struct kv_format);
		struct kv_format *v = (struct kv_format *)((uint64_t)sc->keyValue + kv_size);
		kv_size += (v->key_size + sizeof(struct kv_format));
		if (kv_size > par_s->buf_size) {
			//log_info("Space not enougn needing %u got %u", kv_size, par_s->buf_size);
			if (par_s->allocated)
				free(par_s->kv_buf);
			par_s->buf_size = kv_size;
			par_s->allocated = 1;
			par_s->kv_buf = calloc(1, par_s->buf_size);
		}
		memcpy(par_s->kv_buf, sc->keyValue, kv_size);
	}

	if (free_seek_key)
		free(seek_key);
	return (par_scanner)par_s;
}

void par_close_scanner(par_scanner s)
{
	struct par_scanner *par_s = (struct par_scanner *)s;
	closeScanner((struct scannerHandle *)par_s->sc);
	if (par_s->allocated)
		free(par_s->kv_buf);

	free(par_s);
	return;
}

int par_get_next(par_scanner s)
{
	struct par_scanner *par_s = (struct par_scanner *)s;
	struct scannerHandle *sc = par_s->sc;
	int32_t ret = getNext(sc);
	if (ret == END_OF_DATABASE) {
		par_s->valid = 0;
		return 0;
	}
	uint32_t kv_size = get_key_size(sc) + sizeof(struct kv_format);
	struct kv_format *v = (struct kv_format *)((uint64_t)sc->keyValue + kv_size);
	kv_size += v->key_size + sizeof(struct kv_format);
	if (kv_size > par_s->buf_size) {
		//log_info("Space not enougn needing %u got %u", kv_size, par_s->buf_size);
		if (par_s->allocated)
			free(par_s->kv_buf);

		par_s->buf_size = kv_size;
		par_s->allocated = 1;
		par_s->kv_buf = calloc(1, par_s->buf_size);
	}
	//memcpy(par_s->kv_buf, sc->keyValue, par_s->buf_size);
	//gesalous
	memcpy(par_s->kv_buf, sc->keyValue, kv_size);
	return 1;
}

int par_is_valid(par_scanner s)
{
	struct par_scanner *par_s = (struct par_scanner *)s;
	return par_s->valid;
}

struct par_key par_get_key(par_scanner s)
{
	struct par_scanner *par_s = (struct par_scanner *)s;
	struct par_key key = { .size = *(uint32_t *)par_s->kv_buf, .data = par_s->kv_buf + sizeof(uint32_t) };
	return key;
}

struct par_value par_get_value(par_scanner s)
{
	struct par_scanner *par_s = (struct par_scanner *)s;
	char *value = par_s->kv_buf + *(uint32_t *)par_s->kv_buf + sizeof(uint32_t);
	struct par_value val = { .val_size = *(uint32_t *)value,
				 .val_buffer = value + sizeof(uint32_t),
				 .val_buffer_size = *(uint32_t *)value };

	return val;
}

par_ret_code par_sync(par_handle dbhandle)
{
	log_fatal("Currently developing persistency..");
	(void)dbhandle;
	//exit(EXIT_FAILURE);
	return PAR_FAILURE;
}
