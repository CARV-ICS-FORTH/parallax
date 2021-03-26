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

#include <parallax.h>
#include <log.h>
#include "../allocator/allocator.h"
#include "../btree/btree.h"
#include "../scanner/scanner.h"

klc_handle klc_open(klc_db_options *options)
{
	switch (options->create_flag) {
	case KLC_CREATE_DB:
		return (klc_handle)db_open(options->volume_name, options->volume_start, options->volume_size,
					   (char *)options->db_name, CREATE_DB);
	case KLC_DONOT_CREATE_DB:
		return (klc_handle)db_open(options->volume_name, options->volume_start, options->volume_size,
					   (char *)options->db_name, DONOT_CREATE_DB);
	default:
		printf("Unknown open option flag\n");
		return NULL;
	}
}

void klc_close(klc_handle handle)
{
	(void)handle;
	/* db_close((db_handle *)handle); */
}

klc_ret_code klc_put(klc_handle handle, struct klc_key_value *key_value)
{
	int ret = insert_key_value((db_handle *)handle, (char *)key_value->k.data, (char *)key_value->v.data,
				   key_value->k.size, key_value->v.size);
	if (ret == SUCCESS)
		return KLC_SUCCESS;

	return KLC_FAILURE;
}

klc_ret_code klc_get(klc_handle handle, struct klc_key *key, struct klc_value **value)
{
	struct val {
		uint32_t size;
		char val[];
	};

	struct val *v = find_key((db_handle *)handle, (char *)key->data, key->size);

	if (v == NULL)
		return KLC_KEY_NOT_FOUND;

	if (*value == NULL)
		*value = calloc(1, sizeof(struct klc_value) + v->size);

	v = (struct val *)((uint64_t)v + sizeof(struct val) + v->size);
	(*value)->size = v->size;
	(*value)->data = (const char *)&v[1];
	memcpy((char *)(*value)->data, v->val, v->size);

	return KLC_SUCCESS;
}

klc_ret_code klc_exists(klc_handle handle, struct klc_key *key)
{
	char *v = find_key((db_handle *)handle, (char *)key->data, key->size);

	if (v == NULL)
		return KLC_KEY_NOT_FOUND;

	return KLC_SUCCESS;
}

/* klc_ret_code klc_delete(klc_handle handle, struct klc_key *key) */
/* { */
/* 	int ret = delete_key((db_handle *)handle, (void *)key->data, key->size); */

/* 	if (ret == SUCCESS) */
/* 		return KLC_SUCCESS; */

/* 	return KLC_FAILURE; */
/* } */

/*scanner staff*/
#define KLC_MAX_PREALLOCATED_SIZE 256
struct klc_scanner {
	char buf[KLC_MAX_PREALLOCATED_SIZE];
	struct scannerHandle *sc;
	uint32_t buf_size;
	uint16_t allocated;
	uint16_t valid;
	char *kv_buf;
};

klc_scanner klc_init_scanner(klc_handle handle, struct klc_key *key, klc_seek_mode mode)
{
	char tmp[KLC_MAX_PREALLOCATED_SIZE];
	struct db_handle *hd = (struct db_handle *)handle;
	struct klc_seek_key {
		uint32_t key_size;
		char key[];
	};
	char smallest_key[4] = { '\0' };
	struct scannerHandle *sc = NULL;
	struct klc_scanner *klc_s = NULL;
	struct klc_seek_key *seek_key = NULL;
	char free_seek_key = 0;

	enum SEEK_SCANNER_MODE native_mode = 0;
	switch (mode) {
	case KLC_GREATER:
		native_mode = GREATER;
		goto init_seek_key;
	case KLC_GREATER_OR_EQUAL:
		native_mode = GREATER_OR_EQUAL;
		goto init_seek_key;
	case KLC_FETCH_FIRST: {
		uint32_t *size = (uint32_t *)smallest_key;
		*size = 1;
		goto init_scanner;
	}
	default:
		printf("Unknown seek scanner mode");
		return NULL;
	}
init_seek_key:
	if (key->size + sizeof(uint32_t) > KLC_MAX_PREALLOCATED_SIZE) {
		seek_key = (struct klc_seek_key *)calloc(1, sizeof(struct klc_seek_key) + key->size);
		free_seek_key = 1;
	} else
		seek_key = (struct klc_seek_key *)tmp;

	seek_key->key_size = key->size;
	memcpy(seek_key->key, key->data, key->size);

init_scanner:
	sc = (struct scannerHandle *)calloc(1, sizeof(struct scannerHandle));
	klc_s = (struct klc_scanner *)calloc(1, sizeof(struct klc_scanner));

	init_dirty_scanner(sc, hd, seek_key, native_mode);
	klc_s->sc = sc;
	klc_s->allocated = 0;
	klc_s->buf_size = KLC_MAX_PREALLOCATED_SIZE;
	klc_s->kv_buf = klc_s->buf;
	// Now check what we got
	if (sc->key_value.kv == NULL)
		klc_s->valid = 0;
	else {
		klc_s->valid = 1;
		uint32_t kv_size = sc->key_value.kv->key_size + sizeof(struct kv_format);
		struct kv_format *v = (struct kv_format *)((uint64_t)sc->key_value.kv + kv_size);
		kv_size += (v->key_size + sizeof(struct kv_format));
		if (kv_size > klc_s->buf_size) {
			//log_info("Space not enougn needing %u got %u", kv_size, klc_s->buf_size);
			if (klc_s->allocated)
				free(klc_s->kv_buf);
			klc_s->buf_size = kv_size;
			klc_s->allocated = 1;
			klc_s->kv_buf = calloc(1, klc_s->buf_size);
		}
		memcpy(klc_s->kv_buf, sc->key_value.kv, klc_s->buf_size);
	}

	if (free_seek_key)
		free(seek_key);
	return (klc_scanner)klc_s;
}

void klc_close_scanner(klc_scanner s)
{
	struct klc_scanner *klc_s = (struct klc_scanner *)s;
	closeScanner((struct scannerHandle *)klc_s->sc);
	free(klc_s->sc);
	if (klc_s->allocated)
		free(klc_s->kv_buf);

	free(klc_s);
	return;
}

int klc_get_next(klc_scanner s)
{
	struct klc_scanner *klc_s = (struct klc_scanner *)s;
	struct scannerHandle *sc = klc_s->sc;
	int32_t ret = getNext(sc);
	if (ret == END_OF_DATABASE) {
		klc_s->valid = 0;
		return 0;
	}
	uint32_t kv_size = sc->key_value.kv->key_size + sizeof(struct kv_format);
	struct kv_format *v = (struct kv_format *)((uint64_t)sc->key_value.kv + kv_size);
	kv_size += v->key_size + sizeof(struct kv_format);
	if (kv_size > klc_s->buf_size) {
		//log_info("Space not enougn needing %u got %u", kv_size, klc_s->buf_size);
		if (klc_s->allocated)
			free(klc_s->kv_buf);

		klc_s->buf_size = kv_size;
		klc_s->allocated = 1;
		klc_s->kv_buf = calloc(1, klc_s->buf_size);
	}
	memcpy(klc_s->kv_buf, sc->key_value.kv, klc_s->buf_size);
	return 1;
}

int klc_is_valid(klc_scanner s)
{
	struct klc_scanner *klc_s = (struct klc_scanner *)s;
	return klc_s->valid;
}

struct klc_key klc_get_key(klc_scanner s)
{
	struct klc_scanner *klc_s = (struct klc_scanner *)s;
	struct klc_key key = { .size = *(uint32_t *)klc_s->kv_buf, .data = klc_s->kv_buf + sizeof(uint32_t) };
	return key;
}

struct klc_value klc_get_value(klc_scanner s)
{
	struct klc_scanner *klc_s = (struct klc_scanner *)s;
	char *value = klc_s->kv_buf + *(uint32_t *)klc_s->kv_buf + sizeof(uint32_t);
	struct klc_value val = { .size = *(uint32_t *)value, .data = value + sizeof(uint32_t) };

	return val;
}

klc_ret_code klc_sync(klc_handle dbhandle)
{
	struct db_handle *handle = (struct db_handle *)dbhandle;
	snapshot(handle->volume_desc);
	return KLC_SUCCESS;
}
