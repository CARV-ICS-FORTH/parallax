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
#include "../allocator/log_structures.h"
#include "../allocator/persistent_operations.h"
#include "../allocator/region_log.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../btree/set_options.h"
#include "../common/common.h"
#include "../include/parallax/structures.h"
#include "../lib/allocator/device_structures.h"
#include "../lib/scanner/scanner_mode.h"
#include "../scanner/scanner.h"
#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PAR_MAX_PREALLOCATED_SIZE 256

char *par_format(char *device_name, uint32_t max_regions_num)
{
	return kvf_init_parallax(device_name, max_regions_num);
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
#ifdef LOG_LEVEL_RELEASE
	log_set_level(2);
#endif

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

// cppcheck-suppress unusedFunction
char *par_get_db_name(par_handle handle, const char **error_message)
{
	if (!handle) {
		*error_message = "NULL file handle.";
		return NULL;
	}
	db_handle *dbhandle = (db_handle *)handle;
	return dbhandle->db_desc->db_superblock->db_name;
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
//cppcheck-suppress constParameterPointer
struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	db_handle *dbhandle = (db_handle *)handle;
	uint64_t is_db_replica = dbhandle->db_options.options[REPLICA_MODE].value;
	if (is_db_replica) {
		*error_message = "DB is in replica mode, insert cannot procceed!";
		struct par_put_metadata invalid_put_metadata = { 0 };
		return invalid_put_metadata;
	}
	return insert_key_value((db_handle *)handle, (char *)key_value->k.data, (char *)key_value->v.val_buffer,
				key_value->k.size, key_value->v.val_size, insertOp, error_message);
}

struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction)
{
	return serialized_insert_key_value((db_handle *)handle, (struct kv_splice_base *)serialized_key_value,
					   append_to_log, insertOp, abort_on_compaction, error_message);
}

// cppcheck-suppress constParameterPointer
void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
	if (value == NULL) {
		*error_message = "value cannot be NULL";
		return;
	}

	/*Serialize user key in KEY_SPLICE*/
	char buf[MAX_KEY_SPLICE_SIZE];
	bool malloced = false;
	struct key_splice *key_splice = key_splice_create((char *)key->data, key->size, buf, sizeof(buf), &malloced);

	const struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_splice = key_splice,
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
		free(key_splice);

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

	const struct db_handle *hd = (struct db_handle *)handle;

	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_splice = (struct key_splice *)key_serialized,
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

// cppcheck-suppress constParameterPointer
par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	/*Serialize user key in KV_FORMAT*/
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	bool malloced = false;
	struct key_splice *key_splice =
		key_splice_create((char *)key->data, key->size, buf, PAR_MAX_PREALLOCATED_SIZE, &malloced);

	const struct db_handle *hd = (struct db_handle *)handle;
	/*Prepare lookup reply*/
	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .key_splice = key_splice,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 1,
					   .found = 0,
					   .retrieve = 0 };

	find_key(&get_op);
	if (malloced)
		free(key_splice);

	if (!get_op.found)
		return PAR_KEY_NOT_FOUND;

	return PAR_SUCCESS;
}

// cppcheck-suppress unusedFunction
uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat)
{
	db_handle *dbhandle = (db_handle *)handle;
	uint64_t is_db_replica = dbhandle->db_options.options[REPLICA_MODE].value;
	if (!is_db_replica) {
		log_fatal("Cannot flush in memory buffers to logs in primary mode");
		BUG_ON();
	}

	enum log_type log_type = SMALL_LOG;
	if (log_cat == BIG) {
		log_type = BIG_LOG;
	}
	return pr_add_and_flush_segment_in_log(dbhandle, buf, buf_size, IO_size, log_type, UINT64_MAX);
}

uint64_t par_init_compaction_id(par_handle handle)
{
	db_handle *dbhandle = (db_handle *)handle;
	/*Acquire a txn_id for the allocations of the compaction*/
	return regl_start_txn(dbhandle->db_desc);
}

// cppcheck-suppress constParameterPointer
void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	struct db_handle *hd = (struct db_handle *)handle;
	insert_key_value(hd, (void *)key->data, "empty", key->size, 0, deleteOp, error_message);
}

/*scanner staff*/

struct par_scanner {
	char buf[PAR_MAX_PREALLOCATED_SIZE];
	struct scanner *sc;
	uint32_t buf_size;
	uint16_t allocated;
	uint16_t valid;
	char *kv_buf;
};

// cppcheck-suppress constParameterPointer
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
	if (key && key->size + sizeof(key->size) > PAR_MAX_PREALLOCATED_SIZE) {
		*error_message = "Cannot serialize key buffer, buffer to small";
		return NULL;
	}

	char seek_key_buffer[PAR_MAX_PREALLOCATED_SIZE];

	struct key_splice *seek_key_splice = NULL;
	bool malloced = false;
	enum seek_scanner_mode scanner_mode = 0;
	switch (mode) {
	case PAR_GREATER:
		scanner_mode = GREATER;
		seek_key_splice = key_splice_create((char *)key->data, key->size, seek_key_buffer,
						    PAR_MAX_PREALLOCATED_SIZE, &malloced);
		break;
	case PAR_GREATER_OR_EQUAL:
		seek_key_splice = key_splice_create((char *)key->data, key->size, seek_key_buffer,
						    PAR_MAX_PREALLOCATED_SIZE, &malloced);
		break;
	case PAR_FETCH_FIRST:
		scanner_mode = GREATER_OR_EQUAL;
		seek_key_splice = key_splice_create_smallest(seek_key_buffer, PAR_MAX_PREALLOCATED_SIZE, &malloced);
		break;
	default:
		*error_message = "Unknown seek scanner mode";
		return NULL;
	}

	struct scanner *scanner = (struct scanner *)calloc(1, sizeof(struct scanner));
	struct par_scanner *p_scanner = (struct par_scanner *)calloc(1, sizeof(struct par_scanner));

	struct db_handle *internal_db_handle = (struct db_handle *)handle;

	scanner_seek(scanner, internal_db_handle, seek_key_splice, scanner_mode);
	if (malloced)
		free(seek_key_splice);
	seek_key_splice = NULL;
	p_scanner->sc = scanner;
	p_scanner->allocated = 0;
	p_scanner->buf_size = PAR_MAX_PREALLOCATED_SIZE;
	p_scanner->kv_buf = p_scanner->buf;

	p_scanner->valid = 1;
	if (scanner->keyValue == NULL) {
		log_debug("Null key value after init of scanner");
		p_scanner->valid = 0;
		return p_scanner;
	}

	struct bt_kv_log_address log_address = { .addr = scanner->keyValue, .tail_id = UINT8_MAX, .in_tail = 0 };
	if (!scanner->kv_level_id && BIG_INLOG == scanner->kv_cat)
		log_address =
			bt_get_kv_log_address(&scanner->db->db_desc->big_log, ABSOLUTE_ADDRESS(scanner->keyValue));

	uint32_t kv_size = kv_splice_get_kv_size((struct kv_splice *)log_address.addr);
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
	scanner_close((struct scanner *)par_s->sc);
	if (par_s->allocated)
		free(par_s->kv_buf);

	free(par_s);
}

int par_get_next(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct scanner *scanner_hd = par_s->sc;
	if (!scanner_get_next(scanner_hd)) {
		par_s->valid = 0;
		return 0;
	}

	struct bt_kv_log_address log_address = { .addr = scanner_hd->keyValue, .tail_id = UINT8_MAX, .in_tail = 0 };
	if (!scanner_hd->kv_level_id && BIG_INLOG == scanner_hd->kv_cat)
		log_address = bt_get_kv_log_address(&scanner_hd->db->db_desc->big_log,
						    ABSOLUTE_ADDRESS(scanner_hd->keyValue));

	uint32_t kv_size = kv_splice_get_kv_size((struct kv_splice *)log_address.addr);
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
	struct par_key key = { .size = kv_splice_get_key_size(kv_buf), .data = kv_splice_get_key_offset_in_kv(kv_buf) };
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_scanner *par_s = (struct par_scanner *)sc;
	struct kv_splice *kv_buf = (struct kv_splice *)par_s->kv_buf;
	struct par_value val = { .val_size = kv_splice_get_value_size(kv_buf),
				 .val_buffer = kv_splice_get_value_offset_in_kv(kv_buf, kv_splice_get_key_size(kv_buf)),
				 .val_buffer_size = kv_splice_get_value_size(kv_buf) };

	return val;
}

// cppcheck-suppress unusedFunction
par_ret_code par_sync(par_handle handle)
{
	struct db_handle *parallax = (struct db_handle *)handle;
	RWLOCK_WRLOCK(&parallax->db_desc->L0.guard_of_level.rx_lock);
	spin_loop(&(parallax->db_desc->L0.active_operations), 0);
	uint8_t active_tree = parallax->db_desc->L0.active_tree;
	pr_flush_L0(parallax->db_desc, active_tree);
	parallax->db_desc->L0.allocation_txn_id[active_tree] = regl_start_txn(parallax->db_desc);
	RWLOCK_UNLOCK(&parallax->db_desc->L0.guard_of_level.rx_lock);
	return PAR_SUCCESS;
}

/**
 * Create, populate and return a buffer containing the default db_options values from option.yml file. Callers can modify the buffer at will.
 * @retval Array with NUM_OF_OPTIONS sizeo of struct options_desc
 */
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

void par_flush_superblock(par_handle handle)
{
	struct db_handle *dbhandle = (struct db_handle *)handle;
	pr_flush_db_superblock(dbhandle->db_desc);
}

uint32_t par_get_max_kv_pair_size(void)
{
	return KV_MAX_SIZE - kv_splice_get_metadata_size();
}
