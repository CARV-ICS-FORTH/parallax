/*
 * Manto test (sister of Tiresia) simulates all the steps that take place in incremental compaction.
 * The test generates a set of SST objects, generates sorted KV pairs and appends them. Then,
 * it calls the compact method of the level object, which takes this SSTs merge-sorts them,
 * and finally writes them in the device. It does this for num_levels. Then, it goes from each
 * and compacts a single SST. Finally, it lookups and scans all KV pairs in the database. To this
 * end similar to Tiresias it uses BerkeleyDB as the source of truth.
 */
#include "../btree/key_splice.h"
#include "../lib/allocator/region_log.h"
#include "../lib/btree/conf.h"
#include "../lib/btree/device_level.h"
#include "../lib/btree/sst.h"
#include "btree/btree.h"
#include "btree/kv_pairs.h"
#include "btree/sst.h"
#include "parallax/structures.h"
#include "scanner/scanner.h"
#include <assert.h>
#include <db.h>
#include <log.h>
#include <parallax/parallax.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_VOLUME_NAME 256
#define MANTO_KV_SIZE 512
#define MANTO_KEY_SIZE 30 //MAX_KEY_SIZE
#define MAX_SSTS 256UL
struct workload_config {
	par_handle handle;
	DB *truth;
	uint64_t total_keys;
	uint64_t txn_id;
	uint32_t progress_report;
};

static void generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++) {
		// key_buffer[i] = (rand() % 255) + 1;
		key_buffer[i] = 96 + (rand() % 25) + 1;
	}
}

static void generate_random_value(char *value_buffer, uint32_t value_size)
{
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

static void populate_randomly_bdb(struct workload_config *workload_config)
{
	log_info("Manto: generating random kv pairs and inserting them to BerkeleyDB total keys are: %lu...",
		 workload_config->total_keys);
	unsigned char key_buffer[MANTO_KEY_SIZE] = { 0 };
	unsigned char value_buffer[MANTO_KV_SIZE] = { 0 };
	uint64_t unique_keys = 0;
	for (uint64_t i = 0; i < workload_config->total_keys; i++) {
		struct par_key_value kv_pair = { 0 };

		kv_pair.k.size = rand() % (MANTO_KEY_SIZE + 1);

		if (!kv_pair.k.size)
			kv_pair.k.size++;
		kv_pair.v.val_size = rand() % (MANTO_KV_SIZE - (kv_pair.k.size + sizeof(uint32_t)));
		if (kv_pair.v.val_size < 4)
			kv_pair.v.val_size = 4;

		generate_random_key(key_buffer, kv_pair.k.size);
		kv_pair.k.data = (char *)key_buffer;
		generate_random_value((char *)value_buffer, kv_pair.v.val_size);
		kv_pair.v.val_buffer = (char *)value_buffer;

		DBT truth_key = { 0 };
		DBT truth_data = { 0 };
		truth_key.data = (void *)kv_pair.k.data;
		truth_key.size = kv_pair.k.size;
		truth_data.data = kv_pair.v.val_buffer;
		truth_data.size = kv_pair.v.val_size;
		assert(truth_data.size < 4096);
		int ret = workload_config->truth->put(workload_config->truth, NULL, &truth_key, &truth_data,
						      DB_NOOVERWRITE);
		if (ret == DB_KEYEXIST) {
			// workload_config->truth->err(workload_config->truth, ret,
			// 			    "Put failed because key size %u payload: %.*s already exists",
			// 			    truth_key.size, truth_key.size, truth_key.data);
			continue;
		}
		++unique_keys;
		if (!(i % workload_config->progress_report))
			log_info("BerkeleyDB progress in population  %lu keys", i);
	}

	workload_config->total_keys = unique_keys;
	log_info("Population of BerkeleyDB ended successfully! :-) keys: %ld", workload_config->total_keys);
}

static bool create_ssts(struct workload_config *workload, int num_ssts, struct sst_meta *ssts[])
{
	DBC *cursor = NULL;
	DBT key;
	DBT value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));

	// Open a cursor for the database
	if (workload->truth->cursor(workload->truth, NULL, &cursor, 0) != 0) {
		log_fatal("Failed to open BerkeleyDB cursor");
		_exit(EXIT_FAILURE);
	}

	int sst_id = 0;

	struct sst *curr_sst = sst_create(SST_SIZE, workload->txn_id, workload->handle, 1);
	// Iterate over the keys
	uint32_t num_kv_pairs = 0;
	while (cursor->c_get(cursor, &key, &value, DB_NEXT) == 0) {
		struct kv_splice *splice = kv_splice_create(key.size, key.data, value.size, value.data);
		struct kv_splice_base splice_base = {
			.kv_splice = splice, .kv_cat = SMALL_INPLACE, .kv_type = KV_FORMAT, .is_tombstone = false
		};
		while (false == sst_append_KV_pair(curr_sst, &splice_base)) {
			sst_flush(curr_sst);
			log_debug("Created SST no: %d", sst_id);
			ssts[sst_id] = sst_get_meta(curr_sst);
			sst_close(curr_sst);
			if (++sst_id >= num_ssts) {
				log_fatal(
					"Did not manage to fit all KV pairs in %d SSTs of size: %lu kv pairs are: %u increase num SSTs or reduce num KVs",
					num_ssts, SST_SIZE, num_kv_pairs);
				_exit(EXIT_FAILURE);
			}
			//ok get first and last splice to update the guards
			curr_sst = sst_create(SST_SIZE, workload->txn_id, workload->handle, 1);
		}
		++num_kv_pairs;
		free(splice);
		// log_debug("Key: %.*s, Value size: %d\n", (int)key.size, (char *)key.data, (int)value.size);
	}
	sst_flush(curr_sst);
	log_debug("Created SST no: %d", sst_id);
	ssts[sst_id] = sst_get_meta(curr_sst);
	sst_close(curr_sst);
	// Close the cursor
	cursor->c_close(cursor);

	return true;
}

bool populate_mem_guards(struct device_level *level, int num_ssts, struct sst_meta *ssts[])
{
	int actual_ssts = 0;
	for (; actual_ssts < num_ssts && ssts[actual_ssts] != NULL; actual_ssts++)
		;
	log_debug("---> SSTs created are: %d out of %d", actual_ssts, num_ssts);
	level_add_ssts(level, actual_ssts, ssts, 1);
	return true;
}

bool verify_scanner(struct workload_config *workload, uint8_t level_id, int32_t tree_id)
{
	DBC *cursor = NULL;
	DBT key;
	DBT value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	// Open a cursor for the database
	if (workload->truth->cursor(workload->truth, NULL, &cursor, 0) != 0) {
		log_fatal("Failed to open BerkeleyDB cursor");
		_exit(EXIT_FAILURE);
	}
	struct level_scanner_dev *scanner = level_scanner_dev_init(workload->handle, level_id, tree_id);
	level_scanner_dev_seek(scanner, NULL, false);
	// Iterate over the keys
	uint32_t num_kv_pairs = 0;
	while (cursor->c_get(cursor, &key, &value, DB_NEXT) == 0 && num_kv_pairs < workload->total_keys) {
		struct kv_splice_base splice;
		if (false == level_scanner_dev_curr(scanner, &splice)) {
			log_fatal("Scanned ended too soon lost keys");
			_exit(EXIT_FAILURE);
		}
		uint32_t value_size = kv_splice_base_get_value_size(&splice);
		uint32_t key_size = kv_splice_base_get_key_size(&splice);
		char *parallax_key = kv_splice_base_get_key_buf(&splice);

		if (key_size != key.size) {
			log_fatal("Key sizes mismatch expected: %u got: %u", key.size, key_size);
		}

		if (0 != memcmp(key.data, parallax_key, key_size < key.size ? key_size : key.size)) {
			log_fatal("key mismatch waited %.*s ----> got %.*s", key.size, (char *)key.data, key_size,
				  parallax_key);
			_exit(EXIT_FAILURE);
		}

		//Now check the value
		if (value_size != value.size) {
			log_fatal("Values mismatch expected: %u got: %u", value.size, value_size);
			_exit(EXIT_FAILURE);
		}
		++num_kv_pairs;
		if (0 == num_kv_pairs % workload->progress_report)
			log_debug("Scanner: Found up to key no: %u", num_kv_pairs);
		level_scanner_dev_next(scanner);
	}
	if (workload->total_keys != num_kv_pairs) {
		log_fatal("Test failed found %u keys expected: %lu keys", num_kv_pairs, workload->total_keys);
		_exit(EXIT_FAILURE);
	}
	// Close the cursor
	cursor->c_close(cursor);
	return true;
}

bool verify_comp_scanner(struct workload_config *workload, uint8_t level_id, int32_t tree_id)
{
	DBC *cursor = NULL;
	DBT key;
	DBT value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	struct db_handle *handle = (struct db_handle *)workload->handle;
	// Open a cursor for the database
	if (workload->truth->cursor(workload->truth, NULL, &cursor, 0) != 0) {
		log_fatal("Failed to open BerkeleyDB cursor");
		_exit(EXIT_FAILURE);
	}
	struct level_compaction_scanner *scanner = level_comp_scanner_init(
		handle->db_desc->dev_levels[level_id], tree_id, SST_SIZE, handle->db_desc->db_volume->vol_fd);

	// Iterate over the keys
	uint32_t num_kv_pairs = 0;
	while (cursor->c_get(cursor, &key, &value, DB_NEXT) == 0 && num_kv_pairs < workload->total_keys) {
		struct kv_splice_base splice;
		if (false == level_comp_scanner_get_curr(scanner, &splice)) {
			log_fatal("Comp Scanner ended too soon lost keys");
			_exit(EXIT_FAILURE);
		}
		uint32_t value_size = kv_splice_base_get_value_size(&splice);
		uint32_t key_size = kv_splice_base_get_key_size(&splice);
		char *parallax_key = kv_splice_base_get_key_buf(&splice);

		if (key_size != key.size) {
			log_fatal("Key sizes mismatch expected: %u got: %u", key.size, key_size);
		}

		if (0 != memcmp(key.data, parallax_key, key_size < key.size ? key_size : key.size)) {
			log_fatal("key mismatch waited %.*s ----> got %.*s", key.size, (char *)key.data, key_size,
				  parallax_key);
			_exit(EXIT_FAILURE);
		}

		//Now check the value
		if (value_size != value.size) {
			log_fatal("Values mismatch expected: %u got: %u", value.size, value_size);
			_exit(EXIT_FAILURE);
		}
		++num_kv_pairs;
		if (0 == num_kv_pairs % workload->progress_report)
			log_debug("Comp Scanner: Found up to key no: %u", num_kv_pairs);

		if (level_comp_scanner_next(scanner) == false)
			break;
	}
	if (workload->total_keys != num_kv_pairs) {
		log_fatal("Test failed found %u keys expected: %lu keys", num_kv_pairs, workload->total_keys);
		_exit(EXIT_FAILURE);
	}
	// Close the cursor
	cursor->c_close(cursor);
	return true;
}

bool verify_keys(struct workload_config *workload, struct device_level *level, int32_t tree_id)
{
	DBC *cursor = NULL;
	DBT key;
	DBT value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	// Open a cursor for the database
	if (workload->truth->cursor(workload->truth, NULL, &cursor, 0) != 0) {
		log_fatal("Failed to open BerkeleyDB cursor");
		log_debug("Going to next leaf...");
		_exit(EXIT_FAILURE);
	}

	// Iterate over the keys
	uint32_t num_kv_pairs = 0;
	while (cursor->c_get(cursor, &key, &value, DB_NEXT) == 0 && num_kv_pairs < workload->total_keys) {
		bool malloced = false;
		struct key_splice *key_splice = key_splice_create(key.data, key.size, NULL, 0, &malloced);
		assert(malloced);

		struct lookup_operation get_op = { .key_splice = key_splice, .retrieve = 1 };
		if (false == level_lookup(level, &get_op, tree_id)) {
			log_fatal("Lookup: Failed to find key: %.*s", key.size, (char *)key.data);
			_exit(EXIT_FAILURE);
		}
		//Now check the value
		if (value.size != get_op.size) {
			log_fatal("Values mismatch expected: %u got: %u", value.size, get_op.size);
			_exit(EXIT_FAILURE);
		}

		if (0 != memcmp(value.data, get_op.buffer_to_pack_kv, value.size)) {
			log_fatal("Value corruption");
			_exit(EXIT_FAILURE);
		}

		if (malloced)
			free(key_splice);
		free(get_op.buffer_to_pack_kv);

		++num_kv_pairs;
		if (0 == num_kv_pairs % workload->progress_report)
			log_debug("Found up to key no: %u", num_kv_pairs);
	}
	if (workload->total_keys != num_kv_pairs) {
		log_fatal("Test failed found %u keys expected: %lu keys", num_kv_pairs, workload->total_keys);
		_exit(EXIT_FAILURE);
	}
	// Close the cursor
	cursor->c_close(cursor);
	return true;
}

int main(int argc, char *argv[])
{
	log_info("Args are: %d", argc);
	if (argc != 9 || strcmp(argv[1], "--volume_name") != 0 || strcmp(argv[3], "--num_ssts") != 0 ||
	    strcmp(argv[5], "--num_of_kvs") != 0 || strcmp(argv[7], "--bdb_path") != 0) {
		log_warn("Usage: %s --volume_name <name> --num_ssts <number> --num_of_kvs <number> --bdb_path <path>\n",
			 argv[0]);
		return 1; // Exit with an error code
	}

	// Copy values from command-line arguments
	char volume_name[MAX_VOLUME_NAME] = { 0 };
	char truth_db[MAX_VOLUME_NAME] = { 0 };

	strncpy(volume_name, argv[2], sizeof(volume_name) - 1);
	// Convert num_ssts from string to int
	int num_of_ssts = strtol(argv[4], NULL, 10);
	// Convert num_of_kvs from string to long
	long num_of_kvs = strtol(argv[6], NULL, 10);
	// Copy bdb_path
	strncpy(truth_db, argv[8], sizeof(truth_db) - 1);
	strncpy(volume_name, argv[2], sizeof(truth_db) - 1);

	log_info("BerkeleyDB path is %s", truth_db);
	/*First open source of truth BerkeleyDB database*/
	DB *truthDB = { 0 };
	int ret = db_create(&truthDB, NULL, 0);
	if (ret) {
		truthDB->err(truthDB, ret, "Database open failed: %s", "truth.db");
		_Exit(EXIT_FAILURE);
	}

	bool truth_db_exists = false;
	ret = truthDB->open(truthDB, NULL, truth_db, NULL, DB_BTREE, /*DB_CREATE | DB_TRUNCATE*/ 0, 0);
	if (0 == ret) {
		log_info("BDB %s already exists, not  populating it again", truth_db);
		truth_db_exists = true;
	}

	if (!truth_db_exists) {
		ret = truthDB->open(truthDB, NULL, truth_db, NULL, DB_BTREE, DB_CREATE, 0);
		if (ret) {
			truthDB->err(truthDB, ret, "Database open failed: %s", "truth.db");
			return (ret);
		}
		log_info("Created BDB %s already exists, going to populate as well", truth_db);
	}
	//open ParallaxDB
	par_db_options db_options = { 0 };
	db_options.volume_name = volume_name;
	const char *error_message = par_format(db_options.volume_name, 16);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		_Exit(EXIT_FAILURE);
	}
	db_options.db_name = "MANTO_DB";
	db_options.create_flag = PAR_CREATE_DB;
	db_options.options = par_get_default_options();
	par_handle parallax_db = par_open(&db_options, &error_message);

	// Generate and print keys

	struct workload_config workload = {
		.handle = parallax_db,
		.truth = truthDB,
		.total_keys = num_of_kvs,
		.progress_report = 10000,
	};
	db_handle *internal_db = (db_handle *)workload.handle;

	workload.txn_id = regl_start_txn(internal_db->db_desc);
	populate_randomly_bdb(&workload);
	log_debug("num_of_ssts = %u", num_of_ssts);

	struct sst_meta *ssts[MAX_SSTS] = { 0 };
	create_ssts(&workload, num_of_ssts, ssts);
	populate_mem_guards(internal_db->db_desc->dev_levels[1], MAX_SSTS, ssts);

	verify_keys(&workload, internal_db->db_desc->dev_levels[1], 1);
	verify_scanner(&workload, 1, 1);
	verify_comp_scanner(&workload, 1, 1);
	level_free_space(internal_db->db_desc->dev_levels[1], 1, internal_db->db_desc, workload.txn_id);
	regl_flush_txn(internal_db->db_desc, workload.txn_id);
	regl_apply_txn_buf_freeops_and_destroy(internal_db->db_desc, workload.txn_id);
	log_debug("First round successful population and deletion of level");
	log_debug("Second round population WITHOUT deletion");
	//done again
	workload.txn_id = regl_start_txn(internal_db->db_desc);

	memset(ssts, 0x00, sizeof(ssts));
	create_ssts(&workload, num_of_ssts, ssts);
	populate_mem_guards(internal_db->db_desc->dev_levels[1], MAX_SSTS, ssts);

	verify_keys(&workload, internal_db->db_desc->dev_levels[1], 1);
	verify_scanner(&workload, 1, 1);
	verify_comp_scanner(&workload, 1, 1);
	regl_flush_txn(internal_db->db_desc, workload.txn_id);
	regl_apply_txn_buf_freeops_and_destroy(internal_db->db_desc, workload.txn_id);
	par_flush_superblock(workload.handle);

	log_debug("Second round SUCCESS, closing DB...");
	if (par_close(workload.handle)) {
		log_fatal("Failed to close ParallaxDB");
	}
	log_debug("Close SUCCESS opening DB...");
	workload.handle = par_open(&db_options, &error_message);
	internal_db = (db_handle *)workload.handle;
	log_debug("Opened DB verifying keys....");
	verify_keys(&workload, internal_db->db_desc->dev_levels[1], 0);
	verify_scanner(&workload, 1, 0);

	truthDB->close(truthDB, 0);
	log_info("Manto, sister of Tiresias, passed successfully!");
	return 0;
}
