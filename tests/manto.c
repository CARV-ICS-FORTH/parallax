/**
 * Manto test (sister of Tiresia) simulates all the steps that take place in incremental compaction.
 * The test generates a set of SST objects, generates sorted KV pairs and appends them. Then,
 * it calls the compact method of the level object, which takes this SSTs merge-sorts them,
 * and finally writes them in the device. It does this for num_levels. Then, it goes from each
 * and compacts a single SST. Finally, it lookups and scans all KV pairs in the database. To this
 * end similar to Tiresias it uses BerkeleyDB as the source of truth.
 */
#include "../btree/key_splice.h"
#include "../lib/btree/conf.h"
#include "../lib/btree/sst.h"
#include "btree/kv_pairs.h"
#include "btree/sst.h"
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
#define MANTO_KV_SIZE 4096
#define MANTO_KEY_SIZE MAX_KEY_SIZE
#define SST_SIZE 2097152UL

struct workload_config {
	par_handle handle;
	DB *truth;
	uint64_t total_keys;
	uint32_t progress_report;
};

static void generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++) {
		// key_buffer[i] = (rand() % 255) + 1;
		key_buffer[i] = 96 + (rand() % 25) + 1;
	}
}

static void generate_random_value(char *value_buffer, uint32_t value_size, uint32_t id)
{
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

static void populate_randomly_bdb(struct workload_config *workload_config)
{
	log_info("Manto: generating random kv pairs and inserting them to BerkeleyDB total keys are: %lu...",
		 workload_config->total_keys);
	const char *error_message = NULL;
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
		generate_random_value((char *)value_buffer, kv_pair.v.val_size, i);
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

// Function to generate a random number between min and max (inclusive)
int generateRandom(int min, int max)
{
	return rand() % (max - min + 1) + min;
}

static struct sst *create_ssts(struct workload_config *workload, int num_ssts)
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

	struct sst **ssts = calloc(num_ssts, sizeof(struct sst *));
	int sst_id = 0;
	ssts[sst_id] = sst_create(SST_SIZE);
	// Iterate over the keys
	uint32_t num_kv_pairs = 0;
	while (cursor->c_get(cursor, &key, &value, DB_NEXT) == 0) {
		struct kv_splice *splice = kv_splice_create(key.size, key.data, value.size, value.data);
		while (false == sst_append_KV_pair(ssts[sst_id], splice)) {
			if (++sst_id >= num_ssts) {
				log_warn("Did not manage to fit all KV pairs in %d SSTs of size: %lu kv pairs are: %u",
					 num_ssts, SST_SIZE, num_kv_pairs);
				free(splice);
				goto exit;
			}
			ssts[sst_id] = sst_create(SST_SIZE);
		}
		++num_kv_pairs;
		free(splice);
		log_debug("Key: %.*s, Value size: %d\n", (int)key.size, (char *)key.data, (int)value.size);
	}
exit:
	free(ssts);
	// Close the cursor
	cursor->c_close(cursor);
	return NULL;
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
		.handle = NULL, .truth = truthDB, .total_keys = num_of_kvs, .progress_report = 100000
	};
	populate_randomly_bdb(&workload);
	log_debug("num_of_ssts = %u", num_of_ssts);
	create_ssts(&workload, num_of_ssts);

	truthDB->close(truthDB, 0);
	return 0;
}
