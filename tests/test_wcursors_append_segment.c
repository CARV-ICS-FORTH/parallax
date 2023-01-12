/**
 * Test for validating wcursor's append segment functionality
 * Test logic:
 *      1. Create a Berkley DB instance and polulate it with 1 million random KV pairs
 *      2. Initialize a scanner for Berkley DB and get the random KV pairs in a increasing-sorted manner
 *      3. use wcursor_append_kv for each scanner's KV, to create the new index-leaf segments as should uppon a compaction
 *      4. Parse the above segments and use wcursor_append_segment to create a new identical index-leaf segments
 *      5. validate using memcmp that all segments are 1-1 with each other
*/
#include "allocator/persistent_operations.h"
#include "arg_parser.h"
// #include "btree/level_cursor.h"
#include "btree/level_write_cursor.h"
#include "parallax/structures.h"
#include <assert.h>
#include <btree/kv_pairs.h>
#include <db.h>
#include <log.h>
#include <parallax/parallax.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define MAX_KV_PAIR_SIZE 4096
#define MY_MAX_KEY_SIZE 255

static void test_wcursors_generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++)
		key_buffer[i] = rand() % 256;
}

static void test_wcursors_generate_random_value(char *value_buffer, uint32_t value_size, uint32_t id)
{
	*(uint32_t *)value_buffer = id;
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

static DB *test_wcursors_open_BDB(char *BDB_path)
{
	DB *BDB = { 0 };
	int ret = db_create(&BDB, NULL, 0);
	if (ret) {
		BDB->err(BDB, ret, "Database open failed: %s", "truth.db");
		_exit(EXIT_FAILURE);
	}
	bool truth_db_exists = false;
	ret = BDB->open(BDB, NULL, BDB_path, NULL, DB_BTREE, /*DB_CREATE | DB_TRUNCATE*/ 0, 0);
	if (0 == ret) {
		log_info("BDB %s already exists, not  populating it again", BDB_path);
		truth_db_exists = true;
	}

	if (!truth_db_exists) {
		ret = BDB->open(BDB, NULL, BDB_path, NULL, DB_BTREE, DB_CREATE, 0);
		if (ret) {
			BDB->err(BDB, ret, "Database open failed: %s", "truth.db");
			exit(EXIT_FAILURE);
		}
		log_info("Created BDB %s already exists, going to populate as well", BDB_path);
	}
	return BDB;
}

static void test_wcursors_populate_BDB_randomly(DB *BDB, uint64_t total_keys)
{
	log_info("Starting population for %lu keys...", total_keys);
	unsigned char key_buffer[MY_MAX_KEY_SIZE] = { 0 };
	unsigned char value_buffer[MAX_KV_PAIR_SIZE] = { 0 };
	uint64_t unique_keys = 0;
	for (uint64_t i = 0; i < total_keys; i++) {
		uint32_t key_size = rand() % (MY_MAX_KEY_SIZE + 1);
		if (!key_size)
			key_size++;
		uint32_t val_size = rand() % (MAX_KV_PAIR_SIZE - (key_size + sizeof(uint32_t)));
		if (val_size < 4)
			val_size = 4;

		test_wcursors_generate_random_key(key_buffer, key_size);
		test_wcursors_generate_random_value((char *)value_buffer, val_size, i);

		DBT truth_key = { 0 };
		DBT truth_data = { 0 };
		truth_key.data = (void *)key_buffer;
		truth_key.size = key_size;
		truth_data.data = value_buffer;
		truth_data.size = val_size;
		int ret = BDB->put(BDB, NULL, &truth_key, &truth_data, DB_NOOVERWRITE);
		if (ret == DB_KEYEXIST) {
			// workload_config->truth->err(workload_config->truth, ret,
			// 			    "Put failed because key size %u payload: %.*s already exists",
			// 			    truth_key.size, truth_key.size, truth_key.data);
			continue;
		}
		++unique_keys;
	}
	log_info("Population ended Successfully! :-)");
}

static par_handle test_wcursors_open_parallax(struct wrap_option *options)
{
	par_db_options db_options = { 0 };
	db_options.volume_name = get_option(options, 1);
	log_debug("Volume name %s", db_options.volume_name);

	const char *error_message = par_format(db_options.volume_name, 16);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		_exit(EXIT_FAILURE);
	}

	db_options.db_name = "wcursors_append_segment";
	db_options.create_flag = PAR_CREATE_DB;
	db_options.options = par_get_default_options();
	db_options.options[REPLICA_MODE].value = 1;
	db_options.options[PRIMARY_MODE].value = 0;
	par_handle parallax_db = par_open(&db_options, &error_message);
	return parallax_db;
}

static void test_wcursors_append_all_kvs(DB *BDB, struct wcursor_level_write_cursor *wcursor)
{
	DBC *cursorp = NULL;
	DBT key = { 0 };
	DBT data = { 0 };
	/* Database open omitted for clarity */
	/* Get a cursor */
	BDB->cursor(BDB, NULL, &cursorp, 0);

	int ret = cursorp->get(cursorp, &key, &data, DB_NEXT);
	for (; ret == 0; ret = cursorp->get(cursorp, &key, &data, DB_NEXT)) {
		uint32_t key_size = key.size;
		uint32_t value_size = data.size;
		uint32_t kv_splice_metadata = kv_splice_get_metadata_size();
		struct kv_splice *kv_buf = (struct kv_splice *)calloc(1, key_size + value_size + kv_splice_metadata);
		kv_splice_set_key(kv_buf, key.data, key.size);
		kv_splice_set_key_size(kv_buf, key.size);
		kv_splice_set_value(kv_buf, data.data, data.size);
		kv_splice_set_value_size(kv_buf, data.size);

		struct kv_splice_base par_key = { .cat = SMALL_INPLACE, .kv_splice = kv_buf };

		wcursor_append_KV_pair(wcursor, &par_key);
	}
	cursorp->close(cursorp);
}

static void test_wcursors_fetch_segment(int fd, char *buf, uint64_t segment_offt)
{
	ssize_t bytes_read = 0;
	while (bytes_read < SEGMENT_SIZE) {
		ssize_t bytes = pread(fd, &buf[bytes_read], SEGMENT_SIZE - bytes_read, segment_offt + bytes_read);
		if (-1 == bytes) {
			log_fatal("Failed to read error code");
			perror("Error");
			BUG_ON();
		}
		bytes_read += bytes;
	}
}

static uint32_t test_wcursors_find_segment_height(char *buf)
{
	struct segment_header *segment_hdr = (struct segment_header *)buf;
	struct node_header *node_type = (struct node_header *)((char *)segment_hdr + sizeof(struct segment_header));
	return node_type->height;
}

static void test_wcursors_copy_segments(struct wcursor_level_write_cursor *wcursor_segments, par_handle dbhandle,
					uint32_t level_id)
{
	struct db_handle *handle = (struct db_handle *)dbhandle;
	char *buf = NULL;
	if (posix_memalign((void **)&buf, ALIGNMENT_SIZE, SEGMENT_SIZE)) {
		log_fatal("poxix mem aligned failed");
		assert(0);
	}
	char *next_buf = NULL;
	if (posix_memalign((void **)&next_buf, ALIGNMENT_SIZE, SEGMENT_SIZE)) {
		log_fatal("poxix mem aligned failed");
		assert(0);
	}

	char *last_segment_offt_of_level[MAX_HEIGHT];
	for (int i = 0; i < MAX_HEIGHT; i++) {
		if (posix_memalign((void **)&last_segment_offt_of_level[i], ALIGNMENT_SIZE, SEGMENT_SIZE)) {
			log_fatal("poxix mem aligned failed");
			assert(0);
		}
	}

	uint64_t curr_segment_offt = ABSOLUTE_ADDRESS(handle->db_desc->levels[level_id].first_segment[1]);
	uint64_t tail_segment_offt = ABSOLUTE_ADDRESS(handle->db_desc->levels[level_id].last_segment[1]);
	while (curr_segment_offt != tail_segment_offt) {
		// copy segment
		test_wcursors_fetch_segment(wcursor_segments->fd, buf, curr_segment_offt);
		struct segment_header *curr_segment_hdr = (struct segment_header *)buf;
		curr_segment_offt = (uint64_t)curr_segment_hdr->next_segment;
		// copy next segment aswell, we need to check if this segment is the last of this level
		test_wcursors_fetch_segment(wcursor_segments->fd, next_buf, curr_segment_offt);
		// write segment
		uint32_t height = test_wcursors_find_segment_height(buf);
		uint32_t next_height = test_wcursors_find_segment_height(next_buf);
		assert(height < MAX_HEIGHT && next_height < MAX_HEIGHT);
		if (height != next_height) {
			// last segment for level height, store in into the buffer
			memcpy(last_segment_offt_of_level[height], buf, SEGMENT_SIZE);
			continue;
		}
		wcursor_append_index_segment(wcursor_segments, height, buf, SEGMENT_SIZE, 0);
	}
	assert(curr_segment_offt == tail_segment_offt);
	// keep last segment in the array for the last segments
	test_wcursors_fetch_segment(wcursor_segments->fd, buf, curr_segment_offt);
	memcpy(last_segment_offt_of_level[MAX_HEIGHT - 1], buf, SEGMENT_SIZE);

	// link last segments with the level above and flush them
	for (int i = 0; i < MAX_HEIGHT; i++) {
		wcursor_append_index_segment(wcursor_segments, i, last_segment_offt_of_level[i], SEGMENT_SIZE, 1);
	}
}

static void test_wcursors_create_compaction_index_for_level(DB *BDB, par_handle handle, uint32_t level_id)
{
	// init wcursor
	log_info("Initialize a level write cursor for level 2");
	uint32_t tree_id = 1;
	par_init_compaction_id(handle, level_id, tree_id);
	struct wcursor_level_write_cursor *write_cursor = wcursor_init_write_cursor(level_id, handle, tree_id, true);
	// append all KVs
	log_info("Insert all key-values in BDB to the level write cursor..");
	test_wcursors_append_all_kvs(BDB, write_cursor);
	// stitch segments, free cursor
	wcursor_flush_write_cursor(write_cursor);
	wcursor_close_write_cursor(write_cursor);
	struct db_handle *dbhandle = (struct db_handle *)handle;
	pr_flush_compaction(dbhandle->db_desc, level_id, tree_id);
	log_info("Index for level 2 is constructed, cursor closed");
}

static void test_wcursors_validate_segments(par_handle handle)
{
	// memcmp all segments
	struct db_handle *dbhandle = (struct db_handle *)handle;
	struct segment_header *curr_segment_level_2 = dbhandle->db_desc->levels[2].first_segment[1];
	struct segment_header *last_segment_level_2 = dbhandle->db_desc->levels[2].last_segment[1];
	struct segment_header *curr_segment_level_4 = dbhandle->db_desc->levels[4].first_segment[1];
	struct segment_header *last_segment_level_4 = dbhandle->db_desc->levels[4].last_segment[1];
	while (curr_segment_level_2 != last_segment_level_2) {
		char *segment_payload_level_2 = (char *)curr_segment_level_2 + sizeof(struct segment_header);
		char *segment_payload_level_4 = (char *)curr_segment_level_4 + sizeof(struct segment_header);
		int ret = memcmp(segment_payload_level_2, segment_payload_level_4,
				 SEGMENT_SIZE - sizeof(struct segment_header));
		if (0 != ret) {
			log_fatal("There is a difference between the segments payload, this should never happen");
			assert(0);
			exit(EXIT_FAILURE);
		}

		// step both cursors
		curr_segment_level_2 = (struct segment_header *)REAL_ADDRESS(curr_segment_level_2->next_segment);
		curr_segment_level_4 = (struct segment_header *)REAL_ADDRESS(curr_segment_level_4->next_segment);
	}
	// check last segment aswell
	int ret = memcmp((char *)last_segment_level_2, (char *)last_segment_level_4,
			 SEGMENT_SIZE - sizeof(struct segment_header));
	if (0 != ret) {
		log_fatal("There is a difference between the segments payload, this should never happen");
		assert(0);
		exit(EXIT_FAILURE);
	}
}

static void test_wcursors(DB *BDB, par_handle handle)
{
	test_wcursors_create_compaction_index_for_level(BDB, handle, 2);

	// parse new segments and use wcursor_append_segment
	log_info("Initialize a level write cursor for level 4");
	uint32_t level_id = 4;
	uint32_t tree_id = 1;
	par_init_compaction_id(handle, level_id, tree_id);
	struct wcursor_level_write_cursor *write_cursor_segments =
		wcursor_init_write_cursor(level_id, handle, tree_id, true);

	log_info("Traverse level 2 index and populate all segments in level 4 cursor");
	test_wcursors_copy_segments(write_cursor_segments, handle, 2);

	wcursor_close_write_cursor(write_cursor_segments);

	log_info("Validate that all segments are equal in both indexes");
	test_wcursors_validate_segments(handle);
}

int main(int argc, char **argv)
{
	int help_flag = 0;

	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for test_medium.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { "num_of_kvs", required_argument, 0, 'b' },
		  "--num_of_kvs=number, parameter that specifies the number of operation the test will execute.",
		  NULL,
		  INTEGER },
		{ { "BDB_file", optional_argument, 0, 'a' },
		  "--BDB_file=path to BerkeleyDB (BDB) file, parameter that specifies the BDB that the test uses.",
		  NULL,
		  STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};

	unsigned optional_args_len = 0;
	unsigned options_len = sizeof(options) / sizeof(struct wrap_option);
	log_debug("Options len %u", options_len);
	arg_parse(argc, argv, options, options_len - optional_args_len);
	arg_print_options(help_flag, options, options_len);
	uint64_t total_keys = *(int *)get_option(options, 2);
	log_debug("Total keys %lu", total_keys);
	srand(1);

	/*First open BerkeleyDB database*/
	char *BDB_path = get_option(options, 3);
	log_info("BerkeleyDB path is %s", BDB_path);
	DB *BDB = test_wcursors_open_BDB(BDB_path);

	log_info("Populate Berkley DB");
	test_wcursors_populate_BDB_randomly(BDB, total_keys);

	// open parallax
	log_info("Opening Parallax at path %s", (char *)get_option(options, 1));
	par_handle handle = test_wcursors_open_parallax(options);

	// test logic
	test_wcursors(BDB, handle);
}
