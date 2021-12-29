#define _LARGEFILE64_SOURCE
#include <allocator/volume_manager.h>
#include <assert.h>
#include <btree/btree.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PATH "/tmp/ramdisk/kv_store.dat"
#define KV_SIZE 1500
#define KEY_PREFIX "ts"
#define NUM_KEYS num_keys
#define TOTAL_KEYS 0
uint64_t num_keys = 600;

typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

void serially_insert_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 10000 == 0)
			log_info("%s", k->key_buf);
		insert_key_value(hd, k->key_buf, v->value_buf, k->key_size, v->value_size, insertOp);
	}
	free(k);
	log_info("Population ended");
}

void get_all_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .kv_buf = k->key_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 0,
					   .found = 0,
					   .retrieve = 0 };

	log_info("Search for all keys");

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf + 4, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + 4 + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(&k->key_buf[4]) + 1;
		*(uint32_t *)k->key_buf = k->key_size;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		if (i % 10000 == 0)
			log_info("%s", &k->key_buf[4]);
		find_key(&get_op);

		assert(get_op.found);
	}
	free(k);
	log_info("Searching finished");
}

void delete_half_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	log_info("Delete started");
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS) / 2; i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */

		if (i % 10000 == 0)
			log_info("%s", k->key_buf);
		insert_key_value(hd, k->key_buf, "empty", k->key_size, 0, deleteOp);
	}
	free(k);
	log_info("Delete finished");
}

void get_all_valid_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	struct lookup_operation get_op = { .db_desc = hd->db_desc,
					   .kv_buf = k->key_buf,
					   .buffer_to_pack_kv = NULL,
					   .size = 0,
					   .buffer_overflow = 0,
					   .found = 0,
					   .tombstone = 0,
					   .retrieve = 0 };

	log_info("Search for all keys");

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS) / 2; i++) {
		memcpy(k->key_buf + 4, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + 4 + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(&k->key_buf[4]) + 1;
		*(uint32_t *)k->key_buf = k->key_size;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		/* if (i % 10000 == 0) */
		log_info("%s", &k->key_buf[4]);
		find_key(&get_op);
		if (!get_op.tombstone) {
			log_info("%d", get_op.tombstone);
			BREAKPOINT;
		}
		/* assert(get_op.tombstone); */
		/* assert(get_op.found); */
		get_op.tombstone = 0;
		get_op.found = 0;
	}
	free(k);
	log_info("Searching finished");
}

int main(void)
{
	db_handle *handle;
	int64_t size;
	int fd = open(PATH, O_RDONLY);

	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
		perror("ioctl");
		/*maybe we have a file?*/
		printf("[%s:%s:%d] querying file size\n", __FILE__, __func__, __LINE__);
		size = lseek64(fd, 0, SEEK_END);
		if (size == -1) {
			printf("[%s:%s:%d] failed to determine volume size exiting...\n", __FILE__, __func__, __LINE__);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}

	close(fd);

	handle = db_open(PATH, 0, size, "test.db", CREATE_DB);
	assert(handle);
	//snapshot(handle->volume_desc);
	serially_insert_keys(handle);
	log_info(
		"-------------------------------------------------------------------FINISH-------------------------------------------------------------------------------");
	get_all_keys(handle);
	delete_half_keys(handle);
	get_all_valid_keys(handle);
	//snapshot(handle->volume_desc);

	return 0;
}
