#define _LARGEFILE64_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <unistd.h>
#include <log.h>
#include <allocator/volume_manager.h>
#include <btree/btree.h>

#define PATH "/tmp/ramdisk/kreon.dat"
#define KV_SIZE 1500
#define KEY_PREFIX "ts"
#define NUM_KEYS num_keys
#define TOTAL_KEYS 0
uint64_t num_keys = 1000000;
int update_half = 0;

typedef struct key {
	uint32_t key_size;
	char key_buf[0];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[0];
} value;

void serially_insert_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (update_half && i % 2 == 1)
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 10000 == 0)
			log_info("%s", k->key_buf);
		insert_key_value(hd, k->key_buf, v->value_buf, k->key_size, v->value_size);
	}
	free(k);
	log_info("Population ended");
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
	snapshot(handle->volume_desc);
	update_half = 1;
	serially_insert_keys(handle);
	log_info(
		"-------------------------------------------------------------------FINISH-------------------------------------------------------------------------------");
	serially_insert_keys(handle);
	snapshot(handle->volume_desc);

	return 0;
}
