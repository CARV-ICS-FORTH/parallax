#define _LARGEFILE64_SOURCE
#include <allocator/volume_manager.h>
#include <assert.h>
#include <btree/btree.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if 0
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define SCAN_SIZE 50
#define VOLUME_NAME "/tmp/ramdisk/kreon.dat"
#define TOTAL_KEYS 0
#define NUM_KEYS num_keys
#define SD 0
#define RD 1
#define SOTE 2
#define SETO 3
#define RSOTE 4
#define RSETO 5
#define PERSIST persist
uint64_t num_keys;
int persist = 1;
int recover;

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
	bt_insert_req req;
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

		req.metadata.handle = hd;
		req.metadata.kv_size = k->key_size + v->value_size + (2 * sizeof(uint32_t));
		assert(req.metadata.kv_size == KV_SIZE);
		req.key_value_buf = k;
		req.metadata.level_id = 0;
		req.metadata.key_format = KV_FORMAT;
		req.metadata.append_to_log = 1;
		req.metadata.gc_request = 0;
		req.metadata.recovery_request = 0;
		_insert_key_value(&req);
	}

	free(k);
	log_info("Population ended");
}

void validate_serially_allkeys_exist(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	(void)hd;

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(find_key(hd, k->key_buf, k->key_size));
	}

	log_info("All keys were found");
	free(k);
}

int match_workload(char *workload)
{
	if (!strcmp("serial_deletes", workload))
		return SD;

	return -1;
}

void run_workload(void (*f[])(db_handle *), db_handle *hd)
{
	for (int i = 0; i < 2; ++i) {
		if (f[i] == NULL)
			break;

		f[i](hd);

		if (i == 0 && PERSIST && recover == CREATE_DB) {
			log_info("COMMITING LOG");
			//commit_db_logs_per_volume(hd->volume_desc);
			exit(EXIT_FAILURE);
		}
	}
}
#endif
/* ./test_recovery |numofoperations| |workload| |save state(0 or 1)| |CREATE_DB or NOT (0 or 1)|*/
int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
#if 0
	assert(argc == 5);
	(void)argc;
	if (!atoi(argv[4]))
		recover = CREATE_DB;
	else
		recover = DONOT_CREATE_DB;

	PERSIST = atoi(argv[3]);
	int64_t device_size;
	void (*f[2])(db_handle *) = { NULL };
	num_keys = atoll(argv[1]);
	FD = open(VOLUME_NAME, O_RDWR); /* open the device */
	if (ioctl(FD, BLKGETSIZE64, &device_size) == -1) {
		/*maybe we have a file?*/
		device_size = lseek64(FD, 0, SEEK_END);
		if (device_size == -1) {
			log_fatal("failed to determine volume size exiting...");
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}

	db_handle *hd = db_open(VOLUME_NAME, 0, device_size, "test_recovery", recover);

	if (recover == CREATE_DB) {
		hd->db_desc->dirty = 1;
		snapshot(hd->volume_desc);
	}

	if (recover == CREATE_DB) {
		f[0] = serially_insert_keys;
		f[1] = validate_serially_allkeys_exist;
	} else if (recover == DONOT_CREATE_DB) {
		f[0] = validate_serially_allkeys_exist;
		f[1] = NULL;
	} else
		assert(0);

	run_workload(f, hd);
	log_info("Recovery test Successfull");
	return 1;
#endif
}
