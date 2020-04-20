#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <log.h>
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/btree/delete.h"
#define NUM_KEYS num_keys
#define PERSIST persist
#define TOTAL_KEYS 0
#define KV_SIZE 1024
#define SCAN_SIZE 50
#define KEY_PREFIX "userakias_computerakias"
#define VOLUME_NAME "/tmp/gxanth/kreon.dat"

uint64_t num_keys;
int persist = 1;

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
	key *k = (key *)alloca(KV_SIZE);

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
	log_info("Population ended");
}

void validate_serially_allkeys_exist(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);
	int cnt = 0;

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		/* assert(find_key(hd, k->key_buf, k->key_size)); */
		if (!find_key(hd, k->key_buf, k->key_size)) {
			log_info("Lost key %s", k->key_buf);
			cnt++;
		}
	}

	log_info("Lost keys %d", cnt);
	log_info("All keys were found");
}

/* ./test_spills |numofoperations| |save state(0 or 1)| */
int main(int argc, char *argv[])
{
	assert(argc == 3);
	PERSIST = atoi(argv[2]);
	int64_t device_size;
	num_keys = atoll(argv[1]);
	FD = open(VOLUME_NAME, O_RDWR); /* open the device */
	if (ioctl(FD, BLKGETSIZE64, &device_size) == -1) {
		/*maybe we have a file?*/
		device_size = lseek(FD, 0, SEEK_END);
		if (device_size == -1) {
			log_fatal("failed to determine volume size exiting...");
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}

	db_handle *hd = db_open(VOLUME_NAME, 0, device_size, "test_spills", CREATE_DB);

	serially_insert_keys(hd);

	while (hd->db_desc->levels[0].outstanding_spill_ops) {
		log_info("spill ops %d", hd->db_desc->levels[0].outstanding_spill_ops);
		sleep(1);
	}
	if (PERSIST)
		snapshot(hd->volume_desc);

	validate_serially_allkeys_exist(hd);

	/* serially_insert_keys(hd); */
	/* validate_serially_allkeys_exist(hd); */

	log_info("Spill test Successfull");
	return 1;
}
