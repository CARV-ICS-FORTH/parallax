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
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define SCAN_SIZE 50
#define VOLUME_NAME "/dev/nvme0n1"
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

void serially_insert_otekeys(db_handle *hd)
{
	bt_insert_req req;
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (!(i & 1))
			continue;
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

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (i & 1)
			continue;
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

void serially_insert_etokeys(db_handle *hd)
{
	bt_insert_req req;
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (!(i & 1))
			continue;
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

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (i & 1)
			continue;
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

void reverse_insert_etokeys(db_handle *hd)
{
	bt_insert_req req;
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = TOTAL_KEYS + NUM_KEYS; i > TOTAL_KEYS; --i) {
		if (i & 1)
			continue;
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

	for (i = TOTAL_KEYS + NUM_KEYS; i > TOTAL_KEYS; --i) {
		if (!(i & 1))
			continue;
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

void reverse_insert_otekeys(db_handle *hd)
{
	bt_insert_req req;
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = TOTAL_KEYS + NUM_KEYS; i > TOTAL_KEYS; --i) {
		if (!(i & 1))
			continue;
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

	for (i = TOTAL_KEYS + NUM_KEYS; i > TOTAL_KEYS; --i) {
		if (i & 1)
			continue;
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

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(find_key(hd, k->key_buf, k->key_size));
	}
	log_info("All keys were found");
}

void validate_reverse_allkeys_exist(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	for (i = TOTAL_KEYS + NUM_KEYS; i > TOTAL_KEYS; --i) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(find_key(hd, k->key_buf, k->key_size));
	}
	log_info("All keys were found");
}

void delete_serially_allkeys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(delete_key(hd, k->key_buf, k->key_size) == SUCCESS);
	}
	log_info("%d keys were deleted", NUM_KEYS);

	assert(hd->db_desc->levels[0].root_w[0]->type == leafRootNode);
}

void serially_delete_otekeys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (!(i & 1))
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(delete_key(hd, k->key_buf, k->key_size) == SUCCESS);
	}

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (i & 1)
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(delete_key(hd, k->key_buf, k->key_size) == SUCCESS);
	}

	log_info("%d keys were deleted", NUM_KEYS);

	assert(hd->db_desc->levels[0].root_w[0]->type == leafRootNode);
}

void serially_delete_etokeys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (i & 1)
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(delete_key(hd, k->key_buf, k->key_size) == SUCCESS);
	}

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (!(i & 1))
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		assert(delete_key(hd, k->key_buf, k->key_size) == SUCCESS);
	}

	log_info("%d keys were deleted", NUM_KEYS);

	assert(hd->db_desc->levels[0].root_w[0]->type == leafRootNode);
}

void reverse_delete_serially_allkeys(db_handle *hd)
{
	int64_t i;
	key *k = (key *)alloca(KV_SIZE);
	int ret;

	for (i = (TOTAL_KEYS + NUM_KEYS - 1); i > TOTAL_KEYS; --i) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		ret = delete_key(hd, k->key_buf, k->key_size);
		assert(ret == SUCCESS);
	}

	assert(hd->db_desc->levels[0].root_w[0]->type == leafRootNode);

	log_info("%d keys were deleted", NUM_KEYS);
}

void count_missing_keys(db_handle *hd)
{
	uint64_t i;
	key *k = (key *)alloca(KV_SIZE);
	int cnt = 0;

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		void *value = find_key(hd, k->key_buf, k->key_size);

		if (!value)
			++cnt;
	}

	assert(cnt == NUM_KEYS);
	log_info("All keys were found");
}

int match_workload(char *s)
{
	if (!strcmp("serial_deletes", s))
		return SD;
	else if (!strcmp("reverse_deletes", s))
		return RD;
	else if (!strcmp("serial_deletesote", s))
		return SOTE;
	else if (!strcmp("serial_deleteseto", s))
		return SETO;
	else if (!strcmp("reverse_deletesote", s))
		return RSOTE;
	else if (!strcmp("reverse_deleteseto", s))
		return RSETO;

	return -1;
}

void run_workload(void (*f[3])(db_handle *), db_handle *hd)
{
	int i;

	for (i = 0; i < 3; ++i) {
		f[i](hd);
		if (i == 1 && PERSIST)
			snapshot(hd->volume_desc);
	}
}

/* ./test_deletes |numofoperations| |workload| |save state(0 or 1)| */
int main(int argc, char *argv[])
{
	assert(argc == 4);
	PERSIST = atoi(argv[3]);
	int64_t device_size;
	void (*f[3])(db_handle *);
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

	db_handle *hd = db_open(VOLUME_NAME, 0, device_size, "test_deletes", CREATE_DB);
	switch (match_workload(argv[2])) {
	case SD:
		f[0] = serially_insert_keys;
		f[1] = validate_serially_allkeys_exist;
		f[2] = delete_serially_allkeys;
		break;
	case RD:
		f[0] = serially_insert_keys;
		f[1] = validate_serially_allkeys_exist;
		f[2] = reverse_delete_serially_allkeys;
		break;
	case SOTE:
		f[0] = serially_insert_otekeys;
		f[1] = validate_serially_allkeys_exist;
		f[2] = serially_delete_otekeys;
		break;
	case SETO:
		f[0] = serially_insert_etokeys;
		f[1] = validate_serially_allkeys_exist;
		f[2] = serially_delete_etokeys;
		break;
	case RSOTE:
		f[0] = reverse_insert_otekeys;
		f[1] = validate_reverse_allkeys_exist;
		f[2] = reverse_delete_serially_allkeys;
		break;
	case RSETO:
		f[0] = reverse_insert_etokeys;
		f[1] = validate_reverse_allkeys_exist;
		f[2] = reverse_delete_serially_allkeys;
		break;
	default:
		assert(0);
	}

	run_workload(f, hd);
	log_info("Delete test Successfull");
	return 1;
}
