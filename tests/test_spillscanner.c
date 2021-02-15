#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <log.h>
#include <btree/btree.h>
#include <scanner/scanner.h>
#define TOTAL_KEYS 1000000
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define VOLUME_NAME "/dev/nvme0n1"
#define NUM_KEYS 1000000ULL
#define SCAN_SIZE 50

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
	key *k = (key *)malloc(KV_SIZE + 1);

	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0x00, v->value_size);

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
	free(k);
	log_info("Lost keys %d", cnt);
	log_info("All keys were found");
}

void scankeys_with_spill_scanner(db_handle *hd)
{
	node_header *spill_root;
	db_descriptor *db_desc = hd->db_desc;
	key *k = (key *)malloc(KV_SIZE);
	level_scanner *level_sc;
	uint64_t i = TOTAL_KEYS, j;
	int level_id = 0;
	int rc;

	int active_tree = db_desc->levels[level_id].active_tree;
	if (db_desc->levels[level_id].root_w[active_tree] != NULL)
		spill_root = db_desc->levels[level_id].root_w[active_tree];
	else
		spill_root = db_desc->levels[level_id].root_r[active_tree];

	level_sc = _init_spill_buffer_scanner(hd, level_id, spill_root, NULL);

	//level_sc = _init_spill_buffer_scanner(hd, spill_req.src_root, spill_req.start_key);
	assert(level_sc != NULL);

	j = 0;
	do {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		char *scan_key = (char *)(*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE));
		if (memcmp(k->key_buf, scan_key + 4, k->key_size) != 0) {
			log_fatal("Test failed after %d keys expected key %s got %lu:%s prefix is %s", j, k->key_buf,
				  *(uint32_t *)scan_key, scan_key + 4, level_sc->keyValue);
			exit(EXIT_FAILURE);
		}
		//else
		//log_info("Success got %lu:%s", *(uint32_t *)key, key + 4);

		rc = _get_next_KV(level_sc);
		if (rc == END_OF_DATABASE)
			break;

		++j;
		++i;
	} while (rc != END_OF_DATABASE);

	assert(j == NUM_KEYS - 1);
}

int main(void)
{
	db_handle *hd = db_open(VOLUME_NAME, 0, 250059350016L, "spillscan_test", CREATE_DB);

	serially_insert_keys(hd);
	validate_serially_allkeys_exist(hd);
	scankeys_with_spill_scanner(hd);
	log_info("scan test Successfull");
	return 1;
}
