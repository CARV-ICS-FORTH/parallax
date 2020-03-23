#pragma once
#include <stdint.h>
#include "../kreon_server/client_regions.h"

typedef enum krc_scan_state { KRC_UNITIALIZED = 2, KRC_FETCH_NEXT_BATCH, KRC_END_OF_DB } krc_scan_state;

typedef struct krc_key {
	uint32_t key_size;
	uint8_t *key_buf;
} krc_key;

typedef struct krc_value {
	uint32_t val_size;
	uint8_t *val_buf;
} krc_value;

typedef struct krc_scan_entry {
	krc_key *key;
	krc_value *val;
} krc_scan_entry;

typedef struct krc_handle {
	_Client_Regions *client_regions;
} krc_handle;

typedef struct krc_scanner {
	krc_handle *hd;
	krc_key *prefix_key;
	krc_key *start_key;
	krc_key *stop_key;
	uint32_t prefetch_num_entries;
	uint32_t prefetch_mem_size;
	uint32_t pos;
	uint8_t start_infinite : 2;
	uint8_t stop_infinite : 2;
	uint8_t prefix_filter_enable : 2;
	uint8_t is_valid : 2;
	krc_scan_state state;
	krc_scan_entry *scan_buffer;
} krc_scanner;

typedef enum krc_error_codes { KRC_SUCCESS = 0, KRC_ZK_FAILURE_CONNECT, KRC_PUT_FAILURE } krc_error_codes;

krc_handle *krc_init(char *zookeeper_ip, int zk_port, uint32_t *error_code);

uint32_t krc_close(krc_handle *handle);
uint32_t krc_put(krc_handle *hd, uint32_t key_size, void *key, uint32_t val_size, void *value);
krc_value *get(krc_handle *hd, uint32_t key_size, void *key, uint32_t *error_code);

/*scanner API*/
krc_scanner *krc_scan_init(krc_handle *hd, uint32_t prefetch_entries, uint32_t prefetch_mem_size_hint);
void krc_scan_set_start(krc_scanner *sc, uint32_t start_key_size, void *start_key);
void krc_scan_set_stop(krc_scanner *sc, uint32_t stop_key_size, void *stop_key);
void krc_scan_set_prefix_filter(krc_scanner *sc, uint32_t prefix_size, void *prefix);
void krc_scan_get_next(krc_scanner *sc);
uint8_t krc_scan_is_valid(krc_scanner *sc);
void krc_scan_close(krc_scanner *sc);

