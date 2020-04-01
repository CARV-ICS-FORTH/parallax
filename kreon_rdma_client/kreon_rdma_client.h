#pragma once
#include <stdint.h>

typedef enum krc_ret_code {
	KRC_SUCCESS = 0,
	KRC_FAILURE,
	KRC_ZK_FAILURE_CONNECT,
	KRC_PUT_FAILURE,
	KRC_KEY_NOT_FOUND,
	KRC_VALUE_TOO_LARGE
} krc_ret_code;

typedef enum krc_scan_state {
	KRC_UNITIALIZED = 2,
	KRC_FETCH_NEXT_BATCH,
	KRC_ISSUE_MGET_REQ,
	KRC_ADVANCE,
	KRC_END_OF_DB,
	KRC_BUFFER_OVERFLOW,
} krc_scan_state;

typedef enum krc_seek_mode { KRC_GREATER_OR_EQUAL = 1, KRC_GREATER } krc_seek_mode;
typedef struct krc_key {
	uint32_t key_size;
	char key_buf[];
} krc_key;

typedef struct krc_value {
	uint32_t val_size;
	char val_buf[];
} krc_value;

//typedef struct krc_handle {
//	_Client_Regions *client_regions;
//} krc_handle;

typedef struct krc_scanner {
	//krc_handle *hd;
	//connection_rdma *conn;

	krc_key *prefix_key;
	krc_key *start_key;
	krc_key *stop_key;
	krc_key *curr_key;
	krc_value *curr_value;
	uint32_t prefetch_num_entries;
	uint32_t prefetch_mem_size;
	uint32_t pos;
	uint8_t start_infinite : 2;
	krc_seek_mode seek_mode;
	uint8_t stop_infinite : 2;
	uint8_t prefix_filter_enable : 2;
	uint8_t is_valid : 2;
	krc_scan_state state;
	/*copy of the server's reply*/
	void *multi_kv_buf;
	void *curr_region;
} krc_scanner;

krc_ret_code krc_init(char *zookeeper_ip, int zk_port);
krc_ret_code krc_close();

uint32_t krc_put(uint32_t key_size, void *key, uint32_t val_size, void *value);
krc_value *krc_get(uint32_t key_size, void *key, uint32_t reply_length, uint32_t *error_code);

/*scanner API*/
krc_scanner *krc_scan_init(uint32_t prefetch_entries, uint32_t prefetch_mem_size_hint);
void krc_scan_set_start(krc_scanner *sc, uint32_t start_key_size, void *start_key, krc_seek_mode seek_mode);
void krc_scan_set_stop(krc_scanner *sc, uint32_t stop_key_size, void *stop_key);
void krc_scan_set_prefix_filter(krc_scanner *sc, uint32_t prefix_size, void *prefix);
void krc_scan_get_next(krc_scanner *sc);
uint8_t krc_scan_is_valid(krc_scanner *sc);
void krc_scan_close(krc_scanner *sc);

