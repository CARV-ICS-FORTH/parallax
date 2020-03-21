#pragma once
#include <stdint.h>
#include "../kreon_server/client_regions.h"


typedef struct krc_value {
	uint32_t val_size;
	uint8_t *val_buf;
} krc_value;

typedef struct krc_handle {
	_Client_Regions *client_regions;
} krc_handle;
typedef enum krc_error_codes { KRC_SUCCESS = 0, KRC_ZK_FAILURE_CONNECT, KRC_PUT_FAILURE } krc_error_codes;

krc_handle *krc_init(char *zookeeper_ip, int zk_port, uint32_t *error_code);

uint32_t krc_close(krc_handle *handle);
uint32_t krc_put(krc_handle *hd, uint32_t key_size, void *key, uint32_t val_size, void *value);

krc_value *get(krc_handle *hd, uint32_t key_size, void *key, uint32_t *error_code);

