/* #ifndef __PARALLAX_H_ */
/* #define __PARALLAX_H_ */
// Copyright [2020] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include <stdint.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

typedef void *klc_handle;
typedef void *klc_scanner;
typedef enum klc_seek_mode { KLC_GREATER, KLC_GREATER_OR_EQUAL, KLC_FETCH_FIRST } klc_seek_mode;

typedef enum klc_ret_code {
	KLC_SUCCESS = 0,
	KLC_FAILURE,
	KLC_KEY_NOT_FOUND,
} klc_ret_code;

typedef enum klc_db_initializers { KLC_CREATE_DB = 4, KLC_DONOT_CREATE_DB = 5 } klc_db_initializers;

// klc_db_options contains the basic metadata to initialize a region.
typedef struct klc_db_options {
	char *volume_name; // File or a block device to store the region's data
	const char *db_name; // Region name
	uint64_t volume_start; // Base offset to the file or device to write data
	uint64_t volume_size; // File or device size
	enum klc_db_initializers create_flag; // With KLC_CREATE_DB the region if is created if it does not exist.
		// With KLC_DONOT_CREATE_DB the region is not created if it exists.
} klc_db_options;

struct klc_key {
	uint32_t size;
	const char *data;
};

struct klc_value {
	uint32_t size;
	const char *data;
};

struct klc_key_value {
	struct klc_key k;
	struct klc_value v;
};

// Opens a region based on the options provided.
klc_handle klc_open(klc_db_options *options);
// Closes the region referenced by handle. Syncs data to the file or device before exiting.
void klc_close(klc_handle handle);
// Inserts the key in the region if it does not exist else this becomes an update internally.
klc_ret_code klc_put(klc_handle handle, struct klc_key_value *key_value);
// Takes a key and searches for it. If the key exists in the region then, it allocates the value if it is NULL and the client is responsible to release the memory.
// Otherwise it copies the data to the existing data buffer provided by the value pointer.
klc_ret_code klc_get(klc_handle handle, struct klc_key *key, struct klc_value **value);
// Searches for a key and returns if the key exists in the region.
klc_ret_code klc_exists(klc_handle handle, struct klc_key *key);
// Deletes an existing key in the region.
klc_ret_code klc_delete(klc_handle handle, struct klc_key *key);
/*scanner staff*/
klc_scanner klc_init_scanner(klc_handle db_handle, struct klc_key *key, klc_seek_mode mode);
void klc_close_scanner(klc_scanner sc);
// Advances the scanner iterator to the next key-value.
int klc_get_next(klc_scanner sc);
// Checks the scanner if the current key-value is valid else we reached the end of database.
int klc_is_valid(klc_scanner sc);
// Takes a scanner and returns the current key size + key in the iterator.
struct klc_key klc_get_key(klc_scanner sc);
// Takes a scanner and returns the current value size + value in the iterator.
struct klc_value klc_get_value(klc_scanner sc);
// Syncs data to the file or device.
klc_ret_code klc_sync(klc_handle db_handle);

/* #endif // __PARALLAX_H_ */
