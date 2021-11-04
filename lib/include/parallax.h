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

typedef void *par_handle;
typedef void *par_scanner;
typedef enum par_seek_mode { PAR_GREATER, PAR_GREATER_OR_EQUAL, PAR_FETCH_FIRST } par_seek_mode;

typedef enum par_ret_code {
	PAR_SUCCESS = 0,
	PAR_FAILURE,
	PAR_KEY_NOT_FOUND,
} par_ret_code;

typedef enum par_db_initializers { PAR_CREATE_DB = 4, PAR_DONOT_CREATE_DB = 5 } par_db_initializers;

// par_db_options contains the basic metadata to initialize a region.
typedef struct par_db_options {
	char *volume_name; // File or a block device to store the region's data
	const char *db_name; // Region name
	uint64_t volume_start; // Base offset to the file or device to write data
	uint64_t volume_size; // File or device size
	enum par_db_initializers create_flag; // With PAR_CREATE_DB the region if is created if it does not exist.
		// With PAR_DONOT_CREATE_DB the region is not created if it exists.
} par_db_options;

struct par_key {
	uint32_t size;
	const char *data;
};

struct par_value {
	uint32_t size;
	const char *data;
};

struct par_key_value {
	struct par_key k;
	struct par_value v;
};

// Opens a region based on the options provided.
par_handle par_open(par_db_options *options);
// Closes the region referenced by handle. Syncs data to the file or device before exiting.
void par_close(par_handle handle);
// Inserts the key in the region if it does not exist else this becomes an update internally.
par_ret_code par_put(par_handle handle, struct par_key_value *key_value);
// Takes a key and searches for it. If the key exists in the region then, it allocates the value if it is NULL and the client is responsible to release the memory.
// Otherwise it copies the data to the existing data buffer provided by the value pointer.
par_ret_code par_get(par_handle handle, struct par_key *key, struct par_value **value);
// Searches for a key and returns if the key exists in the region.
par_ret_code par_exists(par_handle handle, struct par_key *key);
// Deletes an existing key in the region.
par_ret_code par_delete(par_handle handle, struct par_key *key);
/*scanner staff*/
par_scanner par_init_scanner(par_handle db_handle, struct par_key *key, par_seek_mode mode);
void par_close_scanner(par_scanner sc);
// Advances the scanner iterator to the next key-value.
int par_get_next(par_scanner sc);
// Checks the scanner if the current key-value is valid else we reached the end of database.
int par_is_valid(par_scanner sc);
// Takes a scanner and returns the current key size + key in the iterator.
struct par_key par_get_key(par_scanner sc);
// Takes a scanner and returns the current value size + value in the iterator.
struct par_value par_get_value(par_scanner sc);
// Syncs data to the file or device.
par_ret_code par_sync(par_handle db_handle);

/* #endif // __PARALLAX_H_ */
