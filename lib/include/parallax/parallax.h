// Copyright [2022] [FORTH-ICS]
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

#ifndef PARALLAX_H_
#define PARALLAX_H_

#include "structures.h"
#include <stdint.h>

/**
 * Calls the device formatting function of Parallax to initialize the volume's metadata. It does the same job as kv_format.parallax.
 * @param device_name Raw device or file to XFS filesystem. e.g /dev/sdc or $HOME/test.dat
 * @param max_regions_num Maximum regions that will be needed in this deployment it should always be > 1.
 * @return The error message.
 * @retval NULL Function successfully executed. NON-NULL The reason the function failed.
 */
char *par_format(char *device_name, uint32_t max_regions_num) __attribute__((warn_unused_result));

/**
 * Opens a DB based on the options provided.
 * @param db_options User DB options to configure the DB's behavior.
 * @param error_message The reason the call failed.
 * @return Returns a par_handle to perform operations in the DB.
 * @retval NULL The function failed check @p error_message to find the reason it failed. NON-NULL The function ran successfully.
 */
par_handle par_open(par_db_options *db_options, char **error_message);

/**
 * Closes the DB referenced by handle. Syncs data to the file or device before exiting.
 * @param handle Handle returned by \ref par_open.
 * @return Error message in case of failure.
 */

char *par_close(par_handle handle) __attribute__((warn_unused_result));
/*This will be removed before merging the public api*/
typedef enum par_ret_code {
	PAR_SUCCESS = 0,
	PAR_FAILURE,
	PAR_KEY_NOT_FOUND,
	PAR_GET_NOT_ENOUGH_BUFFER_SPACE
} par_ret_code;

/**
 * Returns the category of the KV based on its key-value size and the operation to perform.
 * @param key_size
 * @param value_size
 * @param op_type Operation to execute valid operation insertOp, deleteOp.
 * @return On success return the KV category.
 */
enum kv_category get_kv_category(uint32_t key_size, uint32_t value_size, request_type operation, char **error_message);

/**
 * Inserts the key in the DB if it does not exist else this becomes an update internally.
 * @param handle DB handle provided by par_open.
 * @param key_value KV to insert.
 * @param error_message Contains error message if call fails.
 */
void par_put(par_handle handle, struct par_key_value *key_value, char **error_message);

/**
 * Inserts a serialized key value pair by using the buffer provided by the
 * user. @param serialized_key_value is a buffer containing the serialized key
 * value pair. The format of the key value pair is | key_size | key |
 * value_size | value |, where {key,value}_size is uint32_t.
 */
void par_put_serialized(par_handle handle, char *serialized_key_value, char **error_message);

/**
 * Takes as input a key and searches for it. If the key exists in the DB, then
 * it allocates the value if it is NULL and the client is responsible to release
 * the memory. Otherwise it copies the data to the existing data buffer provided
 * by the value pointer.
 * @param handle DB handle provided by par_open.
 * @param key to be searched.
 * @param value buffer to be filled uppon get success.
 * @param error_message Contains error message if call fails.
 */
void par_get(par_handle handle, struct par_key *key, struct par_value *value, char **error_message);

/**
 * Searches for a key and returns if the key exists in the DB.
 */
par_ret_code par_exists(par_handle handle, struct par_key *key);

/**
 * Deletes an existing key in the DB.
 */
void par_delete(par_handle handle, struct par_key *key, char **error_message);

/**
 * scanner API. At the current state scanner supports snapshot isolation. The lifetime of a scanner start with
 * a call to par_init_scanner and ends with par_close_scanner. Currently, to provide snapshot isolation during
 * an active scanner no updates or insers can be performed in the DB. We will add other types of scanner with
 * relaxed semantics for higher concurrency soon
 */
par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode);
void par_close_scanner(par_scanner sc);

/**
 * Advances the scanner iterator to the next key-value.
 */
//TODO Describe return values of this function
int par_get_next(par_scanner sc);

/**
 * Checks the scanner if the current key-value is valid else we reached the end of database.
 */
//TODO Describe return values of this function
int par_is_valid(par_scanner sc);

/**
 * Takes a scanner and returns the current key size + key in the iterator.
 */
struct par_key par_get_key(par_scanner sc);

/**
 * Takes a scanner and returns the current value size + value in the iterator.
 */
struct par_value par_get_value(par_scanner sc);

/**
 * Syncs data to the file or device.
 */
par_ret_code par_sync(par_handle handle);

/**
 * Create, populate and return a buffer containing the default db_options values from option.yml file. Callers can modify the buffer at will.
 * @retval Array with NUM_OF_OPTIONS sizeo of struct options_desc
 */
struct par_options_desc *par_get_default_options(void);

#endif // PARALLAX_H_
