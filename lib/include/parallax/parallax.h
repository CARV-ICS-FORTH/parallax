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

#include <stdint.h>

typedef void *par_handle;
typedef void *par_scanner;
typedef enum par_seek_mode { PAR_GREATER, PAR_GREATER_OR_EQUAL, PAR_FETCH_FIRST } par_seek_mode;

typedef enum par_db_initializers { PAR_CREATE_DB = 4, PAR_DONOT_CREATE_DB = 5 } par_db_initializers;

typedef struct par_db_options {
	char *volume_name; /*File or a block device to store the DB's data*/
	const char *db_name; /*DB name*/
	/**
	 * With PAR_CREATE_DB the DB if is created if it does not exist.
	 * With PAR_DONOT_CREATE_DB the DB is not created if it exists.
	 */
	enum par_db_initializers create_flag;

} par_db_options;

struct par_key {
	uint32_t size;
	const char *data;
};

/**
 * If val_buffer is not NULL during a get operation val_buffer_size keeps the
 * size of the application preallocated buffer where Parallax will copy there
 * the corresponding value of the key. If val_buffer is NULL Parallax ignores
 * this field, allocates a buffer, and copies the value which then returns to
 * the application. The application is responsible to free this buffer.
 */
struct par_value {
	uint32_t val_buffer_size;
	uint32_t val_size;
	char *val_buffer;
};

struct par_key_value {
	struct par_key k;
	struct par_value v;
};

/**
 ** Calls the device formatting function of Parallax to initialize the volume's metadata. It does the same job as kv_format.parallax.
 * @param device_name Raw device or file to XFS filesystem. e.g /dev/sdc or $HOME/test.dat
 * @param max_regions_num Maximum regions that will be needed in this deployment it should always be > 1.
 * @return The error message.
 * @retval NULL Function successfully executed.
 * @retval NON-NULL The reason the function failed.
 */
char *par_format(char *device_name, uint32_t max_regions_num) __attribute__((warn_unused_result));

/**
 ** Opens a DB based on the options provided.
 * @param db_options User DB options to configure the DB's behavior.
 * @param error_message The reason the call failed.
 * @return Returns a par_handle to perform operations in the DB.
 * @retval NULL The function failed check @p error_message to find the reason it failed.
 * @retval NON-NULL	The function ran successfully.
 */
par_handle par_open(par_db_options *db_options, char **error_message);

/**
 ** Closes the DB referenced by handle. Syncs data to the file or device before exiting.
 * @param handle Handle returned by \ref par_open.
 * @return Error message in case of failure.
 */

char *par_close(par_handle handle) __attribute__((warn_unused_result));
typedef enum par_ret_code {
	PAR_SUCCESS = 0,
	PAR_FAILURE,
	PAR_KEY_NOT_FOUND,
	PAR_GET_NOT_ENOUGH_BUFFER_SPACE
} par_ret_code;

/**
  * Inserts the key in the DB if it does not exist else this becomes an update internally.
*/
void par_put(par_handle handle, struct par_key_value *key_value, char **error_message);

/**
 * Inserts a serialized key value pair by using the buffer provided by the user.
 * @param serialized_key_value is a buffer containing the serialized key value pair.
 * The format of the key value pair is | key_size | key | value_size | value |, where {key,value}_size is uint32_t.
 * */
void par_put_serialized(par_handle handle, char *serialized_key_value, char **error_message);

/**
  * Takes as input a key and searches for it. If the key exists in the DB then, it allocates the value if it is NULL and the client is responsible to release the memory.
  * Otherwise it copies the data to the existing data buffer provided by the value pointer.
  * @return PAR_GET_NOT_ENOUGH_BUFFER_SPACE when the user provided buffer does not have enough space to store the value.
*/
par_ret_code par_get(par_handle handle, struct par_key *key, struct par_value *value);

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

#endif // PARALLAX_H_
