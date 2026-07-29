#ifndef PAR_NET_PUT_H
#define PAR_NET_PUT_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_put_req;

struct par_net_put_rep;

#ifdef USE_INFINIBAND
struct par_net_put_batch_req;
#endif

/**
  * @brief calculates total size of par_net_put_req struct and the sizes
  * of the key and value.
  *
  *	@param key_size
  *	@param value_size
  *
  * @return Total size of struct
  *
  */
size_t par_net_put_req_calc_size(uint32_t key_size, uint32_t value_size);

/**
  * @brief Constructor for the par_net_put class, initializes values to be
  * ready for serialization
  *
  * @param region_id
  * @param key_size
  * @param key
  * @param value_size
  * @param value
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  *
  */
struct par_net_put_req *par_net_put_req_create(uint64_t region_id, uint32_t key_size, const char *key,
					       uint32_t value_size, const char *value, char *buffer,
					       size_t *buffer_len);

/**
 * @brief getter for region_id
 *
 * @param request
 *
 * @return region_id
*/
uint64_t par_net_put_get_region_id(struct par_net_put_req *request);

/**
 * @brief getter for key size
 *
 * @param request
 *
 * @return key size
*/
uint32_t par_net_put_get_key_size(struct par_net_put_req *request);

/**
 * @brief getter for value size
 *
 * @param request
 *
 * @return value size
*/
uint32_t par_net_put_get_value_size(struct par_net_put_req *request);

/**
 * @brief getter for key
 *
 * @param request
 *
 * @return key
*/
char *par_net_put_get_key(struct par_net_put_req *request);

/**
 * @brief getter for value
 *
 * @param request
 *
 * @return value
*/
char *par_net_put_get_value(struct par_net_put_req *request);

/**
 * @brief calculates the size of the par_net_open_req struct
 *
 * @return the par_net_open_rep struct's size
*/
size_t par_net_put_rep_calc_size(void);

/**
 * @brief Constructor for the par_net_put_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param metadata - par_put return value
 * @param rep_len - length of the reply
 *
 * @return par_net_put_rep object
*/
struct par_net_put_rep *par_net_put_rep_create(int status, struct par_put_metadata metadata, char *buffer,
					       size_t buffer_len);

/**
 * @brief Takes the reply from server and gets the return value for par_put for the client
 *
 * @param buffer
 *
 * @return par_put return value
 *
*/
struct par_put_metadata par_net_put_rep_handle_reply(struct par_net_put_rep *reply);

#ifdef USE_INFINIBAND

size_t par_net_put_batch_req_calc_size(struct par_key_value *kv_array, int count);

struct par_net_put_batch_req *par_net_put_batch_req_create(uint64_t region_id, struct par_key_value *kv_array,
							   int count, char *buffer, size_t *buffer_len);

uint64_t par_net_put_batch_get_region_id(struct par_net_put_batch_req *request);

uint32_t par_net_put_batch_get_num_kvs(struct par_net_put_batch_req *request);

char *par_net_put_batch_get_data_ptr(struct par_net_put_batch_req *request);

#endif

#endif
