#ifndef PAR_NET_GET_H
#define PAR_NET_GET_H

#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct par_net_get_req;

struct par_net_get_rep;

size_t par_net_get_req_calc_size(uint32_t key_size);

/**
  * @brief Constructor for the par_net_put class, initializes values to be
  * ready for serialization
  *
  * @param region_id
  * @param key_size
  * @param key
  * @param buffer
  * @param buffer_len
  *
  * @return An object of the response struct on success and NULL on failure
  *
  */
struct par_net_get_req *par_net_get_req_create(uint64_t region_id, uint32_t key_size, const char *key, bool fetch_value,
					       char *buffer, size_t *buffer_len);

bool par_net_get_req_fetch_value(struct par_net_get_req *request);
/**
 * @brief getter for region_id
 *
 * @param request
 *
 * @return region_id
*/
uint64_t par_net_get_get_region_id(struct par_net_get_req *request);

/**
 * @brief getter for key size
 *
 * @param request
 *
 * @return key size
*/
uint32_t par_net_get_get_key_size(struct par_net_get_req *request);

/**
 * @brief getter for key
 *
 * @param request
 *
 * @return key
*/
char *par_net_get_get_key(struct par_net_get_req *request);

/**
 * @brief calculates the size of the par_net_del_req struct
 *
 * @return the par_net_del_rep struct's size
*/
size_t par_net_get_rep_calc_size(uint32_t value_size);

/**
 * @brief Constructor for the par_net_get_rep class, initializes values to reply to client
 *
 * @param status - 0 for success and 1 for failure
 * @param rep_len - length of the reply
 *
 * @return par_net_get_rep object
*/
struct par_net_get_rep *par_net_get_rep_set_header(bool is_found, struct par_value *value, char *buffer,
						   size_t buffer_len);

/**
 * @brief Takes the reply from server and checks if it's done correctly
 *
 * @param buffer
 *
*/
bool par_net_get_rep_handle_reply(struct par_net_get_rep *reply, struct par_value *value);

bool par_net_get_rep_is_found(struct par_net_get_rep *request);

uint32_t par_net_get_rep_error_code(struct par_net_get_rep *request);

size_t par_net_get_rep_header_size(void);

#endif
