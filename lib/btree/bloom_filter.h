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
#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include "btree.h"
#include <stdbool.h>
#include <stdint.h>
struct pbf_desc;

/**
 * @brief Initializes a new bloom filter for the level. It approximates the
 * capacity of the bloom filter (aka the number of key value pairs that it will
 * address) based on the level size in keys
 * @param db_desc the descripto of the database
 * @param level_id the id of the level
 * @param tree_id the tree in the level
 * @return reference to the object or NULL on failure.
 */
struct pbf_desc *pbf_create(db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id);

/**
 * @brief Writes a bloom filter to a file on disk
 * @param bloom_filter reference to the bloom filter object to be persisted
 * @return true on success false on failure
 */
bool pbf_persist_bloom_filter(struct pbf_desc *bloom_filter);

/**
 * @brief Recovers if needed all bloom filters for the device.
 * @return true on success false on failure
 */
bool pbf_recover(db_descriptor *db_desc);

/**
 * @brief Deletes the bloom file
 * @param bloom the descriptor to the bloom filter.
 * @return true on success false on failure
 */
bool pbf_delete_bloom_file(struct pbf_desc *bloom);

/**
 * @brief Frees the in memory structure of the bloom filter and also deletes
 * the associated bloom file on the device.
 * @param bloom_filter the descriptor to the parallax bloom filter.
 * @return true on success false on failure
 */
bool pbf_destroy_bloom_filter(struct pbf_desc *bloom_filter);

/**
 * @brief Adds a key in the bloom filter
 * @return true on success false on failure
 */
bool pbf_bloom_add(struct pbf_desc *bloom_filter, char *key, int32_t size);

/**
 * @brief Checks if key is present
 * @param bloom_filter the descriptor of the bloom filter
 * @param key pointer to the key
 * @param size key size
 */
bool pbf_check(struct pbf_desc *bloom_filter, char *key, int32_t size);

/**
 * @brief Reads the contents of a bloom filter from a file and creates its
 * in-memory representation.
 * @param db_desc the descriptor of the database that this bloom filter belongs
 * to
 * @param level_id the id of the level thats this bloom filter belongs to
 * @param tree_id the id of the tree within the level that this bloom_filter
 * belongs to
 * @param bloom_file_hash the hash of the file where the bloom filter is stored
 * on disk
 * @return the descriptor of the in-memory representation of the bloom filter.
 */
struct pbf_desc *pbf_recover_bloom_filter(db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id,
					  uint64_t bloom_file_hash);

/**
 * @brief return the bloom file hash associated with this bloom filter
 * @param bloom_filter descriptor of the bloom filter
 * @return the hash of the file that contains the bloom filter state
 */
uint64_t pbf_get_bf_file_hash(struct pbf_desc *bloom_filter);
#endif
