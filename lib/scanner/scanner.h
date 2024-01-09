// Copyright [2021] [FORTH-ICS]
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
#ifndef SCANNER_H
#define SCANNER_H
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/kv_pairs.h"
#include "min_max_heap.h"
#include "stack.h"
#include <stdbool.h>
#include <stdint.h>
struct key_splice;
enum seek_scanner_mode { GREATER = 5, GREATER_OR_EQUAL = 6, FETCH_FIRST };

struct level_scanner {
	struct kv_splice_base splice;
	db_handle *db;
	stackT stack;
	struct node_header *root;
	// struct level_leaf_api *leaf_api;
	// struct level_index_api *index_api;
	// struct leaf_iterator *leaf_iter;
	uint8_t level_id;
	bool is_compaction_scanner;
	uint8_t valid;
};

/**
 * @brief Initializes a level_scanner object
 * @param level_scanner pointer to the memory location of the scanner object.
 * @param db_handle pointer to the db object this scanner is used for
 * @param level_id the level of the LSM-tree.
 * @returns true on success false on failure
 */
bool level_scanner_init(struct level_scanner *level_scanner, db_handle *database, uint8_t level_id, uint8_t tree_id);

/**
 * @brief Posistions a previously initialized level scanner to the corresponding key value pair.
 * @param level_scanner pointer to the level_scanner object
 * @param start_key_splice the key splice where we want to position the
 * scanner. Key splice may not be an actual kv pair stored in the database.
 * @param seek_mode GREATER positions the scanner in a kv pair greater than key
 * splice, GREATER_OR_EQUAL positions the scanner to a kv pair greater or equal
 * to the key splice, and FETCH_FIRST positions the scanner to the first kv
 * pair of the database.
 * @returns true on SUCCESS or false on failure in after seek end of database
 * has been reached.
 */
bool level_scanner_seek(struct level_scanner *level_scanner, struct key_splice *start_key_splice,
			enum seek_scanner_mode seek_mode);

/**
 * @brief Retrieves the next kv pair.
 * @param level_scanner pointer to the level_scanner object
 * @returns true on success or false if end of database has been reached
 */
bool level_scanner_get_next(struct level_scanner *level_scanner);

/**
 * @brief Allocates and initializes a compaction scanner. The main difference
 * is that it returns either kv pairs or kv separated kv pairs.
 */
struct level_scanner *level_scanner_init_compaction_scanner(db_handle *database, uint8_t level_id, uint8_t tree_id);
void level_scanner_close(struct level_scanner *level_scanner);

struct scanner {
	// struct level_scanner level_scanner[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct level_scanner L0_scanner[NUM_TREES_PER_LEVEL];
	struct level_scanner_dev *dev_scanner[MAX_LEVELS];
	struct sh_heap heap;
	db_handle *db;
	void *keyValue;
	int32_t type; /*to be removed also*/
	int32_t kv_level_id;
	uint8_t tickets[LEVEL_ENTRY_POINTS];
	uint8_t kv_cat;
};

void scanner_init(struct scanner *scanner, struct db_handle *database, void *start_key,
		  enum seek_scanner_mode seek_flag);
/**
 * @brief Positions the cursor to the next KV pair.
 * @param scanner pointer the
 * scanner object @return true if the advancement of the cursos is sucessfull
 * false if we have reached the end of the database
*/
bool scanner_get_next(struct scanner *scanner);

void scanner_close(struct scanner *scanner);
#if MEASURE_SST_USED_SPACE
void perf_measure_leaf_capacity(db_handle *hd, int level_id);
#endif
#endif
