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
#include "../btree/btree_node.h"
#include "../btree/conf.h"
#include "../btree/kv_pairs.h"
#include "min_max_heap.h"
#include "parallax/structures.h"
#include "stack.h"
#include <stdbool.h>
#include <stdint.h>

#define FULL_SCANNER 1
#define END_OF_DATABASE 2
#define COMPACTION_BUFFER_SCANNER 3
#define LEVEL_SCANNER 4

typedef enum SEEK_SCANNER_MODE { GREATER = 5, GREATER_OR_EQUAL = 6, FETCH_FIRST } SEEK_SCANNER_MODE;

typedef enum SCANNER_TYPE { FORWARD_SCANNER = 1 } SCANNER_TYPE;

struct level_scanner {
	struct kv_splice_base splice;
	db_handle *db;
	stackT stack;
	struct node_header *root;
	int32_t type;
	uint8_t level_id;
	uint8_t valid : 1;
	uint8_t dirty : 1;
};

typedef struct scannerHandle {
	struct level_scanner LEVEL_SCANNERS[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct sh_heap heap;
	db_handle *db;
	void *keyValue;
	int32_t type; /*to be removed also*/
	int32_t kv_level_id;
	uint8_t kv_cat;
	SCANNER_TYPE type_of_scanner;
} scannerHandle;

int32_t level_scanner_seek(struct level_scanner *level_sc, struct key_splice *start_key_splice, SEEK_SCANNER_MODE mode);
int32_t level_scanner_get_next(struct level_scanner *sc);
void init_dirty_scanner(scannerHandle *sc, db_handle *handle, void *start_key, char seek_flag);
void close_scanner(scannerHandle *scanner);

void seek_to_last(scannerHandle *sc, db_handle *handle);

/** Positions the cursor to the next KV pair.
 * @param scanner pointer the
 * scanner object @return true if the advancement of the cursos is sucessfull
 * false if we have reached the end of the database
*/
bool get_next(scannerHandle *scanner);

struct level_scanner *_init_compaction_buffer_scanner(db_handle *handle, int level_id, struct node_header *node,
						      void *start_key);

void close_compaction_buffer_scanner(struct level_scanner *level_sc);
void close_dirty_scanner(scannerHandle *sc);
#if MEASURE_SST_USED_SPACE
void perf_measure_leaf_capacity(db_handle *hd, int level_id);
#endif
#endif
