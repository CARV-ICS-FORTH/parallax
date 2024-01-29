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
#include "L0_scanner.h"
#include "min_max_heap.h"
#include "scanner_mode.h"
#include <stdbool.h>
#include <stdint.h>

struct scanner {
	// struct level_scanner level_scanner[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct L0_scanner L0_scanner[NUM_TREES_PER_LEVEL];
	struct level_scanner_dev *dev_scanner[MAX_LEVELS];
	struct sh_heap heap;
	db_handle *db;
	void *keyValue;
	int32_t type; /*to be removed also*/
	int32_t kv_level_id;
	uint8_t kv_cat;
	uint64_t tickets[MAX_LEVELS];
};

void scanner_seek(struct scanner *scanner, struct db_handle *database, void *start_key,
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
