#pragma once
#include "stack.h"
#include "min_max_heap.h"
#include "../allocator/allocator.h"
#include "../btree/btree.h"
#define FULL_SCANNER 1

#define SPILL_BUFFER_SCANNER 3
#define CLOSE_SPILL_BUFFER_SCANNER 4
#define LEVEL_SCANNER 5

#define END_OF_DATABASE 2
#define KREON_BUFFER_OVERFLOW 0x0F

typedef enum SEEK_SCANNER_MODE { GREATER = 5, GREATER_OR_EQUAL = 6, FETCH_FIRST } SEEK_SCANNER_MODE;

typedef struct level_scanner {
	struct bt_leaf_entry kv_entry;
	db_handle *db;
	stackT stack;
	node_header *root; /*root of the tree when the cursor was initialized/reset, related to CPAAS-188*/
	void *keyValue;
	int kv_format;
	uint32_t level_id;
	int32_t type;
	uint8_t valid : 1;
	uint8_t dirty : 1;
} level_scanner;

typedef struct scannerHandle {
	level_scanner LEVEL_SCANNERS[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct sh_min_heap heap;
	db_handle *db;
	void *keyValue;
	int32_t type; /*to be removed also*/
	int32_t malloced;
} scannerHandle;

/*
 * Standalone version
 *
 * Example use to print all the database in sorted order:
 *
 * scannerHandle *scanner = initScanner(db, NULL);
 * while(isValid(scanner)){
 * 		std::cout << "[" << entries
 *							<< "][" << getKeySize(scanner)
 *							<< "][" << (char *)getKeyPtr(scanner)
 *							<< "][" << getValueSize(scanner)
 *							<< "][" << (char *)getValuePtr(scanner)
 *							<< "]"
 *							<< std::endl;
 *		getNextKV(scanner);
 * }
 * closeScanner(scanner);
 */
scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *key, char seek_mode);
void closeScanner(scannerHandle *sc);

void init_dirty_scanner(scannerHandle *sc, db_handle *handle, void *start_key, char seek_flag);

int32_t getNext(scannerHandle *sc);
int isValid(scannerHandle *sc);
int32_t getKeySize(scannerHandle *sc);
void *getKeyPtr(scannerHandle *sc);
int32_t getValueSize(scannerHandle *sc);
void *getValuePtr(scannerHandle *sc);

/**
 * __seek_scanner: positions the cursor to the appropriate position
 * returns:
 *        SUCCESS: Cursor positioned
 *        END_OF_DATABASE: End of database reached
 *
 **/

level_scanner *_init_spill_buffer_scanner(db_handle *handle, int level_id, node_header *node, void *start_key);
int32_t _seek_scanner(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode);

/**
 * __get_next_KV: brings the next kv pair
 * returns:
 *        SUCCESS, sc->keyValue field contains the address where the
 *        END_OF_DATABASE, end of database reached
 **/
int32_t _get_next_KV(level_scanner *sc);
void _close_spill_buffer_scanner(level_scanner *sc, node_header *root);
#if MEASURE_SST_USED_SPACE
void perf_measure_leaf_capacity(db_handle *hd, int level_id);
#endif
