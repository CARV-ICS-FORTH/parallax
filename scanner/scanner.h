#include "stack.h"
#include "min_max_heap.h"
#include "../allocator/allocator.h"
#define FULL_SCANNER 1
#define QUALLIE_SCANNER 2

#define SPILL_BUFFER_SCANNER 3
#define CLOSE_SPILL_BUFFER_SCANNER 4
#define LEVEL_SCANNER 5
#define MAX_FREE_SPILL_BUFFER_SCANNER_SIZE 128
#define MAX_PREFETCH_SIZE 511

#define QUALIE_BUFFER_MAX_SIZE 256
#define STOP_ROW_REACHED  1
#define END_OF_DATABASE 2
#define ROW_CHANGED 3


#define OUT_OF_QUALIE_SPACE 123
#define QUALIE_ADDITION_SUCCESS 134
#define MAX_LONG 9223372036854775807L
#define PRODUCE_NEXT_QUALIE 102
#define PRODUCE_NEXT_ROW 45
#define DISCOVER_NEXT_QUALIE 103

#define SPILL_BUFFER_SCAN 130

#define SCAN_REORGANIZE 0xAF

typedef struct level_scanner
{
	db_handle *db;
#ifdef SCAN_REORGANIZATION
	node_header * leaf;
#endif
  stackT stack;
  node_header *root;/*root of the tree when the cursor was initialized/reset, related to CPAAS-188*/
	void *keyValue;
  uint32_t level_id;
	int32_t type;/* to be removed also */
	uint8_t valid;
} level_scanner;

typedef struct scannerHandle 
{
	level_scanner LEVEL_SCANNERS[TOTAL_TREES];
	db_handle *db;/*In which db this scanner belongs to*/
	minHeap heap;
	void *keyValue;
	int32_t type;/*to be removed also*/
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
scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *key);
void closeScanner(scannerHandle *sc);
int32_t getNext(scannerHandle * sc);

void getNextKV(scannerHandle *sc);
void getPrevKV(scannerHandle *sc);
void seekToFirst(scannerHandle *sc);
void seekToLast(scannerHandle *sc);

int isValid(scannerHandle *sc);
int32_t getKeySize(scannerHandle *sc);
void *getKeyPtr(scannerHandle *sc);

int32_t getValueSize(scannerHandle *sc);
void *getValuePtr(scannerHandle *sc);

/*Functions added at 30/05/2016 to support transactional qualie and full scans*/
scannerHandle * cursorInit();/*allocate only resources associated with the scanner*/
void cursorSeek(db_handle* handle, void *key, long tsMax, int32_t type);

/**
 * __seek_scanner: positions the cursor to the appropriate position
 * returns:
 *        SUCCESS: Cursor positioned
 *        END_OF_DATABASE: End of database reached
 *
 **/

level_scanner * _init_spill_buffer_scanner(db_handle *handle, node_header * node,void * start_key);

int32_t _seek_scanner(level_scanner *sc, void * start_key_buf, char MODE);

/**
 * __get_next_KV: brings the next kv pair
 * returns:
 *        SUCCESS, sc->keyValue field contains the address where the
 *        END_OF_DATABASE, end of database reached
 **/
int32_t _get_next_KV(level_scanner * sc);
void _close_spill_buffer_scanner(level_scanner * sc, node_header * root);
#if 0
int32_t prefetch_leaves(db_handle *handle, void * key, node_header ** prefetch_leaves_array, int prefetch_size, int tree_id);
#endif
node_header * get_addr_of_leaf(db_handle * handle,void *key, int32_t tree_id);

