#ifndef L0_SCANNER_H
#define L0_SCANNER_H
#include "../btree/btree.h"
#include "../btree/kv_pairs.h"
#include "scanner_mode.h"
#include "stack.h"
#include <stdbool.h>
#include <stdint.h>
struct key_splice;
struct node_header;

struct L0_scanner {
	struct kv_splice_base splice;
	db_handle *db;
	stackT stack;
	struct node_header *root;
	uint8_t level_id;
	bool is_compaction_scanner;
	uint8_t valid;
};

/**
 * @brief Initializes a level_scanner object
 * @param L0_scanner pointer to the memory location of the scanner object.
 * @param database pointer to the db object this scanner is used for
 * @param level_id the level of the LSM-tree.
 * @param tree_id
 * @returns true on success false on failure
 */
bool L0_scanner_init(struct L0_scanner *L0_scanner, db_handle *database, uint8_t level_id, uint8_t tree_id);

/**
 * @brief Posistions a previously initialized level scanner to the corresponding key value pair.
 * @param L0_scanner pointer to the level_scanner object
 * @param start_key_splice the key splice where we want to position the
 * scanner. Key splice may not be an actual kv pair stored in the database.
 * @param seek_mode GREATER positions the scanner in a kv pair greater than key
 * splice, GREATER_OR_EQUAL positions the scanner to a kv pair greater or equal
 * to the key splice, and FETCH_FIRST positions the scanner to the first kv
 * pair of the database.
 * @returns true on SUCCESS or false on failure in after seek end of database
 * has been reached.
 */
bool L0_scanner_seek(struct L0_scanner *L0_scanner, struct key_splice *start_key_splice,
		     enum seek_scanner_mode seek_mode);

/**
 * @brief Retrieves the next kv pair.
 * @param L0_scanner pointer to the level_scanner object
 * @returns true on success or false if end of database has been reached
 */
bool L0_scanner_get_next(struct L0_scanner *L0_scanner);

/**
 * @brief Allocates and initializes a compaction scanner. The main difference
 * is that it returns either kv pairs or kv separated kv pairs.
 */
struct L0_scanner *L0_scanner_init_compaction_scanner(db_handle *database, uint8_t level_id, uint8_t tree_id);
void L0_scanner_close(struct L0_scanner *L0_scanner);

void L0_scanner_read_lock_node(struct L0_scanner *L0_scanner, struct node_header *node);

void L0_scanner_read_unlock_node(struct L0_scanner *L0_scanner, struct node_header *node);

#endif
