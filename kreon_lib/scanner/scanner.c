#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include "stack.h"
#include "../../build/external-deps/log/src/log.h"
#include "scanner.h"
#include "../btree/btree.h"
#include "../btree/conf.h"

extern unsigned long long scan_prefix_hit;
extern unsigned long long scan_prefix_miss;

extern int32_t index_order;
extern int32_t leaf_order;

int32_t _get_next_KV(level_scanner *sc);
int _init_level_scanner(level_scanner *level_sc, db_handle *handle, void *start_key, uint32_t level_id, char seek_mode);

/**
 * Spill buffer operation will use this scanner. Traversal begins from root_w
 * and
 * free all index nodes (leaves and index) during traversal.However, since we
 * have also
 * root_r we need to rescan root_r to free possible staff. Free operations will
 * be written in a matrix
 * which later is gonna be sorted to eliminate the duplicates and apply the free
 * operations (applying twice a 	* free operation for the same address
 * may
 * result in CORRUPTION :-S
 */
level_scanner *_init_spill_buffer_scanner(db_handle *handle, node_header *node, void *start_key)
{
	level_scanner *level_sc;
	level_sc = malloc(sizeof(level_scanner));
	stack_init(&level_sc->stack);
	level_sc->db = handle;
	level_sc->root = node;

	level_sc->type = SPILL_BUFFER_SCANNER;
	level_sc->keyValue = (void *)malloc(PREFIX_SIZE + sizeof(uint64_t)); /*typicall 20 bytes 8
                                                         prefix 
                                                         the address to the KV
                                                         log*/
	/*position scanner now to the appropriate row*/
	if (_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during spill operation, is that possible?");
		// will happen in close_spill_buffer_scanner stack_destroy(&(sc->stack));
		// free(sc);
		return NULL;
	}
	return level_sc;
}

void _close_spill_buffer_scanner(level_scanner *level_sc, node_header *root)
{
	free(level_sc->keyValue);
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}

scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *start_key, char seek_flag)
{
	heap_node nd;
	uint8_t level_id;
	uint8_t active_tree;
	int retval;

	if (sc == NULL) { // this is for mongodb
		sc = malloc(sizeof(scannerHandle));
		sc->malloced = 1;
		snapshot(handle->volume_desc);
	} else {
		sc->malloced = 0;
	}
	if (handle->db_desc->dirty)
		snapshot(handle->volume_desc);

	active_tree = handle->db_desc->levels[0].active_tree;
	sc->db = handle;
	initMinHeap(&sc->heap, active_tree);

	/*XXX TODO XXX*/
	// future call
	// register my epoch to prevent cleaner from recycling entries I might be
	// working on
	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		active_tree = handle->db_desc->levels[level_id].active_tree;
		if (handle->db_desc->levels[level_id].root_r[active_tree] != NULL) {
			retval = _init_level_scanner(&sc->LEVEL_SCANNERS[level_id], handle, start_key, level_id,
						     seek_flag);
			if (retval == 0) {
				sc->LEVEL_SCANNERS[level_id].valid = 1;
				nd.data = sc->LEVEL_SCANNERS[level_id].keyValue;
				nd.level_id = level_id;
				insertheap_node(&sc->heap, &nd);

			} else
				sc->LEVEL_SCANNERS[level_id].valid = 0;
		} else
			sc->LEVEL_SCANNERS[level_id].valid = 0;
	}

	sc->type = FULL_SCANNER;
	// fill sc->keyValue field
	if (getNext(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
		sc->keyValue = NULL;
	}
	return sc;
}

int _init_level_scanner(level_scanner *level_sc, db_handle *handle, void *start_key, uint32_t level_id, char seek_mode)
{
	uint8_t active_tree = handle->db_desc->levels[level_id].active_tree;

	level_sc->db = handle;
	level_sc->level_id = level_id;
	level_sc->root = handle->db_desc->levels[level_id].root_r[active_tree]; /*related to CPAAS-188*/
	stack_init(&level_sc->stack);
	/* position scanner now to the appropriate row */
	if (_seek_scanner(level_sc, start_key, seek_mode) == END_OF_DATABASE) {
		// printf("[%s:%s:%d] EMPTY DATABASE!\n",__FILE__,__func__,__LINE__);
		stack_destroy(&(level_sc->stack));
		return -1;
	}
	level_sc->type = LEVEL_SCANNER;
	return 0;
}

void closeScanner(scannerHandle *sc)
{
	int32_t i;

	for (i = 0; i < MAX_LEVELS; i++) {
		if (sc->LEVEL_SCANNERS[i].valid) {
			stack_destroy(&(sc->LEVEL_SCANNERS[i].stack));
		}
	}

	if (sc->malloced)
		free(sc);
}

/*XXX TODO XXX, please check if this is legal*/
int isValid(scannerHandle *sc)
{
	if (sc->keyValue != NULL)
		return 1;
	return 0;
}

int32_t getKeySize(scannerHandle *sc)
{
	return *(int32_t *)(sc->keyValue);
}

void *getKeyPtr(scannerHandle *sc)
{
	return (void *)((char *)(sc->keyValue) + sizeof(int32_t));
}

int32_t getValueSize(scannerHandle *sc)
{
	int32_t key_size = getKeySize(sc);
	int32_t *val_ptr = (int32_t *)((char *)(sc->keyValue) + sizeof(int32_t) + key_size);
	return *val_ptr;
}

void *getValuePtr(scannerHandle *sc)
{
	int32_t key_size = getKeySize(sc);
	char *val_ptr = (char *)(sc->keyValue) + sizeof(int32_t) + key_size;
	return val_ptr + sizeof(int32_t);
}

int32_t _seek_scanner(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	char key_buf_prefix[PREFIX_SIZE];
	stackElementT element;
	void *full_pivot_key;
	void *addr = NULL;
	char *index_key_prefix;
	index_node *inode;
	leaf_node *lnode;
	node_header *node;
	int64_t ret;
	int32_t start_idx = 0;
	int32_t end_idx = 0;
	int32_t middle;
	char level_key_format;

	/*drop all paths*/
	stack_reset(&(level_sc->stack));
	/*put guard*/
	element.guard = 1;
	element.leftmost = 0;
	element.rightmost = 0;
	element.idx = 0;
	element.node = NULL;
	stack_push(&(level_sc->stack), element);
	node = level_sc->root; // CPAAS-118 related

	if (node->type == leafRootNode && node->numberOfEntriesInNode == 0) {
		/*we seek in an empty tree*/
		return END_OF_DATABASE;
	}

	while (node->type != leafNode && node->type != leafRootNode) {
		inode = (index_node *)node;
		start_idx = 0;
		end_idx = inode->header.numberOfEntriesInNode - 1;
		middle = (start_idx + end_idx) / 2;

		while (1) {
			middle = (start_idx + end_idx) / 2;
			/*reconstruct full key*/
			addr = &(inode->p[middle].pivot);
			full_pivot_key = (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(full_pivot_key, start_key_buf, KV_FORMAT, KV_FORMAT);
			//log_info("pivot %s app %s ret %lld",full_pivot_key+4,start_key_buf+4,ret);

			if (ret == 0) {
				addr = &(inode->p[middle].right[0]);
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx) {
					addr = &(inode->p[middle].left[0]);
					middle--;
					break;
				}
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					addr = &(inode->p[middle].right[0]);
					//middle++;
					break;
				}
			}
		}

		assert(middle < (int64_t)node->numberOfEntriesInNode);
		element.node = node;
		element.guard = 0;
		if (middle <= 0) {
			element.leftmost = 1;
			element.rightmost = 0;
			element.idx = 0;
			node = (node_header *)(MAPPED + inode->p[0].left[0]);
		} else if (middle >= (int64_t)node->numberOfEntriesInNode - 1) {
			/*last path of node*/
			element.leftmost = 0;
			element.rightmost = 1;
			element.idx = middle;
			node = (node_header *)(MAPPED + inode->p[middle].right[0]);
		} else {
			element.leftmost = 0;
			element.rightmost = 0;
			element.idx = middle;
			node = (node_header *)(MAPPED + inode->p[middle].right[0]);
		}
		stack_push(&(level_sc->stack), element);
	}

	/*reached leaf node, setup prefixes*/
	if (start_key_buf == NULL)
		memset(key_buf_prefix, 0, PREFIX_SIZE * sizeof(char));
	else {
		memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(int32_t)), PREFIX_SIZE);
	}

	/*now perform binary search inside the leaf*/
	lnode = (leaf_node *)node;
	start_idx = 0;
	end_idx = lnode->header.numberOfEntriesInNode - 1;
	middle = 0;

	while (start_idx <= end_idx) {
		middle = (start_idx + end_idx) / 2;

		index_key_prefix = &lnode->prefix[middle][0];
		ret = prefix_compare(index_key_prefix, key_buf_prefix, PREFIX_SIZE);

		if (ret < 0) {
			start_idx = middle + 1;
			//if (start_idx > end_idx) {
			//	middle++;
			//	break;
			//}
		} else if (ret > 0) {
			end_idx = middle - 1;
			//if (start_idx > end_idx)
			//	break;
		} else {
			/*prefix is the same*/
			addr = (void *)(MAPPED + lnode->pointer[middle]);
			ret = _tucana_key_cmp(addr, start_key_buf, KV_FORMAT, KV_FORMAT);

			if (ret == 0) {
				break;
			} else if (ret < 0) {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					break;
				}
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					break;
			}
		}
	}

	/*further checks*/
	if (middle <= 0 && lnode->header.numberOfEntriesInNode > 1) {
		element.node = node;
		element.idx = 0;
		element.leftmost = 1;
		element.rightmost = 0;
		element.guard = 0;
		//log_debug("Leftmost boom");
		stack_push(&(level_sc->stack), element);
		middle = 0;
	} else if (middle >= (int64_t)lnode->header.numberOfEntriesInNode - 1) {
		//log_info("rightmost");
		middle = lnode->header.numberOfEntriesInNode - 1;
		element.node = node;
		element.idx = 0;
		element.leftmost = 0;
		element.rightmost = 1;
		element.guard = 0;
		stack_push(&(level_sc->stack), element);
		middle = lnode->header.numberOfEntriesInNode - 1;
	} else {
		//log_info("middle is %d", middle);
		element.node = node;
		element.idx = middle;
		element.leftmost = 0;
		element.rightmost = 0;
		element.guard = 0;
		stack_push(&(level_sc->stack), element);
	}

	if (level_sc->type == SPILL_BUFFER_SCANNER) {
		level_key_format = KV_PREFIX;
		// log_info("stack_top %llu node %llu leaf_order %llu and
		// sizeof(node_header) %d", (LLU)addr, (LLU)node,
		//	 leaf_order, sizeof(node_header));
		/*we assume that sc->keyValue has size of PREFIX_SIZE + sizeof(uint64_t)*/
		/*prefix first*/
		memcpy(level_sc->keyValue, &lnode->prefix[middle][0], PREFIX_SIZE);
		/*pointer second*/
		*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE) = MAPPED + lnode->pointer[middle];
		// log_info("key is %s\n", (MAPPED + *(uint64_t *)addr) + sizeof(int32_t));
	} else { /*normal scanner*/
		level_key_format = KV_FORMAT;
		level_sc->keyValue = (void *)MAPPED + lnode->pointer[middle];
		//log_info("full key is %s", level_sc->keyValue + 4);
	}

	if (start_key_buf != NULL) {
		if (mode == GREATER) {
			while (_tucana_key_cmp(level_sc->keyValue, start_key_buf, level_key_format, KV_FORMAT) <= 0) {
				if (_get_next_KV(level_sc) == END_OF_DATABASE)
					return END_OF_DATABASE;
			}
		} else if (mode == GREATER_OR_EQUAL) {
			//log_info("key is %s", level_sc->keyValue + 4);
			while (_tucana_key_cmp(level_sc->keyValue, start_key_buf, level_key_format, KV_FORMAT) < 0) {
				if (_get_next_KV(level_sc) == END_OF_DATABASE)
					return END_OF_DATABASE;
			}
		}
	}
#ifdef DEBUG_SCAN
	if (start_key_buf != NULL)
		log_info("start_key_buf = %s sc->keyValue = %s\n", start_key_buf + 4, level_sc->keyValue);
	else
		log_info("start_key_buf NULL sc->keyValue = %s\n", level_sc->keyValue);
#endif
	return SUCCESS;
}

int32_t getNext(scannerHandle *sc)
{
	uint8_t stat;
	heap_node nd;
	heap_node next_nd;

	while (1) {
		stat = getMinAndRemove(&sc->heap, &nd);
		if (stat != EMPTY_MIN_HEAP) {
			sc->keyValue = nd.data;
			// refill
			if (_get_next_KV(&sc->LEVEL_SCANNERS[nd.level_id]) != END_OF_DATABASE) {
				// printf("[%s:%s:%d] refilling from level_id
				// %d\n",__FILE__,__func__,__LINE__, nd.level_id);
				next_nd.level_id = nd.level_id;
				next_nd.data = sc->LEVEL_SCANNERS[nd.level_id].keyValue;
				insertheap_node(&sc->heap, &next_nd);
			}
			if (nd.duplicate == 1) {
				assert(0);
				// printf("[%s:%s:%d] ommiting duplicate
				// %s\n",__FILE__,__func__,__LINE__, (char *)nd.data+4);
				continue;
			}
			return KREON_OK;
		} else
			return END_OF_DATABASE;
	}
}

/**
 * 05/01/2015 11:01 : Returns a serialized buffer in the following form:
 * Key_len|key|value_length|value
 * update: 25/10/2016 14:21: for tucana_2 related scans buffer returned will
 * in the following form:
 * prefix(8 bytes)|hash(4 bytes)|address_to_data(8 bytes)
 * update: 09/03/2017 14:15: for SPILL_BUFFER_SCANNER only we ll return codes
 * when a leaf search is exhausted
 **/
int32_t _get_next_KV(level_scanner *sc)
{
	stackElementT stack_top;
	node_header *node;
	index_node *inode;
	leaf_node *lnode;
	uint32_t idx;
	uint32_t up = 1;

	stack_top = stack_pop(&(sc->stack)); /*get the element*/
	if (stack_top.guard) {
		sc->keyValue = NULL;
		return END_OF_DATABASE;
	}
	if (stack_top.node->type != leafNode && stack_top.node->type != leafRootNode) {
		log_fatal("Corrupted scanner stack, top element should be a leaf node");
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	node = stack_top.node;
	while (1) {
		if (up) {
			/*check if we can advance in the current node*/
			if (stack_top.rightmost) {
				stack_top = stack_pop(&(sc->stack));
				if (!stack_top.guard) {
					//log_debug("rightmost in stack throw and continue type %s",
					//	  node_type(stack_top.node->type));
					continue;
				} else {
					return END_OF_DATABASE;
				}
			} else if (stack_top.leftmost) {
				//log_debug("leftmost? %s", node_type(stack_top.node->type));
				stack_top.leftmost = 0;

				if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
					//log_info("got a leftmost leaf advance");
					idx = 1;
					stack_top.idx = 1;
					node = stack_top.node;
					stack_push(&sc->stack, stack_top);
					break;
				} else if (stack_top.node->type == internalNode || stack_top.node->type == rootNode) {
					//log_debug("Calculate and push type %s", node_type(stack_top.node->type));
					/*special case applies only for the root*/
					if (stack_top.node->numberOfEntriesInNode == 1)
						stack_top.rightmost = 1;
					stack_top.idx = 0;
					stack_push(&sc->stack, stack_top);
					inode = (index_node *)stack_top.node;
					node = (node_header *)(MAPPED + inode->p[0].right[0]);
					assert(node->type == rootNode || node->type == leafRootNode ||
					       node->type == internalNode || node->type == leafNode);
					//stack_top.node = node;
					//log_debug("Calculate and push type %s", node_type(stack_top.node->type));
					//stack_push(&sc->stack, stack_top);
					up = 0;
					continue;
				} else {
					log_fatal("Corrupted node");
					assert(0);
				}
			} else {
				//log_debug("Advancing, %s idx = %d entries %d", node_type(stack_top.node->type),
				//	  stack_top.idx, stack_top.node->numberOfEntriesInNode);
				++stack_top.idx;
				if (stack_top.idx >= stack_top.node->numberOfEntriesInNode - 1)
					stack_top.rightmost = 1;
			}
			stack_push(&sc->stack, stack_top);

			if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
				idx = stack_top.idx;
				node = stack_top.node;
				break;
			} else if (stack_top.node->type == internalNode || stack_top.node->type == rootNode) {
				inode = (index_node *)stack_top.node;
				node = (node_header *)(MAPPED + (uint64_t)inode->p[stack_top.idx].right[0]);
				up = 0;
				assert(node->type == rootNode || node->type == leafRootNode ||
				       node->type == internalNode || node->type == leafNode);
				continue;
			} else {
				log_fatal("Corrupted node");
				assert(0);
				exit(EXIT_FAILURE);
			}
		} else {
			/*push yourself, update node and continue*/

			stack_top.node = node;
			//log_debug("Saved type %s", node_type(stack_top.node->type));
			stack_top.idx = 0;
			stack_top.leftmost = 1;
			stack_top.rightmost = 0;
			stack_top.guard = 0;
			stack_push(&sc->stack, stack_top);
			if (node->type == leafNode || node->type == leafRootNode) {
				//log_info("consumed first entry of leaf");
				idx = 0;
				break;
			} else if (node->type == internalNode || node->type == rootNode) {
				inode = (index_node *)node;
				node = (node_header *)(MAPPED + (uint64_t)inode->p[0].left[0]);
			} else {
				log_fatal("Reached corrupted node");
				assert(0);
			}
		}
	}
	lnode = (leaf_node *)node;
	//log_warn("Key %lu:%s idx is %d", *(uint32_t *)(MAPPED + (uint64_t)lnode->pointer[idx]),
	//MAPPED + lnode->pointer[idx] + 4, idx);
	/*fill buffer and return*/
	if (sc->type == SPILL_BUFFER_SCANNER) {
		/*prefix first*/
		memcpy(sc->keyValue, &lnode->prefix[idx][0], PREFIX_SIZE);
		/*pointer second*/
		*(uint64_t *)(sc->keyValue + PREFIX_SIZE) = MAPPED + lnode->pointer[idx];
	} else {
		/*normal scanner*/
		sc->keyValue = (void *)MAPPED + lnode->pointer[idx];
		//log_info("consuming idx %d key %s num entries %lu",idx,sc->keyValue+4,lnode->header.numberOfEntriesInNode);
	}
	// else if (sc->type != CLOSE_SPILL_BUFFER_SCANNER) /*Do nothing for
	// close_buffer_Scanner*/
	//	sc->keyValue = (void *)MAPPED + *(uint64_t *)stack_top;
	return SUCCESS;
}

uint32_t multiget_calc_kv_size(db_handle *handle, void *start_key, void *stop_key, uint32_t number_of_keys,
			       long extension)
{
	// FIXME Instead of closing the scanner handle rewind it to start_key and
	// reuse it for the call to multi_get
	scannerHandle sc;
	uint32_t i;
	char seek_mode = (extension) ? extension : GREATER_OR_EQUAL;
	uint32_t transfer_size = 0;
	// FIXME
	/*snapshot(handle->volume_desc);*/
	initScanner(&sc, handle, start_key, seek_mode);
	if (sc.keyValue == NULL) {
		closeScanner(&sc);
		return END_OF_DATABASE;
	}

	for (i = 0; i < number_of_keys; i++) {
		transfer_size = sizeof(uint32_t) + *(uint32_t *)sc.keyValue;
		transfer_size += sizeof(uint32_t) + *(uint32_t *)((char *)sc.keyValue + transfer_size);
		if (getNext(&sc) == END_OF_DATABASE) {
			break;
		}
	}
	closeScanner(&sc);
	return transfer_size;
}

uint32_t multi_get(db_handle *handle, void *start_key, void *end_key, void *buffer, uint32_t buffer_length,
		   uint32_t number_of_keys, long extension)
{
	scannerHandle sc;
	uint32_t i;
	uint32_t buffer_position = sizeof(uint32_t);
	uint32_t keys_retrieved = 0;
	int rc = KREON_OK;
	char seek_mode = (extension) ? extension : GREATER_OR_EQUAL;
	// FIXME
	/*snapshot(handle->volume_desc);*/
	initScanner(&sc, handle, start_key, seek_mode);
	if (sc.keyValue == NULL) {
		closeScanner(&sc);
		return END_OF_DATABASE;
	}

	for (i = 0; i < number_of_keys; i++) {
		uint32_t transfer_size = sizeof(uint32_t) + *(uint32_t *)sc.keyValue;
		transfer_size += sizeof(uint32_t) + *(uint32_t *)((char *)sc.keyValue + transfer_size);
		if (buffer_position + transfer_size <= buffer_length) {
			memcpy((char *)buffer + buffer_position, sc.keyValue, transfer_size);
			buffer_position += transfer_size;
			++keys_retrieved;
		} else {
			rc = KREON_BUFFER_OVERFLOW;
			break;
		}
		if (getNext(&sc) == END_OF_DATABASE) {
			rc = END_OF_DATABASE;
			break;
		}
	}
	closeScanner(&sc);
	*(uint32_t *)buffer = keys_retrieved;
	return rc;
}
