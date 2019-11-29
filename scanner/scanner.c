#include <assert.h>

#include "stack.h"
#include "scanner.h"
#include "../btree/btree.h"
#include "../btree/conf.h"

#define GREATER 5
#define GREATER_OR_EQUAL 6
extern unsigned long long scan_prefix_hit;
extern unsigned long long scan_prefix_miss;

extern int32_t index_order;
extern int32_t leaf_order;

int32_t _get_next_KV(level_scanner * sc);
int _init_level_scanner(level_scanner *level_sc, db_handle * handle, void * start_key, uint32_t level_id);


/**
 * Spill buffer operation will use this scanner. Traversal begins from root_w and
 * free all index nodes (leaves and index) during traversal.However, since we have also
 * root_r we need to rescan root_r to free possible staff. Free operations will be written in a matrix
 * which later is gonna be sorted to eliminate the duplicates and apply the free operations (applying twice a 	* free operation for the same address may result in CORRUPTION :-S
 */
level_scanner * _init_spill_buffer_scanner(db_handle *handle, node_header * node,void * start_key)
{
	level_scanner * level_sc;
	level_sc = malloc(sizeof(level_scanner));
	stack_init(&level_sc->stack);
	level_sc->db = handle;
	level_sc->root = node;

	level_sc->type = SPILL_BUFFER_SCANNER;
	level_sc->keyValue = (void *)malloc(PREFIX_SIZE+sizeof(uint64_t));/*typicall 20 bytes 8 prefix, 4 hash, and 8 the address to the KV log*/
	/*position scanner now to the appropriate row*/
	if(_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE){

		printf("[%s:%s:%d] empty internal buffer during spill operation, is that possible?\n",__FILE__,__func__,__LINE__);
		//will happen in close_spill_buffer_scanner stack_destroy(&(sc->stack));
		//free(sc);
		return NULL;
	}
	return level_sc;
}

void _close_spill_buffer_scanner(level_scanner * level_sc, node_header * root)
{
	free(level_sc->keyValue);
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}


scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *start_key)
{
	heap_node nd;
	int32_t i;
	int retval;

	if(sc == NULL){ // this is for mongodb
		sc = malloc(sizeof(scannerHandle));
		sc->malloced = 1;
		snapshot(handle->volume_desc);
	}else{
		sc->malloced = 0;
	}

	sc->db = handle;
	initMinHeap(&sc->heap, handle->db_desc->active_tree);

	/*XXX TODO XXX*/
	//future call
	//register my epoch to prevent cleaner from recycling entries I might be working on
	for(i=0;i<TOTAL_TREES;i++)
	{
		if(handle->db_desc->root_r[i] != NULL){

			retval = _init_level_scanner(&sc->LEVEL_SCANNERS[i], handle,start_key,i);
			if(retval == 0){
				sc->LEVEL_SCANNERS[i].valid = 1;
				nd.data = sc->LEVEL_SCANNERS[i].keyValue;
				nd.level_id = i;
				insertheap_node(&sc->heap, &nd);
#ifdef SCAN_REORGANIZATION
				uint8_t inc= 0;
				uint8_t counter = 0;
				if(i == NUM_OF_TREES_PER_LEVEL) {//keeps scan stats only for level 1
					//assert
					if( sc->LEVEL_SCANNERS[i].leaf->leaf_id/2 > (COUNTER_SIZE-1)) {
						printf("[%s:%s:%d] FATAL scan counter stats overflow, increase COUNTER_SIZE\n",__FILE__,__func__,__LINE__);
						exit(EXIT_FAILURE);
					}

					counter = handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2];
					if(sc->LEVEL_SCANNERS[i].leaf->leaf_id % 2 == 0){
						counter = (counter & 0x0F);
						if(counter < COUNTER_THREASHOLD) {
							inc = 1;
							//printf("[%s:%s:%d] counter is %d for leaf with id %llu\n",__FILE__,__func__,__LINE__,counter,(LLU)sc->LEVEL_SCANNERS[i].leaf->leaf_id);
							__sync_fetch_and_add(&handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2],inc);
							counter = handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2] & 0x0F;
						}
					} else {
						counter = counter >> 4;
						if(counter < COUNTER_THREASHOLD) {
							inc = 16;
							//printf("[%s:%s:%d] counter is %d for leaf with id %llu\n",__FILE__,__func__,__LINE__,counter,(LLU)sc->LEVEL_SCANNERS[i].leaf->leaf_id/2);
							__sync_fetch_and_add(&handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2],inc);
							counter = handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2] >> 4;
						}
					}
				}

				if(i == NUM_OF_TREES_PER_LEVEL &&
						counter == COUNTER_THREASHOLD) {
					//printf("[%s:%s:%d] reached threashold time to reorganize leaf with id %llu\n",__FILE__,__func__,__LINE__,(LLU)sc->LEVEL_SCANNERS[i].leaf->leaf_id);
					__sync_fetch_and_add(&(handle->db_desc->scan_access_counter[sc->LEVEL_SCANNERS[i].leaf->leaf_id/2]),inc);
					void * key_addresses[256];
					void * #define ata_addresses[256];
					void *addr = (void *)((uint64_t)sc->LEVEL_SCANNERS[i].leaf)+sizeof(node_header);
					for(j=0;j<sc->LEVEL_SCANNERS[i].leaf->num_entries;j++){
						key_addresses[j] = (void *) MAPPED + *(uint64_t *)addr;
						/*let the 4KB page fault happen without locking the db, for level-0*/
						data_addresses[j] =  key_addresses[j]+sizeof(uint32_t)+*(uint32_t *)key_addresses[j];
						addr += sizeof(uint64_t);
					}
					/*acquire db lock for the log*/
					//	pthread_mutex_lock(&sc->db->db_desc->write_lock);
					/*acquire spiller lock for LEVEL-1*/
					//pthread_mutex_lock(&sc->db->db_desc->spiller_lock);
					/*insert in the DB*/
					for(j=0;j<sc->LEVEL_SCANNERS[i].leaf->num_entries;j++){
						_insert_key_value(sc->db, key_addresses[j],data_addresses[j],SCAN_REORGANIZE);
					}
					//pthread_mutex_unlock(&sc->db->db_desc->write_lock);
					//pthread_mutex_unlock(&sc->db->db_desc->spiller_lock);
				}

#endif
			} else
				sc->LEVEL_SCANNERS[i].valid = 0;
		}
		else
			sc->LEVEL_SCANNERS[i].valid = 0;
	}

	sc->type = FULL_SCANNER;
	//fill sc->keyValue field
	if(getNext(sc) == END_OF_DATABASE){
		printf("[%s:%s:%d] reached end of database\n",__FILE__,__func__,__LINE__);
		sc->keyValue = NULL;
	}
	return sc;
}

int _init_level_scanner(level_scanner *level_sc, db_handle * handle, void * start_key, uint32_t level_id)
{
	level_sc->db = handle;
	level_sc->level_id = level_id;
	level_sc->root = handle->db_desc->root_r[level_id];/*related to CPAAS-188*/
	stack_init(&level_sc->stack);
	/* position scanner now to the appropriate row */
	if(_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE)
	{
		//printf("[%s:%s:%d] EMPTY DATABASE!\n",__FILE__,__func__,__LINE__);
		stack_destroy(&(level_sc->stack));
		return -1;
	}
	level_sc->type = LEVEL_SCANNER;
	return 0;
}



void closeScanner(scannerHandle *sc)
{
	int32_t i;

	for(i=0;i<TOTAL_TREES;i++){
		if(sc->LEVEL_SCANNERS[i].valid){
			stack_destroy(&(sc->LEVEL_SCANNERS[i].stack));
		}
	}

	if(sc->malloced)
		free(sc);
}

/*XXX TODO XXX, please check if this is legal*/
int isValid(scannerHandle *sc)
{
	if(sc->keyValue != NULL)
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


node_header * get_addr_of_leaf(db_handle * handle,void *key, int32_t tree_id)
{
	//printf("[%s:%s:%d] tree id is %d\n",__FILE__,__func__,__LINE__,tree_id);
	node_header * node;
	void * addr;
	char exit = 0x00;;

	//if(handle->db_desc->root_w[tree_id]!=NULL)
	//node = handle->db_desc->root_w[tree_id];
	if(handle->db_desc->root_r[tree_id] != NULL)
		node = handle->db_desc->root_r[tree_id];
	else
		return NULL;

	while(node->height > 0)
	{
		if(node->height == 1)
			exit = 0x01;
		addr = _index_node_binary_search((index_node *)node, key, KV_PREFIX);
		node = (node_header *)(MAPPED + *(uint64_t *)addr);
		if(exit == 0x01)
			break;
	}
	//printf("[%s:%s:%d] node addr %llu type %d\n\n",__FILE__,__func__,__LINE__,(LLU)node,node->type);
	return node;
}

int32_t _seek_scanner(level_scanner *level_sc, void * start_key_buf, char MODE){
	char key_buf_prefix[PREFIX_SIZE];
	void * addr = NULL;
	node_header * tempNode;
	void * index_key_buf;
	int64_t ret;
	int32_t start_idx = 0;
	int32_t end_idx = 0;
	int32_t middle;
	uint64_t *index_key_prefix;
	char level_key_format;

	stack_reset(&(level_sc->stack));/*drop all paths*/
	tempNode = level_sc->root;//CPAAS-118 related


	/*special case howevers it happens*/
	if(tempNode->type == leafRootNode)
		stack_push(&(level_sc->stack), 0x0000000000000000);/*guard the stack*/

	if(tempNode->num_entries == 0)
		return END_OF_DATABASE; /*happens only when we seek in an empty tree*/

	while(tempNode->type != leafNode && tempNode->type != leafRootNode){

		addr = _index_node_binary_search((index_node *)tempNode, start_key_buf, KV_FORMAT);
		/* check if we have followed the last path */
		if((uint64_t)addr == ((uint64_t)tempNode + (uint64_t)sizeof(node_header)+(uint64_t)((tempNode->num_entries)*16)))
		{
			if(tempNode->type == rootNode){
				stack_push(&(level_sc->stack), 0x0000000000000000);
			}
			tempNode = (node_header *)(MAPPED + *(uint64_t *)addr);
			continue;
		}
		stack_push(&(level_sc->stack), (stackElementT)addr);
		tempNode = (node_header *)(MAPPED + *(uint64_t *)addr);
	}

	if(start_key_buf == NULL)
		memset(key_buf_prefix, 0, PREFIX_SIZE * sizeof(char));
	else{
		memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(int32_t)), PREFIX_SIZE);
	}

	/*now perform binary search inside the leaf*/
	start_idx = 0;
	end_idx = tempNode->num_entries - 1;
	middle = 0;

	while(start_idx <= end_idx){

		middle = (start_idx + end_idx)/2;
		addr = (void *)((uint64_t)tempNode + (uint64_t)sizeof(node_header) + (uint64_t)(middle*sizeof(uint64_t)));
		index_key_prefix = (uint64_t *)( (uint64_t)tempNode + (uint64_t)sizeof(node_header) + (uint64_t)(leaf_order * sizeof(uint64_t)) + (middle * PREFIX_SIZE) );
		ret = prefix_compare((char *)index_key_prefix, key_buf_prefix, PREFIX_SIZE);
		if(ret < 0)
			start_idx = middle + 1;
		else if(ret > 0)
			end_idx = middle - 1;

		else{ //prefix is the same, unreachable segment for fixed size keys

			addr = (void *)((uint64_t)tempNode+(uint64_t)sizeof(node_header)+(uint64_t)(middle*sizeof(uint64_t)));
			index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(index_key_buf, start_key_buf, KV_FORMAT, KV_FORMAT);

			if(ret == 0){
				break;
			}else if(ret < 0){
				start_idx = middle+1;
				if(start_idx > end_idx){
					middle++;
					break;
				}
			}else if(ret > 0){
				end_idx = middle-1;
				if(start_idx > end_idx)
					break;
			}
		}
	}

	/*further checks*/
	if(middle < 0)
		middle = 0;
	else if (middle >= tempNode->num_entries)
		middle = tempNode->num_entries - 1;

	addr = (void *)((uint64_t)tempNode + (uint64_t)sizeof(node_header) + (uint64_t)(middle*sizeof(uint64_t)));
	if(middle < (tempNode->num_entries -1))
		stack_push(&(level_sc->stack), (stackElementT)addr+sizeof(uint64_t));
	else
		stack_push(&(level_sc->stack), (stackElementT)addr);

	if(level_sc->type == SPILL_BUFFER_SCANNER){
		level_key_format = KV_PREFIX;
		void * node = (void *)addr - ((uint64_t)addr%NODE_SIZE);
#ifdef DEBUG_TUCANA_2
		printf("[%s:%s:%d] stack_top %llu node %llu leaf_order %llu and sizeof(node_header) %d\n",__FILE__,__func__,__LINE__, (LLU)addr,     (LLU)node, leaf_order, sizeof(node_header));
#endif
		uint64_t position = ((uint64_t)addr-((uint64_t)node +sizeof(node_header)))/sizeof(uint64_t);

#ifdef DEBUG_TUCANA_2
		printf("[%s:%s:%d] position is %llu\n",__FILE__, __func__, __LINE__,(LLU)position);
#endif
		/*we assume that sc->keyValue has been allocated at tucana_2 init 20 bytes*/
		memcpy(level_sc->keyValue, (void *)(uint64_t)node+sizeof(node_header)+(leaf_order*sizeof(uint64_t))+(position*PREFIX_SIZE), PREFIX_SIZE);/*prefix*/
		*(uint64_t *)(level_sc->keyValue+PREFIX_SIZE) = MAPPED + *(uint64_t *)((uint64_t)node+sizeof(node_header)+(position*sizeof(uint64_t)));
#ifdef DEBUG_TUCANA_2
		printf("[%s:%s:%d] key is %s\n",__FILE__,__func__,__LINE__,(MAPPED + *(uint64_t *)addr)+sizeof(int32_t));
#endif

	} else {/*normal scanner*/
		level_key_format = KV_FORMAT;
		level_sc->keyValue = (void *)(MAPPED + *(uint64_t *)addr);
#ifdef SCAN_REORGANIZATION
		if(level_sc->level_id == NUM_OF_TREES_PER_LEVEL){/*level-1 scanner*/
			level_sc->leaf = tempNode;
		}
#endif
	}

	//Added new cmp function, please check again
	if(MODE == GREATER){
		while(_tucana_key_cmp(level_sc->keyValue,start_key_buf, level_key_format, KV_FORMAT)<= 0){
			if(_get_next_KV(level_sc) == END_OF_DATABASE)
				return END_OF_DATABASE;
		}
	}
	else if(MODE == GREATER_OR_EQUAL){
		while( _tucana_key_cmp(level_sc->keyValue,start_key_buf, level_key_format, KV_FORMAT)< 0){
			if(_get_next_KV(level_sc) == END_OF_DATABASE)
				return END_OF_DATABASE;
		}
	}
#ifdef DEBUG_SCAN
	if(start_key_buf != NULL)
		printf("[%s:%s:%d] start_key_buf = %s sc->keyValue = %s\n",__FILE__,__func__,__LINE__,start_key_buf+4, level_sc->keyValue);
	else
		printf("[%s:%s:%d] start_key_buf NULL sc->keyValue = %s\n",__FILE__,__func__,__LINE__, level_sc->keyValue);
#endif
	return SUCCESS;
}


int32_t getNext(scannerHandle * sc)
{
	uint8_t stat;
	heap_node nd;
	heap_node next_nd;

	while(1)
	{
		stat = getMinAndRemove(&sc->heap, &nd);
		if(stat != EMPTY_MIN_HEAP)
		{
			sc->keyValue = nd.data;
			//refill
			if(_get_next_KV(&sc->LEVEL_SCANNERS[nd.level_id]) != END_OF_DATABASE){
				//printf("[%s:%s:%d] refilling from level_id %d\n",__FILE__,__func__,__LINE__, nd.level_id);
				next_nd.level_id = nd.level_id;
				next_nd.data = sc->LEVEL_SCANNERS[nd.level_id].keyValue;
				insertheap_node(&sc->heap, &next_nd);
			}
			if(nd.duplicate == 1)
			{
				//printf("[%s:%s:%d] ommiting duplicate %s\n",__FILE__,__func__,__LINE__, (char *)nd.data+4);
				continue;
			}
			return KREON_OK;
		}
		else
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
int32_t _get_next_KV(level_scanner * sc)
{
	uint64_t stack_top;
	node_header * curr_node;
	node_header * child_node;
	uint64_t position;
	int16_t direction = 0;/*direction upwards the tree, 1 going downwards the tree*/

	while(1)
	{
		stack_top = stack_pop(&(sc->stack));/*get the element*/
		if(stack_top == 0x0000000000000000)
		{
			sc->keyValue = NULL;
			return END_OF_DATABASE;
		}
		curr_node = (node_header *)(stack_top - (stack_top%DEVICE_BLOCK_SIZE));
		position  = stack_top - ((uint64_t)curr_node+(uint64_t)sizeof(node_header));
		/* TODO: Log Direct Write */
		if(curr_node->type == leafNode || curr_node->type == leafRootNode)
		{
#ifdef DEBUG_SCAN
			if(position%8 != 0){
				printf("%s: FATAL misaligned addr 8 %llu\n", __func__,(LLU)position%8);
				exit(-1);
			}
#endif
			/*Finds the position of the node inside the log*/
			if((position/8) < curr_node->num_entries-1)
			{
#ifdef DEBUG_SCAN
				printf("%s, advancing to next pointer in leaf position %llu entries %d\n",__func__,(LLU)position, curr_node->num_entries);
#endif
				stack_push(&sc->stack, (stack_top+sizeof(uint64_t)));
			}
			/*we have exceed leaf or leafRoot node children. Continue either to End or to proceed*/
			else if(sc->type == SPILL_BUFFER_SCANNER)
			{
				//printf("[%s:%s:%d] releasing dram frame of leaf\n",__FILE__,__func__,__LINE__);
				free_buffered(sc->db,curr_node,NODE_SIZE,-1);
			}
			break;
		}
		else/*index node*/
		{
			if(direction == 0){
				stack_top += (2*sizeof(uint64_t));
#ifdef DEBUG_SCAN
				if(position%16 != 0)
				{
					printf("%s: FATAL misaligned addr 16: %llu\n",__func__, (LLU)position%16);
					exit(-1);
				}
#endif
				if((position/16) < curr_node->num_entries-1)
					stack_push(&sc->stack, stack_top);
				else
				{
					if(curr_node->type == rootNode)
						stack_push(&sc->stack, 0x0000000000000000);/*mark End Of Database*/
					/*release dram frame for spills*/
					if(sc->type == SPILL_BUFFER_SCANNER)
					{
						block_header * curr = (block_header *) (MAPPED + (uint64_t)curr_node->first_key_block);
						block_header *last = (block_header *)(MAPPED + (uint64_t)curr_node->last_key_block);
						block_header * to_free;
						while((uint64_t)curr != (uint64_t)last)
						{
							to_free = curr;
							curr = (block_header *) ((uint64_t)MAPPED + (uint64_t)curr->next_block);
							free_buffered(sc->db,to_free,KEY_BLOCK_SIZE,-1);
						}
						free_buffered(sc->db,last,KEY_BLOCK_SIZE,-1);
						/*finally node_header*/
						free_buffered(sc->db,curr_node,NODE_SIZE,-1);
					}
				}
				child_node = (node_header *)(MAPPED + *(uint64_t *)stack_top + (uint64_t)sizeof(node_header));
				stack_push(&sc->stack, (stackElementT)child_node);
				direction = 1;/*going downwards now*/
				continue;
			}else{
				stack_push(&sc->stack, stack_top);
				child_node = (node_header *)(MAPPED + *(uint64_t *)stack_top + (uint64_t)sizeof(node_header));
				stack_push(&sc->stack, (stackElementT)child_node);
				continue;
			}
		}
	}
	/*<tucana_2>*/
	//Please check if position is correct
	if(sc->type == SPILL_BUFFER_SCANNER)
	{
		void * node = (void *)stack_top - (stack_top%NODE_SIZE);
		position = (stack_top - ((uint64_t)node  + sizeof(node_header)))/sizeof(uint64_t);

#ifdef DEBUG_TUCANA_2
		printf("[%s:%s:%d] stack_top %llu node %llu leaf_order %d and sizeof(node_header) %d\n",__FILE__,__func__,__LINE__, (LLU)stack_top, node, leaf_order, sizeof(node_header));
		printf("[%s:%s:%d] position is %llu\n",__FILE__, __func__, __LINE__,(LLU)position);
#endif
		/*we assume that sc->keyValue has been allocated at tucana_2 init 20 bytes*/
		memcpy(sc->keyValue, (void *) (uint64_t)node+sizeof(node_header)+(leaf_order*sizeof(uint64_t))+(position*PREFIX_SIZE), PREFIX_SIZE);/*prefix*/
		*(uint64_t *)(sc->keyValue+PREFIX_SIZE) = MAPPED + *(uint64_t *)((uint64_t)node+sizeof(node_header)+(position*sizeof(uint64_t)));

#ifdef DEBUG_TUCANA_2
		printf("[%s:%s:%d] key is %s\n",__FILE__,__func__,__LINE__,(MAPPED + *(uint64_t *)stack_top)+sizeof(int32_t));
#endif
	}

	else if(sc->type != CLOSE_SPILL_BUFFER_SCANNER)/*Do nothing for close_buffer_Scanner*/
		sc->keyValue = (void *) MAPPED + *(uint64_t *)stack_top;

	return SUCCESS;
}
