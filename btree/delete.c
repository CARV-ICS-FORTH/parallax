#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "../scanner/scanner.h"
#include "stats.h"
#include "assertions.h"
#include "conf.h"
#include "delete.h"

extern int32_t index_order;
extern int32_t leaf_order;
extern uint64_t snapshot_v1,snapshot_v2;


void * _index_node_binary_search_and_fill_metadata(index_node *node, void *key_buf, char query_key_format,ancestors* prev)
{
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t num_entries = node->header.num_entries;
	int pos = prev->size - 1;
	int next = prev->size;
	while(num_entries > 0)
	{
		middle = (start_idx + end_idx) / 2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if(ret == 0){
			prev->node_has_key[pos] = 1;
                        prev->neighbors[next].left =(node_header *)(MAPPED + node->p[middle].left[0]);
                        prev->neighbors[next].pivot = (void*)node->p[middle].pivot;

			if((middle + 1) < (num_entries - 1))
				prev->neighbors[next].right = (node_header *)(MAPPED + node->p[middle + 1].right[0]);

                        addr = &(node->p[middle].right[0]);
			break;
		}
		else if(ret > 0){
			end_idx = middle - 1;
			if(start_idx > end_idx){
				addr = &(node->p[middle].left[0]);
				prev->neighbors[next].pivot = (void*)node->p[middle].pivot;
				middle--;
				if((middle) > 0)
					prev->neighbors[next].left = (node_header *)(MAPPED + node->p[middle].left[0]);

                                if((middle + 1) < num_entries)
					prev->neighbors[next].right = (node_header *)(MAPPED + node->p[middle+1].right[0]);

				break;
			}
		}
		else{ /* ret < 0 */
			start_idx = middle + 1;
			if(start_idx > end_idx){
				addr = &(node->p[middle].right[0]);
				prev->neighbors[next].pivot = (void*)node->p[middle].pivot;
				middle++;
				if((middle - 1) > 0)
					prev->neighbors[next].left = (node_header *)(MAPPED + node->p[middle-1].left[0]);

				if((middle) < num_entries)
					prev->neighbors[next].right = (node_header *)(MAPPED + node->p[middle].right[0]);

				break;
			}
		}
	}

	if(middle < 0){
		addr = &(node->p[0].left[0]);
		prev->neighbors[next].pivot = (void*)node->p[0].pivot;
		prev->neighbors[next].right = (node_header *)(MAPPED + node->p[0].right[0]);
	}else if(middle >= num_entries){
		addr = &(node->p[num_entries - 1].right[0]);
		prev->neighbors[next].pivot = (void*)node->p[num_entries - 1].pivot;
		prev->neighbors[next].left = (node_header *)(MAPPED + node->p[num_entries - 1].left[0]);
	}
	prev->parent[prev->size++] = (node_header *)node;

	return addr;
}


int8_t __delete_key(delete_request* req){

	ancestors               prev_nodes;
	lock_table *		upper_level_nodes[MAX_HEIGHT];	/*The array with the locks that belong to this thread from upper levels*/
	rotate_data		init	= {.left = NULL,.right = NULL,.pivot = NULL};
	volume_descriptor *	volume_desc;
	node_header* node_copy;
	superindex * soft_superindex;
	void *			next_addr;
	db_descriptor *		db_desc;
	node_header *		parent;
	node_header *		son;
	node_header *		temp;
	lock_table *		lock;
	lock_table **		level_lock_table;
	int64_t *		writers_counter;
	node_header *		flag	= NULL;
	volatile uint64_t	v1,v2;
	int			i;
	unsigned		size	= 0;	/*Size of upper_level_nodes*/
	unsigned		release	= 0;	/*Counter to know the position that releasing should begin */
	uint32_t		order;
	int8_t			ret;

	req->ancs = &prev_nodes;
	db_desc = req->handle->db_desc;
	volume_desc = req->handle->volume_desc;
	soft_superindex = req->handle->volume_desc->soft_superindex;

	if(req->level_id < NUM_OF_TREES_PER_LEVEL){
		writers_counter = &db_desc->count_writers_level_0;
		level_lock_table=db_desc->multiwrite_level_0;
	}else{
		writers_counter = &db_desc->count_writers_level_1;
		level_lock_table=db_desc->multiwrite_level_1;
	}

retry:
	MUTEX_LOCK(&req->handle->db_desc->rcu_root);
	__sync_fetch_and_add(&req->handle->db_desc->rcu_root_v1,1);
	/* _unlock_upper_levels(upper_level_nodes,size,release); */
	size	= 0;
	release	= 0;
	__sync_fetch_and_add(writers_counter,1);

	prev_nodes.size = 0;
	for(i=0;i<MAX_HEIGHT;++i){
		prev_nodes.neighbors[i] = init;
		prev_nodes.parent[i] = NULL;
		prev_nodes.node_has_key[i] = 0;
	}

	v2 = snapshot_v2;
	v1 = snapshot_v1;
	if(v1 != v2){
		__sync_fetch_and_sub(writers_counter,1);
		__sync_fetch_and_add(&req->handle->db_desc->rcu_root_v2,1);
		MUTEX_UNLOCK(&req->handle->db_desc->rcu_root);
		goto retry;
	}

	parent = flag = NULL;

	if(req->level_id < NUM_OF_TREES_PER_LEVEL){
		req->level_id = db_desc->active_tree;
		req->allocator_desc.level_id = db_desc->active_tree;
	}

	son = db_desc->root_w[req->level_id];

	if(son->height != 0){
		while(1){
			if(son->type == leafNode || son->type == leafRootNode)
				order = (leaf_order/2) + 1;
			else
				order = (index_order/2) + 1;

			if(son->num_entries < order && son->type != rootNode){
				son->v1++;
				rotate_data siblings ={.left = NULL,.right = NULL,.pivot = NULL,.pos_left = -1,.pos_right = -1};
				__find_position_in_index((index_node*)parent, (struct splice*)req->key_buf,&siblings);
				__find_left_and_right_siblings((index_node*)parent,req->key_buf,&siblings);
				ret = transfer_node_to_neighbor_index_node((index_node*)son,(index_node*)parent,&siblings,req);

				if(ret == 3){
					merge_with_index_neighbor((index_node*)son,(index_node*)parent,&siblings,req);
				}

				son->v2++;
				__sync_fetch_and_sub(writers_counter,1);
				__sync_fetch_and_add(&req->handle->db_desc->rcu_root_v2,1);
				MUTEX_UNLOCK(&req->handle->db_desc->rcu_root);
				goto retry;

			}else if(son->epoch <= volume_desc->dev_superindex->epoch){
				node_copy = (*req->allocator_desc.allocate_space)((void *)req->allocator_desc.handle, NODE_SIZE, req->allocator_desc.level_id, NEW_ROOT);
				memcpy(node_copy, son, NODE_SIZE);
				node_copy->epoch = soft_superindex->epoch;
				node_copy->v1=0;
				node_copy->v2=0;

				/*Update father's pointer*/
				if(parent!=NULL)
					parent->v1++;

				*(uint64_t *)next_addr = (uint64_t)node_copy-MAPPED;

				if(parent!=NULL)
					parent->v2++;

				/* Free the node */
				(*req->allocator_desc.free_space)((void *)req->allocator_desc.handle,son,NODE_SIZE,req->allocator_desc.level_id);
				__sync_fetch_and_sub(writers_counter,1);
				__sync_fetch_and_add(&req->handle->db_desc->rcu_root_v2,1);
				MUTEX_UNLOCK(&req->handle->db_desc->rcu_root);
				goto retry;
			}

			v2 = db_desc->rcu_root_v2;
			next_addr = _index_node_binary_search_and_fill_metadata((index_node *)son, req->key_buf, req->key_format,&prev_nodes);
			parent = son;
			temp = (node_header *) (MAPPED + *(uint64_t *)next_addr);
			/*Taking the lock of the next node before its traversal*/
			/* lock = _find_position(level_lock_table,temp,db_desc); */

			v1 = db_desc->rcu_root_v1;
			/* if((temp->type==rootNode || temp->type==leafRootNode) && v1!=v2){ */
			/* 	__sync_fetch_and_sub(writers_counter,1); */
			/* 	goto retry; */
			/* } */

			upper_level_nodes[size++]=lock;
			/* if(RWLOCK_WRLOCK(&lock->rx_lock)!=0){ */
			/* 	printf("[%s %s %d] ERROR locking\n",__func__,__FILE__,__LINE__); */
			/* 	raise(SIGINT); */
			/* 	exit(-1); */
			/* } */
			son = temp;

			if(son->height == 0)
				break;
		}
	}
	assert(!son->height);
	/* if(son->type == leafRootNode){ */
	/* 	log_error("Cannot handle leafRootNode yet!"); */
	/* 	exit(EXIT_FAILURE); */
        /* } */

	flag = NULL;
	son->v1++;/*lamport counter*/

	if (!flag){
		son->v1++;
		ret = __delete_from_leaf(req,(index_node *)parent,(leaf_node *)son,(struct splice *)req->key_buf);
		son->v2++;
	}else{
		ret = 5;
		//rcuUnlock(flag, db_desc, req->);
	}

        son->v2++;/*lamport counter*/

	/*Unlock remaining locks*/
	/* _unlock_upper_levels(upper_level_nodes,size,release); */
	__sync_fetch_and_sub(writers_counter,1);

	__sync_fetch_and_add(&req->handle->db_desc->rcu_root_v2,1);
	MUTEX_UNLOCK(&db_desc->rcu_root);
	return ret;
}


uint8_t __delete_from_leaf(delete_request* req,
			   index_node* parent,leaf_node* leaf,
			   struct splice* key){
	void * key_addr_in_leaf;
	/* We need these variables to find the neighboring nodes
	   in case we delete a kv pair from the first or the last node.  */
	rotate_data siblings = {.left = NULL, .right = NULL, .pivot = NULL};
	int pos;
	int8_t ret;

	if(parent)
		__find_left_and_right_siblings(parent,key,&siblings);

	if(siblings.left != NULL)
		assert(siblings.left->type == leafNode);

	if(siblings.right != NULL)
		assert(siblings.right->type == leafNode);


        key_addr_in_leaf = __find_key_addr_in_leaf(leaf, key);/* XXX TODO XXX __find_key_addr_in_leaf should return the position in the leaf node
								 to avoid duplication of code.*/
	pos = __find_position_in_leaf(leaf,key);
	if(key_addr_in_leaf){
		if(pos != -1){
			delete_key_value(req->handle->db_desc,leaf,pos);

			if(leaf->header.type == leafRootNode)
				return 0;

			ret = check_for_underflow_in_leaf(leaf,&siblings,req);

			if(ret == 3){
				/* We could not borrow anything from the left and right neighbors.
				   We will try to merge with one of them.
				   If we cannot merge that's a fatal error!
				*/
				merge_with_leaf_neighbor(leaf,&siblings,req);
			}

			return 0;
		}
	}

	return -1;
}

void delete_key_value(db_descriptor* db_desc, leaf_node* leaf, int pos)
{

	if(pos > 0 && pos < (leaf->header.num_entries - 1)){
		memmove(&leaf->pointer[pos], &leaf->pointer[pos+1], (leaf->header.num_entries - (pos + 1))*sizeof(uint64_t));
		memmove(&leaf->prefix[pos],&leaf->prefix[pos+1],PREFIX_SIZE*(leaf->header.num_entries - (pos + 1)));
	}else if(pos == (leaf->header.num_entries - 1)){/* Key is in the last position of the leaf */
	}else if (pos == 0){	/* Key in the first position of the leaf */
		memmove(&leaf->pointer[0],&leaf->pointer[1],(leaf->header.num_entries - 1)*sizeof(uint64_t));
		memmove(&leaf->prefix[0],&leaf->prefix[1],PREFIX_SIZE*(leaf->header.num_entries - 1));
	}else{
		log_debug("Error unknown case to delete a KV pair position = %d",pos);
		assert(0);
		exit(EXIT_FAILURE);
	}

	--leaf->header.num_entries;
}

void __update_index_pivot_in_place(allocator_descriptor* allocator_desc, db_handle *handle, node_header * node, void * node_index_addr, void * key_buf)
{
	void * key_addr;
	int32_t avail_space;
 	int32_t req_space;
	int32_t allocated_space;
	block_header * d_header = NULL;
	block_header * last_d_header = NULL;

	int key_len = *(uint32_t *)key_buf;
	if(node->type == leafNode || node->type == leafRootNode){
		log_fatal("We should not access leafNode as there are no pivots in leaves.");
		assert(0);
	}

	if(node->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - (node->key_log_size % (int32_t)KEY_BLOCK_SIZE);

	req_space = (key_len + sizeof(int32_t));
	if(avail_space < req_space){ /*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space+sizeof(node_header))/KEY_BLOCK_SIZE;

		if((req_space+sizeof(node_header))%KEY_BLOCK_SIZE != 0)
			allocated_space++;

		allocated_space *= KEY_BLOCK_SIZE;
		d_header = (*allocator_desc->allocate_space)(allocator_desc->handle, allocated_space, allocator_desc->level_id,KEY_LOG_SPLIT);
		d_header->next_block = NULL;
		last_d_header = (block_header *)(MAPPED + (uint64_t)node->last_key_block);
		last_d_header->next_block = (void *)((uint64_t)d_header - MAPPED);
		node->last_key_block = last_d_header->next_block;
		node->key_log_size += (avail_space +  sizeof(block_header));/* position the log to the newly added block */
	}

	/* put the KV now */
	key_addr = (void *)MAPPED +(uint64_t)node->last_key_block + (uint64_t)(node->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(int32_t) + key_len);/*key length */
	*(uint64_t *)node_index_addr = (uint64_t)key_addr - MAPPED;
	node->key_log_size += sizeof(int32_t) + key_len;
}

void * _index_node_binary_search_posret(index_node *node, void *key_buf, char query_key_format,rel_pos* neighbor)
{
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t num_entries = node->header.num_entries;

	while(num_entries > 0)
	{
		middle = (start_idx + end_idx) / 2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if(ret == 0){
			addr = &(node->p[middle].right[0]);
			neighbor->right_pos = neighbor->left_pos =  middle;
			neighbor->left_entry = &node->p[middle];
			if((middle + 1) < node->header.num_entries){
				neighbor->right_entry = &node->p[middle+1];
			}
			break;
		}
		else if(ret > 0){
			end_idx = middle - 1;
			if(start_idx > end_idx){
				addr = &(node->p[middle].left[0]);

				if((middle - 1) > 0){
					neighbor->left_entry = &node->p[middle-1];
					neighbor->left_pos = middle - 1;
				}
				neighbor->right_pos = middle;
				neighbor->right_entry = &node->p[middle];

				middle--;
				break;
			}
		}
		else{ /* ret < 0 */
			start_idx = middle + 1;
			if(start_idx > end_idx){
				neighbor->right_entry = NULL;
				neighbor->left_entry = &node->p[middle];
				neighbor->left_pos = neighbor->right_pos = middle;

				if((middle + 1) < node->header.num_entries){
					neighbor->right_entry = &node->p[middle+1];
					neighbor->right_pos = middle + 1;
				}
				addr = &(node->p[middle].right[0]);
				middle++;
				break;
			}
		}
	}

	if(middle < 0){
		addr = &(node->p[0].left[0]);
		neighbor->left_entry = NULL;
                neighbor->right_entry = &node->p[0];
		neighbor->right_pos = 0;
        }else if(middle >= node->header.num_entries){
		addr = &(node->p[node->header.num_entries - 1].right[0]);
		neighbor->left_entry = &node->p[node->header.num_entries - 1];
		neighbor->left_pos = node->header.num_entries - 1;
		neighbor->right_entry = NULL;
	}
	return addr;
}

void underflow_borrow_from_right_neighbor(leaf_node* curr,leaf_node* right,delete_request* req){
	rel_pos neighbor_metadata = {.left_entry = NULL,.right_entry = NULL};
	node_header * parent = req->ancs->parent[req->ancs->size-1];
	void* key_addr;
	/* raise(SIGINT); */

	/* First steal the kv pointer + prefix */
	curr->pointer[curr->header.num_entries] = right->pointer[0];
        memcpy(curr->prefix[curr->header.num_entries], right->prefix[0], PREFIX_SIZE);
	++curr->header.num_entries;

	/* Fix the pointers and prefixes of the right neighbor */
	memmove(&right->pointer[0],
		&right->pointer[1],
		(right->header.num_entries-1) * sizeof(uint64_t));

	memmove(right->prefix[0],
		right->prefix[1],
		PREFIX_SIZE*(right->header.num_entries-1));

	--right->header.num_entries;

	key_addr = (void *)(MAPPED + right->pointer[0]);
	assert(parent->type != leafNode);

	_index_node_binary_search_posret((index_node *)req->ancs->parent[req->ancs->size-1], req->key_buf, KV_FORMAT,&neighbor_metadata);

	if(neighbor_metadata.right_entry == NULL){
		log_fatal("We are the rightmost node so we cannot borrow from the right leaf");
		assert(0);
	}

	/* Fix the pivot in the parent node */
	__update_index_pivot_in_place(&req->allocator_desc, req->handle,parent, (&neighbor_metadata.right_entry->pivot), key_addr);

}


void underflow_borrow_from_left_neighbor(leaf_node* curr,leaf_node* left,delete_request* req){
	rel_pos neighbor_metadata = {.left_entry = NULL,.right_entry = NULL};
	void * key_addr;

	memmove(curr->prefix[1],
		curr->prefix[0],
		PREFIX_SIZE*curr->header.num_entries);

	memmove(&curr->pointer[1],
		&curr->pointer[0],
		sizeof(uint64_t)*curr->header.num_entries);

	/* Move the leftmost KV pair */

	curr->pointer[0] = left->pointer[left->header.num_entries - 1];
	memcpy(curr->prefix[0], left->prefix[left->header.num_entries - 1], PREFIX_SIZE);
	++curr->header.num_entries;
        --left->header.num_entries;
	/* NOTE in this case we don't have to move anything as it is the last KV pair. */
	key_addr = (void *)(MAPPED + curr->pointer[0]);
	_index_node_binary_search_posret((index_node *)req->ancs->parent[req->ancs->size-1], req->key_buf, KV_FORMAT,&neighbor_metadata);

	assert(neighbor_metadata.left_entry);

	/* A pivot change should happen in the parent index node */
	__update_index_pivot_in_place(&req->allocator_desc, req->handle,req->ancs->parent[req->ancs->size-1], &neighbor_metadata.left_entry->pivot, key_addr);
}

void merge_with_right_neighbor(leaf_node* curr, leaf_node* right,
			       delete_request* req){

	rel_pos parent_metadata = {.left_entry = NULL,.right_entry = NULL,
				   .left_pos = 0,.right_pos = 0};
	index_node* parent = (index_node*)req->ancs->parent[req->ancs->size-1];

	memcpy(&curr->pointer[curr->header.num_entries],
	       &right->pointer[0],
	       right->header.num_entries*sizeof(uint64_t));

	memcpy(curr->prefix[curr->header.num_entries],
	       right->prefix[0],
	       right->header.num_entries*PREFIX_SIZE);

	curr->header.num_entries += right->header.num_entries;

	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT,&parent_metadata);

	assert(right == ((leaf_node*)(MAPPED+parent->p[parent_metadata.right_pos+1].left[0])));

	if(parent->header.num_entries == 1){
		if(parent->header.type == rootNode){
			curr->header.type = leafRootNode;
			curr->header.height = 0;
			req->handle->db_desc->root_w[req->handle->db_desc->active_tree] = (node_header*)curr;
			return;
		}
		assert(0);
	}

	parent->p[parent_metadata.right_pos].pivot = parent->p[parent_metadata.right_pos+1].pivot;

	memmove(&parent->p[parent_metadata.right_pos+1],
		&parent->p[parent_metadata.right_pos+2],
		(sizeof(index_entry)*(parent->header.num_entries - (parent_metadata.right_pos+2)))+sizeof(uint64_t));

	--parent->header.num_entries;

	//In this case we do not have to change anything to the right neighbor
	//nor to change the pivots in our parent.Reclaim the node space here.

}


void merge_with_left_neighbor(leaf_node* curr, leaf_node* left,
			      delete_request* req){
	rel_pos parent_metadata = {.left_entry = NULL,.right_entry = NULL,
				   .left_pos = 0,.right_pos = 0};
	index_node* parent = (index_node*)req->ancs->parent[req->ancs->size-1];
	/* First move the kv pointers + prefixes to make space
	   for the kv pointers + prefixes of the left leaf */
	memmove(&curr->prefix[left->header.num_entries],
		&curr->prefix[0],
		PREFIX_SIZE*curr->header.num_entries);

	memmove(&curr->pointer[left->header.num_entries],
		&curr->pointer[0],
		sizeof(uint64_t)*curr->header.num_entries);

	/* copy the kv pointers + prefixes from the left leaf */

	memcpy(&curr->prefix[0],
	       &left->prefix[0],
	       PREFIX_SIZE*left->header.num_entries);

	memcpy(&curr->pointer[0],
	       &left->pointer[0],
	       sizeof(uint64_t)*left->header.num_entries);


	/* Shift every index entry of the parent to the left
	   to remove the left leaf node from the index*/
	curr->header.num_entries += left->header.num_entries;
	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT,&parent_metadata);

	if(parent->header.num_entries == 1){
		if(parent->header.type == rootNode){
			curr->header.type = leafRootNode;
			req->handle->db_desc->root_w[req->handle->db_desc->active_tree] = (node_header*)curr;
			return;
		}
		assert(0);
	}

	memmove(&parent->p[parent_metadata.left_pos],
		&parent->p[parent_metadata.left_pos+1],
		(sizeof(index_entry)*(parent->header.num_entries - (parent_metadata.left_pos + 1))) + sizeof(uint64_t));

	--parent->header.num_entries;
	/* Free the left leaf node */

}

int8_t merge_with_leaf_neighbor(leaf_node* leaf,rotate_data* siblings,
			    delete_request* req){

	leaf_node*	left		 = (leaf_node*) siblings->left;
	leaf_node*	right		 = (leaf_node*) siblings->right;
	int		merge_with_left	 = 0;
	int		merge_with_right = 0;
	int8_t		ret		 = 0;

	if(left)
		merge_with_left = leaf->header.num_entries + left->header.num_entries;

	if(right)
		merge_with_right = leaf->header.num_entries + right->header.num_entries;

	if(merge_with_left && merge_with_left < leaf_order){
		/* We can merge with the right neighbor */
		ret = 1;
		left->header.v1++;
		merge_with_left_neighbor(leaf,left,req);
		left->header.v2++;
	}else if (merge_with_right && merge_with_right < leaf_order){
		/* We can merge with the left neighbor */
		ret = 2;
		right->header.v1++;
		merge_with_right_neighbor(leaf,right,req);
		right->header.v2++;
	}else{
		log_fatal("If we reached this case then we cannot borrow a key");
		log_fatal("from the left or right neighbor nor we can merge with them");
		assert(0);
	}
        return ret;
}


int8_t check_for_underflow_in_leaf(leaf_node* leaf,rotate_data* siblings,delete_request* req){
	leaf_node*	left  = (leaf_node*) siblings->left;
	leaf_node*	right = (leaf_node*) siblings->right;
	int8_t		ret   = 0;

	/* If underflow is detected pivots have to change also. */

        if (leaf->header.num_entries < (leaf_order / 2)) {


		if (right &&(right->header.num_entries >= ((leaf_order/ 2) + 1))) {
			/* Steal the leftmost KV pair from the right sibling */
			ret = 1;
			right->header.v1++;
			underflow_borrow_from_right_neighbor(leaf, right, req);
			right->header.v2++;
		} else if (left && (left->header.num_entries >= ((leaf_order / 2) + 1))) {
			/* Steal the rightmost KV pair from the left sibling */
			ret = 2;
			left->header.v1++;
			underflow_borrow_from_left_neighbor(leaf, left, req);
			left->header.v2++;
		} else {
			/* We could not borrow a KV pair from the siblings
			   a merge should be triggered now. */
			ret = 3;
		}
        }
	return ret;
}

void __find_left_and_right_siblings(index_node* parent,void* key,rotate_data* siblings){
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = parent->header.num_entries - 1;
	int32_t num_entries = parent->header.num_entries;

	while(num_entries > 0){
		middle = (start_idx + end_idx) / 2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return;

		addr = &(parent->p[middle].pivot);
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key, KV_FORMAT, KV_FORMAT);
		if(ret == 0){
			siblings->pivot = index_key_buf;//Saving the pivot in case we need to replace it.
			addr = &(parent->p[middle].right[0]);
                        siblings->left = (node_header *)(MAPPED + parent->p[middle].left[0]);

                        if((middle + 1) < (parent->header.num_entries - 1))
				siblings->right = (node_header *)(MAPPED + parent->p[middle + 1].right[0]);
			break;
		}
		else if(ret > 0){
			end_idx = middle - 1;
			if(start_idx > end_idx){
				addr = &(parent->p[middle].left[0]);
				middle--;

				if((middle) > 0)
					siblings->left = (node_header *)(MAPPED + parent->p[middle].left[0]);

                                if((middle + 1) < num_entries)
					siblings->right = (node_header *)(MAPPED + parent->p[middle + 1].right[0]);
				break;
			}
		}
		else{ /* ret < 0 */
			start_idx = middle + 1;
			if(start_idx > end_idx){
				addr = &(parent->p[middle].right[0]);
				siblings->left = (node_header *)(MAPPED + parent->p[middle].left[0]);
				middle++;

                                if((middle) < num_entries)
					siblings->right =(node_header *)(MAPPED + parent->p[middle].right[0]);
				break;
			}
		}
	}

	if(middle < 0){
		addr = &(parent->p[0].left[0]);
                siblings->right = (node_header *)(MAPPED + parent->p[0].right[0]);
        }
	else if(middle >= parent->header.num_entries){
		addr = &(parent->p[parent->header.num_entries - 1].right[0]);
                siblings->left = (node_header *)(MAPPED + parent->p[parent->header.num_entries - 1].left[0]);
	}

}

//Retuns the position of the KV pair if it is present in the leaf node.
int __find_position_in_leaf(leaf_node *leaf, struct splice *key)
{
	int32_t start_idx = 0, end_idx = leaf->header.num_entries - 1;
	char key_buf_prefix[PREFIX_SIZE] = { '\0' };
	int32_t middle = 0;
	memcpy(key_buf_prefix, key->data, MIN(key->size, PREFIX_SIZE));

	while(start_idx <= end_idx){
		middle = (start_idx + end_idx) / 2;

		int32_t ret = prefix_compare(leaf->prefix[middle], key_buf_prefix, PREFIX_SIZE);

		if(ret < 0)
			start_idx = middle + 1;
		else if(ret > 0)
			end_idx = middle - 1;
		else{
			void *index_key = (void *)(MAPPED + leaf->pointer[middle]);
			ret = _tucana_key_cmp(index_key, key, KV_FORMAT, KV_FORMAT);
			if(ret == 0)
				return middle;
			else if(ret < 0)
				start_idx = middle + 1;
			else
				end_idx = middle - 1;
		}
	}
	return -1;
}

void __find_position_in_index(index_node *node,struct splice *key,
			      rotate_data* siblings)
{
	void * addr = NULL;
	void * index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t num_entries = node->header.num_entries;

	while(num_entries > 0){
		middle = (start_idx + end_idx) / 2;

		if(num_entries > index_order || middle < 0 || middle >= num_entries)
			return;

		addr = &(node->p[middle].pivot);
		index_key_buf =  (void *)(MAPPED + *(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key, KV_FORMAT, KV_FORMAT);
		if(ret == 0){
			addr = &(node->p[middle].right[0]);
			siblings->pos_left = middle;
			siblings->pos_right = middle+1;
			break;
		}
		else if(ret > 0){
			end_idx = middle - 1;
			if(start_idx > end_idx){
				addr = &(node->p[middle].left[0]);

				if((middle-1) > 0)
					siblings->pos_left = middle - 1;

				siblings->pos_right = middle;
				middle--;

        			break;
			}
		}
		else{ /* ret < 0 */
			start_idx = middle + 1;
			if(start_idx > end_idx){
				addr = &(node->p[middle].right[0]);
				siblings->pos_left = middle;

				if((middle+1) < node->header.num_entries)
					siblings->pos_right = middle + 1;

				middle++;
				break;
			}
		}
	}

	if(middle < 0){
		addr = &(node->p[0].left[0]);
		siblings->pos_right = 0;
        }
	else if(middle >= num_entries){
		addr = &(node->p[num_entries - 1].right[0]);
		siblings->pos_left = num_entries - 1;
	}

	return;
}


int8_t delete_key(db_handle *handle, void *key, uint32_t size){
	delete_request req;
	char __tmp[KV_MAX_SIZE];
	int8_t ret;

	req.key_buf = __tmp;
	*(uint32_t *)req.key_buf = size;
	memcpy((void *)(uint64_t)req.key_buf+sizeof(uint32_t),key,size);
	req.allocator_desc.handle = handle;
	req.handle = handle;
	req.allocator_desc.allocate_space = &allocate_segment;
	req.allocator_desc.free_space = &free_buffered;
	req.key_format = KV_FORMAT;
	ret = _delete_key(&req);
	/* sleep(10); */
	return ret;
}


int8_t _delete_key(delete_request * req){
	int8_t ret1,ret2 = 1;
	int i;
	/* delete the key from level 0 */
	for(i = 0;i<NUM_OF_TREES_PER_LEVEL;++i){
		if(req->handle->db_desc->root_w[i]){
			req->handle->db_desc->active_tree = i;
			break;
		}
	}

	req->allocator_desc.level_id = req->handle->db_desc->active_tree;
	req->level_id = req->handle->db_desc->active_tree;
	ret1 = __delete_key(req);

	/* delete the key from level 1 */
	/* req->allocator_desc.level_id = NUM_OF_TREES_PER_LEVEL; */
	/* req->level_id = NUM_OF_TREES_PER_LEVEL; */
	/* ret2 = __delete_key(req); */

	if (!ret1 || !ret2){
		req->handle->db_desc->dirty = 1;
		return 0;
	}

	return 1;
}


void transfer_node_from_right_neighbor(index_node* curr,index_node* right,
					    index_node* parent,
					    delete_request* req,int pos){
	void*	key_addr = (void *)(MAPPED+parent->p[pos].pivot);
	void*	pivot	 = &curr->p[curr->header.num_entries].pivot;

	/* Take the pivot of the parent and place
	   it as the last pivot in the current node.
	   Also take the leftmost node from the right neighbor
	   and place it as the last node in the current node.*/

	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) curr, pivot, key_addr);
	curr->p[curr->header.num_entries].right[0] = right->p[0].left[0];
	++curr->header.num_entries;

	/* Update the pivot of the parent node
	   with the leftmost pivot of the right neighbor. */
	key_addr = (void*)(MAPPED+right->p[0].pivot);
	pivot = &parent->p[pos].pivot;
	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) parent, pivot, key_addr);

	/* Finally shift every entry of the right neighbor to the left
	   to delete the transferred node from it.*/
	memmove(&right->p[0],&right->p[1],(sizeof(index_entry)*(right->header.num_entries - 1))+sizeof(uint64_t));
	--right->header.num_entries;
}

void transfer_node_from_left_neighbor(index_node* curr,index_node* left,
					   index_node* parent,
					   delete_request* req,int pos){
	assert(pos != -1);
	void*	key_addr = (void *)(MAPPED+parent->p[pos].pivot);
	void*	pivot;

	/* Take the leftmost pivot of the parent and place
	   it as the last pivot in the current node.
	   Also take the leftmost node from the right neighbor
	   and place it as the last node in the current node.*/
	memmove(&curr->p[1], &curr->p[0], (sizeof(index_entry)*curr->header.num_entries)+sizeof(uint64_t));
	pivot = &curr->p[0].pivot;

	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) curr, pivot, key_addr);
	curr->p[0].left[0] = left->p[left->header.num_entries-1].right[0];
	++curr->header.num_entries;

	/* Update the pivot of the parent node
	   with the leftmost pivot of the right neighbor. */
	key_addr = (void*)(MAPPED+left->p[left->header.num_entries - 1].pivot);
	pivot = &parent->p[pos].pivot;
	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) parent, pivot, key_addr);

	/* finally remove the entry that was moved to the left.*/
	--left->header.num_entries;
}

uint8_t transfer_node_to_neighbor_index_node(index_node* curr,
					     index_node* parent,
					     rotate_data* siblings,
					     delete_request* req)
{
	index_node*	left  = (index_node*)siblings->left;
	index_node*	right = (index_node*)siblings->right;
	int8_t		ret   = 0;

	parent->header.v1++;

	if (right && (right->header.num_entries >= ((index_order / 2) + 1))) {
		ret = 1;
		right->header.v1++;
		transfer_node_from_right_neighbor(curr, right, parent, req,
						       siblings->pos_right);
		right->header.v2++;
        } else if (left && (left->header.num_entries >= ((index_order / 2) + 1))) {
		ret = 2;
		left->header.v1++;
		transfer_node_from_left_neighbor(curr, left, parent, req,
						      siblings->pos_left);
		left->header.v2++;
        } else
		ret = 3;

	parent->header.v2++;
        return ret;
}

void merge_with_right_index_node(index_node*	 curr,
				 index_node*	 right,
				 index_node*	 parent,
				 delete_request* req,
				 int 		 pos)
{
	void * key_addr = (void*)(MAPPED+parent->p[pos].pivot);
        void *pivot = &curr->p[curr->header.num_entries].pivot;
	int i,j;


	assert(((index_node *)(MAPPED+parent->p[pos].left[0])) == curr);
        /* Take the pivot of the parent node
	   and place it as the rightmost pivot
	   in the current node. */
	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) curr, pivot, key_addr);
	++curr->header.num_entries;
	/* Copy the nodes of the right neighbor to the current node. */
	for(i = curr->header.num_entries,j=0;j<right->header.num_entries;++i,++j){
		curr->p[i].left[0] = right->p[j].left[0];
		pivot = &curr->p[i].pivot;
		key_addr = (void*)(MAPPED+right->p[j].pivot);
		__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) curr, pivot, key_addr);
	}

	curr->header.num_entries += right->header.num_entries;
	curr->p[curr->header.num_entries-1].right[0] = right->p[right->header.num_entries-1].right[0];

	if(parent->header.num_entries == 1){
		if(parent->header.type == rootNode){
			curr->header.type = rootNode;
			req->handle->db_desc->root_w[req->handle->db_desc->active_tree] = (node_header*)curr;
			return;
		}
		assert(0);
	}

	/* Shift every entry of the parent node to the left
	   to remove the right node and free it.*/

	parent->p[pos].right[0] = parent->p[pos].left[0];
	memmove(&parent->p[pos],
		&parent->p[pos+1],
		sizeof(index_entry)*(parent->header.num_entries-(pos+1))+sizeof(uint64_t));


	assert(((index_node *)(MAPPED+parent->p[pos].left[0])) == curr);
	--parent->header.num_entries;
}

void merge_with_left_index_node(index_node*	 curr,
				index_node*	 left,
				index_node*	 parent,
				delete_request*  req,
				int 		 pos){

	void * key_addr = (void*)(MAPPED+parent->p[pos].pivot);
        void *pivot = &left->p[left->header.num_entries].pivot;
	int i,j;


	assert(((index_node *)(MAPPED+parent->p[pos+1].left[0])) == curr);
	assert(((index_node *)(MAPPED+parent->p[pos].left[0])) == left);

        /* Take the pivot of the parent node
	   and place it as the rightmost pivot
	   in the left node. */
	__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) left, pivot, key_addr);
	++left->header.num_entries;

	/* Copy the nodes of the current node to the left neighbor. */
	for (i = left->header.num_entries,j = 0; j < curr->header.num_entries ;++i,++j) {
		left->p[i].left[0] = curr->p[j].left[0];
		pivot = &left->p[i].pivot;
		key_addr = (void*)(MAPPED+curr->p[j].pivot);
		__update_index_pivot_in_place(&req->allocator_desc,req->handle,(node_header*) left, pivot, key_addr);
	}
	left->header.num_entries += curr->header.num_entries;
	left->p[left->header.num_entries-1].right[0] = curr->p[curr->header.num_entries-1].right[0];

	/* Shift every entry of the parent node to the left
	   to remove the right node and free it.*/
	if(parent->header.num_entries == 1){
		if(parent->header.type == rootNode){
			left->header.type = rootNode;
			req->handle->db_desc->root_w[req->handle->db_desc->active_tree] = (node_header*)left;
			return;
		}
		assert(0);
	}

	parent->p[pos+1].left[0] = parent->p[pos].left[0];
	memmove(&parent->p[pos],
		&parent->p[pos+1],
		sizeof(index_entry)*(parent->header.num_entries-(pos+1))+sizeof(uint64_t));

	assert(((index_node *)(MAPPED+parent->p[pos].left[0])) == left);
	--parent->header.num_entries;

}

int8_t merge_with_index_neighbor(index_node*	  curr,
				  index_node*	  parent,
				  rotate_data*	  siblings,
				  delete_request* req)
{

	index_node*	left		 = (index_node*)siblings->left;
	index_node*	right		 = (index_node*)siblings->right;
	uint64_t	merge_with_left	 = 0;
	uint64_t	merge_with_right = 0;
	int8_t		ret		 = 0;

	assert(left != curr);
	assert(right != curr);

	if(left)
		merge_with_left = curr->header.num_entries + left->header.num_entries;

	parent->header.v1++;
	if(right)
		merge_with_right = curr->header.num_entries + right->header.num_entries;

	if(merge_with_right && merge_with_right < index_order){
		ret = 1;
		right->header.v1++;
		merge_with_right_index_node(curr,right,parent,req,siblings->pos_right);
		right->header.v2++;
	}else if(merge_with_left && merge_with_left < index_order){
		ret = 2;
		left->header.v1++;
		merge_with_left_index_node(curr,left,parent,req,siblings->pos_left);
		left->header.v2++;
	}else{
		log_fatal("We should either transfer a node or merge.");
		assert(0);
	}
	parent->header.v2++;

	return ret;
}
