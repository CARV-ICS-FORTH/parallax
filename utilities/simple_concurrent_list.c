#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include "simple_concurrent_list.h"
#include "../kreon_server/conf.h"
#include "../utilities/macros.h"

SIMPLE_CONCURRENT_LIST * init_simple_concurrent_list()
{
	SIMPLE_CONCURRENT_LIST * list = (SIMPLE_CONCURRENT_LIST *) malloc(sizeof(SIMPLE_CONCURRENT_LIST));
	list->size =  0;
	list->first = NULL;
	list->last = NULL;
	return list;
}



void * get_first_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list)
{
	return list->first;
}




void add_node_in_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, SIMPLE_CONCURRENT_LIST_NODE * node)
{
  node->marked_for_deletion = 0;
  node->next = NULL;
	if(list->size == 0){
		list->last = node;
		list->first = node;
	} else {
		list->last->next = node;
		list->last = node;
	}
	++list->size;
}

void add_last_in_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, void * data)
{
	assert(data != NULL);
	SIMPLE_CONCURRENT_LIST_NODE * node = malloc(sizeof(SIMPLE_CONCURRENT_LIST_NODE));
	node->marked_for_deletion = 0;
	node->data = data;
	node->next = NULL;
	if(list->size == 0){
		list->last = node;
		list->first = node;
	} else {
		list->last->next = node;
		list->last = node;
	}
	++list->size;
}



int mark_element_for_deletion_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, void * data)
{
	DPRINT("\t deletion\n");

	SIMPLE_CONCURRENT_LIST_NODE * node;
	node = list->first;
	while(node != NULL){
		if(node->data == data){
			node->marked_for_deletion = 1;
			DPRINT("\t marked connection\n");
			return 1;
		}
		node = node->next;
	}
	return 0;
}


void remove_element_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, 
    SIMPLE_CONCURRENT_LIST_NODE * previous_node, SIMPLE_CONCURRENT_LIST_NODE * node)
{
	if(previous_node != NULL){
		previous_node->next = node->next;
		if(node == list->last){
			list->last = previous_node;
		}
			assert(list->size > 0);
      //DPRINT("Nodes now are %d\n",list->size);
		--list->size;
	}
	else if(previous_node == NULL){
		if(list->size > 1){
      assert(list->first == node);
			list->first = node->next;
			assert(list->size > 0);
      assert(list->first != NULL);
      //DPRINT("Nodes now are %d\n",list->size);
			--list->size;
		} else {
			list->first = NULL;
			list->last = NULL;
			assert(list->size > 0);
      //DPRINT("Nodes now are %d\n",list->size);
			--list->size;
    }
	}
  node->next = NULL;

}

void delete_element_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, 
    SIMPLE_CONCURRENT_LIST_NODE * previous_node, SIMPLE_CONCURRENT_LIST_NODE * node)
{
	if(previous_node != NULL){
		previous_node->next = node->next;
		if(node == list->last){
			list->last = previous_node;
		}
			assert(list->size > 0);
		--list->size;
	}
	else if(previous_node == NULL){
		if(list->size > 1){
			list->first = node->next;
			--list->size;
		} else {
			list->first = NULL;
			list->last = NULL;
			assert(list->size > 0);
			--list->size;

		}
	}
  node->next = NULL;
	/*data field already freed from spinning thread kernel*/
	free(node);
}


