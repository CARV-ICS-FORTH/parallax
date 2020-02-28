#ifndef _SIMPLE_CONCURRENT_LISTH_
#define _SIMPLE_CONCURRENT_LISTH_
#include <stdio.h>
#define CONCURRENT_MODE 120
#define SINGLE_THREAD_MODE 981

typedef struct SIMPLE_CONCURRENT_LIST_NODE
{
	volatile void * data;
	struct SIMPLE_CONCURRENT_LIST_NODE * next;
	char marked_for_deletion;
}SIMPLE_CONCURRENT_LIST_NODE;

typedef struct SIMPLE_CONCURRENT_LIST
{
	SIMPLE_CONCURRENT_LIST_NODE * first;
	SIMPLE_CONCURRENT_LIST_NODE * last;
	int size;
} SIMPLE_CONCURRENT_LIST;

SIMPLE_CONCURRENT_LIST * init_simple_concurrent_list();
void add_last_in_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, void * data);
void * get_first_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list);
void destroy_node_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST_NODE *node);
int mark_element_for_deletion_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, void * data);
void delete_element_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, SIMPLE_CONCURRENT_LIST_NODE * previous_node, SIMPLE_CONCURRENT_LIST_NODE * node);
void remove_element_from_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, SIMPLE_CONCURRENT_LIST_NODE * previous_node, SIMPLE_CONCURRENT_LIST_NODE * node);
void add_node_in_simple_concurrent_list(SIMPLE_CONCURRENT_LIST * list, SIMPLE_CONCURRENT_LIST_NODE * node);
#endif


