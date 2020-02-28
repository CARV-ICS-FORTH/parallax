#include <stdlib.h>
#include <string.h>
#include "list.h"



LIST * init_list(void (*destroy_node)(NODE *node))
{
	LIST * list = (LIST *) malloc(sizeof(LIST));
	list->size =  0;
	list->first = NULL;
	list->last = NULL;
	return list;
}

void * get_first(LIST * list)
{
	return list->first;
}

void add_first(LIST * list, void * data, const char * tag)
{
	NODE * node = (NODE *)malloc(sizeof(NODE));
	node->data = data;
	if (tag) {
		node->tag = malloc(strlen(tag)+1);
		strcpy(node->tag, tag);
	}
	if(list->size == 0){
		node->prev = NULL;
		node->next = NULL;
		list->first = node;
		list->last = node;

	} else {
		node->prev = NULL;
		node->next = list->first;
		list->first->prev = node;
		list->first = node;
	}
	list->size++;
}


void add_last(LIST * list, void * data, const char * tag){

	NODE * node = malloc(sizeof(NODE));
	node->data = data;
	if(tag!=NULL){
		node->tag = malloc(strlen(tag)+1);
		strcpy(node->tag, tag);
	}
	if(list->size == 0){
		node->prev = NULL;
		node->next = NULL;
		list->first = node;
		list->last = node;
	} else {
		node->prev = list->last;
		node->next = NULL;
		list->last->next = node;
		list->last = node;
	}
	list->size++;

}


void * remove_first(LIST * list)
{
	NODE * node;
	if(list->size > 1){
		node = list->first;
		list->first = list->first->next;
		list->first->prev = NULL;
		--list->size;
		//destroyNode(node);
		return node;
	}
	else if(list->size == 1){

		node = list->first;
		list->size =  0;
		list->first = NULL;
		list->last = NULL;
		//destroyNode(node);
		return node;
	}
	else
		return NULL;/* list empty */
}

int remove_element(LIST * list, void * data)
{
	NODE * node;
	int i;
	node = list->first;
	for(i=0; i<list->size; i++) {
		if(node->data == data)
		{
			if(node->next!= NULL)/*node is not the last*/
				node->next->prev = node->prev;
			else
				list->last = node->prev;
			if(node->prev != NULL)/*node is not the first*/
				node->prev->next = node->next;
			else
				list->first = node->next;
			list->size--;
			destroy_node(node);
			return 1;
		}
		node = node->next;
	}
	return 0;
}

void * find_element(LIST * list, char * key)
{
	NODE * node = list->first;
	int i;
	i = 0;
	for(i=0;i<list->size;i++) {
		if(strcmp(node->tag, key) == 0)
			return node->data;
		node = node->next;
	}
	return NULL;
}



/*custom destroy code*/
void destroy_node(NODE *node)
{
/*XXX TODO XXX*/
}

void destroy_list(LIST * list)
{
	void * node;
	while((node = remove_first(list))!= NULL)
		destroy_node(node);
}
