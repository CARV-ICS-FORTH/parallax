#ifndef _LISTH_
#define _LISTH_
#include <stdio.h>
typedef struct NODE {
	void *data;
	char *tag;
	/*function pointer for the custom destroy node function*/
	void (*destroy_node)(struct NODE *node);
	struct NODE *prev;
	struct NODE *next;
} NODE;

typedef struct LIST {
	NODE *first;
	NODE *last;
	int size;
} LIST;

LIST *initList(void (*destroy_node)(NODE *node));
void addFirst(LIST *list, void *data, const char *tag);
void addLast(LIST *list, void *data, const char *tag);
void *getFirst(LIST *list);
void *findElement(LIST *list, char *key);
void *removeFirst(LIST *list);
int removeElement(LIST *list, void *data);
void destroyNode(NODE *node);
void destroyList(LIST *list);
#endif
