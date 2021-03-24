// Copyright [2020] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <string.h>
#include "list.h"
#include <log.h>

struct klist *klist_init(void)
{
	struct klist *list = (struct klist *)calloc(1, sizeof(struct klist));
	if (!list) {
		log_fatal("Calloc failed");
		exit(EXIT_FAILURE);
	}
	list->size = 0;
	list->first = NULL;
	list->last = NULL;
	return list;
}

void *klist_get_first(struct klist *list)
{
	if (!list)
		return NULL;
	return list->first;
}

void klist_add_first(struct klist *list, void *data, const char *data_key, destroy_node_data destroy_data)
{
	struct klist_node *node = (struct klist_node *)calloc(1, sizeof(struct klist_node));
	if (!node) {
		log_fatal("Calloc failed out of memory");
		exit(EXIT_FAILURE);
	}
	node->data = data;
	if (data_key) {
		node->key = calloc(1, strlen(data_key) + 1);
		if (!node->key) {
			log_fatal("Calloc failed out of memory");
			exit(EXIT_FAILURE);
		}
		strcpy(node->key, data_key);
	}
	node->destroy_data = destroy_data;
	if (list->size == 0) {
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
	++list->size;
}

void klist_add_last(struct klist *list, void *data, const char *data_key, destroy_node_data destroy_data)
{
	struct klist_node *node = calloc(1, sizeof(struct klist_node));
	if (!node) {
		log_fatal("Calloc failed");
		exit(EXIT_FAILURE);
	}
	node->data = data;
	if (data_key != NULL) {
		node->key = calloc(1, strlen(data_key) + 1);
		if (!node->key) {
			log_fatal("calloc failed");
			exit(EXIT_FAILURE);
		}
		strcpy(node->key, data_key);
	}
	node->destroy_data = destroy_data;
	if (list->size == 0) {
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
	++list->size;
}

void *klist_remove_first(struct klist *list)
{
	struct klist_node *node;
	if (list->size > 1) {
		node = list->first;
		list->first = list->first->next;
		list->first->prev = NULL;
		--list->size;
		return node;
	} else if (list->size == 1) {
		node = list->first;
		list->size = 0;
		list->first = NULL;
		list->last = NULL;
		return node;
	} else
		return NULL;
}

int klist_remove_element(struct klist *list, void *data)
{
	struct klist_node *node;
	node = list->first;
	for (int i = 0; i < list->size; i++) {
		if (node->data == data) {
			if (node->next != NULL) /*node is not the last*/
				node->next->prev = node->prev;
			else
				list->last = node->prev;
			if (node->prev != NULL) /*node is not the first*/
				node->prev->next = node->next;
			else
				list->first = node->next;
			--list->size;
			if (node->key)
				free(node->key);
			free(node);
			return 1;
		}
		node = node->next;
	}
	return 0;
}

int klist_delete_element(struct klist *list, void *data)
{
	struct klist_node *node;
	node = list->first;
	for (int i = 0; i < list->size; i++) {
		if (node->data == data) {
			if (node->next != NULL) /*node is not the last*/
				node->next->prev = node->prev;
			else
				list->last = node->prev;
			if (node->prev != NULL) /*node is not the first*/
				node->prev->next = node->next;
			else
				list->first = node->next;
			--list->size;
			(*node->destroy_data)(node->data);
			if (node->key)
				free(node->key);
			free(node);
			return 1;
		}
		node = node->next;
	}
	return 0;
}

void *klist_find_element_with_key(struct klist *list, char *data_key)
{
	struct klist_node *node = list->first;
	for (int i = 0; i < list->size; i++) {
		if (strcmp(node->key, data_key) == 0)
			return node->data;
		node = node->next;
	}
	return NULL;
}

void klist_destroy(struct klist *list)
{
	struct klist_node *node = list->first;
	struct klist_node *next_node = NULL;
	while (node != NULL) {
		next_node = node->next;
		klist_delete_element(list, node->data);
		node = next_node;
	}
	free(list);
}
