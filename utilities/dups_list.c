#include "dups_list.h"
#include <assert.h>
#include <stdlib.h>

struct dups_list *init_dups_list(void)
{
	struct dups_list *new_list = calloc(1, sizeof(struct dups_list));
	return new_list;
}

void append_node(struct dups_list *list, uint64_t dev_offset, uint64_t kv_size)
{
	assert(list);

	struct dups_node *new_node = calloc(1, sizeof(struct dups_node));

	new_node->dev_offt = dev_offset;
	new_node->kv_size = kv_size;

	if (!list->head || list->head->dev_offt >= dev_offset) {
		new_node->next = list->head;
		list->head = new_node;
	} else {
		struct dups_node *curr = list->head;
		while (curr->next && curr->next->dev_offt < dev_offset) {
			curr = curr->next;
		}
		new_node->next = curr->next;
		curr->next = new_node;
	}
}

struct dups_node *find_element(struct dups_list *list, uint64_t dev_offset)
{
	assert(list);

	struct dups_node *node;

	for (node = list->head; node && node->dev_offt != dev_offset; node = node->next)
		;

	return node;
}

void free_dups_list(struct dups_list **list)
{
	assert(*list);
	struct dups_node *next_node = NULL;

	for (struct dups_node *temp_node = (*list)->head; temp_node; temp_node = next_node) {
		next_node = temp_node->next;
		free(temp_node);
	}

	free(*list);
	*list = NULL;
}
