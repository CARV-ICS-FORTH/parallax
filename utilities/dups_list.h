#ifndef DUPS_LIST_H_
#define DUPS_LIST_H_
#include <stdint.h>

struct dups_node {
	uint64_t dev_offt;
	uint64_t kv_size;
	struct dups_node *next;
};

struct dups_list {
	struct dups_node *head;
};

struct dups_list *init_dups_list(void);

/*Takes a device offset and appends at the end of the list.
 *It is a checked runtime error for `list` not to be NULL.*/
void append_node(struct dups_list *list, uint64_t dev_offset, uint64_t kv_size);

struct dups_node *find_element(struct dups_list *list, uint64_t dev_offset);

/*Takes a `list` initialized by `init_dups_list` and releases the memory allocated for its nodes.
 *It is checked runtime error for `list` not to be NULL. */
void free_dups_list(struct dups_list **list);
#endif // DUPS_LIST_H_
