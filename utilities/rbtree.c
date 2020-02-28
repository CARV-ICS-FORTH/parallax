
/*
   Red Black Trees
   (C) 1999  Andrea Arcangeli <andrea@suse.de>
   (C) 2002  David Woodhouse <dwmw2@infradead.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   linux/lib/rbtree.c
   */

#include "rbtree.h"
#include "server_regions.h"
#include <signal.h>

//gesalous
int rb_tree_compare(void *key_1, void * key_2, int size_2)
{

    int size_1 = *(int *)key_1;
    int ret;

    if(memcmp(key_1+4,"+oo",3)==0)
        return 1;

    if(size_1 <= size_2)
        ret = memcmp(key_1+sizeof(int),key_2,size_1);
    else
        ret = memcmp(key_1+sizeof(int),key_2,size_2);

    //printf("[%s:%s:%d] comparing key 1 %s:%d with key 2 %s:%d ret is %d\n",__FILE__,__func__,__LINE__,key_1+4,size_1,key_2,size_2, ret);
    if(ret > 0)
        return 1;
    else if(ret < 0)
        return -1;
    else
        return 0;
}


static void __rb_rotate_left(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *right = node->rb_right;
    struct rb_node *parent = rb_parent(node);

    if ((node->rb_right = right->rb_left))
        rb_set_parent(right->rb_left, node);
    right->rb_left = node;

    rb_set_parent(right, parent);

    if (parent)
    {
        if (node == parent->rb_left)
            parent->rb_left = right;
        else
            parent->rb_right = right;
    }
    else
        root->rb_node = right;
    rb_set_parent(node, right);
}

static void __rb_rotate_right(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *left = node->rb_left;
    struct rb_node *parent = rb_parent(node);

    if ((node->rb_left = left->rb_right))
        rb_set_parent(left->rb_right, node);
    left->rb_right = node;

    rb_set_parent(left, parent);

    if (parent)
    {
        if (node == parent->rb_right)
            parent->rb_right = left;
        else
            parent->rb_left = left;
    }
    else
        root->rb_node = left;
    rb_set_parent(node, left);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *parent, *gparent;

    while ((parent = rb_parent(node)) && rb_is_red(parent))
    {
        gparent = rb_parent(parent);

        if (parent == gparent->rb_left)
        {
            {
                register struct rb_node *uncle = gparent->rb_right;
                if (uncle && rb_is_red(uncle))
                {
                    rb_set_black(uncle);
                    rb_set_black(parent);
                    rb_set_red(gparent);
                    node = gparent;
                    continue;
                }
            }

            if (parent->rb_right == node)
            {
                register struct rb_node *tmp;
                __rb_rotate_left(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            rb_set_black(parent);
            rb_set_red(gparent);
            __rb_rotate_right(gparent, root);
        } else {
            {
                register struct rb_node *uncle = gparent->rb_left;
                if (uncle && rb_is_red(uncle))
                {
                    rb_set_black(uncle);
                    rb_set_black(parent);
                    rb_set_red(gparent);
                    node = gparent;
                    continue;
                }
            }

            if (parent->rb_left == node)
            {
                register struct rb_node *tmp;
                __rb_rotate_right(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            rb_set_black(parent);
            rb_set_red(gparent);
            __rb_rotate_left(gparent, root);
        }
    }

    rb_set_black(root->rb_node);
}

static void __rb_erase_color(struct rb_node *node, struct rb_node *parent,
        struct rb_root *root)
{
    struct rb_node *other;

    while ((!node || rb_is_black(node)) && node != root->rb_node)
    {
        if (parent->rb_left == node)
        {
            other = parent->rb_right;
            if (rb_is_red(other))
            {
                rb_set_black(other);
                rb_set_red(parent);
                __rb_rotate_left(parent, root);
                other = parent->rb_right;
            }
            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                    (!other->rb_right || rb_is_black(other->rb_right)))
            {
                rb_set_red(other);
                node = parent;
                parent = rb_parent(node);
            }
            else
            {
                if (!other->rb_right || rb_is_black(other->rb_right))
                {
                    rb_set_black(other->rb_left);
                    rb_set_red(other);
                    __rb_rotate_right(other, root);
                    other = parent->rb_right;
                }
                rb_set_color(other, rb_color(parent));
                rb_set_black(parent);
                rb_set_black(other->rb_right);
                __rb_rotate_left(parent, root);
                node = root->rb_node;
                break;
            }
        }
        else
        {
            other = parent->rb_left;
            if (rb_is_red(other))
            {
                rb_set_black(other);
                rb_set_red(parent);
                __rb_rotate_right(parent, root);
                other = parent->rb_left;
            }
            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                    (!other->rb_right || rb_is_black(other->rb_right)))
            {
                rb_set_red(other);
                node = parent;
                parent = rb_parent(node);
            }
            else
            {
                if (!other->rb_left || rb_is_black(other->rb_left))
                {
                    rb_set_black(other->rb_right);
                    rb_set_red(other);
                    __rb_rotate_left(other, root);
                    other = parent->rb_left;
                }
                rb_set_color(other, rb_color(parent));
                rb_set_black(parent);
                rb_set_black(other->rb_left);
                __rb_rotate_right(parent, root);
                node = root->rb_node;
                break;
            }
        }
    }
    if (node)
        rb_set_black(node);
}

void rb_erase(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *child, *parent;
    int color;

    if (!node->rb_left)
        child = node->rb_right;
    else if (!node->rb_right)
        child = node->rb_left;
    else
    {
        struct rb_node *old = node, *left;
        node = node->rb_right;
        while ((left = node->rb_left) != NULL)
            node = left;

        if (rb_parent(old)) {
            if (rb_parent(old)->rb_left == old)
                rb_parent(old)->rb_left = node;
            else
                rb_parent(old)->rb_right = node;
        } else
            root->rb_node = node;

        child = node->rb_right;
        parent = rb_parent(node);
        color = rb_color(node);

        if (parent == old) {
            parent = node;
        } else {
            if (child)
                rb_set_parent(child, parent);
            parent->rb_left = child;

            node->rb_right = old->rb_right;
            rb_set_parent(old->rb_right, node);
        }

        node->rb_parent_color = old->rb_parent_color;
        node->rb_left = old->rb_left;
        rb_set_parent(old->rb_left, node);

        goto color;
    }

    parent = rb_parent(node);
    color = rb_color(node);

    if (child)
        rb_set_parent(child, parent);
    if (parent)
    {
        if (parent->rb_left == node)
            parent->rb_left = child;
        else
            parent->rb_right = child;
    }
    else
        root->rb_node = child;

color:
    if (color == RB_BLACK)
        __rb_erase_color(child, parent, root);
}

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct rb_node *rb_first(const struct rb_root *root)
{
    struct rb_node  *n;

    n = root->rb_node;
    if (!n)
        return NULL;
    while (n->rb_left)
        n = n->rb_left;
    return n;
}

struct rb_node *rb_last(const struct rb_root *root)
{
    struct rb_node  *n;

    n = root->rb_node;
    if (!n)
        return NULL;
    while (n->rb_right)
        n = n->rb_right;
    return n;
}

struct rb_node *rb_next(const struct rb_node *node)
{
    struct rb_node *parent;

    if (rb_parent(node) == node)
        return NULL;

    /* If we have a right-hand child, go down and then left as far
       as we can. */
    if (node->rb_right) {
        node = node->rb_right; 
        while (node->rb_left)
            node=node->rb_left;
        return (struct rb_node *)node;
    }

    /* No right-hand children.  Everything down and left is
       smaller than us, so any 'next' node must be in the general
       direction of our parent. Go up the tree; any time the
       ancestor is a right-hand child of its parent, keep going
       up. First time it's a left-hand child of its parent, said
       parent is our 'next' node. */
    while ((parent = rb_parent(node)) && node == parent->rb_right)
        node = parent;

    return parent;
}

struct rb_node *rb_prev(const struct rb_node *node)
{
    struct rb_node *parent;

    if (rb_parent(node) == node)
        return NULL;

    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (node->rb_left) {
        node = node->rb_left; 
        while (node->rb_right)
            node=node->rb_right;
        return (struct rb_node *)node;
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while ((parent = rb_parent(node)) && node == parent->rb_left)
        node = parent;

    return parent;
}

void rb_replace_node(struct rb_node *victim, struct rb_node *newnode,
        struct rb_root *root)
{
    struct rb_node *parent = rb_parent(victim);

    /* Set the surrounding nodes to point to the replacement */
    if (parent) {
        if (victim == parent->rb_left)
            parent->rb_left = newnode;
        else
            parent->rb_right = newnode;
    } else {
        root->rb_node = newnode;
    }
    if (victim->rb_left)
        rb_set_parent(victim->rb_left, newnode);
    if (victim->rb_right)
        rb_set_parent(victim->rb_right, newnode);

    /* Copy the pointers/colour from the victim to the replacement */
    *newnode = *victim;
}

void Init_Tree_Min_Key( struct _tree_min_key *tree_min_key, char *min_range, void *region )
{
    tree_min_key->rb_node = RB_NODE_NULL;
    tree_min_key->Min_range = min_range;
    //gesalous
    printf("[%s:%s:%d] min range %d:%s region min %s\n",__FILE__,__func__,__LINE__,*(int *)tree_min_key->Min_range,tree_min_key->Min_range+4,((_tucana_region_S *)region)->ID_region.minimum_range+4);
    printf("[%s:%s:%d] region max %s\n",__FILE__,__func__,__LINE__,((_tucana_region_S *)region)->ID_region.maximum_range+4);
    tree_min_key->region = region;
}

void insert_tree_min_key( struct rb_root *root, struct _tree_min_key *tree_min_key )
{
    struct rb_node **link = &root->rb_node, *parent;
    char *min_key = tree_min_key->Min_range;

    /* Go to the bottom of the tree */
    parent = *link;
    while ( *link ){
        struct _tree_min_key *aux_tree_min_key;

        parent = *link;
        aux_tree_min_key = rb_entry(parent, struct _tree_min_key, rb_node);
        //printf("\n\n[%s:%s:%d]******* Updating regions table with key of size %d actual = %s  min range %d:%s********\n",__FILE__,__func__,__LINE__,*(int *)min_key, min_key+sizeof(int),
        //    *(int*)aux_tree_min_key->Min_range,aux_tree_min_key->Min_range+4);

        //if (aux_tree_min_key->sector > sector)
        // < 0 if aux_tree_min_key->Min_range < min_key
        // == 0 if aux_tree_min_key->Min_range == min_key
        // > 0 if aux_tree_min_key->Min_range > min_key
        if ( rb_tree_compare(aux_tree_min_key->Min_range, min_key+sizeof(int),*(int*)min_key) > 0 )
            link = &(*link)->rb_left;
        else
            link = &(*link)->rb_right;
    }
    /* Put the tree_min_key node there */
    rb_link_node( &tree_min_key->rb_node, parent, link );
    rb_insert_color( &tree_min_key->rb_node, root );
}

struct _tree_min_key *find_min_key_on_rbtree(struct rb_root *root, char *min_key , int min_key_len)
{
    struct rb_node *node = root->rb_node;  /* top of the tree */
    struct _tree_min_key *previous;
    struct _tree_min_key * tree_min_key;
    _tucana_region_S * region;
    int re_min, re_max;
    previous = NULL;
    while(node){
        tree_min_key = rb_entry( node, struct _tree_min_key, rb_node );
        re_min = rb_tree_compare(tree_min_key->Min_range, min_key, min_key_len);
        //printf("[%s:%s:%d] comparing tree key %s with key %s\n",__FILE__,__func__,__LINE__,tree_min_key->Min_range+4,min_key+4);
        region = (_tucana_region_S *)tree_min_key->region;
        if(region->ID_region.minimum_range !=NULL){
            re_max = rb_tree_compare(region->ID_region.maximum_range, min_key, min_key_len );
            //printf("[%s:%s:%d] comparing region max range %s with key %s\n",__FILE__,__func__,__LINE__,region->ID_region.maximum_range+4,min_key+4);
            // < 0 if tree_min_key->Min_range < min_key
            // == 0 if tree_min_key->Min_range == min_key
            // > 0 if tree_min_key->Min_range > min_key
            if(re_min <=0 && re_max > 0){
                /*found the corresponding range*/
                return tree_min_key;
            }
        }
        if(re_min > 0){
            node = node->rb_left;
        }
        else if ( re_min < 0 ){
            //gesalous
            previous = NULL;
            //previous = tree_min_key;
            node = node->rb_right;
        }
        else
            return tree_min_key;  // Found it
    }
    raise(SIGINT);
    return previous;
}
void *find_region_min_key_on_rbtree(struct rb_root *root, char *min_key, int min_key_len )
{
    void *region;
    struct _tree_min_key *tree_min_key;
    region = NULL;
    tree_min_key = NULL;
    tree_min_key = find_min_key_on_rbtree( root, min_key, min_key_len);

    if ( tree_min_key == NULL ){
        DPRINT("region key: %s not found (is NULL) in rb tree\n",min_key+4);
        return region;
    }
    region = tree_min_key->region;
    return region;
}

void printf_tree_min_key(struct rb_root *root )
{
    int i;
    struct rb_node *node = rb_first(root);  /* top of the tree */

    i=0;
    while (node != NULL )
    {
        struct _tree_min_key *tree_min_key = rb_entry( node, struct _tree_min_key, rb_node );
        struct rb_node *pre_node = node;
        printf("Node[%d] %s\n",i,tree_min_key->Min_range);
        i++;
        node = rb_next(pre_node);
        if (i >= 8 ) break;
    }
}

