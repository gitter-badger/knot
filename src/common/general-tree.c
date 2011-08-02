#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "common/general-tree.h"
#include "common/errors.h"

MOD_TREE_DEFINE(general_tree_node, avl);

static void gen_rem_func(struct general_tree_node *n1)
{
	free(n1);
}

//static void gen_tree_init(general_tree_t *tree)
//{
//	MOD_TREE_INIT(tree->tree, gen_cmp_func, gen_mrg_func);
//}

general_tree_t *gen_tree_new(int (*comp_func)(void *, void *),
                             int (*mrg_func)(void **, void **))
{
	general_tree_t *ret = malloc(sizeof(general_tree_t));
	printf("new %p\n", ret);
	ret->tree = malloc(sizeof(general_avl_tree_t));
//	CHECK_ALLOC_LOG(ret, NULL);
//	ret->cmp_func = comp_func;
//	ret->mrg_func = mrg_func;
	MOD_TREE_INIT(ret->tree, comp_func, mrg_func);
	return ret;
}

int gen_tree_add(general_tree_t *tree,
                 void *node)
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
//	CHECK_ALLOC_LOG(tree, -1);
	memset(tree_node, 0, sizeof(struct general_tree_node));
	tree_node->data = node;
//	tree_node->cmp_func = tree->cmp_func;
//	tree_node->mrg_func = tree->mrg_func;
	MOD_TREE_INSERT(tree->tree, general_tree_node, avl, tree_node);
	return 0;
}

void gen_tree_remove(general_tree_t *tree,
                     void *node)
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
//	CHECK_ALLOC_LOG(tree, -1);
	tree_node->data = node;
//	tree_node->cmp_func = tree->cmp_func;
//	tree_node->mrg_func = tree->mrg_func;
	MOD_TREE_REMOVE(tree->tree, general_tree_node, avl, tree_node,
	                gen_rem_func);
}

void *gen_tree_find(general_tree_t *tree,
                    void *what)
{
	struct general_tree_node tree_node;
	tree_node.data = what;
//	tree_node.cmp_func = tree->cmp_func;
//	tree_node.mrg_func = tree->mrg_func;
	struct general_tree_node *found_node =
		MOD_TREE_FIND(tree->tree, general_tree_node, avl, &tree_node);
	if (found_node) {
		return found_node->data;
	} else {
		return NULL;
	}
}

int gen_tree_find_less_or_equal(general_tree_t *tree,
                                void *what,
                                void **found)
{
	struct general_tree_node *f, *prev;
	struct general_tree_node tree_node;
	tree_node.data = what;
	int exact_match =
		MOD_TREE_FIND_LESS_EQUAL(tree->tree, general_tree_node, avl,
	                                 &tree_node, &f, &prev);
	*found = (exact_match > 0) ? f->data : NULL;
	return exact_match;
}

void gen_tree_apply_inorder(general_tree_t *tree,
                            void (*app_func)
                            (void *node, void *data), void *data)
{
	MOD_TREE_FORWARD_APPLY(tree->tree, general_tree_node, avl,
	                   app_func, data);
}

void gen_tree_destroy(general_tree_t **tree,
                      void (*dest_func)(void *node, void *data), void *data)
{
	MOD_TREE_DESTROY((*tree)->tree, general_tree_node, avl, dest_func,
	                 gen_rem_func, data);
	free(*tree);
	*tree = NULL;
}

