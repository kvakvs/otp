/*
 * %CopyrightBegin%
 *
 * Copyright Ericsson AB 1998-2013. All Rights Reserved.
 *
 * The contents of this_ file are subject to the Erlang Public License,
 * Version 1.1, (the "License"); you may not use this_ file except in
 * compliance with the License. You should have received a copy of the
 * Erlang Public License along with this_ software. If not, it can be
 * retrieved online at http://www.erlang.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * %CopyrightEnd%
 */

/*
** Implementation of ordered ETS tables.
** The tables are implemented as AVL trees (Published by Adelson-Velski
** and Landis). A nice source for learning about these trees is
** Wirth's Algorithms + Datastructures = Programs.
** The implementation here is however not made with recursion
** as the examples in Wirths book are.
*/

/*
#ifdef DEBUG
#define HARDDEBUG 1
#endif
*/
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include "erl_process.h"
#include "error.h"
#define ERTS_WANT_DB_INTERNAL__
#include "erl_db.h"
#include "bif.h"
#include "big.h"
#include "erl_binary.h"

#include "erl_db_tree.h"

#define GETKEY_WITH_POS(Keypos, Tplp) (*((Tplp) + Keypos))
#define NITEMS(tb) ((int)erts_smp_atomic_read_nob(&(tb)->common.nitems))

/*
** A stack of this_ size is enough for an AVL tree with more than
** 0xFFFFFFFF elements. May be subject to change if
** the datatype of the element counter is changed to a 64 bit integer.
** The Maximal height of an AVL tree is calculated as:
** h(n) <= 1.4404 * log(n + 2) - 0.328
** Where n denotes the number of nodes, h(n) the height of the tree
** with n nodes and log is the binary logarithm.
*/

#define STACK_NEED 50
#define TREE_MAX_ELEMENTS 0xFFFFFFFFUL

#define PUSH_NODE(Dtt, Tdt)                     \
    ((Dtt)->array[(Dtt)->pos++] = Tdt)

#define POP_NODE(Dtt)     \
     (((Dtt)->pos) ?      \
      (Dtt)->array[--((Dtt)->pos)] : nullptr)

#define TOP_NODE(Dtt)                   \
     ((Dtt->pos) ?      \
      (Dtt)->array[(Dtt)->pos - 1] : nullptr)

#define EMPTY_NODE(Dtt) (TOP_NODE(Dtt) == nullptr)



/* Obtain table static stack if available. nullptr if not.
** Must be released with release_stack()
*/
static DbTreeStack *get_static_stack(DbTableTree *tb)
{
  if (!erts_smp_atomic_xchg_acqb(&tb->is_stack_busy, 1)) {
    return &tb->static_stack;
  }

  return nullptr;
}

/* Obtain static stack if available, otherwise empty dynamic stack.
** Must be released with release_stack()
*/
static DbTreeStack *get_any_stack(DbTableTree *tb)
{
  DbTreeStack *stack;

  if (!erts_smp_atomic_xchg_acqb(&tb->is_stack_busy, 1)) {
    return &tb->static_stack;
  }

  stack = (DbTreeStack *)erts_db_alloc(ERTS_ALC_T_DB_STK, (DbTable *) tb,
                                       sizeof(DbTreeStack) + sizeof(TreeDbTerm *) * STACK_NEED);
  stack->pos = 0;
  stack->slot = 0;
  stack->array = (TreeDbTerm **)(stack + 1);
  return stack;
}

static void release_stack(DbTableTree *tb, DbTreeStack *stack)
{
  if (stack == &tb->static_stack) {
    ASSERT(erts_smp_atomic_read_nob(&tb->is_stack_busy) == 1);
    erts_smp_atomic_set_relb(&tb->is_stack_busy, 0);
  } else {
    erts_db_free(ERTS_ALC_T_DB_STK, (DbTable *) tb,
                 (void *) stack, sizeof(DbTreeStack) + sizeof(TreeDbTerm *) * STACK_NEED);
  }
}

static ERTS_INLINE void reset_static_stack(DbTableTree *tb)
{
  tb->static_stack.pos = 0;
  tb->static_stack.slot = 0;
}

static ERTS_INLINE void free_term(DbTableTree *tb, TreeDbTerm *p)
{
  db_free_term((DbTable *)tb, p, offsetof(TreeDbTerm, dbterm));
}

static ERTS_INLINE TreeDbTerm *new_dbterm(DbTableTree *tb, Eterm obj)
{
  TreeDbTerm *p;

  if (tb->common.compress) {
    p = (TreeDbTerm *)db_store_term_comp(&tb->common, nullptr, offsetof(TreeDbTerm, dbterm), obj);
  } else {
    p = (TreeDbTerm *)db_store_term(&tb->common, nullptr, offsetof(TreeDbTerm, dbterm), obj);
  }

  return p;
}
static ERTS_INLINE TreeDbTerm *replace_dbterm(DbTableTree *tb, TreeDbTerm *old,
    Eterm obj)
{
  TreeDbTerm *p;
  ASSERT(old != nullptr);

  if (tb->common.compress) {
    p = (TreeDbTerm *)db_store_term_comp(&tb->common, &(old->dbterm), offsetof(TreeDbTerm, dbterm),
                                         obj);
  } else {
    p = (TreeDbTerm *)db_store_term(&tb->common, &(old->dbterm), offsetof(TreeDbTerm, dbterm), obj);
  }

  return p;
}

/*
** Some macros for "direction stacks"
*/
#define DIR_LEFT 0
#define DIR_RIGHT 1
#define DIR_END 2

/*
 * Special binary flag
 */
#define BIN_FLAG_ALL_OBJECTS         BIN_FLAG_USR1

/*
 * Number of records to delete before trapping.
 */
#define DELETE_RECORD_LIMIT 12000

/*
** Debugging
*/
#ifdef HARDDEBUG
static TreeDbTerm *traverse_until(TreeDbTerm *t, int *current, int to);
static void check_slot_pos(DbTableTree *tb);
static void check_saved_stack(DbTableTree *tb);
static int check_table_tree(DbTableTree *tb, TreeDbTerm *t);

#define TREE_DEBUG
#endif

#ifdef TREE_DEBUG
/*
** Primitive trace macro
*/
#define DBG erts_fprintf(stderr,"%d\n",__LINE__)

/*
** Debugging dump
*/

static void do_dump_tree2(DbTableTree *, int to, void *to_arg, int show,
                          TreeDbTerm *t, int offset);

#else

#define DBG /* nothing */

#endif

/*
** Datatypes
*/

/*
 * This structure is filled in by analyze_pattern() for the select
 * functions.
 */
struct mp_info {
  int all_objects;    /* True if complete objects are always
         * returned from the match_spec (can use
         * copy_shallow on the return value) */
  int something_can_match;  /* The match_spec is not "impossible" */
  int some_limitation;  /* There is some limitation on the search
         * area, i. e. least and/or most is set.*/
  int got_partial;    /* The limitation has a partially bound
         * key */
  Eterm least;    /* The lowest matching key (possibly
         * partially bound expression) */
  Eterm most;                 /* The highest matching key (possibly
         * partially bound expression) */

  TreeDbTerm *save_term;      /* If the key is completely bound, this_
         * will be the Tree node we're searching
         * for, otherwise it will be useless */
  Binary *mp;                 /* The compiled match program */
};

/*
 * Used by doit_select(_chunk)
 */
struct select_context {
  Process *p;
  Eterm accum;
  Binary *mp;
  Eterm end_condition;
  Eterm *lastobj;
  int32_t max;
  int keypos;
  int all_objects;
  ssize_t got;
  ssize_t chunk_size;
};

/*
 * Used by doit_select_count
 */
struct select_count_context {
  Process *p;
  Binary *mp;
  Eterm end_condition;
  Eterm *lastobj;
  int32_t max;
  int keypos;
  int all_objects;
  ssize_t got;
};

/*
 * Used by doit_select_delete
 */
struct select_delete_context {
  Process *p;
  DbTableTree *tb;
  size_t accum;
  Binary *mp;
  Eterm end_condition;
  int erase_lastterm;
  TreeDbTerm *lastterm;
  int32_t max;
  int keypos;
};

/*
** Forward declarations
*/
static TreeDbTerm *linkout_tree(DbTableTree *tb, Eterm key, Eterm *key_base);
static TreeDbTerm *linkout_object_tree(DbTableTree *tb,
                                       Eterm object);
static int do_free_tree_cont(DbTableTree *tb, int num_left);
static void free_term(DbTableTree *tb, TreeDbTerm *p);
static int balance_left(TreeDbTerm **this_);
static int balance_right(TreeDbTerm **this_);
static int delsub(TreeDbTerm **this_);
static TreeDbTerm *slot_search(Process *p, DbTableTree *tb, ssize_t slot);
static TreeDbTerm *find_node(DbTableTree *tb, Eterm key);
static TreeDbTerm **find_node2(DbTableTree *tb, Eterm key);
static TreeDbTerm *find_next(DbTableTree *tb, DbTreeStack *, Eterm key, Eterm *kbase);
static TreeDbTerm *find_prev(DbTableTree *tb, DbTreeStack *, Eterm key, Eterm *kbase);
static TreeDbTerm *find_next_from_pb_key(DbTableTree *tb, DbTreeStack *,
    Eterm key);
static TreeDbTerm *find_prev_from_pb_key(DbTableTree *tb, DbTreeStack *,
    Eterm key);
static void traverse_backwards(DbTableTree *tb,
                               DbTreeStack *,
                               Eterm lastkey, Eterm *lk_base,
                               int (*doit)(DbTableTree *tb,
                                   TreeDbTerm *,
                                   void *,
                                   int),
                               void *context);
static void traverse_forward(DbTableTree *tb,
                             DbTreeStack *,
                             Eterm lastkey, Eterm *lk_base,
                             int (*doit)(DbTableTree *tb,
                                 TreeDbTerm *,
                                 void *,
                                 int),
                             void *context);
static int key_given(DbTableTree *tb, Eterm pattern, TreeDbTerm **ret,
                     Eterm *partly_bound_key);
static ssize_t cmp_partly_bound(Eterm partly_bound_key, Eterm bound_key, Eterm *bk_base);
static ssize_t do_cmp_partly_bound(Eterm a, Eterm b, Eterm *b_base, int *done);

static int analyze_pattern(DbTableTree *tb, Eterm pattern,
                           struct mp_info *mpi);
static int doit_select(DbTableTree *tb,
                       TreeDbTerm *this_,
                       void *ptr,
                       int forward);
static int doit_select_count(DbTableTree *tb,
                             TreeDbTerm *this_,
                             void *ptr,
                             int forward);
static int doit_select_chunk(DbTableTree *tb,
                             TreeDbTerm *this_,
                             void *ptr,
                             int forward);
static int doit_select_delete(DbTableTree *tb,
                              TreeDbTerm *this_,
                              void *ptr,
                              int forward);

static int partly_bound_can_match_lesser(Eterm partly_bound_1,
    Eterm partly_bound_2);
static int partly_bound_can_match_greater(Eterm partly_bound_1,
    Eterm partly_bound_2);
static int do_partly_bound_can_match_lesser(Eterm a, Eterm b,
    int *done);
static int do_partly_bound_can_match_greater(Eterm a, Eterm b,
    int *done);
static BIF_RETTYPE ets_select_reverse(BIF_ALIST_3);


/* Method interface functions */
static int db_first_tree(Process *p, DbTable *tbl,
                         Eterm *ret);
static int db_next_tree(Process *p, DbTable *tbl,
                        Eterm key, Eterm *ret);
static int db_last_tree(Process *p, DbTable *tbl,
                        Eterm *ret);
static int db_prev_tree(Process *p, DbTable *tbl,
                        Eterm key,
                        Eterm *ret);
static int db_put_tree(DbTable *tbl, Eterm obj, int key_clash_fail);
static int db_get_tree(Process *p, DbTable *tbl,
                       Eterm key,  Eterm *ret);
static int db_member_tree(DbTable *tbl, Eterm key, Eterm *ret);
static int db_get_element_tree(Process *p, DbTable *tbl,
                               Eterm key, int ndex,
                               Eterm *ret);
static int db_erase_tree(DbTable *tbl, Eterm key, Eterm *ret);
static int db_erase_object_tree(DbTable *tbl, Eterm object, Eterm *ret);
static int db_slot_tree(Process *p, DbTable *tbl,
                        Eterm slot_term,  Eterm *ret);
static int db_select_tree(Process *p, DbTable *tbl,
                          Eterm pattern, int reversed, Eterm *ret);
static int db_select_count_tree(Process *p, DbTable *tbl,
                                Eterm pattern,  Eterm *ret);
static int db_select_chunk_tree(Process *p, DbTable *tbl,
                                Eterm pattern, ssize_t chunk_size,
                                int reversed, Eterm *ret);
static int db_select_continue_tree(Process *p, DbTable *tbl,
                                   Eterm continuation, Eterm *ret);
static int db_select_count_continue_tree(Process *p, DbTable *tbl,
    Eterm continuation, Eterm *ret);
static int db_select_delete_tree(Process *p, DbTable *tbl,
                                 Eterm pattern,  Eterm *ret);
static int db_select_delete_continue_tree(Process *p, DbTable *tbl,
    Eterm continuation, Eterm *ret);
static void db_print_tree(int to, void *to_arg,
                          int show, DbTable *tbl);
static int db_free_table_tree(DbTable *tbl);

static int db_free_table_continue_tree(DbTable *tbl);

static void db_foreach_offheap_tree(DbTable *,
                                    void (*)(ErlOffHeap *, void *),
                                    void *);

static int db_delete_all_objects_tree(Process *p, DbTable *tbl);

#ifdef HARDDEBUG
static void db_check_table_tree(DbTable *tbl);
#endif
static int db_lookup_dbterm_tree(DbTable *, Eterm key, DbUpdateHandle *);
static void db_finalize_dbterm_tree(DbUpdateHandle *);

/*
** Static variables
*/

Export ets_select_reverse_exp;

/*
** External interface
*/
DbTableMethod db_tree = {
  db_create_tree,
  db_first_tree,
  db_next_tree,
  db_last_tree,
  db_prev_tree,
  db_put_tree,
  db_get_tree,
  db_get_element_tree,
  db_member_tree,
  db_erase_tree,
  db_erase_object_tree,
  db_slot_tree,
  db_select_chunk_tree,
  db_select_tree, /* why not chunk size=0 ??? */
  db_select_delete_tree,
  db_select_continue_tree,
  db_select_delete_continue_tree,
  db_select_count_tree,
  db_select_count_continue_tree,
  db_delete_all_objects_tree,
  db_free_table_tree,
  db_free_table_continue_tree,
  db_print_tree,
  db_foreach_offheap_tree,
#ifdef HARDDEBUG
  db_check_table_tree,
#else
  nullptr,
#endif
  db_lookup_dbterm_tree,
  db_finalize_dbterm_tree

};





void db_initialize_tree(void)
{
  erts_init_trap_export(&ets_select_reverse_exp, am_ets, am_reverse, 3,
                        &ets_select_reverse);
  return;
};

/*
** Table interface routines ie what's called by the bif's
*/

int db_create_tree(Process *p, DbTable *tbl)
{
  DbTableTree *tb = &tbl->tree;
  tb->root = nullptr;
  tb->static_stack.array = (TreeDbTerm **)erts_db_alloc(ERTS_ALC_T_DB_STK,
                           (DbTable *) tb,
                           sizeof(TreeDbTerm *) * STACK_NEED);
  tb->static_stack.pos = 0;
  tb->static_stack.slot = 0;
  erts_smp_atomic_init_nob(&tb->is_stack_busy, 0);
  tb->deletion = 0;
  return DB_ERROR_NONE;
}

static int db_first_tree(Process *p, DbTable *tbl, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  TreeDbTerm *this_;

  if ((this_ = tb->root) == nullptr) {
    *ret = am_EOT;
    return DB_ERROR_NONE;
  }

  /* Walk down the tree to the left */
  if ((stack = get_static_stack(tb)) != nullptr) {
    stack->pos = stack->slot = 0;
  }

  while (this_->left != nullptr) {
    if (stack) {
      PUSH_NODE(stack, this_);
    }

    this_ = this_->left;
  }

  if (stack) {
    PUSH_NODE(stack, this_);
    stack->slot = 1;
    release_stack(tb, stack);
  }

  *ret = db_copy_key(p, tbl, &this_->dbterm);
  return DB_ERROR_NONE;
}

static int db_next_tree(Process *p, DbTable *tbl, Eterm key, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  TreeDbTerm *this_;

  if (is_atom(key) && key == am_EOT) {
    return DB_ERROR_BADKEY;
  }

  stack = get_any_stack(tb);
  this_ = find_next(tb, stack, key, nullptr);
  release_stack(tb, stack);

  if (this_ == nullptr) {
    *ret = am_EOT;
    return DB_ERROR_NONE;
  }

  *ret = db_copy_key(p, tbl, &this_->dbterm);
  return DB_ERROR_NONE;
}

static int db_last_tree(Process *p, DbTable *tbl, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  TreeDbTerm *this_;
  DbTreeStack *stack;

  if ((this_ = tb->root) == nullptr) {
    *ret = am_EOT;
    return DB_ERROR_NONE;
  }

  /* Walk down the tree to the right */
  if ((stack = get_static_stack(tb)) != nullptr) {
    stack->pos = stack->slot = 0;
  }

  while (this_->right != nullptr) {
    if (stack) {
      PUSH_NODE(stack, this_);
    }

    this_ = this_->right;
  }

  if (stack) {
    PUSH_NODE(stack, this_);
    stack->slot = NITEMS(tb);
    release_stack(tb, stack);
  }

  *ret = db_copy_key(p, tbl, &this_->dbterm);
  return DB_ERROR_NONE;
}

static int db_prev_tree(Process *p, DbTable *tbl, Eterm key, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  TreeDbTerm *this_;
  DbTreeStack *stack;

  if (is_atom(key) && key == am_EOT) {
    return DB_ERROR_BADKEY;
  }

  stack = get_any_stack(tb);
  this_ = find_prev(tb, stack, key, nullptr);
  release_stack(tb, stack);

  if (this_ == nullptr) {
    *ret = am_EOT;
    return DB_ERROR_NONE;
  }

  *ret = db_copy_key(p, tbl, &this_->dbterm);
  return DB_ERROR_NONE;
}

static ERTS_INLINE ssize_t cmp_key(DbTableTree *tb, Eterm key, Eterm *key_base,
                                TreeDbTerm *obj)
{
  return cmp_rel(key, key_base,
                 GETKEY(tb, obj->dbterm.tpl), obj->dbterm.tpl);
}

static ERTS_INLINE int cmp_key_eq(DbTableTree *tb, Eterm key, Eterm *key_base,
                                  TreeDbTerm *obj)
{
  Eterm obj_key = GETKEY(tb, obj->dbterm.tpl);
  return is_same(key, key_base, obj_key, obj->dbterm.tpl)
         || cmp_rel(key, key_base, obj_key, obj->dbterm.tpl) == 0;
}

static int db_put_tree(DbTable *tbl, Eterm obj, int key_clash_fail)
{
  DbTableTree *tb = &tbl->tree;
  /* Non recursive insertion in AVL tree, building our own stack */
  TreeDbTerm **tstack[STACK_NEED];
  int tpos = 0;
  int dstack[STACK_NEED + 1];
  int dpos = 0;
  int state = 0;
  TreeDbTerm **this_ = &tb->root;
  ssize_t c;
  Eterm key;
  int dir;
  TreeDbTerm *p1, *p2, *p;

  key = GETKEY(tb, tuple_val(obj));

  reset_static_stack(tb);

  dstack[dpos++] = DIR_END;

  for (;;)
    if (!*this_) { /* Found our place */
      state = 1;

      if (erts_smp_atomic_inc_read_nob(&tb->common.nitems) >= TREE_MAX_ELEMENTS) {
        erts_smp_atomic_dec_nob(&tb->common.nitems);
        return DB_ERROR_SYSRES;
      }

      *this_ = new_dbterm(tb, obj);
      (*this_)->balance = 0;
      (*this_)->left = (*this_)->right = nullptr;
      break;
    } else if ((c = cmp_key(tb, key, nullptr, *this_)) < 0) {
      /* go lefts */
      dstack[dpos++] = DIR_LEFT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->left);
    } else if (c > 0) { /* go right */
      dstack[dpos++] = DIR_RIGHT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->right);
    } else if (!key_clash_fail) { /* Equal key and this_ is a set, replace. */
      *this_ = replace_dbterm(tb, *this_, obj);
      break;
    } else {
      return DB_ERROR_BADKEY; /* key already exists */
    }

  while (state && (dir = dstack[--dpos]) != DIR_END) {
    this_ = tstack[--tpos];
    p = *this_;

    if (dir == DIR_LEFT) {
      switch (p->balance) {
      case 1:
        p->balance = 0;
        state = 0;
        break;

      case 0:
        p->balance = -1;
        break;

      case -1: /* The icky case */
        p1 = p->left;

        if (p1->balance == -1) { /* Single LL rotation */
          p->left = p1->right;
          p1->right = p;
          p->balance = 0;
          (*this_) = p1;
        } else { /* Double RR rotation */
          p2 = p1->right;
          p1->right = p2->left;
          p2->left = p1;
          p->left = p2->right;
          p2->right = p;
          p->balance = (p2->balance == -1) ? +1 : 0;
          p1->balance = (p2->balance == 1) ? -1 : 0;
          (*this_) = p2;
        }

        (*this_)->balance = 0;
        state = 0;
        break;
      }
    } else { /* dir == DIR_RIGHT */
      switch (p->balance) {
      case -1:
        p->balance = 0;
        state = 0;
        break;

      case 0:
        p->balance = 1;
        break;

      case 1:
        p1 = p->right;

        if (p1->balance == 1) { /* Single RR rotation */
          p->right = p1->left;
          p1->left = p;
          p->balance = 0;
          (*this_) = p1;
        } else { /* Double RL rotation */
          p2 = p1->left;
          p1->left = p2->right;
          p2->right = p1;
          p->right = p2->left;
          p2->left = p;
          p->balance = (p2->balance == 1) ? -1 : 0;
          p1->balance = (p2->balance == -1) ? 1 : 0;
          (*this_) = p2;
        }

        (*this_)->balance = 0;
        state = 0;
        break;
      }
    }
  }

  return DB_ERROR_NONE;
}

static int db_get_tree(Process *p, DbTable *tbl, Eterm key, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  Eterm copy;
  Eterm *hp, *hend;
  TreeDbTerm *this_;

  /*
   * This is always a set, so we know exactly how large
   * the data is when we have found it.
   * The list created around it is purely for interface conformance.
   */

  this_ = find_node(tb, key);

  if (this_ == nullptr) {
    *ret = NIL;
  } else {
    hp = vm::heap_alloc(p, this_->dbterm.size + 2);
    hend = hp + this_->dbterm.size + 2;
    copy = db_copy_object_from_ets(&tb->common, &this_->dbterm, &hp, &MSO(p));
    *ret = CONS(hp, copy, NIL);
    hp += 2;
    vm::heap_free(p, hend, hp);
  }

  return DB_ERROR_NONE;
}

static int db_member_tree(DbTable *tbl, Eterm key, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;

  *ret = (find_node(tb, key) == nullptr) ? am_false : am_true;
  return DB_ERROR_NONE;
}

static int db_get_element_tree(Process *p, DbTable *tbl,
                               Eterm key, int ndex, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  /*
   * Look the node up:
   */
  Eterm *hp;
  TreeDbTerm *this_;

  /*
   * This is always a set, so we know exactly how large
   * the data is when we have found it.
   * No list is created around elements in set's so there are no list
   * around the element here either.
   */

  this_ = find_node(tb, key);

  if (this_ == nullptr) {
    return DB_ERROR_BADKEY;
  } else {
    if (ndex > arityval(this_->dbterm.tpl[0])) {
      return DB_ERROR_BADPARAM;
    }

    *ret = db_copy_element_from_ets(&tb->common, p, &this_->dbterm, ndex, &hp, 0);
  }

  return DB_ERROR_NONE;
}

static int db_erase_tree(DbTable *tbl, Eterm key, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  TreeDbTerm *res;

  *ret = am_true;

  if ((res = linkout_tree(tb, key, nullptr)) != nullptr) {
    free_term(tb, res);
  }

  return DB_ERROR_NONE;
}

static int db_erase_object_tree(DbTable *tbl, Eterm object, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  TreeDbTerm *res;

  *ret = am_true;

  if ((res = linkout_object_tree(tb, object)) != nullptr) {
    free_term(tb, res);
  }

  return DB_ERROR_NONE;
}


static int db_slot_tree(Process *p, DbTable *tbl,
                        Eterm slot_term, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  ssize_t slot;
  TreeDbTerm *st;
  Eterm *hp, *hend;
  Eterm copy;

  /*
   * The notion of a "slot" is not natural in a tree, but we try to
   * simulate it by giving the n'th node in the tree instead.
   * Traversing a tree in this_ way is not very convenient, but by
   * using the saved stack we at least sometimes will get acceptable
   * performance.
   */

  if (is_not_small(slot_term) ||
      ((slot = signed_val(slot_term)) < 0) ||
      (slot > NITEMS(tb))) {
    return DB_ERROR_BADPARAM;
  }

  if (slot == NITEMS(tb)) {
    *ret = am_EOT;
    return DB_ERROR_NONE;
  }

  /*
   * We use the slot position and search from there, slot positions
   * are counted from 1 and up.
   */
  ++slot;
  st = slot_search(p, tb, slot);

  if (st == nullptr) {
    *ret = am_false;
    return DB_ERROR_UNSPEC;
  }

  hp = vm::heap_alloc(p, st->dbterm.size + 2);
  hend = hp + st->dbterm.size + 2;
  copy = db_copy_object_from_ets(&tb->common, &st->dbterm, &hp, &MSO(p));
  *ret = CONS(hp, copy, NIL);
  hp += 2;
  vm::heap_free(p, hend, hp);
  return DB_ERROR_NONE;
}



static BIF_RETTYPE ets_select_reverse(BIF_ALIST_3)
{
  Process *p = BIF_P;
  Eterm a1 = BIF_ARG_1;
  Eterm a2 = BIF_ARG_2;
  Eterm a3 = BIF_ARG_3;
  Eterm list;
  Eterm result;
  Eterm *hp;
  Eterm *hend;

  int max_iter = CONTEXT_REDS * 10;

  if (is_nil(a1)) {
    hp = vm::heap_alloc(p, 3);
    BIF_RET(TUPLE2(hp, a2, a3));
  } else if (is_not_list(a1)) {
error:
    BIF_ERROR(p, BADARG);
  }

  list = a1;
  result = a2;
  hp = hend = nullptr;

  while (is_list(list)) {
    Eterm *pair = list_val(list);

    if (--max_iter == 0) {
      BUMP_ALL_REDS(p);
      vm::heap_free(p, hend, hp);
      BIF_TRAP3(&ets_select_reverse_exp, p, list, result, a3);
    }

    if (hp == hend) {
      hp = vm::heap_alloc(p, 64);
      hend = hp + 64;
    }

    result = CONS(hp, CAR(pair), result);
    hp += 2;
    list = CDR(pair);
  }

  if (is_not_nil(list))  {
    goto error;
  }

  vm::heap_free(p, hend, hp);
  BUMP_REDS(p, CONTEXT_REDS - max_iter / 10);
  hp = vm::heap_alloc(p, 3);
  BIF_RET(TUPLE2(hp, result, a3));
}

static BIF_RETTYPE bif_trap1(Export *bif,
                             Process *p,
                             Eterm p1)
{
  BIF_TRAP1(bif, p, p1);
}

static BIF_RETTYPE bif_trap3(Export *bif,
                             Process *p,
                             Eterm p1,
                             Eterm p2,
                             Eterm p3)
{
  BIF_TRAP3(bif, p, p1, p2, p3);
}

/*
** This is called either when the select bif traps or when ets:select/1
** is called. It does mostly the same as db_select_tree and may in either case
** trap to itself again (via the ets:select/1 bif).
** Note that this_ is common for db_select_tree and db_select_chunk_tree.
*/
static int db_select_continue_tree(Process *p,
                                   DbTable *tbl,
                                   Eterm continuation,
                                   Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  struct select_context sc;
  unsigned sz;
  Eterm *hp;
  Eterm lastkey;
  Eterm end_condition;
  Binary *mp;
  Eterm key;
  Eterm *tptr;
  ssize_t chunk_size;
  ssize_t reverse;


#define RET_TO_BIF(Term, State) do { *ret = (Term); return State; } while(0);

  /* Decode continuation. We know it's a tuple but not the arity or
     anything else */

  tptr = tuple_val(continuation);

  if (arityval(*tptr) != 8) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  if (!is_small(tptr[4]) || !is_binary(tptr[5]) ||
      !(is_list(tptr[6]) || tptr[6] == NIL) || !is_small(tptr[7]) ||
      !is_small(tptr[8])) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  lastkey = tptr[2];
  end_condition = tptr[3];

  if (!(thing_subtag(*binary_val(tptr[5])) == REFC_BINARY_SUBTAG)) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  mp = ((ProcBin *) binary_val(tptr[5]))->val;

  if (!IsMatchProgBinary(mp)) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  chunk_size = signed_val(tptr[4]);

  sc.p = p;
  sc.accum = tptr[6];
  sc.mp = mp;
  sc.end_condition = NIL;
  sc.lastobj = nullptr;
  sc.max = 1000;
  sc.keypos = tb->common.keypos;
  sc.all_objects = mp->flags & BIN_FLAG_ALL_OBJECTS;
  sc.chunk_size = chunk_size;
  reverse = unsigned_val(tptr[7]);
  sc.got = signed_val(tptr[8]);

  stack = get_any_stack(tb);

  if (chunk_size) {
    if (reverse) {
      traverse_backwards(tb, stack, lastkey, nullptr, &doit_select_chunk, &sc);
    } else {
      traverse_forward(tb, stack, lastkey, nullptr, &doit_select_chunk, &sc);
    }
  } else {
    if (reverse) {
      traverse_forward(tb, stack, lastkey, nullptr, &doit_select, &sc);
    } else {
      traverse_backwards(tb, stack, lastkey, nullptr, &doit_select, &sc);
    }
  }

  release_stack(tb, stack);

  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0 || (chunk_size && sc.got == chunk_size)) {
    if (chunk_size) {
      Eterm *hp;
      unsigned sz;

      if (sc.got < chunk_size || sc.lastobj == nullptr) {
        /* end of table, sc.lastobj may be nullptr as we may have been
           at the very last object in the table when trapping. */
        if (!sc.got) {
          RET_TO_BIF(am_EOT, DB_ERROR_NONE);
        } else {
          RET_TO_BIF(bif_trap3(&ets_select_reverse_exp, p,
                               sc.accum, NIL, am_EOT),
                     DB_ERROR_NONE);
        }
      }

      key = GETKEY(tb, sc.lastobj);
      sz = size_object_rel(key, sc.lastobj);
      hp = vm::heap_alloc(p, 9 + sz);
      key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);
      continuation = TUPLE8
                     (hp,
                      tptr[1],
                      key,
                      tptr[3],
                      tptr[4],
                      tptr[5],
                      NIL,
                      tptr[7],
                      make_small(0));
      RET_TO_BIF(bif_trap3(&ets_select_reverse_exp, p,
                           sc.accum, NIL, continuation),
                 DB_ERROR_NONE);
    } else {
      RET_TO_BIF(sc.accum, DB_ERROR_NONE);
    }
  }

  key = GETKEY(tb, sc.lastobj);

  if (chunk_size) {
    if (end_condition != NIL &&
        ((!reverse && cmp_partly_bound(end_condition, key, sc.lastobj) < 0) ||
         (reverse && cmp_partly_bound(end_condition, key, sc.lastobj) > 0))) {
      /* done anyway */
      if (!sc.got) {
        RET_TO_BIF(am_EOT, DB_ERROR_NONE);
      } else {
        RET_TO_BIF(bif_trap3(&ets_select_reverse_exp, p,
                             sc.accum, NIL, am_EOT),
                   DB_ERROR_NONE);
      }
    }
  } else {
    if (end_condition != NIL &&
        ((!reverse && cmp_partly_bound(end_condition, key, sc.lastobj) > 0) ||
         (reverse && cmp_partly_bound(end_condition, key, sc.lastobj) < 0))) {
      /* done anyway */
      RET_TO_BIF(sc.accum, DB_ERROR_NONE);
    }
  }

  /* Not done yet, let's trap. */
  sz = size_object_rel(key, sc.lastobj);
  hp = vm::heap_alloc(p, 9 + sz);
  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);
  continuation = TUPLE8
                 (hp,
                  tptr[1],
                  key,
                  tptr[3],
                  tptr[4],
                  tptr[5],
                  sc.accum,
                  tptr[7],
                  make_small(sc.got));
  RET_TO_BIF(bif_trap1(bif_export[BIF_ets_select_1], p, continuation),
             DB_ERROR_NONE);

#undef RET_TO_BIF
}


static int db_select_tree(Process *p, DbTable *tbl,
                          Eterm pattern, int reverse, Eterm *ret)
{
  /* Strategy: Traverse backwards to build resulting list from tail to head */
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  struct select_context sc;
  struct mp_info mpi;
  Eterm lastkey = THE_NON_VALUE;
  Eterm *lk_base = nullptr;
  Eterm key;
  Eterm continuation;
  unsigned sz;
  Eterm *hp;
  TreeDbTerm *this_;
  int errcode;
  Eterm mpb;


#define RET_TO_BIF(Term,RetVal) do {          \
  if (mpi.mp != nullptr) {      \
      erts_bin_free(mpi.mp);        \
  }         \
  *ret = (Term);        \
  return RetVal;              \
    } while(0)

  mpi.mp = nullptr;

  sc.accum = NIL;
  sc.lastobj = nullptr;
  sc.p = p;
  sc.max = 1000;
  sc.end_condition = NIL;
  sc.keypos = tb->common.keypos;
  sc.got = 0;
  sc.chunk_size = 0;

  if ((errcode = analyze_pattern(tb, pattern, &mpi)) != DB_ERROR_NONE) {
    RET_TO_BIF(NIL, errcode);
  }

  if (!mpi.something_can_match) {
    RET_TO_BIF(NIL, DB_ERROR_NONE);
    /* can't possibly match anything */
  }

  sc.mp = mpi.mp;
  sc.all_objects = mpi.all_objects;

  if (!mpi.got_partial && mpi.some_limitation &&
      CMP(mpi.least, mpi.most) == 0) {
    doit_select(tb, mpi.save_term, &sc, 0 /* direction doesn't matter */);
    RET_TO_BIF(sc.accum, DB_ERROR_NONE);
  }

  stack = get_any_stack(tb);

  if (reverse) {
    if (mpi.some_limitation) {
      if ((this_ = find_prev_from_pb_key(tb, stack, mpi.least)) != nullptr) {
        lastkey = GETKEY(tb, this_->dbterm.tpl);
        lk_base = this_->dbterm.tpl;
      }

      sc.end_condition = mpi.most;
    }

    traverse_forward(tb, stack, lastkey, lk_base, &doit_select, &sc);
  } else {
    if (mpi.some_limitation) {
      if ((this_ = find_next_from_pb_key(tb, stack, mpi.most)) != nullptr) {
        lastkey = GETKEY(tb, this_->dbterm.tpl);
        lk_base = this_->dbterm.tpl;
      }

      sc.end_condition = mpi.least;
    }

    traverse_backwards(tb, stack, lastkey, lk_base, &doit_select, &sc);
  }

  release_stack(tb, stack);
#ifdef HARDDEBUG
  erts_fprintf(stderr, "Least: %T\n", mpi.least);
  erts_fprintf(stderr, "Most: %T\n", mpi.most);
#endif
  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0) {
    RET_TO_BIF(sc.accum, DB_ERROR_NONE);
  }

  key = GETKEY(tb, sc.lastobj);
  sz = size_object_rel(key, sc.lastobj);
  hp = vm::heap_alloc(p, 9 + sz + PROC_BIN_SIZE);
  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);

  if (mpi.all_objects) {
    (mpi.mp)->flags |= BIN_FLAG_ALL_OBJECTS;
  }

  mpb = db_make_mp_binary(p, mpi.mp, &hp);

  continuation = TUPLE8
                 (hp,
                  tb->common.id,
                  key,
                  sc.end_condition, /* From the match program, needn't be copied */
                  make_small(0), /* Chunk size of zero means not chunked to the
         continuation BIF */
                  mpb,
                  sc.accum,
                  make_small(reverse),
                  make_small(sc.got));

  /* Don't free mpi.mp, so don't use macro */
  *ret = bif_trap1(bif_export[BIF_ets_select_1], p, continuation);
  return DB_ERROR_NONE;

#undef RET_TO_BIF

}


/*
** This is called either when the select_count bif traps.
*/
static int db_select_count_continue_tree(Process *p,
    DbTable *tbl,
    Eterm continuation,
    Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  struct select_count_context sc;
  unsigned sz;
  Eterm *hp;
  Eterm lastkey;
  Eterm end_condition;
  Binary *mp;
  Eterm key;
  Eterm *tptr;
  Eterm egot;


#define RET_TO_BIF(Term, State) do { *ret = (Term); return State; } while(0);

  /* Decode continuation. We know it's a tuple and everything else as
   this_ is only called by ourselves */

  /* continuation:
     {Table, Lastkey, EndCondition, MatchProgBin, HowManyGot}*/

  tptr = tuple_val(continuation);

  if (arityval(*tptr) != 5) {
    erl::exit(1, "Internal error in ets:select_count/1");
  }

  lastkey = tptr[2];
  end_condition = tptr[3];

  if (!(thing_subtag(*binary_val(tptr[4])) == REFC_BINARY_SUBTAG)) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  mp = ((ProcBin *) binary_val(tptr[4]))->val;

  if (!IsMatchProgBinary(mp)) {
    RET_TO_BIF(NIL, DB_ERROR_BADPARAM);
  }

  sc.p = p;
  sc.mp = mp;
  sc.end_condition = NIL;
  sc.lastobj = nullptr;
  sc.max = 1000;
  sc.keypos = tb->common.keypos;

  if (is_big(tptr[5])) {
    sc.got = big_to_uint32(tptr[5]);
  } else {
    sc.got = unsigned_val(tptr[5]);
  }

  stack = get_any_stack(tb);
  traverse_backwards(tb, stack, lastkey, nullptr, &doit_select_count, &sc);
  release_stack(tb, stack);

  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0) {
    RET_TO_BIF(erts_make_integer(sc.got, p), DB_ERROR_NONE);
  }

  key = GETKEY(tb, sc.lastobj);

  if (end_condition != NIL &&
      (cmp_partly_bound(end_condition, key, sc.lastobj) > 0)) {
    /* done anyway */
    RET_TO_BIF(make_small(sc.got), DB_ERROR_NONE);
  }

  /* Not done yet, let's trap. */
  sz = size_object_rel(key, sc.lastobj);

  if (IS_USMALL(0, sc.got)) {
    hp = vm::heap_alloc(p, sz + 6);
    egot = make_small(sc.got);
  } else {
    hp = vm::heap_alloc(p, BIG_UINT_HEAP_SIZE + sz + 6);
    egot = uint_to_big(sc.got, hp);
    hp += BIG_UINT_HEAP_SIZE;
  }

  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);
  continuation = TUPLE5
                 (hp,
                  tptr[1],
                  key,
                  tptr[3],
                  tptr[4],
                  egot);
  RET_TO_BIF(bif_trap1(&ets_select_count_continue_exp, p, continuation),
             DB_ERROR_NONE);

#undef RET_TO_BIF
}


static int db_select_count_tree(Process *p, DbTable *tbl,
                                Eterm pattern, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  struct select_count_context sc;
  struct mp_info mpi;
  Eterm lastkey = THE_NON_VALUE;
  Eterm *lk_base = nullptr;
  Eterm key;
  Eterm continuation;
  unsigned sz;
  Eterm *hp;
  TreeDbTerm *this_;
  int errcode;
  Eterm egot;
  Eterm mpb;


#define RET_TO_BIF(Term,RetVal) do {          \
  if (mpi.mp != nullptr) {      \
      erts_bin_free(mpi.mp);        \
  }         \
  *ret = (Term);        \
  return RetVal;              \
    } while(0)

  mpi.mp = nullptr;

  sc.lastobj = nullptr;
  sc.p = p;
  sc.max = 1000;
  sc.end_condition = NIL;
  sc.keypos = tb->common.keypos;
  sc.got = 0;

  if ((errcode = analyze_pattern(tb, pattern, &mpi)) != DB_ERROR_NONE) {
    RET_TO_BIF(NIL, errcode);
  }

  if (!mpi.something_can_match) {
    RET_TO_BIF(make_small(0), DB_ERROR_NONE);
    /* can't possibly match anything */
  }

  sc.mp = mpi.mp;
  sc.all_objects = mpi.all_objects;

  if (!mpi.got_partial && mpi.some_limitation &&
      CMP(mpi.least, mpi.most) == 0) {
    doit_select_count(tb, mpi.save_term, &sc, 0 /* dummy */);
    RET_TO_BIF(erts_make_integer(sc.got, p), DB_ERROR_NONE);
  }

  stack = get_any_stack(tb);

  if (mpi.some_limitation) {
    if ((this_ = find_next_from_pb_key(tb, stack, mpi.most)) != nullptr) {
      lastkey = GETKEY(tb, this_->dbterm.tpl);
      lk_base = this_->dbterm.tpl;
    }

    sc.end_condition = mpi.least;
  }

  traverse_backwards(tb, stack, lastkey, lk_base, &doit_select_count, &sc);
  release_stack(tb, stack);
  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0) {
    RET_TO_BIF(erts_make_integer(sc.got, p), DB_ERROR_NONE);
  }

  key = GETKEY(tb, sc.lastobj);
  sz = size_object_rel(key, sc.lastobj);

  if (IS_USMALL(0, sc.got)) {
    hp = vm::heap_alloc(p, sz + PROC_BIN_SIZE + 6);
    egot = make_small(sc.got);
  } else {
    hp = vm::heap_alloc(p, BIG_UINT_HEAP_SIZE + sz + PROC_BIN_SIZE + 6);
    egot = uint_to_big(sc.got, hp);
    hp += BIG_UINT_HEAP_SIZE;
  }

  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);

  if (mpi.all_objects) {
    (mpi.mp)->flags |= BIN_FLAG_ALL_OBJECTS;
  }

  mpb = db_make_mp_binary(p, mpi.mp, &hp);

  continuation = TUPLE5
                 (hp,
                  tb->common.id,
                  key,
                  sc.end_condition, /* From the match program, needn't be copied */
                  mpb,
                  egot);

  /* Don't free mpi.mp, so don't use macro */
  *ret = bif_trap1(&ets_select_count_continue_exp, p, continuation);
  return DB_ERROR_NONE;

#undef RET_TO_BIF

}

static int db_select_chunk_tree(Process *p, DbTable *tbl,
                                Eterm pattern, ssize_t chunk_size,
                                int reverse,
                                Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  DbTreeStack *stack;
  struct select_context sc;
  struct mp_info mpi;
  Eterm lastkey = THE_NON_VALUE;
  Eterm *lk_base = nullptr;
  Eterm key;
  Eterm continuation;
  unsigned sz;
  Eterm *hp;
  TreeDbTerm *this_;
  int errcode;
  Eterm mpb;


#define RET_TO_BIF(Term,RetVal) do {    \
  if (mpi.mp != nullptr) {      \
      erts_bin_free(mpi.mp);    \
  }         \
  *ret = (Term);        \
  return RetVal;              \
    } while(0)

  mpi.mp = nullptr;

  sc.accum = NIL;
  sc.lastobj = nullptr;
  sc.p = p;
  sc.max = 1000;
  sc.end_condition = NIL;
  sc.keypos = tb->common.keypos;
  sc.got = 0;
  sc.chunk_size = chunk_size;

  if ((errcode = analyze_pattern(tb, pattern, &mpi)) != DB_ERROR_NONE) {
    RET_TO_BIF(NIL, errcode);
  }

  if (!mpi.something_can_match) {
    RET_TO_BIF(am_EOT, DB_ERROR_NONE);
    /* can't possibly match anything */
  }

  sc.mp = mpi.mp;
  sc.all_objects = mpi.all_objects;

  if (!mpi.got_partial && mpi.some_limitation &&
      CMP(mpi.least, mpi.most) == 0) {
    doit_select(tb, mpi.save_term, &sc, 0 /* direction doesn't matter */);

    if (sc.accum != NIL) {
      hp = vm::heap_alloc(p, 3);
      RET_TO_BIF(TUPLE2(hp, sc.accum, am_EOT), DB_ERROR_NONE);
    } else {
      RET_TO_BIF(am_EOT, DB_ERROR_NONE);
    }
  }

  stack = get_any_stack(tb);

  if (reverse) {
    if (mpi.some_limitation) {
      if ((this_ = find_next_from_pb_key(tb, stack, mpi.most)) != nullptr) {
        lastkey = GETKEY(tb, this_->dbterm.tpl);
        lk_base = this_->dbterm.tpl;
      }

      sc.end_condition = mpi.least;
    }

    traverse_backwards(tb, stack, lastkey, lk_base, &doit_select_chunk, &sc);
  } else {
    if (mpi.some_limitation) {
      if ((this_ = find_prev_from_pb_key(tb, stack, mpi.least)) != nullptr) {
        lastkey = GETKEY(tb, this_->dbterm.tpl);
        lk_base = this_->dbterm.tpl;
      }

      sc.end_condition = mpi.most;
    }

    traverse_forward(tb, stack, lastkey, lk_base, &doit_select_chunk, &sc);
  }

  release_stack(tb, stack);

  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0 || sc.got == chunk_size) {
    Eterm *hp;
    unsigned sz;

    if (sc.got < chunk_size ||
        sc.lastobj == nullptr) {
      /* We haven't got all and we haven't trapped
         which should mean we are at the end of the
         table, sc.lastobj may be nullptr if the table was empty */

      if (!sc.got) {
        RET_TO_BIF(am_EOT, DB_ERROR_NONE);
      } else {
        RET_TO_BIF(bif_trap3(&ets_select_reverse_exp, p,
                             sc.accum, NIL, am_EOT),
                   DB_ERROR_NONE);
      }
    }

    key = GETKEY(tb, sc.lastobj);
    sz = size_object_rel(key, sc.lastobj);
    hp = vm::heap_alloc(p, 9 + sz + PROC_BIN_SIZE);
    key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);

    if (mpi.all_objects) {
      (mpi.mp)->flags |= BIN_FLAG_ALL_OBJECTS;
    }

    mpb = db_make_mp_binary(p, mpi.mp, &hp);

    continuation = TUPLE8
                   (hp,
                    tb->common.id,
                    key,
                    sc.end_condition, /* From the match program,
          needn't be copied */
                    make_small(chunk_size),
                    mpb,
                    NIL,
                    make_small(reverse),
                    make_small(0));
    /* Don't let RET_TO_BIF macro free mpi.mp*/
    *ret = bif_trap3(&ets_select_reverse_exp, p,
                     sc.accum, NIL, continuation);
    return DB_ERROR_NONE;
  }

  key = GETKEY(tb, sc.lastobj);
  sz = size_object_rel(key, sc.lastobj);
  hp = vm::heap_alloc(p, 9 + sz + PROC_BIN_SIZE);
  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastobj, nullptr);

  if (mpi.all_objects) {
    (mpi.mp)->flags |= BIN_FLAG_ALL_OBJECTS;
  }

  mpb = db_make_mp_binary(p, mpi.mp, &hp);
  continuation = TUPLE8
                 (hp,
                  tb->common.id,
                  key,
                  sc.end_condition, /* From the match program, needn't be copied */
                  make_small(chunk_size),
                  mpb,
                  sc.accum,
                  make_small(reverse),
                  make_small(sc.got));
  /* Don't let RET_TO_BIF macro free mpi.mp*/
  *ret = bif_trap1(bif_export[BIF_ets_select_1], p, continuation);
  return DB_ERROR_NONE;

#undef RET_TO_BIF

}

/*
** This is called when select_delete traps
*/
static int db_select_delete_continue_tree(Process *p,
    DbTable *tbl,
    Eterm continuation,
    Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  struct select_delete_context sc;
  unsigned sz;
  Eterm *hp;
  Eterm lastkey;
  Eterm end_condition;
  Binary *mp;
  Eterm key;
  Eterm *tptr;
  Eterm eaccsum;


#define RET_TO_BIF(Term, State) do {    \
  if (sc.erase_lastterm) {    \
      free_term(tb, sc.lastterm);   \
  }         \
  *ret = (Term);        \
  return State;         \
    } while(0);

  /* Decode continuation. We know it's correct, this_ can only be called
     by trapping */

  tptr = tuple_val(continuation);

  lastkey = tptr[2];
  end_condition = tptr[3];

  sc.erase_lastterm = 0; /* Before first RET_TO_BIF */
  sc.lastterm = nullptr;

  mp = ((ProcBin *) binary_val(tptr[4]))->val;
  sc.p = p;
  sc.tb = tb;

  if (is_big(tptr[5])) {
    sc.accum = big_to_uint32(tptr[5]);
  } else {
    sc.accum = unsigned_val(tptr[5]);
  }

  sc.mp = mp;
  sc.end_condition = NIL;
  sc.max = 1000;
  sc.keypos = tb->common.keypos;

  ASSERT(!erts_smp_atomic_read_nob(&tb->is_stack_busy));
  traverse_backwards(tb, &tb->static_stack, lastkey, nullptr, &doit_select_delete, &sc);

  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0) {
    RET_TO_BIF(erts_make_integer(sc.accum, p), DB_ERROR_NONE);
  }

  key = GETKEY(tb, (sc.lastterm)->dbterm.tpl);

  if (end_condition != NIL &&
      cmp_partly_bound(end_condition, key, sc.lastterm->dbterm.tpl) > 0) { /* done anyway */
    RET_TO_BIF(erts_make_integer(sc.accum, p), DB_ERROR_NONE);
  }

  /* Not done yet, let's trap. */
  sz = size_object_rel(key, sc.lastterm->dbterm.tpl);

  if (IS_USMALL(0, sc.accum)) {
    hp = vm::heap_alloc(p, sz + 6);
    eaccsum = make_small(sc.accum);
  } else {
    hp = vm::heap_alloc(p, BIG_UINT_HEAP_SIZE + sz + 6);
    eaccsum = uint_to_big(sc.accum, hp);
    hp += BIG_UINT_HEAP_SIZE;
  }

  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastterm->dbterm.tpl, nullptr);
  continuation = TUPLE5
                 (hp,
                  tptr[1],
                  key,
                  tptr[3],
                  tptr[4],
                  eaccsum);
  RET_TO_BIF(bif_trap1(&ets_select_delete_continue_exp, p, continuation),
             DB_ERROR_NONE);

#undef RET_TO_BIF
}

static int db_select_delete_tree(Process *p, DbTable *tbl,
                                 Eterm pattern, Eterm *ret)
{
  DbTableTree *tb = &tbl->tree;
  struct select_delete_context sc;
  struct mp_info mpi;
  Eterm lastkey = THE_NON_VALUE;
  Eterm *lk_base = nullptr;
  Eterm key;
  Eterm continuation;
  unsigned sz;
  Eterm *hp;
  TreeDbTerm *this_;
  int errcode;
  Eterm mpb;
  Eterm eaccsum;

#define RET_TO_BIF(Term,RetVal) do {          \
  if (mpi.mp != nullptr) {      \
      erts_bin_free(mpi.mp);        \
  }         \
  if (sc.erase_lastterm) {                \
      free_term(tb, sc.lastterm);         \
  }                                       \
  *ret = (Term);        \
  return RetVal;              \
    } while(0)

  mpi.mp = nullptr;

  sc.accum = 0;
  sc.erase_lastterm = 0;
  sc.lastterm = nullptr;
  sc.p = p;
  sc.max = 1000;
  sc.end_condition = NIL;
  sc.keypos = tb->common.keypos;
  sc.tb = tb;

  if ((errcode = analyze_pattern(tb, pattern, &mpi)) != DB_ERROR_NONE) {
    RET_TO_BIF(0, errcode);
  }

  if (!mpi.something_can_match) {
    RET_TO_BIF(make_small(0), DB_ERROR_NONE);
    /* can't possibly match anything */
  }

  sc.mp = mpi.mp;

  if (!mpi.got_partial && mpi.some_limitation &&
      CMP(mpi.least, mpi.most) == 0) {
    doit_select_delete(tb, mpi.save_term, &sc, 0 /* direction doesn't
                  matter */);
    RET_TO_BIF(erts_make_integer(sc.accum, p), DB_ERROR_NONE);
  }

  if (mpi.some_limitation) {
    if ((this_ = find_next_from_pb_key(tb, &tb->static_stack, mpi.most)) != nullptr) {
      lastkey = GETKEY(tb, this_->dbterm.tpl);
      lk_base = this_->dbterm.tpl;
    }

    sc.end_condition = mpi.least;
  }

  traverse_backwards(tb, &tb->static_stack, lastkey, lk_base, &doit_select_delete, &sc);
  BUMP_REDS(p, 1000 - sc.max);

  if (sc.max > 0) {
    RET_TO_BIF(erts_make_integer(sc.accum, p), DB_ERROR_NONE);
  }

  key = GETKEY(tb, (sc.lastterm)->dbterm.tpl);
  sz = size_object_rel(key, sc.lastterm->dbterm.tpl);

  if (IS_USMALL(0, sc.accum)) {
    hp = vm::heap_alloc(p, sz + PROC_BIN_SIZE + 6);
    eaccsum = make_small(sc.accum);
  } else {
    hp = vm::heap_alloc(p, BIG_UINT_HEAP_SIZE + sz + PROC_BIN_SIZE + 6);
    eaccsum = uint_to_big(sc.accum, hp);
    hp += BIG_UINT_HEAP_SIZE;
  }

  key = copy_struct_rel(key, sz, &hp, &MSO(p), sc.lastterm->dbterm.tpl, nullptr);
  mpb = db_make_mp_binary(p, mpi.mp, &hp);

  continuation = TUPLE5
                 (hp,
                  tb->common.id,
                  key,
                  sc.end_condition, /* From the match program, needn't be copied */
                  mpb,
                  eaccsum);

  /* Don't free mpi.mp, so don't use macro */
  if (sc.erase_lastterm) {
    free_term(tb, sc.lastterm);
  }

  *ret = bif_trap1(&ets_select_delete_continue_exp, p, continuation);
  return DB_ERROR_NONE;

#undef RET_TO_BIF

}

/*
** Other interface routines (not directly coupled to one bif)
*/


/* Display tree contents (for dump) */
static void db_print_tree(int to, void *to_arg,
                          int show,
                          DbTable *tbl)
{
  DbTableTree *tb = &tbl->tree;
#ifdef TREE_DEBUG

  if (show)
    erts_print(to, to_arg, "\nTree data dump:\n"
               "------------------------------------------------\n");

  do_dump_tree2(&tbl->tree, to, to_arg, show, tb->root, 0);

  if (show)
    erts_print(to, to_arg, "\n"
               "------------------------------------------------\n");

#else
  erts_print(to, to_arg, "Ordered set (AVL tree), Elements: %d\n", NITEMS(tb));
#endif
}

/* release all memory occupied by a single table */
static int db_free_table_tree(DbTable *tbl)
{
  while (!db_free_table_continue_tree(tbl))
    ;

  return 1;
}

static int db_free_table_continue_tree(DbTable *tbl)
{
  DbTableTree *tb = &tbl->tree;
  int result;

  if (!tb->deletion) {
    tb->static_stack.pos = 0;
    tb->deletion = 1;
    PUSH_NODE(&tb->static_stack, tb->root);
  }

  result = do_free_tree_cont(tb, DELETE_RECORD_LIMIT);

  if (result) {   /* Completely done. */
    erts_db_free(ERTS_ALC_T_DB_STK,
                 (DbTable *) tb,
                 (void *) tb->static_stack.array,
                 sizeof(TreeDbTerm *) * STACK_NEED);
    ASSERT(erts_smp_atomic_read_nob(&tb->common.memory_size)
           == sizeof(DbTable));
  }

  return result;
}

static int db_delete_all_objects_tree(Process *p, DbTable *tbl)
{
  db_free_table_tree(tbl);
  db_create_tree(p, tbl);
  erts_smp_atomic_set_nob(&tbl->tree.common.nitems, 0);
  return 0;
}

static void do_db_tree_foreach_offheap(TreeDbTerm *,
                                       void (*)(ErlOffHeap *, void *),
                                       void *);

static void db_foreach_offheap_tree(DbTable *tbl,
                                    void (*func)(ErlOffHeap *, void *),
                                    void *arg)
{
  do_db_tree_foreach_offheap(tbl->tree.root, func, arg);
}


/*
** Functions for internal use
*/


static void
do_db_tree_foreach_offheap(TreeDbTerm *tdbt,
                           void (*func)(ErlOffHeap *, void *),
                           void *arg)
{
  ErlOffHeap tmp_offheap;

  if (!tdbt) {
    return;
  }

  do_db_tree_foreach_offheap(tdbt->left, func, arg);
  tmp_offheap.first = tdbt->dbterm.first_oh;
  tmp_offheap.overhead = 0;
  (*func)(&tmp_offheap, arg);
  tdbt->dbterm.first_oh = tmp_offheap.first;
  do_db_tree_foreach_offheap(tdbt->right, func, arg);
}

static TreeDbTerm *linkout_tree(DbTableTree *tb,
                                Eterm key, Eterm *key_base)
{
  TreeDbTerm **tstack[STACK_NEED];
  int tpos = 0;
  int dstack[STACK_NEED + 1];
  int dpos = 0;
  int state = 0;
  TreeDbTerm **this_ = &tb->root;
  ssize_t c;
  int dir;
  TreeDbTerm *q = nullptr;

  /*
   * Somewhat complicated, deletion in an AVL tree,
   * The two helpers balance_left and balance_right are used to
   * keep the balance. As in insert, we do the stacking ourselves.
   */

  reset_static_stack(tb);
  dstack[dpos++] = DIR_END;

  for (;;) {
    if (!*this_) { /* Failure */
      return nullptr;
    } else if ((c = cmp_key(tb, key, key_base, *this_)) < 0) {
      dstack[dpos++] = DIR_LEFT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->left);
    } else if (c > 0) { /* go right */
      dstack[dpos++] = DIR_RIGHT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->right);
    } else { /* Equal key, found the one to delete*/
      q = (*this_);

      if (q->right == nullptr) {
        (*this_) = q->left;
        state = 1;
      } else if (q->left == nullptr) {
        (*this_) = q->right;
        state = 1;
      } else {
        dstack[dpos++] = DIR_LEFT;
        tstack[tpos++] = this_;
        state = delsub(this_);
      }

      erts_smp_atomic_dec_nob(&tb->common.nitems);
      break;
    }
  }

  while (state && (dir = dstack[--dpos]) != DIR_END) {
    this_ = tstack[--tpos];

    if (dir == DIR_LEFT) {
      state = balance_left(this_);
    } else {
      state = balance_right(this_);
    }
  }

  return q;
}

static TreeDbTerm *linkout_object_tree(DbTableTree *tb,
                                       Eterm object)
{
  TreeDbTerm **tstack[STACK_NEED];
  int tpos = 0;
  int dstack[STACK_NEED + 1];
  int dpos = 0;
  int state = 0;
  TreeDbTerm **this_ = &tb->root;
  ssize_t c;
  int dir;
  TreeDbTerm *q = nullptr;
  Eterm key;

  /*
   * Somewhat complicated, deletion in an AVL tree,
   * The two helpers balance_left and balance_right are used to
   * keep the balance. As in insert, we do the stacking ourselves.
   */


  key = GETKEY(tb, tuple_val(object));

  reset_static_stack(tb);
  dstack[dpos++] = DIR_END;

  for (;;) {
    if (!*this_) { /* Failure */
      return nullptr;
    } else if ((c = cmp_key(tb, key, nullptr, *this_)) < 0) {
      dstack[dpos++] = DIR_LEFT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->left);
    } else if (c > 0) { /* go right */
      dstack[dpos++] = DIR_RIGHT;
      tstack[tpos++] = this_;
      this_ = &((*this_)->right);
    } else { /* Equal key, found the only possible matching object*/
      if (!db_eq(&tb->common, object, &(*this_)->dbterm)) {
        return nullptr;
      }

      q = (*this_);

      if (q->right == nullptr) {
        (*this_) = q->left;
        state = 1;
      } else if (q->left == nullptr) {
        (*this_) = q->right;
        state = 1;
      } else {
        dstack[dpos++] = DIR_LEFT;
        tstack[tpos++] = this_;
        state = delsub(this_);
      }

      erts_smp_atomic_dec_nob(&tb->common.nitems);
      break;
    }
  }

  while (state && (dir = dstack[--dpos]) != DIR_END) {
    this_ = tstack[--tpos];

    if (dir == DIR_LEFT) {
      state = balance_left(this_);
    } else {
      state = balance_right(this_);
    }
  }

  return q;
}

/*
** For the select functions, analyzes the pattern and determines which
** part of the tree should be searched. Also compiles the match program
*/
static int analyze_pattern(DbTableTree *tb, Eterm pattern,
                           struct mp_info *mpi)
{
  Eterm lst, tpl, ttpl;
  Eterm *matches, *guards, *bodies;
  Eterm sbuff[30];
  Eterm *buff = sbuff;
  Eterm *ptpl;
  int i;
  int num_heads = 0;
  Eterm key;
  Eterm partly_bound;
  int res;
  Eterm least = 0;
  Eterm most = 0;

  mpi->some_limitation = 1;
  mpi->got_partial = 0;
  mpi->something_can_match = 0;
  mpi->mp = nullptr;
  mpi->all_objects = 1;
  mpi->save_term = nullptr;

  for (lst = pattern; is_list(lst); lst = CDR(list_val(lst))) {
    ++num_heads;
  }

  if (lst != NIL) {/* proper list... */
    return DB_ERROR_BADPARAM;
  }

  if (num_heads > 10) {
    buff = (Eterm *)erts_alloc(ERTS_ALC_T_DB_TMP, sizeof(Eterm) * num_heads * 3);
  }

  matches = buff;
  guards = buff + num_heads;
  bodies = buff + (num_heads * 2);

  i = 0;

  for (lst = pattern; is_list(lst); lst = CDR(list_val(lst))) {
    Eterm body;
    ttpl = CAR(list_val(lst));

    if (!is_tuple(ttpl)) {
      if (buff != sbuff) {
        erts_free(ERTS_ALC_T_DB_TMP, buff);
      }

      return DB_ERROR_BADPARAM;
    }

    ptpl = tuple_val(ttpl);

    if (ptpl[0] != make_arityval(3U)) {
      if (buff != sbuff) {
        erts_free(ERTS_ALC_T_DB_TMP, buff);
      }

      return DB_ERROR_BADPARAM;
    }

    matches[i] = tpl = ptpl[1];
    guards[i] = ptpl[2];
    bodies[i] = body = ptpl[3];

    if (!is_list(body) || CDR(list_val(body)) != NIL ||
        CAR(list_val(body)) != am_DollarUnderscore) {
      mpi->all_objects = 0;
    }

    ++i;

    partly_bound = NIL;
    res = key_given(tb, tpl, &mpi->save_term, &partly_bound);

    if (res >= 0) {     /* Can match something */
      key = 0;
      mpi->something_can_match = 1;

      if (res > 0) {
        key = GETKEY(tb, tuple_val(tpl));
      } else if (partly_bound != NIL) {
        mpi->got_partial = 1;
        key = partly_bound;
      } else {
        mpi->some_limitation = 0;
      }

      if (key != 0) {
        if (least == 0 ||
            partly_bound_can_match_lesser(key, least)) {
          least = key;
        }

        if (most == 0 ||
            partly_bound_can_match_greater(key, most)) {
          most = key;
        }
      }
    }
  }

  mpi->least = least;
  mpi->most = most;

  /*
   * It would be nice not to compile the match_spec if nothing could match,
   * but then the select calls would not fail like they should on bad
   * match specs that happen to specify non existent keys etc.
   */
  if ((mpi->mp = db_match_compile(matches, guards, bodies,
                                  num_heads, DCOMP_TABLE, nullptr))
      == nullptr) {
    if (buff != sbuff) {
      erts_free(ERTS_ALC_T_DB_TMP, buff);
    }

    return DB_ERROR_BADPARAM;
  }

  if (buff != sbuff) {
    erts_free(ERTS_ALC_T_DB_TMP, buff);
  }

  return DB_ERROR_NONE;
}

static int do_free_tree_cont(DbTableTree *tb, int num_left)
{
  TreeDbTerm *root;
  TreeDbTerm *p;

  for (;;) {
    root = POP_NODE(&tb->static_stack);

    if (root == nullptr) {
      break;
    }

    for (;;) {
      if ((p = root->left) != nullptr) {
        root->left = nullptr;
        PUSH_NODE(&tb->static_stack, root);
        root = p;
      } else if ((p = root->right) != nullptr) {
        root->right = nullptr;
        PUSH_NODE(&tb->static_stack, root);
        root = p;
      } else {
        free_term(tb, root);

        if (--num_left > 0) {
          break;
        } else {
          return 0; /* Done enough for now */
        }
      }
    }
  }

  return 1;
}

/*
 * Deletion helpers
 */
static int balance_left(TreeDbTerm **this_)
{
  TreeDbTerm *p, *p1, *p2;
  int b1, b2, h = 1;

  p = *this_;

  switch (p->balance) {
  case -1:
    p->balance = 0;
    break;

  case 0:
    p->balance = 1;
    h = 0;
    break;

  case 1:
    p1 = p->right;
    b1 = p1->balance;

    if (b1 >= 0) { /* Single RR rotation */
      p->right = p1->left;
      p1->left = p;

      if (b1 == 0) {
        p->balance = 1;
        p1->balance = -1;
        h = 0;
      } else {
        p->balance = p1->balance = 0;
      }

      (*this_) = p1;
    } else { /* Double RL rotation */
      p2 = p1->left;
      b2 = p2->balance;
      p1->left = p2->right;
      p2->right = p1;
      p->right = p2->left;
      p2->left = p;
      p->balance = (b2 == 1) ? -1 : 0;
      p1->balance = (b2 == -1) ? 1 : 0;
      p2->balance = 0;
      (*this_) = p2;
    }

    break;
  }

  return h;
}

static int balance_right(TreeDbTerm **this_)
{
  TreeDbTerm *p, *p1, *p2;
  int b1, b2, h = 1;

  p = *this_;

  switch (p->balance) {
  case 1:
    p->balance = 0;
    break;

  case 0:
    p->balance = -1;
    h = 0;
    break;

  case -1:
    p1 = p->left;
    b1 = p1->balance;

    if (b1 <= 0) { /* Single LL rotation */
      p->left = p1->right;
      p1->right = p;

      if (b1 == 0) {
        p->balance = -1;
        p1->balance = 1;
        h = 0;
      } else {
        p->balance = p1->balance = 0;
      }

      (*this_) = p1;
    } else { /* Double LR rotation */
      p2 = p1->right;
      b2 = p2->balance;
      p1->right = p2->left;
      p2->left = p1;
      p->left = p2->right;
      p2->right = p;
      p->balance = (b2 == -1) ? 1 : 0;
      p1->balance = (b2 == 1) ? -1 : 0;
      p2->balance = 0;
      (*this_) = p2;
    }
  }

  return h;
}

static int delsub(TreeDbTerm **this_)
{
  TreeDbTerm **tstack[STACK_NEED];
  int tpos = 0;
  TreeDbTerm *q = (*this_);
  TreeDbTerm **r = &(q->left);
  int h;

  /*
   * Walk down the tree to the right and search
   * for a void right child, pick that child out
   * and return it to be put in the deleted
   * object's place.
   */

  while ((*r)->right != nullptr) {
    tstack[tpos++] = r;
    r = &((*r)->right);
  }

  *this_ = *r;
  *r = (*r)->left;
  (*this_)->left = q->left;
  (*this_)->right = q->right;
  (*this_)->balance = q->balance;
  tstack[0] = &((*this_)->left);
  h = 1;

  while (tpos && h) {
    r = tstack[--tpos];
    h = balance_right(r);
  }

  return h;
}

/*
 * Helper for db_slot
 */

static TreeDbTerm *slot_search(Process *p, DbTableTree *tb, ssize_t slot)
{
  TreeDbTerm *this_;
  TreeDbTerm *tmp;
  DbTreeStack *stack = get_any_stack(tb);
  ASSERT(stack != nullptr);

  if (slot == 1) {
    /* Don't search from where we are if we are
      looking for the first slot */
    stack->slot = 0;
  }

  if (stack->slot == 0) {
    /* clear stack if slot positions
        are not recorded */
    stack->pos = 0;
  }

  if (EMPTY_NODE(stack)) {
    this_ = tb->root;

    if (this_ == nullptr) {
      goto done;
    }

    while (this_->left != nullptr) {
      PUSH_NODE(stack, this_);
      this_ = this_->left;
    }

    PUSH_NODE(stack, this_);
    stack->slot = 1;
  }

  this_ = TOP_NODE(stack);

  while (stack->slot != slot && this_ != nullptr) {
    if (slot > stack->slot) {
      if (this_->right != nullptr) {
        this_ = this_->right;

        while (this_->left != nullptr) {
          PUSH_NODE(stack, this_);
          this_ = this_->left;
        }

        PUSH_NODE(stack, this_);
      } else {
        for (;;) {
          tmp = POP_NODE(stack);
          this_ = TOP_NODE(stack);

          if (this_ == nullptr || this_->left == tmp) {
            break;
          }
        }
      }

      ++(stack->slot);
    } else {
      if (this_->left != nullptr) {
        this_ = this_->left;

        while (this_->right != nullptr) {
          PUSH_NODE(stack, this_);
          this_ = this_->right;
        }

        PUSH_NODE(stack, this_);
      } else {
        for (;;) {
          tmp = POP_NODE(stack);
          this_ = TOP_NODE(stack);

          if (this_ == nullptr || this_->right == tmp) {
            break;
          }
        }
      }

      --(stack->slot);
    }
  }

done:
  release_stack(tb, stack);
  return this_;
}

/*
 * Find next and previous in sort order
 */

static TreeDbTerm *find_next(DbTableTree *tb, DbTreeStack *stack,
                             Eterm key, Eterm *key_base)
{
  TreeDbTerm *this_;
  TreeDbTerm *tmp;
  ssize_t c;

  if ((this_ = TOP_NODE(stack)) != nullptr) {
    if (!cmp_key_eq(tb, key, key_base, this_)) {
      /* Start from the beginning */
      stack->pos = stack->slot = 0;
    }
  }

  if (EMPTY_NODE(stack)) { /* Have to rebuild the stack */
    if ((this_ = tb->root) == nullptr) {
      return nullptr;
    }

    for (;;) {
      PUSH_NODE(stack, this_);

      if ((c = cmp_key(tb, key, key_base, this_)) > 0) {
        if (this_->right == nullptr) /* We are at the previos
              and the element does
              not exist */
        {
          break;
        } else {
          this_ = this_->right;
        }
      } else if (c < 0) {
        if (this_->left == nullptr) { /* Done */
          return this_;
        } else {
          this_ = this_->left;
        }
      } else {
        break;
      }
    }
  }

  /* The next element from this_... */
  if (this_->right != nullptr) {
    this_ = this_->right;
    PUSH_NODE(stack, this_);

    while (this_->left != nullptr) {
      this_ = this_->left;
      PUSH_NODE(stack, this_);
    }

    if (stack->slot > 0) {
      ++(stack->slot);
    }
  } else {
    do {
      tmp = POP_NODE(stack);

      if ((this_ = TOP_NODE(stack)) == nullptr) {
        stack->slot = 0;
        return nullptr;
      }
    } while (this_->right == tmp);

    if (stack->slot > 0) {
      ++(stack->slot);
    }
  }

  return this_;
}

static TreeDbTerm *find_prev(DbTableTree *tb, DbTreeStack *stack,
                             Eterm key, Eterm *key_base)
{
  TreeDbTerm *this_;
  TreeDbTerm *tmp;
  ssize_t c;

  if ((this_ = TOP_NODE(stack)) != nullptr) {
    if (!cmp_key_eq(tb, key, key_base, this_)) {
      /* Start from the beginning */
      stack->pos = stack->slot = 0;
    }
  }

  if (EMPTY_NODE(stack)) { /* Have to rebuild the stack */
    if ((this_ = tb->root) == nullptr) {
      return nullptr;
    }

    for (;;) {
      PUSH_NODE(stack, this_);

      if ((c = cmp_key(tb, key, key_base, this_)) < 0) {
        if (this_->left == nullptr) /* We are at the next
             and the element does
             not exist */
        {
          break;
        } else {
          this_ = this_->left;
        }
      } else if (c > 0) {
        if (this_->right == nullptr) { /* Done */
          return this_;
        } else {
          this_ = this_->right;
        }
      } else {
        break;
      }
    }
  }

  /* The previous element from this_... */
  if (this_->left != nullptr) {
    this_ = this_->left;
    PUSH_NODE(stack, this_);

    while (this_->right != nullptr) {
      this_ = this_->right;
      PUSH_NODE(stack, this_);
    }

    if (stack->slot > 0) {
      --(stack->slot);
    }
  } else {
    do {
      tmp = POP_NODE(stack);

      if ((this_ = TOP_NODE(stack)) == nullptr) {
        stack->slot = 0;
        return nullptr;
      }
    } while (this_->left == tmp);

    if (stack->slot > 0) {
      --(stack->slot);
    }
  }

  return this_;
}

static TreeDbTerm *find_next_from_pb_key(DbTableTree *tb, DbTreeStack *stack,
    Eterm key)
{
  TreeDbTerm *this_;
  TreeDbTerm *tmp;
  ssize_t c;

  /* spool the stack, we have to "re-search" */
  stack->pos = stack->slot = 0;

  if ((this_ = tb->root) == nullptr) {
    return nullptr;
  }

  for (;;) {
    PUSH_NODE(stack, this_);

    if ((c = cmp_partly_bound(key, GETKEY(tb, this_->dbterm.tpl),
                              this_->dbterm.tpl)) >= 0) {
      if (this_->right == nullptr) {
        do {
          tmp = POP_NODE(stack);

          if ((this_ = TOP_NODE(stack)) == nullptr) {
            return nullptr;
          }
        } while (this_->right == tmp);

        return this_;
      } else {
        this_ = this_->right;
      }
    } else { /*if (c < 0)*/
      if (this_->left == nullptr) { /* Done */
        return this_;
      } else {
        this_ = this_->left;
      }
    }
  }
}

static TreeDbTerm *find_prev_from_pb_key(DbTableTree *tb, DbTreeStack *stack,
    Eterm key)
{
  TreeDbTerm *this_;
  TreeDbTerm *tmp;
  ssize_t c;

  /* spool the stack, we have to "re-search" */
  stack->pos = stack->slot = 0;

  if ((this_ = tb->root) == nullptr) {
    return nullptr;
  }

  for (;;) {
    PUSH_NODE(stack, this_);

    if ((c = cmp_partly_bound(key, GETKEY(tb, this_->dbterm.tpl),
                              this_->dbterm.tpl)) <= 0) {
      if (this_->left == nullptr) {
        do {
          tmp = POP_NODE(stack);

          if ((this_ = TOP_NODE(stack)) == nullptr) {
            return nullptr;
          }
        } while (this_->left == tmp);

        return this_;
      } else {
        this_ = this_->left;
      }
    } else { /*if (c < 0)*/
      if (this_->right == nullptr) { /* Done */
        return this_;
      } else {
        this_ = this_->right;
      }
    }
  }
}


/*
 * Just lookup a node
 */
static TreeDbTerm *find_node(DbTableTree *tb, Eterm key)
{
  TreeDbTerm *this_;
  ssize_t res;
  DbTreeStack *stack = get_static_stack(tb);

  if (!stack || EMPTY_NODE(stack)
      || !cmp_key_eq(tb, key, nullptr, (this_ = TOP_NODE(stack)))) {

    this_ = tb->root;

    while (this_ != nullptr && (res = cmp_key(tb, key, nullptr, this_)) != 0) {
      if (res < 0) {
        this_ = this_->left;
      } else {
        this_ = this_->right;
      }
    }
  }

  if (stack) {
    release_stack(tb, stack);
  }

  return this_;
}

/*
 * Lookup a node and return the address of the node pointer in the tree
 */
static TreeDbTerm **find_node2(DbTableTree *tb, Eterm key)
{
  TreeDbTerm **this_;
  ssize_t res;

  this_ = &tb->root;

  while ((*this_) != nullptr && (res = cmp_key(tb, key, nullptr, *this_)) != 0) {
    if (res < 0) {
      this_ = &((*this_)->left);
    } else {
      this_ = &((*this_)->right);
    }
  }

  if (*this_ == nullptr) {
    return nullptr;
  }

  return this_;
}

static int db_lookup_dbterm_tree(DbTable *tbl, Eterm key, DbUpdateHandle *handle)
{
  DbTableTree *tb = &tbl->tree;
  TreeDbTerm **pp = find_node2(tb, key);

  if (pp == nullptr) {
    return 0;
  }

  handle->tb = tbl;
  handle->dbterm = &(*pp)->dbterm;
  handle->mustResize = 0;
  handle->bp = (void **) pp;
  handle->new_size = (*pp)->dbterm.size;
#if HALFWORD_HEAP
  handle->abs_vec = nullptr;
#endif
  return 1;
}

static void db_finalize_dbterm_tree(DbUpdateHandle *handle)
{
  if (handle->mustResize) {
    TreeDbTerm *oldp = (TreeDbTerm *) *handle->bp;

    db_finalize_resize(handle, offsetof(TreeDbTerm, dbterm));
    reset_static_stack(&handle->tb->tree);

    free_term(&handle->tb->tree, oldp);
  }

#ifdef DEBUG
  handle->dbterm = 0;
#endif
  return;
}

/*
 * Traverse the tree with a callback function, used by db_match_xxx
 */
static void traverse_backwards(DbTableTree *tb,
                               DbTreeStack *stack,
                               Eterm lastkey, Eterm *lk_base,
                               int (*doit)(DbTableTree *,
                                   TreeDbTerm *,
                                   void *,
                                   int),
                               void *context)
{
  TreeDbTerm *this_, *next;

  if (lastkey == THE_NON_VALUE) {
    stack->pos = stack->slot = 0;

    if ((this_ = tb->root) == nullptr) {
      return;
    }

    while (this_ != nullptr) {
      PUSH_NODE(stack, this_);
      this_ = this_->right;
    }

    this_ = TOP_NODE(stack);
    next = find_prev(tb, stack, GETKEY(tb, this_->dbterm.tpl),
                     this_->dbterm.tpl);

    if (!((*doit)(tb, this_, context, 0))) {
      return;
    }
  } else {
    next = find_prev(tb, stack, lastkey, lk_base);
  }

  while ((this_ = next) != nullptr) {
    next = find_prev(tb, stack, GETKEY(tb, this_->dbterm.tpl), this_->dbterm.tpl);

    if (!((*doit)(tb, this_, context, 0))) {
      return;
    }
  }
}

/*
 * Traverse the tree with a callback function, used by db_match_xxx
 */
static void traverse_forward(DbTableTree *tb,
                             DbTreeStack *stack,
                             Eterm lastkey, Eterm *lk_base,
                             int (*doit)(DbTableTree *,
                                 TreeDbTerm *,
                                 void *,
                                 int),
                             void *context)
{
  TreeDbTerm *this_, *next;

  if (lastkey == THE_NON_VALUE) {
    stack->pos = stack->slot = 0;

    if ((this_ = tb->root) == nullptr) {
      return;
    }

    while (this_ != nullptr) {
      PUSH_NODE(stack, this_);
      this_ = this_->left;
    }

    this_ = TOP_NODE(stack);
    next = find_next(tb, stack, GETKEY(tb, this_->dbterm.tpl), this_->dbterm.tpl);

    if (!((*doit)(tb, this_, context, 1))) {
      return;
    }
  } else {
    next = find_next(tb, stack, lastkey, lk_base);
  }

  while ((this_ = next) != nullptr) {
    next = find_next(tb, stack, GETKEY(tb, this_->dbterm.tpl), this_->dbterm.tpl);

    if (!((*doit)(tb, this_, context, 1))) {
      return;
    }
  }
}

/*
 * Returns 0 if not given 1 if given and -1 on no possible match
 * if key is given; *ret is set to point to the object concerned.
 */
static int key_given(DbTableTree *tb, Eterm pattern, TreeDbTerm **ret,
                     Eterm *partly_bound)
{
  TreeDbTerm *this_;
  Eterm key;

  ASSERT(ret != nullptr);

  if (pattern == am_Underscore || db_is_variable(pattern) != -1) {
    return 0;
  }

  key = db_getkey(tb->common.keypos, pattern);

  if (is_non_value(key)) {
    return -1;  /* can't possibly match anything */
  }

  if (!db_has_variable(key)) {   /* Bound key */
    if ((this_ = find_node(tb, key)) == nullptr) {
      return -1;
    }

    *ret = this_;
    return 1;
  } else if (partly_bound != nullptr && key != am_Underscore &&
             db_is_variable(key) < 0) {
    *partly_bound = key;
  }

  return 0;
}



static ssize_t do_cmp_partly_bound(Eterm a, Eterm b, Eterm *b_base, int *done)
{
  Eterm *aa;
  Eterm *bb;
  Eterm a_hdr;
  Eterm b_hdr;
  int i;
  ssize_t j;

  /* A variable matches anything */
  if (is_atom(a) && (a == am_Underscore || (db_is_variable(a) >= 0))) {
    *done = 1;
    return 0;
  }

  if (is_same(a, nullptr, b, b_base)) {
    return 0;
  }

  switch (a & _TAG_PRIMARY_MASK) {
  case TAG_PRIMARY_LIST:
    if (!is_list(b)) {
      return cmp_rel(a, nullptr, b, b_base);
    }

    aa = list_val(a);
    bb = list_val_rel(b, b_base);

    while (1) {
      if ((j = do_cmp_partly_bound(*aa++, *bb++, b_base, done)) != 0 || *done) {
        return j;
      }

      if (is_same(*aa, nullptr, *bb, b_base)) {
        return 0;
      }

      if (is_not_list(*aa) || is_not_list(*bb)) {
        return do_cmp_partly_bound(*aa, *bb, b_base, done);
      }

      aa = list_val(*aa);
      bb = list_val_rel(*bb, b_base);
    }

  case TAG_PRIMARY_BOXED:
    if ((b & _TAG_PRIMARY_MASK) != TAG_PRIMARY_BOXED) {
      return cmp_rel(a, nullptr, b, b_base);
    }

    a_hdr = ((*boxed_val(a)) & _TAG_HEADER_MASK) >> _TAG_PRIMARY_SIZE;
    b_hdr = ((*boxed_val_rel(b, b_base)) & _TAG_HEADER_MASK) >> _TAG_PRIMARY_SIZE;

    if (a_hdr != b_hdr) {
      return cmp_rel(a, nullptr, b, b_base);
    }

    if (a_hdr == (_TAG_HEADER_ARITYVAL >> _TAG_PRIMARY_SIZE)) {
      aa = tuple_val(a);
      bb = tuple_val_rel(b, b_base);
      /* compare the arities */
      i = arityval(*aa);  /* get the arity*/

      if (i < arityval(*bb)) {
        return (-1);
      }

      if (i > arityval(*bb)) {
        return (1);
      }

      while (i--) {
        if ((j = do_cmp_partly_bound(*++aa, *++bb, b_base, done)) != 0
            || *done) {
          return j;
        }
      }

      return 0;
    }

  /* Drop through */
  default:
    return cmp_rel(a, nullptr, b, b_base);
  }
}

static ssize_t cmp_partly_bound(Eterm partly_bound_key, Eterm bound_key, Eterm *bk_base)
{
  int done = 0;
  ssize_t ret = do_cmp_partly_bound(partly_bound_key, bound_key, bk_base, &done);
#ifdef HARDDEBUG
  erts_fprintf(stderr, "\ncmp_partly_bound: %T", partly_bound_key);

  if (ret < 0) {
    erts_fprintf(stderr, " < ");
  } else if (ret > 0) {
    erts_fprintf(stderr, " > ");
  } else {
    erts_fprintf(stderr, " == ");
  }

  erts_fprintf(stderr, "%R\n", bound_key, bk_base);
#endif
  return ret;
}

/*
** For partly_bound debugging....
**
BIF_RETTYPE ets_testnisse_2(BIF_ALIST_2)
BIF_ADECL_2
{
    Eterm r1 = make_small(partly_bound_can_match_lesser(BIF_ARG_1,
              BIF_ARG_2));
    Eterm r2 = make_small(partly_bound_can_match_greater(BIF_ARG_1,
               BIF_ARG_2));
    Eterm *hp = vm::heap_alloc(BIF_P,3);
    Eterm ret;

    ret = TUPLE2(hp,r1,r2);
    BIF_RET(ret);
}
**
*/
static int partly_bound_can_match_lesser(Eterm partly_bound_1,
    Eterm partly_bound_2)
{
  int done = 0;
  int ret = do_partly_bound_can_match_lesser(partly_bound_1,
            partly_bound_2,
            &done);
#ifdef HARDDEBUG
  erts_fprintf(stderr, "\npartly_bound_can_match_lesser: %T", partly_bound_1);

  if (ret) {
    erts_fprintf(stderr, " can match lesser than ");
  } else {
    erts_fprintf(stderr, " can not match lesser than ");
  }

  erts_fprintf(stderr, "%T\n", partly_bound_2);
#endif
  return ret;
}

static int partly_bound_can_match_greater(Eterm partly_bound_1,
    Eterm partly_bound_2)
{
  int done = 0;
  int ret = do_partly_bound_can_match_greater(partly_bound_1,
            partly_bound_2,
            &done);
#ifdef HARDDEBUG
  erts_fprintf(stderr, "\npartly_bound_can_match_greater: %T", partly_bound_1);

  if (ret) {
    erts_fprintf(stderr, " can match greater than ");
  } else {
    erts_fprintf(stderr, " can not match greater than ");
  }

  erts_fprintf(stderr, "%T\n", partly_bound_2);
#endif
  return ret;
}

static int do_partly_bound_can_match_lesser(Eterm a, Eterm b,
    int *done)
{
  Eterm *aa;
  Eterm *bb;
  ssize_t i;
  int j;

  if (is_atom(a) && (a == am_Underscore ||
                     (db_is_variable(a) >= 0))) {
    *done = 1;

    if (is_atom(b) && (b == am_Underscore ||
                       (db_is_variable(b) >= 0))) {
      return 0;
    } else {
      return 1;
    }
  } else if (is_atom(b) && (b == am_Underscore ||
                            (db_is_variable(b) >= 0))) {
    *done = 1;
    return 0;
  }

  if (a == b) {
    return 0;
  }

  if (not_eq_tags(a, b)) {
    *done = 1;
    return (CMP(a, b) < 0) ? 1 : 0;
  }

  /* we now know that tags are the same */
  switch (tag_val_def(a)) {
  case TUPLE_DEF:
    aa = tuple_val(a);
    bb = tuple_val(b);

    /* compare the arities */
    if (arityval(*aa) < arityval(*bb)) {
      return 1;
    }

    if (arityval(*aa) > arityval(*bb)) {
      return 0;
    }

    i = arityval(*aa);  /* get the arity*/

    while (i--) {
      if ((j = do_partly_bound_can_match_lesser(*++aa, *++bb,
               done)) != 0
          || *done) {
        return j;
      }
    }

    return 0;

  case LIST_DEF:
    aa = list_val(a);
    bb = list_val(b);

    while (1) {
      if ((j = do_partly_bound_can_match_lesser(*aa++, *bb++,
               done)) != 0
          || *done) {
        return j;
      }

      if (*aa == *bb) {
        return 0;
      }

      if (is_not_list(*aa) || is_not_list(*bb))
        return do_partly_bound_can_match_lesser(*aa, *bb,
                                                done);

      aa = list_val(*aa);
      bb = list_val(*bb);
    }

  default:
    if ((i = CMP(a, b)) != 0) {
      *done = 1;
    }

    return (i < 0) ? 1 : 0;
  }
}

static int do_partly_bound_can_match_greater(Eterm a, Eterm b,
    int *done)
{
  Eterm *aa;
  Eterm *bb;
  ssize_t i;
  int j;

  if (is_atom(a) && (a == am_Underscore ||
                     (db_is_variable(a) >= 0))) {
    *done = 1;

    if (is_atom(b) && (b == am_Underscore ||
                       (db_is_variable(b) >= 0))) {
      return 0;
    } else {
      return 1;
    }
  } else if (is_atom(b) && (b == am_Underscore ||
                            (db_is_variable(b) >= 0))) {
    *done = 1;
    return 0;
  }

  if (a == b) {
    return 0;
  }

  if (not_eq_tags(a, b)) {
    *done = 1;
    return (CMP(a, b) > 0) ? 1 : 0;
  }

  /* we now know that tags are the same */
  switch (tag_val_def(a)) {
  case TUPLE_DEF:
    aa = tuple_val(a);
    bb = tuple_val(b);

    /* compare the arities */
    if (arityval(*aa) < arityval(*bb)) {
      return 0;
    }

    if (arityval(*aa) > arityval(*bb)) {
      return 1;
    }

    i = arityval(*aa);  /* get the arity*/

    while (i--) {
      if ((j = do_partly_bound_can_match_greater(*++aa, *++bb,
               done)) != 0
          || *done) {
        return j;
      }
    }

    return 0;

  case LIST_DEF:
    aa = list_val(a);
    bb = list_val(b);

    while (1) {
      if ((j = do_partly_bound_can_match_greater(*aa++, *bb++,
               done)) != 0
          || *done) {
        return j;
      }

      if (*aa == *bb) {
        return 0;
      }

      if (is_not_list(*aa) || is_not_list(*bb))
        return do_partly_bound_can_match_greater(*aa, *bb,
               done);

      aa = list_val(*aa);
      bb = list_val(*bb);
    }

  default:
    if ((i = CMP(a, b)) != 0) {
      *done = 1;
    }

    return (i > 0) ? 1 : 0;
  }
}

/*
 * Callback functions for the different match functions
 */

static int doit_select(DbTableTree *tb, TreeDbTerm *this_, void *ptr,
                       int forward)
{
  struct select_context *sc = (struct select_context *) ptr;
  Eterm ret;
  Eterm *hp;

  sc->lastobj = this_->dbterm.tpl;

  if (sc->end_condition != NIL &&
      ((forward &&
        cmp_partly_bound(sc->end_condition,
                         GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                         this_->dbterm.tpl) < 0) ||
       (!forward &&
        cmp_partly_bound(sc->end_condition,
                         GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                         this_->dbterm.tpl) > 0))) {
    return 0;
  }

  ret = db_match_dbterm(&tb->common, sc->p, sc->mp, sc->all_objects,
                        &this_->dbterm, &hp, 2);

  if (is_value(ret)) {
    sc->accum = CONS(hp, ret, sc->accum);
  }

  if (MBUF(sc->p)) {
    /*
     * Force a trap and GC if a heap fragment was created. Many heap fragments
     * make the GC slow.
     */
    sc->max = 0;
  }

  if (--(sc->max) <= 0) {
    return 0;
  }

  return 1;
}

static int doit_select_count(DbTableTree *tb, TreeDbTerm *this_, void *ptr,
                             int forward)
{
  struct select_count_context *sc = (struct select_count_context *) ptr;
  Eterm ret;

  sc->lastobj = this_->dbterm.tpl;

  /* Always backwards traversing */
  if (sc->end_condition != NIL &&
      (cmp_partly_bound(sc->end_condition,
                        GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                        this_->dbterm.tpl) > 0)) {
    return 0;
  }

  ret = db_match_dbterm(&tb->common, sc->p, sc->mp, 0,
                        &this_->dbterm, nullptr, 0);

  if (ret == am_true) {
    ++(sc->got);
  }

  if (--(sc->max) <= 0) {
    return 0;
  }

  return 1;
}

static int doit_select_chunk(DbTableTree *tb, TreeDbTerm *this_, void *ptr,
                             int forward)
{
  struct select_context *sc = (struct select_context *) ptr;
  Eterm ret;
  Eterm *hp;

  sc->lastobj = this_->dbterm.tpl;

  if (sc->end_condition != NIL &&
      ((forward &&
        cmp_partly_bound(sc->end_condition,
                         GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                         this_->dbterm.tpl) < 0) ||
       (!forward &&
        cmp_partly_bound(sc->end_condition,
                         GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                         this_->dbterm.tpl) > 0))) {
    return 0;
  }

  ret = db_match_dbterm(&tb->common, sc->p, sc->mp, sc->all_objects,
                        &this_->dbterm, &hp, 2);

  if (is_value(ret)) {
    ++(sc->got);
    sc->accum = CONS(hp, ret, sc->accum);
  }

  if (MBUF(sc->p)) {
    /*
     * Force a trap and GC if a heap fragment was created. Many heap fragments
     * make the GC slow.
     */
    sc->max = 0;
  }

  if (--(sc->max) <= 0 || sc->got == sc->chunk_size) {
    return 0;
  }

  return 1;
}


static int doit_select_delete(DbTableTree *tb, TreeDbTerm *this_, void *ptr,
                              int forward)
{
  struct select_delete_context *sc = (struct select_delete_context *) ptr;
  Eterm ret;
  Eterm key;

  if (sc->erase_lastterm) {
    free_term(tb, sc->lastterm);
  }

  sc->erase_lastterm = 0;
  sc->lastterm = this_;

  if (sc->end_condition != NIL &&
      cmp_partly_bound(sc->end_condition,
                       GETKEY_WITH_POS(sc->keypos, this_->dbterm.tpl),
                       this_->dbterm.tpl) > 0) {
    return 0;
  }

  ret = db_match_dbterm(&tb->common, sc->p, sc->mp, 0,
                        &this_->dbterm, nullptr, 0);

  if (ret == am_true) {
    key = GETKEY(sc->tb, this_->dbterm.tpl);
    linkout_tree(sc->tb, key, this_->dbterm.tpl);
    sc->erase_lastterm = 1;
    ++sc->accum;
  }

  if (--(sc->max) <= 0) {
    return 0;
  }

  return 1;
}

#ifdef TREE_DEBUG
static void do_dump_tree2(DbTableTree *tb, int to, void *to_arg, int show,
                          TreeDbTerm *t, int offset)
{
  if (t == nullptr) {
    return;
  }

  do_dump_tree2(tb, to, to_arg, show, t->right, offset + 4);

  if (show) {
    const char *prefix;
    Eterm term;

    if (tb->common.compress) {
      prefix = "key=";
      term = GETKEY(tb, t->dbterm.tpl);
    } else {
      prefix = "";
      term = make_tuple_rel(t->dbterm.tpl, t->dbterm.tpl);
    }

    erts_print(to, to_arg, "%*s%s%R (addr = %p, bal = %d)\n",
               offset, "", prefix, term, t->dbterm.tpl,
               t, t->balance);
  }

  do_dump_tree2(tb, to, to_arg, show, t->left, offset + 4);
}

#endif

#ifdef HARDDEBUG

void db_check_table_tree(DbTable *tbl)
{
  DbTableTree *tb = &tbl->tree;
  check_table_tree(tb, tb->root);
  check_saved_stack(tb);
  check_slot_pos(tb);
}

static TreeDbTerm *traverse_until(TreeDbTerm *t, int *current, int to)
{
  TreeDbTerm *tmp;

  if (t == nullptr) {
    return nullptr;
  }

  tmp = traverse_until(t->left, current, to);

  if (tmp != nullptr) {
    return tmp;
  }

  ++(*current);

  if (*current == to) {
    return t;
  }

  return traverse_until(t->right, current, to);
}

static void check_slot_pos(DbTableTree *tb)
{
  int pos = 0;
  TreeDbTerm *t;

  if (tb->stack.slot == 0 || tb->stack.pos == 0) {
    return;
  }

  t = traverse_until(tb->root, &pos, tb->stack.slot);

  if (t != tb->stack.array[tb->stack.pos - 1]) {
    erts_fprintf(stderr, "Slot position does not correspont with stack, "
                 "element position %d is really 0x%08X, when stack says "
                 "it's 0x%08X\n", tb->stack.slot, t,
                 tb->stack.array[tb->stack.pos - 1]);
    do_dump_tree2(tb, ERTS_PRINT_STDERR, nullptr, 1, tb->root, 0);
  }
}


static void check_saved_stack(DbTableTree *tb)
{
  TreeDbTerm *t = tb->root;
  DbTreeStack *stack = &tb->static_stack;
  int n = 0;

  if (stack->pos == 0) {
    return;
  }

  if (t != stack->array[0]) {
    erts_fprintf(stderr, "tb->stack[0] is 0x%08X, should be 0x%08X\n",
                 stack->array[0], t);
    do_dump_tree2(tb, ERTS_PRINT_STDERR, nullptr, 1, tb->root, 0);
    return;
  }

  while (n < stack->pos) {
    if (t == nullptr) {
      erts_fprintf(stderr, "nullptr pointer in tree when stack not empty,"
                   " stack depth is %d\n", n);
      do_dump_tree2(tb, ERTS_PRINT_STDERR, nullptr, 1, tb->root, 0);
      return;
    }

    n++;

    if (n < stack->pos) {
      if (stack->array[n] == t->left) {
        t = t->left;
      } else if (stack->array[n] == t->right) {
        t = t->right;
      } else {
        erts_fprintf(stderr, "tb->stack[%d] == 0x%08X does not "
                     "represent child pointer in tree!"
                     "(left == 0x%08X, right == 0x%08X\n",
                     n, tb->stack[n], t->left, t->right);
        do_dump_tree2(tb, ERTS_PRINT_STDERR, nullptr, 1, tb->root, 0);
        return;
      }
    }
  }
}

static int check_table_tree(DbTableTree *tb, TreeDbTerm *t)
{
  int lh, rh;

  if (t == nullptr) {
    return 0;
  }

  lh = check_table_tree(tb, t->left);
  rh = check_table_tree(tb, t->right);

  if ((rh - lh) != t->balance) {
    erts_fprintf(stderr, "Invalid tree balance for this_ node:\n");
    erts_fprintf(stderr, "balance = %d, left = 0x%08X, right = 0x%08X\n",
                 t->balance, t->left, t->right);
    erts_fprintf(stderr, "\nDump:\n---------------------------------\n");
    do_dump_tree2(tb, ERTS_PRINT_STDERR, nullptr, 1, t, 0);
    erts_fprintf(stderr, "\n---------------------------------\n");
  }

  return ((rh > lh) ? rh : lh) + 1;
}

#endif
