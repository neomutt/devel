/**
 * @file
 * Create/manipulate threading in emails
 *
 * @authors
 * Copyright (C) 2017 Peter Lewis <pete@muddygoat.org>
 * Copyright (C) 2017-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2017-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2019 Federico Kircheis <federico.kircheis@gmail.com>
 * Copyright (C) 2021 Eric Blake <eblake@redhat.com>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page neo_mutt_thread Create/manipulate threading in emails
 *
 * Create/manipulate threading in emails
 */

#include "config.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "mutt.h"
#include "mutt_thread.h"
#include "globals.h"
#include "mview.h"
#include "mx.h"
#include "protos.h"

/**
 * UseThreadsMethods - Choices for '$use_threads' for the index
 */
static const struct Mapping UseThreadsMethods[] = {
  // clang-format off
  { "unset",         UT_UNSET },
  { "flat",          UT_FLAT },
  { "threads",       UT_THREADS },
  { "reverse",       UT_REVERSE },
  // aliases
  { "no",            UT_FLAT },
  { "yes",           UT_THREADS },
  { NULL, 0 },
  // clang-format on
};

/// Data for the $use_threads enumeration
const struct EnumDef UseThreadsTypeDef = {
  "use_threads_type",
  4,
  (struct Mapping *) &UseThreadsMethods,
};

/**
 * mutt_thread_style - Which threading style is active?
 * @retval #UT_FLAT    No threading in use
 * @retval #UT_THREADS Normal threads (root above subthread)
 * @retval #UT_REVERSE Reverse threads (subthread above root)
 *
 * @note UT_UNSET is never returned; rather, this function considers the
 *       interaction between $use_threads and $sort.
 */
enum UseThreads mutt_thread_style(void)
{
  const unsigned char c_use_threads = cs_subset_enum(NeoMutt->sub, "use_threads");
  const enum EmailSortType c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  if (c_use_threads > UT_FLAT)
    return c_use_threads;
  if ((c_sort & SORT_MASK) != EMAIL_SORT_THREADS)
    return UT_FLAT;
  if (c_sort & SORT_REVERSE)
    return UT_REVERSE;
  return UT_THREADS;
}

/**
 * get_use_threads_str - Convert UseThreads enum to string
 * @param value Value to convert
 * @retval ptr String form of value
 */
const char *get_use_threads_str(enum UseThreads value)
{
  return mutt_map_get_name(value, UseThreadsMethods);
}

/**
 * sort_validator - Validate the "sort" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
int sort_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
  if (((value & SORT_MASK) == EMAIL_SORT_THREADS) && (value & SORT_LAST))
  {
    buf_printf(err, _("Cannot use 'last-' prefix with 'threads' for %s"), cdef->name);
    return CSR_ERR_INVALID;
  }
  return CSR_SUCCESS;
}

/**
 * is_visible - Is the message visible?
 * @param e   Email
 * @retval true The message is not hidden in some way
 */
static bool is_visible(struct Email *e)
{
  return e->vnum >= 0 || (e->collapsed && e->visible);
}

/**
 * need_display_subject - Determines whether to display a message's subject
 * @param e Email
 * @retval true The subject should be displayed
 */
static bool need_display_subject(struct Email *e)
{
  struct MuttThread *tmp = NULL;
  struct MuttThread *tree = e->thread;

  /* if the user disabled subject hiding, display it */
  const bool c_hide_thread_subject = cs_subset_bool(NeoMutt->sub, "hide_thread_subject");
  if (!c_hide_thread_subject)
    return true;

  /* if our subject is different from our parent's, display it */
  if (e->subject_changed)
    return true;

  /* if our subject is different from that of our closest previously displayed
   * sibling, display the subject */
  for (tmp = tree->prev; tmp; tmp = tmp->prev)
  {
    e = tmp->message;
    if (e && is_visible(e))
    {
      if (e->subject_changed)
        return true;
      break;
    }
  }

  /* if there is a parent-to-child subject change anywhere between us and our
   * closest displayed ancestor, display the subject */
  for (tmp = tree->parent; tmp; tmp = tmp->parent)
  {
    e = tmp->message;
    if (e)
    {
      if (is_visible(e))
        return false;
      if (e->subject_changed)
        return true;
    }
  }

  /* if we have no visible parent or previous sibling, display the subject */
  return true;
}

/**
 * linearize_tree - Flatten an email thread
 * @param tctx Threading context
 */
static void linearize_tree(struct ThreadsContext *tctx)
{
  if (!tctx || !tctx->mailbox_view)
    return;

  struct Mailbox *m = tctx->mailbox_view->mailbox;

  const bool reverse = (mutt_thread_style() == UT_REVERSE);
  struct MuttThread *tree = tctx->tree;
  struct Email **array = m->emails + (reverse ? m->msg_count - 1 : 0);

  while (tree)
  {
    while (!tree->message)
      tree = tree->child;

    *array = tree->message;
    array += reverse ? -1 : 1;

    if (tree->child)
    {
      tree = tree->child;
    }
    else
    {
      while (tree)
      {
        if (tree->next)
        {
          tree = tree->next;
          break;
        }
        else
        {
          tree = tree->parent;
        }
      }
    }
  }
}

/**
 * calculate_visibility - Are tree nodes visible
 * @param tree      Threads tree
 * @param max_depth Maximum depth to check
 *
 * this calculates whether a node is the root of a subtree that has visible
 * nodes, whether a node itself is visible, whether, if invisible, it has
 * depth anyway, and whether any of its later siblings are roots of visible
 * subtrees.  while it's at it, it frees the old thread display, so we can
 * skip parts of the tree in mutt_draw_tree() if we've decided here that we
 * don't care about them any more.
 */
static void calculate_visibility(struct MuttThread *tree, int *max_depth)
{
  if (!tree)
    return;

  struct MuttThread *tmp = NULL;
  struct MuttThread *orig_tree = tree;
  const bool c_hide_top_missing = cs_subset_bool(NeoMutt->sub, "hide_top_missing");
  const bool c_hide_missing = cs_subset_bool(NeoMutt->sub, "hide_missing");
  int hide_top_missing = c_hide_top_missing && !c_hide_missing;
  const bool c_hide_top_limited = cs_subset_bool(NeoMutt->sub, "hide_top_limited");
  const bool c_hide_limited = cs_subset_bool(NeoMutt->sub, "hide_limited");
  int hide_top_limited = c_hide_top_limited && !c_hide_limited;
  int depth = 0;

  /* we walk each level backwards to make it easier to compute next_subtree_visible */
  while (tree->next)
    tree = tree->next;
  *max_depth = 0;

  while (true)
  {
    if (depth > *max_depth)
      *max_depth = depth;

    tree->subtree_visible = 0;
    if (tree->message)
    {
      FREE(&tree->message->tree);
      if (is_visible(tree->message))
      {
        tree->deep = true;
        tree->visible = true;
        tree->message->display_subject = need_display_subject(tree->message);
        for (tmp = tree; tmp; tmp = tmp->parent)
        {
          if (tmp->subtree_visible)
          {
            tmp->deep = true;
            tmp->subtree_visible = 2;
            break;
          }
          else
          {
            tmp->subtree_visible = 1;
          }
        }
      }
      else
      {
        tree->visible = false;
        tree->deep = !c_hide_limited;
      }
    }
    else
    {
      tree->visible = false;
      tree->deep = !c_hide_missing;
    }
    tree->next_subtree_visible = tree->next && (tree->next->next_subtree_visible ||
                                                tree->next->subtree_visible);
    if (tree->child)
    {
      depth++;
      tree = tree->child;
      while (tree->next)
        tree = tree->next;
    }
    else if (tree->prev)
    {
      tree = tree->prev;
    }
    else
    {
      while (tree && !tree->prev)
      {
        depth--;
        tree = tree->parent;
      }
      if (!tree)
        break;
      tree = tree->prev;
    }
  }

  /* now fix up for the OPTHIDETOP* options if necessary */
  if (hide_top_limited || hide_top_missing)
  {
    tree = orig_tree;
    while (true)
    {
      if (!tree->visible && tree->deep && (tree->subtree_visible < 2) &&
          ((tree->message && hide_top_limited) || (!tree->message && hide_top_missing)))
      {
        tree->deep = false;
      }
      if (!tree->deep && tree->child && tree->subtree_visible)
      {
        tree = tree->child;
      }
      else if (tree->next)
      {
        tree = tree->next;
      }
      else
      {
        while (tree && !tree->next)
          tree = tree->parent;
        if (!tree)
          break;
        tree = tree->next;
      }
    }
  }
}

/**
 * mutt_thread_ctx_init - Initialize a threading context
 * @param mv Mailbox view
 * @retval ptr Threading context
 */
struct ThreadsContext *mutt_thread_ctx_init(struct MailboxView *mv)
{
  struct ThreadsContext *tctx = MUTT_MEM_CALLOC(1, struct ThreadsContext);
  tctx->mailbox_view = mv;
  return tctx;
}

/**
 * mutt_thread_ctx_free - Finalize a threading context
 * @param ptr Threading context to free
 */
void mutt_thread_ctx_free(struct ThreadsContext **ptr)
{
  if (!ptr || !*ptr)
  {
    return;
  }

  struct ThreadsContext *tctx = *ptr;

  mutt_hash_free(&tctx->hash);

  FREE(ptr);
}

/**
 * mutt_draw_tree - Draw a tree of threaded emails
 * @param tctx Threading context
 *
 * Since the graphics characters have a value >255, I have to resort to using
 * escape sequences to pass the information to print_enriched_string().  These
 * are the macros MUTT_TREE_* defined in mutt.h.
 *
 * ncurses should automatically use the default ASCII characters instead of
 * graphics chars on terminals which don't support them (see the man page for
 * curs_addch).
 */
void mutt_draw_tree(struct ThreadsContext *tctx)
{
  char *pfx = NULL, *mypfx = NULL, *arrow = NULL, *myarrow = NULL, *new_tree = NULL;
  const bool reverse = (mutt_thread_style() == UT_REVERSE);
  enum TreeChar corner = reverse ? MUTT_TREE_ULCORNER : MUTT_TREE_LLCORNER;
  enum TreeChar vtee = reverse ? MUTT_TREE_BTEE : MUTT_TREE_TTEE;
  const bool c_narrow_tree = cs_subset_bool(NeoMutt->sub, "narrow_tree");
  int depth = 0, start_depth = 0, max_depth = 0, width = c_narrow_tree ? 1 : 2;
  struct MuttThread *nextdisp = NULL, *pseudo = NULL, *parent = NULL;

  struct MuttThread *tree = tctx->tree;

  /* Do the visibility calculations and free the old thread chars.
   * From now on we can simply ignore invisible subtrees */
  calculate_visibility(tree, &max_depth);
  pfx = MUTT_MEM_MALLOC((width * max_depth) + 2, char);
  arrow = MUTT_MEM_MALLOC((width * max_depth) + 2, char);
  const bool c_hide_limited = cs_subset_bool(NeoMutt->sub, "hide_limited");
  const bool c_hide_missing = cs_subset_bool(NeoMutt->sub, "hide_missing");
  while (tree)
  {
    if (depth != 0)
    {
      myarrow = arrow + (depth - start_depth - ((start_depth != 0) ? 0 : 1)) * width;
      if (start_depth == depth)
        myarrow[0] = nextdisp ? MUTT_TREE_LTEE : corner;
      else if (parent->message && !c_hide_limited)
        myarrow[0] = MUTT_TREE_HIDDEN;
      else if (!parent->message && !c_hide_missing)
        myarrow[0] = MUTT_TREE_MISSING;
      else
        myarrow[0] = vtee;
      if (width == 2)
      {
        myarrow[1] = pseudo ? MUTT_TREE_STAR :
                              (tree->duplicate_thread ? MUTT_TREE_EQUALS : MUTT_TREE_HLINE);
      }
      if (tree->visible)
      {
        myarrow[width] = MUTT_TREE_RARROW;
        myarrow[width + 1] = 0;
        new_tree = MUTT_MEM_MALLOC(((size_t) depth * width) + 2, char);
        if (start_depth > 1)
        {
          strncpy(new_tree, pfx, (size_t) width * (start_depth - 1));
          mutt_str_copy(new_tree + (start_depth - 1) * width, arrow,
                        (1 + depth - start_depth) * width + 2);
        }
        else
        {
          mutt_str_copy(new_tree, arrow, ((size_t) depth * width) + 2);
        }
        tree->message->tree = new_tree;
      }
    }
    if (tree->child && (depth != 0))
    {
      mypfx = pfx + (depth - 1) * width;
      mypfx[0] = nextdisp ? MUTT_TREE_VLINE : MUTT_TREE_SPACE;
      if (width == 2)
        mypfx[1] = MUTT_TREE_SPACE;
    }
    parent = tree;
    nextdisp = NULL;
    pseudo = NULL;
    do
    {
      if (tree->child && tree->subtree_visible)
      {
        if (tree->deep)
          depth++;
        if (tree->visible)
          start_depth = depth;
        tree = tree->child;

        /* we do this here because we need to make sure that the first child thread
         * of the old tree that we deal with is actually displayed if any are,
         * or we might set the parent variable wrong while going through it. */
        while (!tree->subtree_visible && tree->next)
          tree = tree->next;
      }
      else
      {
        while (!tree->next && tree->parent)
        {
          if (tree == pseudo)
            pseudo = NULL;
          if (tree == nextdisp)
            nextdisp = NULL;
          if (tree->visible)
            start_depth = depth;
          tree = tree->parent;
          if (tree->deep)
          {
            if (start_depth == depth)
              start_depth--;
            depth--;
          }
        }
        if (tree == pseudo)
          pseudo = NULL;
        if (tree == nextdisp)
          nextdisp = NULL;
        if (tree->visible)
          start_depth = depth;
        tree = tree->next;
        if (!tree)
          break;
      }
      if (!pseudo && tree->fake_thread)
        pseudo = tree;
      if (!nextdisp && tree->next_subtree_visible)
        nextdisp = tree;
    } while (!tree->deep);
  }

  FREE(&pfx);
  FREE(&arrow);
}

/**
 * make_subject_list - Create a sorted list of all subjects in a thread
 * @param[out] subjects String List of subjects
 * @param[in]  cur      Email Thread
 * @param[out] dateptr  Earliest date found in thread
 *
 * Since we may be trying to attach as a pseudo-thread a MuttThread that has no
 * message, we have to make a list of all the subjects of its most immediate
 * existing descendants.
 */
static void make_subject_list(struct ListHead *subjects, struct MuttThread *cur, time_t *dateptr)
{
  struct MuttThread *start = cur;
  struct Envelope *env = NULL;
  time_t thisdate;
  int rc = 0;

  const bool c_thread_received = cs_subset_bool(NeoMutt->sub, "thread_received");
  const bool c_sort_re = cs_subset_bool(NeoMutt->sub, "sort_re");
  while (true)
  {
    while (!cur->message)
      cur = cur->child;

    if (dateptr)
    {
      thisdate = c_thread_received ? cur->message->received : cur->message->date_sent;
      if ((*dateptr == 0) || (thisdate < *dateptr))
        *dateptr = thisdate;
    }

    env = cur->message->env;
    if (env->real_subj && ((env->real_subj != env->subject) || !c_sort_re))
    {
      struct ListNode *np = NULL;
      STAILQ_FOREACH(np, subjects, entries)
      {
        rc = mutt_str_cmp(env->real_subj, np->data);
        if (rc >= 0)
          break;
      }
      if (!np)
        mutt_list_insert_head(subjects, env->real_subj);
      else if (rc > 0)
        mutt_list_insert_after(subjects, np, env->real_subj);
    }

    while (!cur->next && (cur != start))
    {
      cur = cur->parent;
    }
    if (cur == start)
      break;
    cur = cur->next;
  }
}

/**
 * find_subject - Find the best possible match for a parent based on subject
 * @param m   Mailbox
 * @param cur Email to match
 * @retval ptr Best match for a parent
 *
 * If there are multiple matches, the one which was sent the latest, but before
 * the current message, is used.
 */
static struct MuttThread *find_subject(struct Mailbox *m, struct MuttThread *cur)
{
  if (!m)
    return NULL;

  struct HashElem *he = NULL;
  struct MuttThread *tmp = NULL, *last = NULL;
  struct ListHead subjects = STAILQ_HEAD_INITIALIZER(subjects);
  time_t date = 0;

  make_subject_list(&subjects, cur, &date);

  struct ListNode *np = NULL;
  const bool c_thread_received = cs_subset_bool(NeoMutt->sub, "thread_received");
  STAILQ_FOREACH(np, &subjects, entries)
  {
    for (he = mutt_hash_find_bucket(m->subj_hash, np->data); he; he = he->next)
    {
      tmp = ((struct Email *) he->data)->thread;
      if ((tmp != cur) &&                  /* don't match the same message */
          !tmp->fake_thread &&             /* don't match pseudo threads */
          tmp->message->subject_changed && /* only match interesting replies */
          !is_descendant(tmp, cur) &&      /* don't match in the same thread */
          (date >= (c_thread_received ? tmp->message->received : tmp->message->date_sent)) &&
          (!last || (c_thread_received ?
                         (last->message->received < tmp->message->received) :
                         (last->message->date_sent < tmp->message->date_sent))) &&
          tmp->message->env->real_subj &&
          mutt_str_equal(np->data, tmp->message->env->real_subj))
      {
        last = tmp; /* best match so far */
      }
    }
  }

  mutt_list_clear(&subjects);
  return last;
}

/**
 * make_subj_hash - Create a Hash Table for the email subjects
 * @param m Mailbox
 * @retval ptr Newly allocated Hash Table
 */
static struct HashTable *make_subj_hash(struct Mailbox *m)
{
  if (!m)
    return NULL;

  struct HashTable *hash = mutt_hash_new(m->msg_count * 2, MUTT_HASH_ALLOW_DUPS);

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e || !e->env)
      continue;
    if (e->env->real_subj)
      mutt_hash_insert(hash, e->env->real_subj, e);
  }

  return hash;
}

/**
 * pseudo_threads - Thread messages by subject
 * @param tctx Threading context
 *
 * Thread by subject things that didn't get threaded by message-id
 */
static void pseudo_threads(struct ThreadsContext *tctx)
{
  if (!tctx || !tctx->mailbox_view)
    return;

  struct Mailbox *m = tctx->mailbox_view->mailbox;

  struct MuttThread *tree = tctx->tree;
  struct MuttThread *top = tree;
  struct MuttThread *tmp = NULL, *cur = NULL, *parent = NULL, *curchild = NULL,
                    *nextchild = NULL;

  if (!m->subj_hash)
    m->subj_hash = make_subj_hash(m);

  while (tree)
  {
    cur = tree;
    tree = tree->next;
    parent = find_subject(m, cur);
    if (parent)
    {
      cur->fake_thread = true;
      unlink_message(&top, cur);
      insert_message(&parent->child, parent, cur);
      parent->sort_children = true;
      tmp = cur;
      while (true)
      {
        while (!tmp->message)
          tmp = tmp->child;

        /* if the message we're attaching has pseudo-children, they
         * need to be attached to its parent, so move them up a level.
         * but only do this if they have the same real subject as the
         * parent, since otherwise they rightly belong to the message
         * we're attaching. */
        if ((tmp == cur) || mutt_str_equal(tmp->message->env->real_subj,
                                           parent->message->env->real_subj))
        {
          tmp->message->subject_changed = false;

          for (curchild = tmp->child; curchild;)
          {
            nextchild = curchild->next;
            if (curchild->fake_thread)
            {
              unlink_message(&tmp->child, curchild);
              insert_message(&parent->child, parent, curchild);
            }
            curchild = nextchild;
          }
        }

        while (!tmp->next && (tmp != cur))
        {
          tmp = tmp->parent;
        }
        if (tmp == cur)
          break;
        tmp = tmp->next;
      }
    }
  }
  tctx->tree = top;
}

/**
 * mutt_clear_threads - Clear the threading of message in a mailbox
 * @param tctx Threading context
 */
void mutt_clear_threads(struct ThreadsContext *tctx)
{
  if (!tctx || !tctx->tree)
    return;

  struct MailboxView *mv = tctx->mailbox_view;
  if (!mv)
    return;

  struct Mailbox *m = mv->mailbox;
  if (!m || !m->emails)
    return;

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    /* mailbox may have been only partially read */
    e->thread = NULL;
    e->threaded = false;
  }
  tctx->tree = NULL;
  mutt_hash_free(&tctx->hash);
}

/**
 * compare_threads - Helper to sort email threads - Implements ::sort_t - @ingroup sort_api
 */
static int compare_threads(const void *a, const void *b, void *sdata)
{
  const struct MuttThread *ta = *(struct MuttThread const *const *) a;
  const struct MuttThread *tb = *(struct MuttThread const *const *) b;
  const struct ThreadsContext *tctx = sdata;
  ASSERT(ta->parent == tb->parent);

  /* If c_sort ties, remember we are building the thread array in
   * reverse from the index the mails had in the mailbox.  */
  struct Mailbox *m = tctx->mailbox_view->mailbox;
  const enum MailboxType mtype = mx_type(m);
  if (ta->parent)
  {
    return mutt_compare_emails(ta->sort_aux_key, tb->sort_aux_key, mtype,
                               tctx->c_sort_aux, SORT_REVERSE | EMAIL_SORT_UNSORTED);
  }
  else
  {
    return mutt_compare_emails(ta->sort_thread_key, tb->sort_thread_key, mtype,
                               tctx->c_sort, SORT_REVERSE | EMAIL_SORT_UNSORTED);
  }
}

/**
 * mutt_sort_subthreads - Sort the children of a thread
 * @param tctx Threading context
 * @param init If true, rebuild the thread
 */
static void mutt_sort_subthreads(struct ThreadsContext *tctx, bool init)
{
  struct MuttThread *thread = tctx->tree;
  if (!thread)
    return;

  struct MuttThread **array = NULL, *top = NULL, *tmp = NULL;
  struct Email *sort_aux_key = NULL, *oldsort_aux_key = NULL;
  struct Email *oldsort_thread_key = NULL;
  int i, array_size;
  bool sort_top = false;

  /* we put things into the array backwards to save some cycles,
   * but we want to have to move less stuff around if we're
   * resorting, so we sort backwards and then put them back
   * in reverse order so they're forwards */
  const bool reverse = (mutt_thread_style() == UT_REVERSE);
  enum EmailSortType c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  enum EmailSortType c_sort_aux = cs_subset_sort(NeoMutt->sub, "sort_aux");
  if ((c_sort & SORT_MASK) == EMAIL_SORT_THREADS)
  {
    ASSERT(!(c_sort & SORT_REVERSE) != reverse);
    c_sort = c_sort_aux;
  }
  c_sort ^= SORT_REVERSE;
  c_sort_aux ^= SORT_REVERSE;
  if (init || (tctx->c_sort != c_sort) || (tctx->c_sort_aux != c_sort_aux))
  {
    tctx->c_sort = c_sort;
    tctx->c_sort_aux = c_sort_aux;
    init = true;
  }

  top = thread;

  array_size = 256;
  array = MUTT_MEM_CALLOC(array_size, struct MuttThread *);
  while (true)
  {
    if (init || !thread->sort_thread_key || !thread->sort_aux_key)
    {
      thread->sort_thread_key = NULL;
      thread->sort_aux_key = NULL;

      if (thread->parent)
        thread->parent->sort_children = true;
      else
        sort_top = true;
    }

    if (thread->child)
    {
      thread = thread->child;
      continue;
    }
    else
    {
      /* if it has no children, it must be real. sort it on its own merits */
      thread->sort_thread_key = thread->message;
      thread->sort_aux_key = thread->message;

      if (thread->next)
      {
        thread = thread->next;
        continue;
      }
    }

    struct Mailbox *m = tctx->mailbox_view->mailbox;
    const enum MailboxType mtype = mx_type(m);
    while (!thread->next)
    {
      /* if it has siblings and needs to be sorted, sort it... */
      if (thread->prev && (thread->parent ? thread->parent->sort_children : sort_top))
      {
        /* put them into the array */
        for (i = 0; thread; i++, thread = thread->prev)
        {
          if (i >= array_size)
          {
            array_size *= 2;
            MUTT_MEM_REALLOC(&array, array_size, struct MuttThread *);
          }

          array[i] = thread;
        }

        mutt_qsort_r((void *) array, i, sizeof(struct MuttThread *), compare_threads, tctx);

        /* attach them back together.  make thread the last sibling. */
        thread = array[0];
        thread->next = NULL;
        array[i - 1]->prev = NULL;

        if (thread->parent)
          thread->parent->child = array[i - 1];
        else
          top = array[i - 1];

        while (--i)
        {
          array[i - 1]->prev = array[i];
          array[i]->next = array[i - 1];
        }
      }

      if (thread->parent)
      {
        tmp = thread;
        thread = thread->parent;

        if (!thread->sort_thread_key || !thread->sort_aux_key || thread->sort_children)
        {
          /* we just sorted its children */
          thread->sort_children = false;

          oldsort_aux_key = thread->sort_aux_key;
          oldsort_thread_key = thread->sort_thread_key;

          /* update sort keys. sort_aux_key will be the first or last
           * sibling, as appropriate... */
          thread->sort_aux_key = thread->message;
          sort_aux_key = ((!(c_sort_aux & SORT_LAST)) ^ (!(c_sort_aux & SORT_REVERSE))) ?
                             thread->child->sort_aux_key :
                             tmp->sort_aux_key;

          if (c_sort_aux & SORT_LAST)
          {
            if (!thread->sort_aux_key ||
                (mutt_compare_emails(thread->sort_aux_key, sort_aux_key, mtype,
                                     c_sort_aux | SORT_REVERSE, EMAIL_SORT_UNSORTED) > 0))
            {
              thread->sort_aux_key = sort_aux_key;
            }
          }
          else if (!thread->sort_aux_key)
          {
            thread->sort_aux_key = sort_aux_key;
          }

          /* ...but sort_thread_key may require searching the entire
           * list of siblings */
          if ((c_sort_aux & ~SORT_REVERSE) == (c_sort & ~SORT_REVERSE))
          {
            thread->sort_thread_key = thread->sort_aux_key;
          }
          else
          {
            if (thread->message)
            {
              thread->sort_thread_key = thread->message;
            }
            else if (reverse != (!(c_sort_aux & SORT_REVERSE)))
            {
              thread->sort_thread_key = tmp->sort_thread_key;
            }
            else
            {
              thread->sort_thread_key = thread->child->sort_thread_key;
            }
            if (c_sort & SORT_LAST)
            {
              for (tmp = thread->child; tmp; tmp = tmp->next)
              {
                if (tmp->sort_thread_key == thread->sort_thread_key)
                  continue;
                if ((mutt_compare_emails(thread->sort_thread_key, tmp->sort_thread_key, mtype,
                                         c_sort | SORT_REVERSE, EMAIL_SORT_UNSORTED) > 0))
                {
                  thread->sort_thread_key = tmp->sort_thread_key;
                }
              }
            }
          }

          /* if a sort_key has changed, we need to resort it and siblings */
          if ((oldsort_aux_key != thread->sort_aux_key) ||
              (oldsort_thread_key != thread->sort_thread_key))
          {
            if (thread->parent)
              thread->parent->sort_children = true;
            else
              sort_top = true;
          }
        }
      }
      else
      {
        FREE(&array);
        tctx->tree = top;
        return;
      }
    }

    thread = thread->next;
  }
}

/**
 * check_subjects - Find out which emails' subjects differ from their parent's
 * @param mv   Mailbox View
 * @param init If true, rebuild the thread
 */
static void check_subjects(struct MailboxView *mv, bool init)
{
  if (!mv)
    return;

  struct Mailbox *m = mv->mailbox;
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e || !e->thread)
      continue;

    if (e->thread->check_subject)
      e->thread->check_subject = false;
    else if (!init)
      continue;

    /* figure out which messages have subjects different than their parents' */
    struct MuttThread *tmp = e->thread->parent;
    while (tmp && !tmp->message)
    {
      tmp = tmp->parent;
    }

    if (!tmp)
    {
      e->subject_changed = true;
    }
    else if (e->env->real_subj && tmp->message->env->real_subj)
    {
      e->subject_changed = !mutt_str_equal(e->env->real_subj, tmp->message->env->real_subj);
    }
    else
    {
      e->subject_changed = (e->env->real_subj || tmp->message->env->real_subj);
    }
  }
}

/**
 * thread_hash_destructor - Free our hash table data - Implements ::hash_hdata_free_t - @ingroup hash_hdata_free_api
 */
static void thread_hash_destructor(int type, void *obj, intptr_t data)
{
  FREE(&obj);
}

/**
 * mutt_sort_threads - Sort email threads
 * @param tctx Threading context
 * @param init If true, rebuild the thread
 */
void mutt_sort_threads(struct ThreadsContext *tctx, bool init)
{
  if (!tctx || !tctx->mailbox_view)
    return;

  struct MailboxView *mv = tctx->mailbox_view;
  struct Mailbox *m = mv->mailbox;

  struct Email *e = NULL;
  int i, using_refs = 0;
  struct MuttThread *thread = NULL, *tnew = NULL, *tmp = NULL;
  struct MuttThread top = { 0 };
  struct ListNode *ref = NULL;

  ASSERT(m->msg_count > 0);
  if (!tctx->hash)
    init = true;

  if (init)
  {
    tctx->hash = mutt_hash_new(m->msg_count * 2, MUTT_HASH_ALLOW_DUPS);
    mutt_hash_set_destructor(tctx->hash, thread_hash_destructor, 0);
  }

  /* we want a quick way to see if things are actually attached to the top of the
   * thread tree or if they're just dangling, so we attach everything to a top
   * node temporarily */
  top.parent = NULL;
  top.next = NULL;
  top.prev = NULL;

  top.child = tctx->tree;
  for (thread = tctx->tree; thread; thread = thread->next)
    thread->parent = &top;

  /* put each new message together with the matching messageless MuttThread if it
   * exists.  otherwise, if there is a MuttThread that already has a message, thread
   * new message as an identical child.  if we didn't attach the message to a
   * MuttThread, make a new one for it. */
  const bool c_duplicate_threads = cs_subset_bool(NeoMutt->sub, "duplicate_threads");
  for (i = 0; i < m->msg_count; i++)
  {
    e = m->emails[i];
    if (!e)
      continue;

    if (e->thread)
    {
      /* unlink pseudo-threads because they might be children of newly
       * arrived messages */
      thread = e->thread;
      for (tnew = thread->child; tnew;)
      {
        tmp = tnew->next;
        if (tnew->fake_thread)
        {
          unlink_message(&thread->child, tnew);
          insert_message(&top.child, &top, tnew);
          tnew->fake_thread = false;
        }
        tnew = tmp;
      }
    }
    else
    {
      if ((!init || c_duplicate_threads) && e->env->message_id)
        thread = mutt_hash_find(tctx->hash, e->env->message_id);
      else
        thread = NULL;

      if (thread && !thread->message)
      {
        /* this is a message which was missing before */
        thread->message = e;
        e->thread = thread;
        thread->check_subject = true;

        /* mark descendants as needing subject_changed checked */
        for (tmp = (thread->child ? thread->child : thread); tmp != thread;)
        {
          while (!tmp->message)
            tmp = tmp->child;
          tmp->check_subject = true;
          while (!tmp->next && (tmp != thread))
            tmp = tmp->parent;
          if (tmp != thread)
            tmp = tmp->next;
        }

        if (thread->parent)
        {
          /* remove threading info above it based on its children, which we'll
           * recalculate based on its headers.  make sure not to leave
           * dangling missing messages.  note that we haven't kept track
           * of what info came from its children and what from its siblings'
           * children, so we just remove the stuff that's definitely from it */
          do
          {
            tmp = thread->parent;
            unlink_message(&tmp->child, thread);
            thread->parent = NULL;
            thread->sort_thread_key = NULL;
            thread->sort_aux_key = NULL;
            thread->fake_thread = false;
            thread = tmp;
          } while (thread != &top && !thread->child && !thread->message);
        }
      }
      else
      {
        tnew = (c_duplicate_threads ? thread : NULL);

        thread = MUTT_MEM_CALLOC(1, struct MuttThread);
        thread->message = e;
        thread->check_subject = true;
        e->thread = thread;
        mutt_hash_insert(tctx->hash, e->env->message_id ? e->env->message_id : "", thread);

        if (tnew)
        {
          if (tnew->duplicate_thread)
            tnew = tnew->parent;

          thread = e->thread;

          insert_message(&tnew->child, tnew, thread);
          thread->duplicate_thread = true;
          thread->message->threaded = true;
        }
      }
    }
  }

  /* thread by references */
  for (i = 0; i < m->msg_count; i++)
  {
    e = m->emails[i];
    if (!e)
      break;

    if (e->threaded)
      continue;
    e->threaded = true;

    thread = e->thread;
    if (!thread)
      continue;
    using_refs = 0;

    while (true)
    {
      if (using_refs == 0)
      {
        /* look at the beginning of in-reply-to: */
        ref = STAILQ_FIRST(&e->env->in_reply_to);
        if (ref)
        {
          using_refs = 1;
        }
        else
        {
          ref = STAILQ_FIRST(&e->env->references);
          using_refs = 2;
        }
      }
      else if (using_refs == 1)
      {
        /* if there's no references header, use all the in-reply-to:
         * data that we have.  otherwise, use the first reference
         * if it's different than the first in-reply-to, otherwise use
         * the second reference (since at least eudora puts the most
         * recent reference in in-reply-to and the rest in references) */
        if (STAILQ_EMPTY(&e->env->references))
        {
          ref = STAILQ_NEXT(ref, entries);
        }
        else
        {
          if (!mutt_str_equal(ref->data, STAILQ_FIRST(&e->env->references)->data))
            ref = STAILQ_FIRST(&e->env->references);
          else
            ref = STAILQ_NEXT(STAILQ_FIRST(&e->env->references), entries);

          using_refs = 2;
        }
      }
      else
      {
        ref = STAILQ_NEXT(ref, entries); /* go on with references */
      }

      if (!ref)
        break;

      tnew = mutt_hash_find(tctx->hash, ref->data);
      if (tnew)
      {
        if (tnew->duplicate_thread)
          tnew = tnew->parent;
        if (is_descendant(tnew, thread)) /* no loops! */
          continue;
      }
      else
      {
        tnew = MUTT_MEM_CALLOC(1, struct MuttThread);
        mutt_hash_insert(tctx->hash, ref->data, tnew);
      }

      if (thread->parent)
        unlink_message(&top.child, thread);
      insert_message(&tnew->child, tnew, thread);
      thread = tnew;
      if (thread->message || (thread->parent && (thread->parent != &top)))
        break;
    }

    if (!thread->parent)
      insert_message(&top.child, &top, thread);
  }

  /* detach everything from the temporary top node */
  for (thread = top.child; thread; thread = thread->next)
  {
    thread->parent = NULL;
  }
  tctx->tree = top.child;

  check_subjects(mv, init);

  const bool c_strict_threads = cs_subset_bool(NeoMutt->sub, "strict_threads");
  if (!c_strict_threads)
    pseudo_threads(tctx);

  /* if $sort_aux or similar changed after the mailbox is sorted, then
   * all the subthreads need to be resorted */
  if (tctx->tree)
  {
    mutt_sort_subthreads(tctx, init || OptSortSubthreads);
    OptSortSubthreads = false;

    /* Put the list into an array. */
    linearize_tree(tctx);

    /* Draw the thread tree. */
    mutt_draw_tree(tctx);
  }
}

/**
 * mutt_aside_thread - Find the next/previous (sub)thread
 * @param e          Search from this Email
 * @param forwards   Direction to search: 'true' forwards, 'false' backwards
 * @param subthreads Search subthreads: 'true' subthread, 'false' not
 * @retval num Index into the virtual email table
 * @retval  -1 Error
 */
int mutt_aside_thread(struct Email *e, bool forwards, bool subthreads)
{
  if (!e)
    return -1;

  struct MuttThread *cur = NULL;
  struct Email *e_tmp = NULL;

  const enum UseThreads threaded = mutt_thread_style();
  if (threaded == UT_FLAT)
  {
    mutt_error(_("Threading is not enabled"));
    return e->vnum;
  }

  cur = e->thread;

  if (subthreads)
  {
    if (forwards ^ (threaded == UT_REVERSE))
    {
      while (!cur->next && cur->parent)
        cur = cur->parent;
    }
    else
    {
      while (!cur->prev && cur->parent)
        cur = cur->parent;
    }
  }
  else
  {
    while (cur->parent)
      cur = cur->parent;
  }

  if (forwards ^ (threaded == UT_REVERSE))
  {
    do
    {
      cur = cur->next;
      if (!cur)
        return -1;
      e_tmp = find_virtual(cur, false);
    } while (!e_tmp);
  }
  else
  {
    do
    {
      cur = cur->prev;
      if (!cur)
        return -1;
      e_tmp = find_virtual(cur, true);
    } while (!e_tmp);
  }

  return e_tmp->vnum;
}

/**
 * mutt_parent_message - Find the parent of a message
 * @param e         Current Email
 * @param find_root If true, find the root message
 * @retval >=0 Virtual index number of parent/root message
 * @retval -1 Error
 */
int mutt_parent_message(struct Email *e, bool find_root)
{
  if (!e)
    return -1;

  struct MuttThread *thread = NULL;
  struct Email *e_parent = NULL;

  if (!mutt_using_threads())
  {
    mutt_error(_("Threading is not enabled"));
    return e->vnum;
  }

  /* Root may be the current message */
  if (find_root)
    e_parent = e;

  for (thread = e->thread->parent; thread; thread = thread->parent)
  {
    e = thread->message;
    if (e)
    {
      e_parent = e;
      if (!find_root)
        break;
    }
  }

  if (!e_parent)
  {
    mutt_error(_("Parent message is not available"));
    return -1;
  }
  if (!is_visible(e_parent))
  {
    if (find_root)
      mutt_error(_("Root message is not visible in this limited view"));
    else
      mutt_error(_("Parent message is not visible in this limited view"));
    return -1;
  }
  return e_parent->vnum;
}

/**
 * mutt_set_vnum - Set the virtual index number of all the messages in a mailbox
 * @param m       Mailbox
 * @retval num Size in bytes of all messages shown
 */
off_t mutt_set_vnum(struct Mailbox *m)
{
  if (!m)
    return 0;

  off_t vsize = 0;
  const int padding = mx_msg_padding_size(m);

  m->vcount = 0;

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    if (e->vnum >= 0)
    {
      e->vnum = m->vcount;
      m->v2r[m->vcount] = i;
      m->vcount++;
      vsize += e->body->length + e->body->offset - e->body->hdr_offset + padding;
    }
  }

  return vsize;
}

/**
 * mutt_traverse_thread - Recurse through an email thread, matching messages
 * @param e_cur Current Email
 * @param flag  Flag to set, see #MuttThreadFlags
 * @retval num Number of matches
 */
int mutt_traverse_thread(struct Email *e_cur, MuttThreadFlags flag)
{
  struct MuttThread *thread = NULL, *top = NULL;
  struct Email *e_root = NULL;
  const enum UseThreads threaded = mutt_thread_style();
  int final, reverse = (threaded == UT_REVERSE), minmsgno;
  int num_hidden = 0, new_mail = 0, old_mail = 0;
  bool flagged = false;
  int min_unread_msgno = INT_MAX, min_unread = e_cur->vnum;

  if (threaded == UT_FLAT)
  {
    mutt_error(_("Threading is not enabled"));
    return e_cur->vnum;
  }

  if (!e_cur->thread)
  {
    return e_cur->vnum;
  }

  final = e_cur->vnum;
  thread = e_cur->thread;
  while (thread->parent)
    thread = thread->parent;
  top = thread;
  while (!thread->message)
    thread = thread->child;
  e_cur = thread->message;
  minmsgno = e_cur->msgno;

  if (!e_cur->read && e_cur->visible)
  {
    if (e_cur->old)
      old_mail = 2;
    else
      new_mail = 1;
    if (e_cur->msgno < min_unread_msgno)
    {
      min_unread = e_cur->vnum;
      min_unread_msgno = e_cur->msgno;
    }
  }

  if (e_cur->flagged && e_cur->visible)
    flagged = true;

  if ((e_cur->vnum == -1) && e_cur->visible)
    num_hidden++;

  if (flag & (MUTT_THREAD_COLLAPSE | MUTT_THREAD_UNCOLLAPSE))
  {
    e_cur->attr_color = NULL; /* force index entry's color to be re-evaluated */
    e_cur->collapsed = flag & MUTT_THREAD_COLLAPSE;
    if (e_cur->vnum != -1)
    {
      e_root = e_cur;
      if (flag & MUTT_THREAD_COLLAPSE)
        final = e_root->vnum;
    }
  }

  if ((thread == top) && !(thread = thread->child))
  {
    /* return value depends on action requested */
    if (flag & (MUTT_THREAD_COLLAPSE | MUTT_THREAD_UNCOLLAPSE))
    {
      e_cur->num_hidden = num_hidden;
      return final;
    }
    if (flag & MUTT_THREAD_UNREAD)
      return (old_mail && new_mail) ? new_mail : (old_mail ? old_mail : new_mail);
    if (flag & MUTT_THREAD_NEXT_UNREAD)
      return min_unread;
    if (flag & MUTT_THREAD_FLAGGED)
      return flagged;
  }

  while (true)
  {
    e_cur = thread->message;

    if (e_cur)
    {
      if (flag & (MUTT_THREAD_COLLAPSE | MUTT_THREAD_UNCOLLAPSE))
      {
        e_cur->attr_color = NULL; /* force index entry's color to be re-evaluated */
        e_cur->collapsed = flag & MUTT_THREAD_COLLAPSE;
        if (!e_root && e_cur->visible)
        {
          e_root = e_cur;
          if (flag & MUTT_THREAD_COLLAPSE)
            final = e_root->vnum;
        }

        if (reverse && (flag & MUTT_THREAD_COLLAPSE) &&
            (e_cur->msgno < minmsgno) && e_cur->visible)
        {
          minmsgno = e_cur->msgno;
          final = e_cur->vnum;
        }

        if (flag & MUTT_THREAD_COLLAPSE)
        {
          if (e_cur != e_root)
            e_cur->vnum = -1;
        }
        else
        {
          if (e_cur->visible)
            e_cur->vnum = e_cur->msgno;
        }
      }

      if (!e_cur->read && e_cur->visible)
      {
        if (e_cur->old)
          old_mail = 2;
        else
          new_mail = 1;
        if (e_cur->msgno < min_unread_msgno)
        {
          min_unread = e_cur->vnum;
          min_unread_msgno = e_cur->msgno;
        }
      }

      if (e_cur->flagged && e_cur->visible)
        flagged = true;

      if ((e_cur->vnum == -1) && e_cur->visible)
        num_hidden++;
    }

    if (thread->child)
    {
      thread = thread->child;
    }
    else if (thread->next)
    {
      thread = thread->next;
    }
    else
    {
      bool done = false;
      while (!thread->next)
      {
        thread = thread->parent;
        if (thread == top)
        {
          done = true;
          break;
        }
      }
      if (done)
        break;
      thread = thread->next;
    }
  }

  /* re-traverse the thread and store num_hidden in all headers, with or
   * without a virtual index.  this will allow ~v to match all collapsed
   * messages when switching sort order to non-threaded.  */
  if (flag & MUTT_THREAD_COLLAPSE)
  {
    thread = top;
    while (true)
    {
      e_cur = thread->message;
      if (e_cur)
        e_cur->num_hidden = num_hidden + 1;

      if (thread->child)
      {
        thread = thread->child;
      }
      else if (thread->next)
      {
        thread = thread->next;
      }
      else
      {
        bool done = false;
        while (!thread->next)
        {
          thread = thread->parent;
          if (thread == top)
          {
            done = true;
            break;
          }
        }
        if (done)
          break;
        thread = thread->next;
      }
    }
  }

  /* return value depends on action requested */
  if (flag & (MUTT_THREAD_COLLAPSE | MUTT_THREAD_UNCOLLAPSE))
    return final;
  if (flag & MUTT_THREAD_UNREAD)
    return (old_mail && new_mail) ? new_mail : (old_mail ? old_mail : new_mail);
  if (flag & MUTT_THREAD_NEXT_UNREAD)
    return min_unread;
  if (flag & MUTT_THREAD_FLAGGED)
    return flagged;

  return 0;
}

/**
 * mutt_messages_in_thread - Count the messages in a thread
 * @param m    Mailbox
 * @param e    Email
 * @param mit  Flag, e.g. #MIT_NUM_MESSAGES
 * @retval num Number of message / Our position
 */
int mutt_messages_in_thread(struct Mailbox *m, struct Email *e, enum MessageInThread mit)
{
  if (!m || !e)
    return 1;

  struct MuttThread *threads[2];
  int rc;

  const enum UseThreads threaded = mutt_thread_style();
  if ((threaded == UT_FLAT) || !e->thread)
    return 1;

  threads[0] = e->thread;
  while (threads[0]->parent)
    threads[0] = threads[0]->parent;

  threads[1] = (mit == MIT_POSITION) ? e->thread : threads[0]->next;

  for (int i = 0; i < (((mit == MIT_POSITION) || !threads[1]) ? 1 : 2); i++)
  {
    while (!threads[i]->message)
      threads[i] = threads[i]->child;
  }

  if (threaded == UT_REVERSE)
  {
    rc = threads[0]->message->msgno - (threads[1] ? threads[1]->message->msgno : -1);
  }
  else
  {
    rc = (threads[1] ? threads[1]->message->msgno : m->msg_count) -
         threads[0]->message->msgno;
  }

  if (mit == MIT_POSITION)
    rc += 1;

  return rc;
}

/**
 * mutt_make_id_hash - Create a Hash Table for message-ids
 * @param m Mailbox
 * @retval ptr Newly allocated Hash Table
 */
struct HashTable *mutt_make_id_hash(struct Mailbox *m)
{
  struct HashTable *hash = mutt_hash_new(m->msg_count * 2, MUTT_HASH_NO_FLAGS);

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e || !e->env)
      continue;

    if (e->env->message_id)
      mutt_hash_insert(hash, e->env->message_id, e);
  }

  return hash;
}

/**
 * link_threads - Forcibly link messages together
 * @param parent Parent Email
 * @param child  Child Email
 * @param m      Mailbox
 * @retval true On success
 */
static bool link_threads(struct Email *parent, struct Email *child, struct Mailbox *m)
{
  if (child == parent)
    return false;

  mutt_break_thread(child);
  mutt_list_insert_head(&child->env->in_reply_to, mutt_str_dup(parent->env->message_id));
  mutt_set_flag(m, child, MUTT_TAG, false, true);

  child->changed = true;
  child->env->changed |= MUTT_ENV_CHANGED_IRT;
  return true;
}

/**
 * mutt_link_threads - Forcibly link threads together
 * @param parent   Parent Email
 * @param children Array of children Emails
 * @param m        Mailbox
 * @retval true On success
 */
bool mutt_link_threads(struct Email *parent, struct EmailArray *children, struct Mailbox *m)
{
  if (!parent || !children || !m)
    return false;

  bool changed = false;

  struct Email **ep = NULL;
  ARRAY_FOREACH(ep, children)
  {
    struct Email *e = *ep;
    changed |= link_threads(parent, e, m);
  }

  return changed;
}

/**
 * mutt_thread_collapse_collapsed - Re-collapse threads marked as collapsed
 * @param tctx Threading context
 */
void mutt_thread_collapse_collapsed(struct ThreadsContext *tctx)
{
  struct MuttThread *thread = NULL;
  struct MuttThread *top = tctx->tree;
  while ((thread = top))
  {
    while (!thread->message)
      thread = thread->child;

    struct Email *e = thread->message;
    if (e->collapsed)
      mutt_collapse_thread(e);
    top = top->next;
  }
}

/**
 * mutt_thread_collapse - Toggle collapse
 * @param tctx Threading context
 * @param collapse Collapse / uncollapse
 */
void mutt_thread_collapse(struct ThreadsContext *tctx, bool collapse)
{
  struct MuttThread *thread = NULL;
  struct MuttThread *top = tctx->tree;
  while ((thread = top))
  {
    while (!thread->message)
      thread = thread->child;

    struct Email *e = thread->message;

    if (e->collapsed != collapse)
    {
      if (e->collapsed)
        mutt_uncollapse_thread(e);
      else if (mutt_thread_can_collapse(e))
        mutt_collapse_thread(e);
    }
    top = top->next;
  }
}

/**
 * mutt_thread_can_collapse - Check whether a thread can be collapsed
 * @param e Head of the thread
 * @retval true Can be collapsed
 * @retval false Cannot be collapsed
 */
bool mutt_thread_can_collapse(struct Email *e)
{
  const bool c_collapse_flagged = cs_subset_bool(NeoMutt->sub, "collapse_flagged");
  const bool c_collapse_unread = cs_subset_bool(NeoMutt->sub, "collapse_unread");
  return (c_collapse_unread || !mutt_thread_contains_unread(e)) &&
         (c_collapse_flagged || !mutt_thread_contains_flagged(e));
}
