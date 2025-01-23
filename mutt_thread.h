/**
 * @file
 * Create/manipulate threading in emails
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
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

#ifndef MUTT_MUTT_THREAD_H
#define MUTT_MUTT_THREAD_H

#include "email/lib.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct Buffer;
struct ConfigDef;
struct ConfigSet;
struct Mailbox;
struct MailboxView;

/**
 * struct ThreadsContext - The "current" threading state
 */
struct ThreadsContext
{
  struct MailboxView *mailbox_view; ///< Current mailbox
  struct MuttThread  *tree;         ///< Top of thread tree
  struct HashTable   *hash;         ///< Hash Table: "message-id" -> MuttThread
  enum EmailSortType  c_sort;       ///< Last sort method
  enum EmailSortType  c_sort_aux;   ///< Last sort_aux method
};

/**
 * enum TreeChar - Tree characters for menus
 *
 * @sa linearize_tree(), print_enriched_string()
 */
enum TreeChar
{
  MUTT_TREE_LLCORNER = 1, ///< Lower left corner
  MUTT_TREE_ULCORNER,     ///< Upper left corner
  MUTT_TREE_LTEE,         ///< Left T-piece
  MUTT_TREE_HLINE,        ///< Horizontal line
  MUTT_TREE_VLINE,        ///< Vertical line
  MUTT_TREE_SPACE,        ///< Blank space
  MUTT_TREE_RARROW,       ///< Right arrow
  MUTT_TREE_STAR,         ///< Star character (for threads)
  MUTT_TREE_HIDDEN,       ///< Ampersand character (for threads)
  MUTT_TREE_EQUALS,       ///< Equals (for threads)
  MUTT_TREE_TTEE,         ///< Top T-piece
  MUTT_TREE_BTEE,         ///< Bottom T-piece
  MUTT_TREE_MISSING,      ///< Question mark
  MUTT_TREE_MAX,

  MUTT_SPECIAL_INDEX = MUTT_TREE_MAX, ///< Colour indicator
};

typedef uint8_t MuttThreadFlags;         ///< Flags, e.g. #MUTT_THREAD_COLLAPSE
#define MUTT_THREAD_NO_FLAGS          0  ///< No flags are set
#define MUTT_THREAD_COLLAPSE    (1 << 0) ///< Collapse an email thread
#define MUTT_THREAD_UNCOLLAPSE  (1 << 1) ///< Uncollapse an email thread
#define MUTT_THREAD_UNREAD      (1 << 2) ///< Count unread emails in a thread
#define MUTT_THREAD_NEXT_UNREAD (1 << 3) ///< Find the next unread email
#define MUTT_THREAD_FLAGGED     (1 << 4) ///< Count flagged emails in a thread

/**
 * enum MessageInThread - Flags for mutt_messages_in_thread()
 */
enum MessageInThread
{
  MIT_NUM_MESSAGES, ///< How many messages are in the thread
  MIT_POSITION,     ///< Our position in the thread
};

/**
 * enum UseThreads - Which threading style is active, $use_threads
 */
enum UseThreads
{
  UT_UNSET,     ///< Not yet set by user, stick to legacy semantics
  UT_FLAT,      ///< Unthreaded
  UT_THREADS,   ///< Normal threading (root above subthreads)
  UT_REVERSE,   ///< Reverse threading (subthreads above root)
};

extern const struct EnumDef UseThreadsTypeDef;

int mutt_traverse_thread(struct Email *e, MuttThreadFlags flag);
#define mutt_collapse_thread(e)         mutt_traverse_thread(e, MUTT_THREAD_COLLAPSE)
#define mutt_uncollapse_thread(e)       mutt_traverse_thread(e, MUTT_THREAD_UNCOLLAPSE)
#define mutt_thread_contains_unread(e)  mutt_traverse_thread(e, MUTT_THREAD_UNREAD)
#define mutt_thread_contains_flagged(e) mutt_traverse_thread(e, MUTT_THREAD_FLAGGED)
#define mutt_thread_next_unread(e)      mutt_traverse_thread(e, MUTT_THREAD_NEXT_UNREAD)

enum UseThreads mutt_thread_style(void);
#define mutt_using_threads() (mutt_thread_style() > UT_FLAT)
const char *get_use_threads_str(enum UseThreads value);
int sort_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err);

int mutt_aside_thread(struct Email *e, bool forwards, bool subthreads);
#define mutt_next_thread(e)        mutt_aside_thread(e, true,  false)
#define mutt_previous_thread(e)    mutt_aside_thread(e, false, false)
#define mutt_next_subthread(e)     mutt_aside_thread(e, true,  true)
#define mutt_previous_subthread(e) mutt_aside_thread(e, false, true)

struct ThreadsContext *mutt_thread_ctx_init          (struct MailboxView *mv);
void                   mutt_thread_ctx_free          (struct ThreadsContext **ptr);
void                   mutt_thread_collapse_collapsed(struct ThreadsContext *tctx);
void                   mutt_thread_collapse          (struct ThreadsContext *tctx, bool collapse);
bool                   mutt_thread_can_collapse      (struct Email *e);

void                   mutt_clear_threads     (struct ThreadsContext *tctx);
void                   mutt_draw_tree         (struct ThreadsContext *tctx);
bool                   mutt_link_threads      (struct Email *parent, struct EmailArray *children, struct Mailbox *m);
struct HashTable *     mutt_make_id_hash      (struct Mailbox *m);
int                    mutt_messages_in_thread(struct Mailbox *m, struct Email *e, enum MessageInThread mit);
int                    mutt_parent_message    (struct Email *e, bool find_root);
off_t                  mutt_set_vnum          (struct Mailbox *m);
void                   mutt_sort_threads      (struct ThreadsContext *tctx, bool init);

#endif /* MUTT_MUTT_THREAD_H */
