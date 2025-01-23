/**
 * @file
 * GUI display the mailboxes in a side panel
 *
 * @authors
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_SIDEBAR_PRIVATE_H
#define MUTT_SIDEBAR_PRIVATE_H

#include <stdbool.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "email/lib.h"
#include "core/lib.h"

struct IndexSharedData;
struct MuttWindow;

extern struct ListHead SidebarPinned;

/**
 * struct SbEntry - Info about folders in the sidebar
 */
struct SbEntry
{
  char box[256];                  ///< Mailbox path (possibly abbreviated)
  char display[256];              ///< Formatted string to display
  int depth;                      ///< Indentation depth
  struct Mailbox *mailbox;        ///< Mailbox this represents
  bool is_hidden;                 ///< Don't show, e.g. $sidebar_new_mail_only
  const struct AttrColor *color;  ///< Colour to use
};
ARRAY_HEAD(SbEntryArray, struct SbEntry *);

/**
 * ExpandoDataSidebar - Expando UIDs for the Sidebar
 *
 * @sa ED_SIDEBAR, ExpandoDomain
 */
enum ExpandoDataSidebar
{
  ED_SID_DELETED_COUNT = 1,    ///< Mailbox.msg_deleted
  ED_SID_DESCRIPTION,          ///< Mailbox.name
  ED_SID_FLAGGED,              ///< Mailbox.msg_flagged
  ED_SID_FLAGGED_COUNT,        ///< Mailbox.msg_flagged
  ED_SID_LIMITED_COUNT,        ///< Mailbox.vcount
  ED_SID_MESSAGE_COUNT,        ///< Mailbox.msg_count
  ED_SID_NAME,                 ///< SbEntry.box
  ED_SID_NEW_MAIL,             ///< Mailbox.has_new
  ED_SID_NOTIFY,               ///< Mailbox.notify_user
  ED_SID_OLD_COUNT,            ///< Mailbox.msg_unread, Mailbox.msg_new
  ED_SID_POLL,                 ///< Mailbox.poll_new_mail
  ED_SID_READ_COUNT,           ///< Mailbox.msg_count, Mailbox.msg_unread
  ED_SID_TAGGED_COUNT,         ///< Mailbox.msg_tagged
  ED_SID_UNREAD_COUNT,         ///< Mailbox.msg_unread
  ED_SID_UNSEEN_COUNT,         ///< Mailbox.msg_new
};

/**
 * enum DivType - Source of the sidebar divider character
 */
enum DivType
{
  SB_DIV_USER,  ///< User configured using $sidebar_divider_char
  SB_DIV_ASCII, ///< An ASCII vertical bar (pipe)
};

/**
 * struct SidebarWindowData - Sidebar private Window data - @extends MuttWindow
 */
struct SidebarWindowData
{
  struct MuttWindow *win;                 ///< Sidebar Window
  struct IndexSharedData *shared;         ///< Shared Index Data
  struct SbEntryArray entries;            ///< Items to display in the sidebar

  int top_index;             ///< First mailbox visible in sidebar
  int opn_index;             ///< Current (open) mailbox
  int hil_index;             ///< Highlighted mailbox
  int bot_index;             ///< Last mailbox visible in sidebar
  int repage;                ///< Force RECALC to recompute the paging
                             ///  used for the overlays

  short previous_sort;       ///< Old `$sidebar_sort`
  enum DivType divider_type; ///< Type of divider to use, e.g. #SB_DIV_ASCII
  short divider_width;       ///< Width of the divider in screen columns
};

// sidebar.c
void sb_add_mailbox        (struct SidebarWindowData *wdata, struct Mailbox *m);
void sb_remove_mailbox     (struct SidebarWindowData *wdata, const struct Mailbox *m);
void sb_set_current_mailbox(struct SidebarWindowData *wdata, struct Mailbox *m);
struct Mailbox *sb_get_highlight(struct MuttWindow *win);

// commands.c
enum CommandResult sb_parse_sidebar_unpin(struct Buffer *buf, struct Buffer *s, intptr_t data, struct Buffer *err);
enum CommandResult sb_parse_sidebar_pin  (struct Buffer *buf, struct Buffer *s, intptr_t data, struct Buffer *err);

// functions.c
bool sb_next(struct SidebarWindowData *wdata);
bool sb_prev(struct SidebarWindowData *wdata);

// observer.c
int sb_insertion_window_observer(struct NotifyCallback *nc);
void sb_win_add_observers(struct MuttWindow *win);

// sort.c
void sb_sort_entries(struct SidebarWindowData *wdata, enum EmailSortType sort);

// wdata.c
void                      sb_wdata_free(struct MuttWindow *win, void **ptr);
struct SidebarWindowData *sb_wdata_get(struct MuttWindow *win);
struct SidebarWindowData *sb_wdata_new(struct MuttWindow *win, struct IndexSharedData *shared);

// window.c
int sb_recalc(struct MuttWindow *win);
int sb_repaint(struct MuttWindow *win);

#endif /* MUTT_SIDEBAR_PRIVATE_H */
