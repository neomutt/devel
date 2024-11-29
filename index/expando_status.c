/**
 * @file
 * GUI display a user-configurable status line
 *
 * @authors
 * Copyright (C) 1996-2000,2007 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2017-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018 Austin Ray <austin@austinray.io>
 * Copyright (C) 2020-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2021 Eric Blake <eblake@redhat.com>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
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
 * @page index_expando_status GUI display a user-configurable status line
 *
 * GUI display a user-configurable status line
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "expando_status.h"
#include "expando/lib.h"
#include "menu/lib.h"
#include "postpone/lib.h"
#include "globals.h"
#include "mutt_mailbox.h"
#include "mutt_thread.h"
#include "muttlib.h"
#include "mview.h"
#include "shared_data.h"

static void index_mailbox_path(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf);

extern const struct Mapping SortMethods[];

/**
 * get_sort_str - Get the sort method as a string
 * @param buf    Buffer for the sort string
 * @param buflen Length of the buffer
 * @param method Sort method, see #EmailSortType
 * @retval ptr Buffer pointer
 */
static char *get_sort_str(char *buf, size_t buflen, enum EmailSortType method)
{
  snprintf(buf, buflen, "%s%s%s", (method & SORT_REVERSE) ? "reverse-" : "",
           (method & SORT_LAST) ? "last-" : "",
           mutt_map_get_name(method & SORT_MASK, SortMethods));
  return buf;
}

/**
 * global_config_sort - Status: Sorting mode - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_config_sort(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  char tmp[128] = { 0 };

  const enum EmailSortType c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  const char *s = get_sort_str(tmp, sizeof(tmp), c_sort);
  buf_strcpy(buf, s);
}

/**
 * global_config_sort_aux - Status: Aux sorting method - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_config_sort_aux(const struct ExpandoNode *node, void *data,
                                   MuttFormatFlags flags, struct Buffer *buf)
{
  char tmp[128] = { 0 };

  const enum EmailSortType c_sort_aux = cs_subset_sort(NeoMutt->sub, "sort_aux");
  const char *s = get_sort_str(tmp, sizeof(tmp), c_sort_aux);
  buf_strcpy(buf, s);
}

/**
 * global_config_use_threads - Status: Current threading mode - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_config_use_threads(const struct ExpandoNode *node, void *data,
                                      MuttFormatFlags flags, struct Buffer *buf)
{
  const enum UseThreads c_use_threads = mutt_thread_style();
  const char *s = get_use_threads_str(c_use_threads);
  buf_strcpy(buf, s);
}

/**
 * global_hostname - Status: Local hostname - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_hostname(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const char *s = ShortHostname;
  buf_strcpy(buf, s);
}

/**
 * global_version - Status: Version string - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_version(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const char *s = mutt_make_version();
  buf_strcpy(buf, s);
}

/**
 * index_deleted_count_num - Status: Number of deleted messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_deleted_count_num(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_deleted : 0;
}

/**
 * index_description - Status: Description of the mailbox - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_description(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  // If there's a descriptive name, use it. Otherwise, use %f
  if (m && m->name)
  {
    const char *s = m->name;
    buf_strcpy(buf, s);
    return;
  }

  index_mailbox_path(node, data, flags, buf);
}

/**
 * index_flagged_count_num - Status: Number of flagged messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_flagged_count_num(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_flagged : 0;
}

/**
 * index_limit_count_num - Status: Number of messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_limit_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->vcount : 0;
}

/**
 * index_limit_pattern - Status: Active limit pattern - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_limit_pattern(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct MailboxView *mailbox_view = shared->mailbox_view;

  const char *s = mview_has_limit(mailbox_view) ? mailbox_view->pattern : "";
  buf_strcpy(buf, s);
}

/**
 * index_limit_size - Status: Size of the messages - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_limit_size(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct MailboxView *mailbox_view = shared->mailbox_view;

  const off_t num = mailbox_view ? mailbox_view->vsize : 0;
  mutt_str_pretty_size(buf, num);
}

/**
 * index_limit_size_num - Status: Size of the messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_limit_size_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct MailboxView *mailbox_view = shared->mailbox_view;
  if (!mailbox_view)
    return 0;

  return mailbox_view->vsize;
}

/**
 * index_mailbox_path - Status: pathname of the mailbox - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_mailbox_path(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  char tmp[128] = { 0 };

  if (m && m->compress_info && (m->realpath[0] != '\0'))
  {
    mutt_str_copy(tmp, m->realpath, sizeof(tmp));
    mutt_pretty_mailbox(tmp, sizeof(tmp));
  }
  else if (m && (m->type == MUTT_NOTMUCH) && m->name)
  {
    mutt_str_copy(tmp, m->name, sizeof(tmp));
  }
  else if (m && !buf_is_empty(&m->pathbuf))
  {
    mutt_str_copy(tmp, mailbox_path(m), sizeof(tmp));
    mutt_pretty_mailbox(tmp, sizeof(tmp));
  }
  else
  {
    mutt_str_copy(tmp, _("(no mailbox)"), sizeof(tmp));
  }

  buf_strcpy(buf, tmp);
}

/**
 * index_mailbox_size - Status: Size of the current mailbox - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_mailbox_size(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  const off_t num = m ? m->size : 0;
  mutt_str_pretty_size(buf, num);
}

/**
 * index_mailbox_size_num - Status: Size of the current mailbox - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_mailbox_size_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;
  if (!m)
    return 0;

  return m->size;
}

/**
 * index_message_count_num - Status: Number of messages in the mailbox - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_message_count_num(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_count : 0;
}

/**
 * index_new_count_num - Status: Number of new messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_new_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_new : 0;
}

/**
 * index_old_count_num - Status: Number of old messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_old_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? (m->msg_unread - m->msg_new) : 0;
}

/**
 * index_postponed_count_num - Status: Number of postponed messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_postponed_count_num(const struct ExpandoNode *node,
                                      void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  struct Mailbox *m = shared->mailbox;

  return mutt_num_postponed(m, false);
}

/**
 * index_readonly - Status: Modified/read-only flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void index_readonly(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MbTable *c_status_chars = cs_subset_mbtable(NeoMutt->sub, "status_chars");
  if (!c_status_chars || !c_status_chars->len)
    return;

  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  int i = STATUS_CHAR_UNCHANGED;

  if (m)
  {
    if (shared->attach_msg)
      i = STATUS_CHAR_ATTACH;
    else if (m->readonly || m->dontwrite)
      i = STATUS_CHAR_READ_ONLY;
    else if (m->changed || ((m->type != MUTT_IMAP) && m->msg_deleted)) /* deleted doesn't necessarily mean changed in IMAP */
      i = STATUS_CHAR_NEED_RESYNC;
    else
      i = STATUS_CHAR_UNCHANGED;
  }

  if (i >= c_status_chars->len)
    buf_addstr(buf, c_status_chars->chars[STATUS_CHAR_UNCHANGED]);
  else
    buf_addstr(buf, c_status_chars->chars[i]);
}

/**
 * index_read_count_num - Status: Number of read messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_read_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? (m->msg_count - m->msg_unread) : 0;
}

/**
 * index_tagged_count_num - Status: Number of tagged messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_tagged_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_tagged : 0;
}

/**
 * index_unread_count_num - Status: Number of unread messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_unread_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  const struct Mailbox *m = shared->mailbox;

  return m ? m->msg_unread : 0;
}

/**
 * index_unread_mailboxes_num - Status: Number of mailboxes with new mail - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long index_unread_mailboxes_num(const struct ExpandoNode *node,
                                       void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct IndexSharedData *shared = msld->shared;
  struct Mailbox *m = shared->mailbox;

  return mutt_mailbox_check(m, MUTT_MAILBOX_CHECK_NO_FLAGS);
}

/**
 * menu_percentage - Status: Percentage through index - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void menu_percentage(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct MenuStatusLineData *msld = data;
  const struct Menu *menu = msld->menu;
  if (!menu)
    return;

  char tmp[128] = { 0 };

  char *cp = NULL;
  if (menu->top + menu->page_len >= menu->max)
  {
    cp = menu->top ?
             /* L10N: Status bar message: the end of the list emails is visible in the index */
             _("end") :
             /* L10N: Status bar message: all the emails are visible in the index */
             _("all");
  }
  else
  {
    int count = (100 * (menu->top + menu->page_len)) / menu->max;
    /* L10N: Status bar, percentage of way through index.
           `%d` is the number, `%%` is the percent symbol.
           They may be reordered, or space inserted, if you wish. */
    snprintf(tmp, sizeof(tmp), _("%d%%"), count);
    cp = tmp;
  }

  buf_strcpy(buf, cp);
}

/**
 * menu_percentage_num - Status: Percentage through index - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long menu_percentage_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct MenuStatusLineData *msld = data;
  const struct Menu *menu = msld->menu;
  if (!menu)
    return 0;

  if (menu->top + menu->page_len >= menu->max)
    return 100;

  return (100 * (menu->top + menu->page_len)) / menu->max;
}

/**
 * StatusRenderCallbacks1 - Callbacks for Status Expandos
 *
 * @sa StatusFormatDef, ExpandoDataGlobal, ExpandoDataIndex, ExpandoDataMenu
 */
const struct ExpandoRenderCallback StatusRenderCallbacks1[] = {
  // clang-format off
  { ED_GLOBAL, ED_GLO_CONFIG_SORT,        global_config_sort,        NULL },
  { ED_GLOBAL, ED_GLO_CONFIG_SORT_AUX,    global_config_sort_aux,    NULL },
  { ED_GLOBAL, ED_GLO_CONFIG_USE_THREADS, global_config_use_threads, NULL },
  { ED_GLOBAL, ED_GLO_HOSTNAME,           global_hostname,           NULL },
  { ED_GLOBAL, ED_GLO_VERSION,            global_version,            NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * StatusRenderCallbacks2 - Callbacks for Status Expandos
 *
 * @sa StatusFormatDef, ExpandoDataGlobal, ExpandoDataIndex, ExpandoDataMenu
 */
const struct ExpandoRenderCallback StatusRenderCallbacks2[] = {
  // clang-format off
  { ED_INDEX,  ED_IND_DELETED_COUNT,      NULL,                      index_deleted_count_num },
  { ED_INDEX,  ED_IND_DESCRIPTION,        index_description,         NULL },
  { ED_INDEX,  ED_IND_FLAGGED_COUNT,      NULL,                      index_flagged_count_num },
  { ED_INDEX,  ED_IND_LIMIT_COUNT,        NULL,                      index_limit_count_num },
  { ED_INDEX,  ED_IND_LIMIT_PATTERN,      index_limit_pattern,       NULL },
  { ED_INDEX,  ED_IND_LIMIT_SIZE,         index_limit_size,          index_limit_size_num },
  { ED_INDEX,  ED_IND_MAILBOX_PATH,       index_mailbox_path,        NULL },
  { ED_INDEX,  ED_IND_MAILBOX_SIZE,       index_mailbox_size,        index_mailbox_size_num },
  { ED_INDEX,  ED_IND_MESSAGE_COUNT,      NULL,                      index_message_count_num },
  { ED_INDEX,  ED_IND_NEW_COUNT,          NULL,                      index_new_count_num },
  { ED_INDEX,  ED_IND_OLD_COUNT,          NULL,                      index_old_count_num },
  { ED_INDEX,  ED_IND_POSTPONED_COUNT,    NULL,                      index_postponed_count_num },
  { ED_INDEX,  ED_IND_READONLY,           index_readonly,            NULL },
  { ED_INDEX,  ED_IND_READ_COUNT,         NULL,                      index_read_count_num },
  { ED_INDEX,  ED_IND_TAGGED_COUNT,       NULL,                      index_tagged_count_num },
  { ED_INDEX,  ED_IND_UNREAD_COUNT,       NULL,                      index_unread_count_num },
  { ED_INDEX,  ED_IND_UNREAD_MAILBOXES,   NULL,                      index_unread_mailboxes_num },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * StatusRenderCallbacks3 - Callbacks for Status Expandos
 *
 * @sa StatusFormatDef, ExpandoDataGlobal, ExpandoDataIndex, ExpandoDataMenu
 */
const struct ExpandoRenderCallback StatusRenderCallbacks3[] = {
  // clang-format off
  { ED_MENU,   ED_MEN_PERCENTAGE,         menu_percentage,           menu_percentage_num },
  { -1, -1, NULL, NULL },
  // clang-format on
};
