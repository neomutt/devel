/**
 * @file
 * Index Dialog
 *
 * @authors
 * Copyright (C) 2016-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2016-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
 * Copyright (C) 2021 Eric Blake <eblake@redhat.com>
 * Copyright (C) 2022 Igor Serebryany <igor47@moomers.org>
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
 * @page index_dlg_index Index Dialog
 *
 * The Index Dialog is the main screen within NeoMutt.  It contains @ref
 * index_index (a list of emails), @ref pager_dlg_pager (a view of an email) and
 * @ref sidebar_window (a list of mailboxes).
 *
 * ## Windows
 *
 * | Name         | Type         | See Also    |
 * | :----------- | :----------- | :---------- |
 * | Index Dialog | WT_DLG_INDEX | dlg_index() |
 *
 * **Parent**
 * - @ref gui_dialog
 *
 * **Children**
 * - See: @ref index_ipanel
 * - See: @ref pager_ppanel
 * - See: @ref sidebar_window
 *
 * ## Data
 * - #IndexSharedData
 *
 * ## Events
 *
 * None.
 *
 * Some other events are handled by the dialog's children.
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "conn/lib.h"
#include "gui/lib.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "index/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "nntp/lib.h"
#include "pager/lib.h"
#include "pattern/lib.h"
#include "sidebar/lib.h"
#include "expando_index.h"
#include "functions.h"
#include "globals.h"
#include "hook.h"
#include "mutt_logging.h"
#include "mutt_mailbox.h"
#include "mutt_thread.h"
#include "mview.h"
#include "mx.h"
#include "nntp/adata.h"
#include "private_data.h"
#include "protos.h"
#include "shared_data.h"
#include "status.h"
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef USE_INOTIFY
#include "monitor.h"
#endif

/// Help Bar for the Index dialog
static const struct Mapping IndexHelp[] = {
  // clang-format off
  { N_("Quit"),  OP_QUIT },
  { N_("Del"),   OP_DELETE },
  { N_("Undel"), OP_UNDELETE },
  { N_("Save"),  OP_SAVE },
  { N_("Mail"),  OP_MAIL },
  { N_("Reply"), OP_REPLY },
  { N_("Group"), OP_GROUP_REPLY },
  { N_("Help"),  OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/// Help Bar for the News Index dialog
const struct Mapping IndexNewsHelp[] = {
  // clang-format off
  { N_("Quit"),     OP_QUIT },
  { N_("Del"),      OP_DELETE },
  { N_("Undel"),    OP_UNDELETE },
  { N_("Save"),     OP_SAVE },
  { N_("Post"),     OP_POST },
  { N_("Followup"), OP_FOLLOWUP },
  { N_("Catchup"),  OP_CATCHUP },
  { N_("Help"),     OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * check_acl - Check the ACLs for a function
 * @param m   Mailbox
 * @param acl ACL, see #AclFlags
 * @param msg Error message for failure
 * @retval true The function is permitted
 */
bool check_acl(struct Mailbox *m, AclFlags acl, const char *msg)
{
  if (!m)
    return false;

  if (!(m->rights & acl))
  {
    /* L10N: %s is one of the CHECK_ACL entries below. */
    mutt_error(_("%s: Operation not permitted by ACL"), msg);
    return false;
  }

  return true;
}

/**
 * collapse_all - Collapse/uncollapse all threads
 * @param mv     Mailbox View
 * @param menu   current menu
 * @param toggle toggle collapsed state
 *
 * This function is called by the OP_MAIN_COLLAPSE_ALL command and on folder
 * enter if the `$collapse_all` option is set. In the first case, the @a toggle
 * parameter is 1 to actually toggle collapsed/uncollapsed state on all
 * threads. In the second case, the @a toggle parameter is 0, actually turning
 * this function into a one-way collapse.
 */
void collapse_all(struct MailboxView *mv, struct Menu *menu, int toggle)
{
  if (!mv || !mv->mailbox || (mv->mailbox->msg_count == 0) || !menu)
    return;

  struct Email *e_cur = mutt_get_virt_email(mv->mailbox, menu_get_index(menu));
  if (!e_cur)
    return;

  int final;

  /* Figure out what the current message would be after folding / unfolding,
   * so that we can restore the cursor in a sane way afterwards. */
  if (e_cur->collapsed && toggle)
    final = mutt_uncollapse_thread(e_cur);
  else if (mutt_thread_can_collapse(e_cur))
    final = mutt_collapse_thread(e_cur);
  else
    final = e_cur->vnum;

  if (final == -1)
    return;

  struct Email *base = mutt_get_virt_email(mv->mailbox, final);
  if (!base)
    return;

  /* Iterate all threads, perform collapse/uncollapse as needed */
  mv->collapsed = toggle ? !mv->collapsed : true;
  mutt_thread_collapse(mv->threads, mv->collapsed);

  /* Restore the cursor */
  mutt_set_vnum(mv->mailbox);
  menu->max = mv->mailbox->vcount;
  for (int i = 0; i < mv->mailbox->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(mv->mailbox, i);
    if (!e)
      break;
    if (e->index == base->index)
    {
      menu_set_index(menu, i);
      break;
    }
  }

  menu_queue_redraw(menu, MENU_REDRAW_INDEX);
}

/**
 * uncollapse_thread - Open a collapsed thread
 * @param mv    Mailbox View
 * @param index Message number
 */
static void uncollapse_thread(struct MailboxView *mv, int index)
{
  if (!mv || !mv->mailbox)
    return;

  struct Mailbox *m = mv->mailbox;
  struct Email *e = mutt_get_virt_email(m, index);
  if (e && e->collapsed)
  {
    mutt_uncollapse_thread(e);
    mutt_set_vnum(m);
  }
}

/**
 * find_next_undeleted - Find the next undeleted email
 * @param mv         Mailbox view
 * @param msgno      Message number to start at
 * @param uncollapse Open collapsed threads
 * @retval >=0 Message number of next undeleted email
 * @retval  -1 No more undeleted messages
 */
int find_next_undeleted(struct MailboxView *mv, int msgno, bool uncollapse)
{
  if (!mv || !mv->mailbox)
    return -1;

  struct Mailbox *m = mv->mailbox;

  int index = -1;
  for (int i = msgno + 1; i < m->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->deleted)
    {
      index = i;
      break;
    }
  }

  if (uncollapse)
    uncollapse_thread(mv, index);

  return index;
}

/**
 * find_previous_undeleted - Find the previous undeleted email
 * @param mv         Mailbox View
 * @param msgno      Message number to start at
 * @param uncollapse Open collapsed threads
 * @retval >=0 Message number of next undeleted email
 * @retval  -1 No more undeleted messages
 */
int find_previous_undeleted(struct MailboxView *mv, int msgno, bool uncollapse)
{
  if (!mv || !mv->mailbox)
    return -1;

  struct Mailbox *m = mv->mailbox;

  int index = -1;
  for (int i = msgno - 1; i >= 0; i--)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->deleted)
    {
      index = i;
      break;
    }
  }

  if (uncollapse)
    uncollapse_thread(mv, index);

  return index;
}

/**
 * find_first_message - Get index of first new message
 * @param mv Mailbox view
 * @retval num Index of first new message
 *
 * Return the index of the first new message, or failing that, the first
 * unread message.
 */
int find_first_message(struct MailboxView *mv)
{
  if (!mv)
    return 0;

  struct Mailbox *m = mv->mailbox;
  if (!m || (m->msg_count == 0))
    return 0;

  int old = -1;
  for (int i = 0; i < m->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->read && !e->deleted)
    {
      if (!e->old)
        return i;
      if (old == -1)
        old = i;
    }
  }
  if (old != -1)
    return old;

  /* If `$use_threads` is not threaded and `$sort` is reverse, the latest
   * message is first.  Otherwise, the latest message is first if exactly
   * one of `$use_threads` and `$sort` are reverse.
   */
  enum EmailSortType c_sort = cs_subset_sort(m->sub, "sort");
  if ((c_sort & SORT_MASK) == EMAIL_SORT_THREADS)
    c_sort = cs_subset_sort(m->sub, "sort_aux");
  bool reverse = false;
  switch (mutt_thread_style())
  {
    case UT_FLAT:
      reverse = c_sort & SORT_REVERSE;
      break;
    case UT_THREADS:
      reverse = c_sort & SORT_REVERSE;
      break;
    case UT_REVERSE:
      reverse = !(c_sort & SORT_REVERSE);
      break;
    default:
      ASSERT(false);
  }

  if (reverse || (m->vcount == 0))
    return 0;

  return m->vcount - 1;
}

/**
 * resort_index - Resort the index
 * @param mv   Mailbox View
 * @param menu Current Menu
 */
void resort_index(struct MailboxView *mv, struct Menu *menu)
{
  if (!mv || !mv->mailbox || !menu)
    return;

  struct Mailbox *m = mv->mailbox;
  const int old_index = menu_get_index(menu);
  struct Email *e_cur = mutt_get_virt_email(m, old_index);

  int new_index = -1;
  mutt_sort_headers(mv, false);

  /* Restore the current message */
  for (int i = 0; i < m->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (e == e_cur)
    {
      new_index = i;
      break;
    }
  }

  if (mutt_using_threads() && (old_index < 0))
    new_index = mutt_parent_message(e_cur, false);

  if (old_index < 0)
    new_index = find_first_message(mv);

  menu->max = m->vcount;
  menu_set_index(menu, new_index);
  menu_queue_redraw(menu, MENU_REDRAW_INDEX);
}

/**
 * update_index_threaded - Update the index (if threaded)
 * @param mv      Mailbox
 * @param check    Flags, e.g. #MX_STATUS_REOPENED
 * @param oldcount How many items are currently in the index
 */
static void update_index_threaded(struct MailboxView *mv, enum MxStatus check, int oldcount)
{
  struct Email **save_new = NULL;
  const bool lmt = mview_has_limit(mv);

  struct Mailbox *m = mv->mailbox;
  int num_new = MAX(0, m->msg_count - oldcount);

  const bool c_uncollapse_new = cs_subset_bool(m->sub, "uncollapse_new");
  /* save the list of new messages */
  if ((check != MX_STATUS_REOPENED) && (oldcount > 0) &&
      (lmt || c_uncollapse_new) && (num_new > 0))
  {
    save_new = MUTT_MEM_MALLOC(num_new, struct Email *);
    for (int i = oldcount; i < m->msg_count; i++)
      save_new[i - oldcount] = m->emails[i];
  }

  /* Sort first to thread the new messages, because some patterns
   * require the threading information.
   *
   * If the mailbox was reopened, need to rethread from scratch. */
  mutt_sort_headers(mv, (check == MX_STATUS_REOPENED));

  if (lmt)
  {
    for (int i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];

      if ((e->limit_visited && e->visible) ||
          mutt_pattern_exec(SLIST_FIRST(mv->limit_pattern),
                            MUTT_MATCH_FULL_ADDRESS, m, e, NULL))
      {
        /* vnum will get properly set by mutt_set_vnum(), which
         * is called by mutt_sort_headers() just below. */
        e->vnum = 1;
        e->visible = true;
      }
      else
      {
        e->vnum = -1;
        e->visible = false;
      }

      // mark email as visited so we don't re-apply the pattern next time
      e->limit_visited = true;
    }
    /* Need a second sort to set virtual numbers and redraw the tree */
    mutt_sort_headers(mv, false);
  }

  /* uncollapse threads with new mail */
  if (c_uncollapse_new)
  {
    if (check == MX_STATUS_REOPENED)
    {
      mv->collapsed = false;
      mutt_thread_collapse(mv->threads, mv->collapsed);
      mutt_set_vnum(m);
    }
    else if (oldcount > 0)
    {
      for (int j = 0; j < num_new; j++)
      {
        if (save_new[j]->visible)
        {
          mutt_uncollapse_thread(save_new[j]);
        }
      }
      mutt_set_vnum(m);
    }
  }

  FREE(&save_new);
}

/**
 * update_index_unthreaded - Update the index (if unthreaded)
 * @param mv      Mailbox
 * @param check    Flags, e.g. #MX_STATUS_REOPENED
 */
static void update_index_unthreaded(struct MailboxView *mv, enum MxStatus check)
{
  /* We are in a limited view. Check if the new message(s) satisfy
   * the limit criteria. If they do, set their virtual msgno so that
   * they will be visible in the limited view */
  if (mview_has_limit(mv))
  {
    int padding = mx_msg_padding_size(mv->mailbox);
    mv->mailbox->vcount = mv->vsize = 0;
    for (int i = 0; i < mv->mailbox->msg_count; i++)
    {
      struct Email *e = mv->mailbox->emails[i];
      if (!e)
        break;

      if ((e->limit_visited && e->visible) ||
          mutt_pattern_exec(SLIST_FIRST(mv->limit_pattern),
                            MUTT_MATCH_FULL_ADDRESS, mv->mailbox, e, NULL))
      {
        ASSERT(mv->mailbox->vcount < mv->mailbox->msg_count);
        e->vnum = mv->mailbox->vcount;
        mv->mailbox->v2r[mv->mailbox->vcount] = i;
        e->visible = true;
        mv->mailbox->vcount++;
        struct Body *b = e->body;
        mv->vsize += b->length + b->offset - b->hdr_offset + padding;
      }
      else
      {
        e->visible = false;
      }

      // mark email as visited so we don't re-apply the pattern next time
      e->limit_visited = true;
    }
  }

  /* if the mailbox was reopened, need to rethread from scratch */
  mutt_sort_headers(mv, (check == MX_STATUS_REOPENED));
}

/**
 * update_index - Update the index
 * @param menu     Current Menu
 * @param mv      Mailbox
 * @param check    Flags, e.g. #MX_STATUS_REOPENED
 * @param oldcount How many items are currently in the index
 * @param shared   Shared Index data
 */
void update_index(struct Menu *menu, struct MailboxView *mv, enum MxStatus check,
                  int oldcount, const struct IndexSharedData *shared)
{
  if (!menu || !mv)
    return;

  struct Mailbox *m = mv->mailbox;
  if (mutt_using_threads())
    update_index_threaded(mv, check, oldcount);
  else
    update_index_unthreaded(mv, check);

  menu->max = m->vcount;
  const int old_index = menu_get_index(menu);
  int index = -1;
  if (oldcount != 0)
  {
    /* restore the current message to the message it was pointing to */
    for (int i = 0; i < m->vcount; i++)
    {
      struct Email *e = mutt_get_virt_email(m, i);
      if (!e)
        continue;
      if (index_shared_data_is_cur_email(shared, e))
      {
        index = i;
        break;
      }
    }
  }

  if (index < 0)
  {
    index = (old_index < m->vcount) ? old_index : find_first_message(mv);
  }
  menu->max = m->vcount;
  menu_set_index(menu, index);
}

/**
 * index_mailbox_observer - Notification that a Mailbox has changed - Implements ::observer_t - @ingroup observer_api
 *
 * If a Mailbox is closed, then set a pointer to NULL.
 */
static int index_mailbox_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_MAILBOX)
    return 0;
  if (!nc->global_data)
    return -1;
  if (nc->event_subtype != NT_MAILBOX_DELETE)
    return 0;

  struct Mailbox **ptr = nc->global_data;
  if (!*ptr)
    return 0;

  *ptr = NULL;
  mutt_debug(LL_DEBUG5, "mailbox done\n");
  return 0;
}

/**
 * change_folder_mailbox - Change to a different Mailbox by pointer
 * @param menu      Current Menu
 * @param m         Mailbox
 * @param oldcount  How many items are currently in the index
 * @param shared    Shared Index data
 * @param read_only Open Mailbox in read-only mode
 */
void change_folder_mailbox(struct Menu *menu, struct Mailbox *m, int *oldcount,
                           struct IndexSharedData *shared, bool read_only)
{
  if (!m)
    return;

  /* keepalive failure in mutt_enter_fname may kill connection. */
  if (shared->mailbox && (buf_is_empty(&shared->mailbox->pathbuf)))
  {
    mview_free(&shared->mailbox_view);
    mailbox_free(&shared->mailbox);
  }

  if (shared->mailbox)
  {
    char *new_last_folder = NULL;
#ifdef USE_INOTIFY
    int monitor_remove_rc = mutt_monitor_remove(NULL);
#endif
    if (shared->mailbox->compress_info && (shared->mailbox->realpath[0] != '\0'))
      new_last_folder = mutt_str_dup(shared->mailbox->realpath);
    else
      new_last_folder = mutt_str_dup(mailbox_path(shared->mailbox));
    *oldcount = shared->mailbox->msg_count;

    const enum MxStatus check = mx_mbox_close(shared->mailbox);
    if (check == MX_STATUS_OK)
    {
      mview_free(&shared->mailbox_view);
      if (shared->mailbox != m)
      {
        mailbox_free(&shared->mailbox);
      }
    }
    else
    {
#ifdef USE_INOTIFY
      if (monitor_remove_rc == 0)
        mutt_monitor_add(NULL);
#endif
      if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
        update_index(menu, shared->mailbox_view, check, *oldcount, shared);

      FREE(&new_last_folder);
      mutt_pattern_free(&shared->search_state->pattern);
      menu_queue_redraw(menu, MENU_REDRAW_INDEX);
      return;
    }
    FREE(&LastFolder);
    LastFolder = new_last_folder;
  }
  mutt_str_replace(&CurrentFolder, mailbox_path(m));

  /* If the `folder-hook` were to call `unmailboxes`, then the Mailbox (`m`)
   * could be deleted, leaving `m` dangling. */
  // TODO: Refactor this function to avoid the need for an observer
  notify_observer_add(m->notify, NT_MAILBOX, index_mailbox_observer, &m);
  char *dup_path = mutt_str_dup(mailbox_path(m));
  char *dup_name = mutt_str_dup(m->name);

  mutt_folder_hook(dup_path, dup_name);
  if (m)
  {
    /* `m` is still valid, but we won't need the observer again before the end
     * of the function. */
    notify_observer_remove(m->notify, index_mailbox_observer, &m);
  }
  else
  {
    // Recreate the Mailbox as the folder-hook might have invoked `mailboxes`
    // and/or `unmailboxes`.
    m = mx_path_resolve(dup_path);
  }

  FREE(&dup_path);
  FREE(&dup_name);

  if (!m)
    return;

  const OpenMailboxFlags flags = read_only ? MUTT_READONLY : MUTT_OPEN_NO_FLAGS;
  if (mx_mbox_open(m, flags))
  {
    struct MailboxView *mv = mview_new(m, NeoMutt->notify);
    index_shared_data_set_mview(shared, mv);

    menu->max = m->msg_count;
    menu_set_index(menu, find_first_message(shared->mailbox_view));
#ifdef USE_INOTIFY
    mutt_monitor_add(NULL);
#endif
  }
  else
  {
    index_shared_data_set_mview(shared, NULL);
    menu_set_index(menu, 0);
  }

  const bool c_collapse_all = cs_subset_bool(shared->sub, "collapse_all");
  if (mutt_using_threads() && c_collapse_all)
    collapse_all(shared->mailbox_view, menu, 0);

  mutt_clear_error();
  /* force the mailbox check after we have changed the folder */
  struct EventMailbox ev_m = { shared->mailbox };
  mutt_mailbox_check(ev_m.mailbox, MUTT_MAILBOX_CHECK_POSTPONED);
  menu_queue_redraw(menu, MENU_REDRAW_FULL);
  mutt_pattern_free(&shared->search_state->pattern);
}

#ifdef USE_NOTMUCH
/**
 * change_folder_notmuch - Change to a different Notmuch Mailbox by string
 * @param menu      Current Menu
 * @param buf       Folder to change to
 * @param buflen    Length of buffer
 * @param oldcount  How many items are currently in the index
 * @param shared    Shared Index data
 * @param read_only Open Mailbox in read-only mode
 * @retval ptr Mailbox
 */
struct Mailbox *change_folder_notmuch(struct Menu *menu, char *buf, int buflen, int *oldcount,
                                      struct IndexSharedData *shared, bool read_only)
{
  if (!nm_url_from_query(NULL, buf, buflen))
  {
    mutt_message(_("Failed to create query, aborting"));
    return NULL;
  }

  struct Mailbox *m_query = mx_path_resolve(buf);
  change_folder_mailbox(menu, m_query, oldcount, shared, read_only);
  if (!shared->mailbox_view)
    mailbox_free(&m_query);
  return m_query;
}
#endif

/**
 * change_folder_string - Change to a different Mailbox by string
 * @param menu         Current Menu
 * @param buf          Folder to change to
 * @param oldcount     How many items are currently in the index
 * @param shared       Shared Index data
 * @param read_only    Open Mailbox in read-only mode
 */
void change_folder_string(struct Menu *menu, struct Buffer *buf, int *oldcount,
                          struct IndexSharedData *shared, bool read_only)
{
  if (OptNews)
  {
    OptNews = false;
    nntp_expand_path(buf->data, buf->dsize, &CurrentNewsSrv->conn->account);
  }
  else
  {
    const char *const c_folder = cs_subset_string(shared->sub, "folder");
    mx_path_canon(buf, c_folder, NULL);
  }

  enum MailboxType type = mx_path_probe(buf_string(buf));
  if ((type == MUTT_MAILBOX_ERROR) || (type == MUTT_UNKNOWN))
  {
    // Look for a Mailbox by its description, before failing
    struct Mailbox *m = mailbox_find_name(buf_string(buf));
    if (m)
    {
      change_folder_mailbox(menu, m, oldcount, shared, read_only);
    }
    else
    {
      mutt_error(_("%s is not a mailbox"), buf_string(buf));
    }
    return;
  }

  struct Mailbox *m = mx_path_resolve(buf_string(buf));
  change_folder_mailbox(menu, m, oldcount, shared, read_only);
}

/**
 * mutt_make_string - Create formatted strings using mailbox expandos
 * @param buf      Buffer for the result
 * @param max_cols Number of screen columns (-1 means unlimited)
 * @param exp      Expando containing expando tree
 * @param m        Mailbox
 * @param inpgr    Message shown in the pager
 * @param e        Email
 * @param flags    Flags, see #MuttFormatFlags
 * @param progress Pager progress string
 * @retval num Number of screen columns used
 */
int mutt_make_string(struct Buffer *buf, size_t max_cols,
                     const struct Expando *exp, struct Mailbox *m, int inpgr,
                     struct Email *e, MuttFormatFlags flags, const char *progress)
{
  if (!exp)
    return 0;

  struct EmailFormatInfo efi = { 0 };

  efi.email = e;
  efi.mailbox = m;
  efi.msg_in_pager = inpgr;
  efi.pager_progress = progress;

  return expando_filter(exp, IndexRenderCallbacks, &efi, flags, max_cols, EnvList, buf);
}

/**
 * index_make_entry - Format an Email for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $index_format
 */
int index_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  if (!menu || !menu->mdata)
    return 0;

  struct IndexPrivateData *priv = menu->mdata;
  struct IndexSharedData *shared = priv->shared;
  struct Mailbox *m = shared->mailbox;
  if (!shared->mailbox_view)
    menu->current = -1;

  if (!m || (line < 0) || (line >= m->email_max))
    return 0;

  struct Email *e = mutt_get_virt_email(m, line);
  if (!e)
    return 0;

  MuttFormatFlags flags = MUTT_FORMAT_ARROWCURSOR | MUTT_FORMAT_INDEX;
  struct MuttThread *tmp = NULL;

  const enum UseThreads c_threads = mutt_thread_style();
  if ((c_threads > UT_FLAT) && e->tree && e->thread)
  {
    flags |= MUTT_FORMAT_TREE; /* display the thread tree */
    if (e->display_subject)
    {
      flags |= MUTT_FORMAT_FORCESUBJ;
    }
    else
    {
      const bool reverse = c_threads == UT_REVERSE;
      int edgemsgno;
      if (reverse)
      {
        if (menu->top + menu->page_len > menu->max)
          edgemsgno = m->v2r[menu->max - 1];
        else
          edgemsgno = m->v2r[menu->top + menu->page_len - 1];
      }
      else
      {
        edgemsgno = m->v2r[menu->top];
      }

      for (tmp = e->thread->parent; tmp; tmp = tmp->parent)
      {
        if (!tmp->message)
          continue;

        /* if no ancestor is visible on current screen, provisionally force
         * subject... */
        if (reverse ? (tmp->message->msgno > edgemsgno) : (tmp->message->msgno < edgemsgno))
        {
          flags |= MUTT_FORMAT_FORCESUBJ;
          break;
        }
        else if (tmp->message->vnum >= 0)
        {
          break;
        }
      }
      if (flags & MUTT_FORMAT_FORCESUBJ)
      {
        for (tmp = e->thread->prev; tmp; tmp = tmp->prev)
        {
          if (!tmp->message)
            continue;

          /* ...but if a previous sibling is available, don't force it */
          if (reverse ? (tmp->message->msgno > edgemsgno) : (tmp->message->msgno < edgemsgno))
          {
            break;
          }
          else if (tmp->message->vnum >= 0)
          {
            flags &= ~MUTT_FORMAT_FORCESUBJ;
            break;
          }
        }
      }
    }
  }

  const struct Expando *c_index_format = cs_subset_expando(shared->sub, "index_format");
  int msg_in_pager = shared->mailbox_view ? shared->mailbox_view->msg_in_pager : 0;

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  return mutt_make_string(buf, max_cols, c_index_format, m, msg_in_pager, e, flags, NULL);
}

/**
 * index_color - Calculate the colour for a line of the index - Implements Menu::color() - @ingroup menu_color
 */
const struct AttrColor *index_color(struct Menu *menu, int line)
{
  struct IndexPrivateData *priv = menu->mdata;
  struct IndexSharedData *shared = priv->shared;
  struct Mailbox *m = shared->mailbox;
  if (!m || (line < 0))
    return NULL;

  struct Email *e = mutt_get_virt_email(m, line);
  if (!e)
    return NULL;

  if (e->attr_color)
    return e->attr_color;

  email_set_color(m, e);
  return e->attr_color;
}

/**
 * mutt_draw_statusline - Draw a highlighted status bar
 * @param win      Window
 * @param max_cols Maximum number of screen columns
 * @param buf      Message to be displayed
 * @param buflen   Length of the buffer
 *
 * Users configure the highlighting of the status bar, e.g.
 *     color status red default "[0-9][0-9]:[0-9][0-9]"
 *
 * Where regexes overlap, the one nearest the start will be used.
 * If two regexes start at the same place, the longer match will be used.
 */
void mutt_draw_statusline(struct MuttWindow *win, int max_cols, const char *buf, size_t buflen)
{
  if (!buf || !stdscr)
    return;

  size_t i = 0;
  size_t offset = 0;
  bool found = false;
  size_t chunks = 0;
  size_t len = 0;

  /**
   * struct StatusSyntax - Colours of the status bar
   */
  struct StatusSyntax
  {
    const struct AttrColor *attr_color;
    int first; ///< First character of that colour
    int last;  ///< Last character of that colour
  } *syntax = NULL;

  const struct AttrColor *ac_base = merged_color_overlay(simple_color_get(MT_COLOR_NORMAL),
                                                         simple_color_get(MT_COLOR_STATUS));
  do
  {
    struct RegexColor *cl = NULL;
    found = false;

    if (!buf[offset])
      break;

    /* loop through each "color status regex" */
    STAILQ_FOREACH(cl, regex_colors_get_list(MT_COLOR_STATUS), entries)
    {
      regmatch_t pmatch[cl->match + 1];
      memset(pmatch, 0, (cl->match + 1) * sizeof(regmatch_t));

      if (regexec(&cl->regex, buf + offset, cl->match + 1, pmatch, 0) != 0)
        continue; /* regex doesn't match the status bar */

      int first = pmatch[cl->match].rm_so + offset;
      int last = pmatch[cl->match].rm_eo + offset;

      if (first == last)
        continue; /* ignore an empty regex */

      if (!found)
      {
        chunks++;
        MUTT_MEM_REALLOC(&syntax, chunks, struct StatusSyntax);
      }

      i = chunks - 1;
      if (!found || (first < syntax[i].first) ||
          ((first == syntax[i].first) && (last > syntax[i].last)))
      {
        const struct AttrColor *ac_merge = merged_color_overlay(ac_base, &cl->attr_color);

        syntax[i].attr_color = ac_merge;
        syntax[i].first = first;
        syntax[i].last = last;
      }
      found = true;
    }

    if (syntax)
    {
      offset = syntax[i].last;
    }
  } while (found);

  /* Only 'len' bytes will fit into 'max_cols' screen columns */
  len = mutt_wstr_trunc(buf, buflen, max_cols, NULL);

  offset = 0;

  if ((chunks > 0) && (syntax[0].first > 0))
  {
    /* Text before the first highlight */
    mutt_window_addnstr(win, buf, MIN(len, syntax[0].first));
    mutt_curses_set_color(ac_base);
    if (len <= syntax[0].first)
      goto dsl_finish; /* no more room */

    offset = syntax[0].first;
  }

  for (i = 0; i < chunks; i++)
  {
    /* Highlighted text */
    mutt_curses_set_color(syntax[i].attr_color);
    mutt_window_addnstr(win, buf + offset, MIN(len, syntax[i].last) - offset);
    if (len <= syntax[i].last)
      goto dsl_finish; /* no more room */

    size_t next;
    if ((i + 1) == chunks)
    {
      next = len;
    }
    else
    {
      next = MIN(len, syntax[i + 1].first);
    }

    mutt_curses_set_color(ac_base);
    offset = syntax[i].last;
    mutt_window_addnstr(win, buf + offset, next - offset);

    offset = next;
    if (offset >= len)
      goto dsl_finish; /* no more room */
  }

  mutt_curses_set_color(ac_base);
  if (offset < len)
  {
    /* Text after the last highlight */
    mutt_window_addnstr(win, buf + offset, len - offset);
  }

  int width = mutt_strwidth(buf);
  if (width < max_cols)
  {
    /* Pad the rest of the line with whitespace */
    mutt_paddstr(win, max_cols - width, "");
  }
dsl_finish:
  FREE(&syntax);
}

/**
 * dlg_index - Display a list of emails - @ingroup gui_dlg
 * @param dlg Dialog containing Windows to draw on
 * @param m_init Initial mailbox
 * @retval ptr Mailbox open in the index
 *
 * The Index Dialog is the heart of NeoMutt.
 * From here, the user can read and reply to emails, organise them into
 * folders, set labels, etc.
 */
struct Mailbox *dlg_index(struct MuttWindow *dlg, struct Mailbox *m_init)
{
  /* Make sure use_threads/sort/sort_aux are coherent */
  index_adjust_sort_threads(NeoMutt->sub);

  struct IndexSharedData *shared = dlg->wdata;
  index_shared_data_set_mview(shared, mview_new(m_init, NeoMutt->notify));

  struct MuttWindow *panel_index = window_find_child(dlg, WT_INDEX);

  struct IndexPrivateData *priv = panel_index->wdata;
  priv->win_index = window_find_child(panel_index, WT_MENU);

  int op = OP_NULL;

  if (shared->mailbox && (shared->mailbox->type == MUTT_NNTP))
    dlg->help_data = IndexNewsHelp;
  else
    dlg->help_data = IndexHelp;
  dlg->help_menu = MENU_INDEX;

  priv->menu = priv->win_index->wdata;
  priv->menu->make_entry = index_make_entry;
  priv->menu->color = index_color;
  priv->menu->max = shared->mailbox ? shared->mailbox->vcount : 0;
  menu_set_index(priv->menu, find_first_message(shared->mailbox_view));

  struct MuttWindow *old_focus = window_set_focus(priv->menu->win);
  mutt_window_reflow(NULL);

  if (!shared->attach_msg)
  {
    /* force the mailbox check after we enter the folder */
    mutt_mailbox_check(shared->mailbox, MUTT_MAILBOX_CHECK_POSTPONED);
  }
#ifdef USE_INOTIFY
  mutt_monitor_add(NULL);
#endif

  const bool c_collapse_all = cs_subset_bool(shared->sub, "collapse_all");
  if (mutt_using_threads() && c_collapse_all)
  {
    collapse_all(shared->mailbox_view, priv->menu, 0);
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }

  int rc = 0;
  do
  {
    /* Clear the tag prefix unless we just started it.
     * Don't clear the prefix on a timeout, but do clear on an abort */
    if (priv->tag_prefix && (op != OP_TAG_PREFIX) &&
        (op != OP_TAG_PREFIX_COND) && (op != OP_TIMEOUT))
    {
      priv->tag_prefix = false;
    }

    /* check if we need to resort the index because just about
     * any 'op' below could do mutt_enter_command(), either here or
     * from any new priv->menu launched, and change $sort/$sort_aux */
    if (OptNeedResort && shared->mailbox && (shared->mailbox->msg_count != 0) &&
        (menu_get_index(priv->menu) >= 0))
    {
      resort_index(shared->mailbox_view, priv->menu);
    }

    priv->menu->max = shared->mailbox ? shared->mailbox->vcount : 0;
    priv->oldcount = shared->mailbox ? shared->mailbox->msg_count : 0;

    if (shared->mailbox && shared->mailbox_view)
    {
      mailbox_gc_run();

      shared->mailbox_view->menu = priv->menu;
      /* check for new mail in the mailbox.  If nonzero, then something has
       * changed about the file (either we got new mail or the file was
       * modified underneath us.) */
      enum MxStatus check = mx_mbox_check(shared->mailbox);

      if (check == MX_STATUS_ERROR)
      {
        if (buf_is_empty(&shared->mailbox->pathbuf))
        {
          /* fatal error occurred */
          mview_free(&shared->mailbox_view);
          menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
        }

        mutt_pattern_free(&shared->search_state->pattern);
      }
      else if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED) ||
               (check == MX_STATUS_FLAGS))
      {
        /* notify the user of new mail */
        if (check == MX_STATUS_REOPENED)
        {
          mutt_error(_("Mailbox was externally modified.  Flags may be wrong."));
        }
        else if (check == MX_STATUS_NEW_MAIL)
        {
          for (size_t i = 0; i < shared->mailbox->msg_count; i++)
          {
            const struct Email *e = shared->mailbox->emails[i];
            if (e && !e->read && !e->old)
            {
              mutt_message(_("New mail in this mailbox"));
              const bool c_beep_new = cs_subset_bool(shared->sub, "beep_new");
              if (c_beep_new)
                mutt_beep(true);
              const struct Expando *c_new_mail_command =
                  cs_subset_expando(shared->sub, "new_mail_command");
              if (c_new_mail_command)
              {
                struct Buffer *cmd = buf_pool_get();
                menu_status_line(cmd, shared, NULL, -1, c_new_mail_command);
                if (mutt_system(buf_string(cmd)) != 0)
                  mutt_error(_("Error running \"%s\""), buf_string(cmd));
                buf_pool_release(&cmd);
              }
              break;
            }
          }
        }
        else if (check == MX_STATUS_FLAGS)
        {
          mutt_message(_("Mailbox was externally modified"));
        }

        /* avoid the message being overwritten by mailbox */
        priv->do_mailbox_notify = false;

        bool verbose = shared->mailbox->verbose;
        shared->mailbox->verbose = false;
        update_index(priv->menu, shared->mailbox_view, check, priv->oldcount, shared);
        shared->mailbox->verbose = verbose;
        priv->menu->max = shared->mailbox->vcount;
        menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
        mutt_pattern_free(&shared->search_state->pattern);
      }

      index_shared_data_set_email(shared, mutt_get_virt_email(shared->mailbox,
                                                              menu_get_index(priv->menu)));
    }

    if (!shared->attach_msg)
    {
      /* check for new mail in the incoming folders */
      mutt_mailbox_check(shared->mailbox, MUTT_MAILBOX_CHECK_NO_FLAGS);
      if (priv->do_mailbox_notify)
      {
        if (mutt_mailbox_notify(shared->mailbox))
        {
          const bool c_beep_new = cs_subset_bool(shared->sub, "beep_new");
          if (c_beep_new)
            mutt_beep(true);
          const struct Expando *c_new_mail_command = cs_subset_expando(shared->sub, "new_mail_command");
          if (c_new_mail_command)
          {
            struct Buffer *cmd = buf_pool_get();
            menu_status_line(cmd, shared, priv->menu, -1, c_new_mail_command);
            if (mutt_system(buf_string(cmd)) != 0)
              mutt_error(_("Error running \"%s\""), buf_string(cmd));
            buf_pool_release(&cmd);
          }
        }
      }
      else
      {
        priv->do_mailbox_notify = true;
      }
    }

    window_redraw(NULL);

    /* give visual indication that the next command is a tag- command */
    if (priv->tag_prefix)
    {
      msgwin_set_text(NULL, "tag-", MT_COLOR_NORMAL);
    }

    const bool c_arrow_cursor = cs_subset_bool(shared->sub, "arrow_cursor");
    const bool c_braille_friendly = cs_subset_bool(shared->sub, "braille_friendly");
    const int index = menu_get_index(priv->menu);
    if (c_arrow_cursor)
    {
      const char *const c_arrow_string = cs_subset_string(shared->sub, "arrow_string");
      const int arrow_width = mutt_strwidth(c_arrow_string);
      mutt_window_move(priv->menu->win, index - priv->menu->top, arrow_width);
    }
    else if (c_braille_friendly)
    {
      mutt_window_move(priv->menu->win, index - priv->menu->top, 0);
    }
    else
    {
      mutt_window_move(priv->menu->win, index - priv->menu->top,
                       priv->menu->win->state.cols - 1);
    }
    mutt_refresh();

    window_redraw(NULL);
    op = km_dokey(MENU_INDEX, GETCH_NO_FLAGS);

    if (op == OP_REPAINT)
    {
      /* force a real complete redraw.  clrtobot() doesn't seem to be able
       * to handle every case without this.  */
      msgwin_clear_text(NULL);
      mutt_refresh();
      continue;
    }

    /* either user abort or timeout */
    if (op < OP_NULL)
    {
      if (priv->tag_prefix)
        msgwin_clear_text(NULL);
      continue;
    }

    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);

    /* special handling for the priv->tag-prefix function */
    const bool c_auto_tag = cs_subset_bool(shared->sub, "auto_tag");
    if ((op == OP_TAG_PREFIX) || (op == OP_TAG_PREFIX_COND))
    {
      /* A second priv->tag-prefix command aborts */
      if (priv->tag_prefix)
      {
        priv->tag_prefix = false;
        msgwin_clear_text(NULL);
        continue;
      }

      if (!shared->mailbox)
      {
        mutt_error(_("No mailbox is open"));
        continue;
      }

      if (shared->mailbox->msg_tagged == 0)
      {
        if (op == OP_TAG_PREFIX)
        {
          mutt_error(_("No tagged messages"));
        }
        else if (op == OP_TAG_PREFIX_COND)
        {
          mutt_flush_macro_to_endcond();
          mutt_message(_("Nothing to do"));
        }
        continue;
      }

      /* get the real command */
      priv->tag_prefix = true;
      continue;
    }
    else if (c_auto_tag && shared->mailbox && (shared->mailbox->msg_tagged != 0))
    {
      priv->tag_prefix = true;
    }

    mutt_clear_error();

    OptNews = false; /* for any case */

#ifdef USE_NOTMUCH
    nm_db_debug_check(shared->mailbox);
#endif

    rc = index_function_dispatcher(priv->win_index, op);

    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(priv->win_index, op);

    if (rc == FR_UNKNOWN)
    {
      struct MuttWindow *win_sidebar = window_find_child(dlg, WT_SIDEBAR);
      rc = sb_function_dispatcher(win_sidebar, op);
    }
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);

    if (rc == FR_UNKNOWN)
      km_error_key(MENU_INDEX);

#ifdef USE_NOTMUCH
    nm_db_debug_check(shared->mailbox);
#endif
  } while (rc != FR_DONE);

  mview_free(&shared->mailbox_view);
  window_set_focus(old_focus);

  return shared->mailbox;
}

/**
 * email_set_color - Select an Index colour for an Email
 * @param m Mailbox
 * @param e Current Email
 *
 * Calculate the colour for an Email in the Index.
 * Cache the colour in the Email.
 */
void email_set_color(struct Mailbox *m, struct Email *e)
{
  if (!e)
    return;

  struct RegexColor *color = NULL;
  struct PatternCache cache = { 0 };

  const struct AttrColor *ac_merge = NULL;
  STAILQ_FOREACH(color, regex_colors_get_list(MT_COLOR_INDEX), entries)
  {
    if (mutt_pattern_exec(SLIST_FIRST(color->color_pattern),
                          MUTT_MATCH_FULL_ADDRESS, m, e, &cache))
    {
      ac_merge = merged_color_overlay(ac_merge, &color->attr_color);
    }
  }

  struct AttrColor *ac_normal = simple_color_get(MT_COLOR_NORMAL);
  if (ac_merge)
    ac_merge = merged_color_overlay(ac_normal, ac_merge);
  else
    ac_merge = ac_normal;

  e->attr_color = ac_merge;
}

/**
 * index_pager_init - Allocate the Windows for the Index/Pager
 * @retval ptr Dialog containing nested Windows
 */
struct MuttWindow *index_pager_init(void)
{
  struct MuttWindow *dlg = mutt_window_new(WT_DLG_INDEX, MUTT_WIN_ORIENT_HORIZONTAL,
                                           MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                           MUTT_WIN_SIZE_UNLIMITED);

  struct IndexSharedData *shared = index_shared_data_new();
  notify_set_parent(shared->notify, dlg->notify);

  dlg->wdata = shared;
  dlg->wdata_free = index_shared_data_free;

  const bool c_status_on_top = cs_subset_bool(NeoMutt->sub, "status_on_top");

  struct MuttWindow *panel_index = ipanel_new(c_status_on_top, shared);
  struct MuttWindow *panel_pager = ppanel_new(c_status_on_top, shared);

  mutt_window_add_child(dlg, panel_index);
  mutt_window_add_child(dlg, panel_pager);

  return dlg;
}

/**
 * index_change_folder - Change the current folder, cautiously
 * @param dlg Dialog holding the Index
 * @param m   Mailbox to change to
 */
void index_change_folder(struct MuttWindow *dlg, struct Mailbox *m)
{
  if (!dlg || !m)
    return;

  struct IndexSharedData *shared = dlg->wdata;
  if (!shared)
    return;

  struct MuttWindow *panel_index = window_find_child(dlg, WT_INDEX);
  if (!panel_index)
    return;

  struct IndexPrivateData *priv = panel_index->wdata;
  if (!priv)
    return;

  change_folder_mailbox(priv->menu, m, &priv->oldcount, shared, false);
}
