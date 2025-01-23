/**
 * @file
 * Data shared between Index, Pager and Sidebar
 *
 * @authors
 * Copyright (C) 2021-2024 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_INDEX_SHARED_DATA_H
#define MUTT_INDEX_SHARED_DATA_H

#include <stdbool.h>
#include <stdio.h>

struct MailboxView;
struct Email;
struct MuttWindow;

struct MailboxNotify {
  bool has_new_mail;        ///< Does the mailbox have new mails?
  bool notified;            ///< Did we already notify?
};

/**
 * struct IndexSharedData - Data shared between Index, Pager and Sidebar
 */
struct IndexSharedData
{
  struct ConfigSubset *sub;            ///< Config set to use
  struct Account      *account;        ///< Current Account
  struct MailboxView  *mailbox_view;   ///< Current Mailbox view
  struct Mailbox      *mailbox;        ///< Current Mailbox
  struct Email        *email;          ///< Currently selected Email
  size_t               email_seq;      ///< Sequence number of the current email
  struct Notify       *notify;         ///< Notifications: #NotifyIndex, #IndexSharedData
  struct SearchState  *search_state;   ///< State of the current search
  bool                 attach_msg;     ///< Are we in "attach message" mode?
  struct HashTable    *mb_notify;      ///< <mailbox name> -> <MailboxNotify>
};

/**
 * ExpandoDataIndex - Expando UIDs for the Index
 *
 * @sa ED_INDEX, ExpandoDomain
 */
enum ExpandoDataIndex
{
  ED_IND_DELETED_COUNT = 1,    ///< Mailbox.msg_deleted
  ED_IND_DESCRIPTION,          ///< Mailbox.name
  ED_IND_FLAGGED_COUNT,        ///< Mailbox.msg_flagged
  ED_IND_LIMIT_COUNT,          ///< Mailbox.vcount
  ED_IND_LIMIT_PATTERN,        ///< MailboxView.pattern
  ED_IND_LIMIT_SIZE,           ///< MailboxView.vsize
  ED_IND_MAILBOX_PATH,         ///< Mailbox.pathbuf, Mailbox.name
  ED_IND_MAILBOX_SIZE,         ///< Mailbox.size
  ED_IND_MESSAGE_COUNT,        ///< Mailbox.msg_count
  ED_IND_NEW_COUNT,            ///< Mailbox.msg_new
  ED_IND_OLD_COUNT,            ///< Mailbox.msg_unread, Mailbox.msg_new
  ED_IND_POSTPONED_COUNT,      ///< mutt_num_postponed()
  ED_IND_READONLY,             ///< Mailbox.readonly, Mailbox.dontwrite
  ED_IND_READ_COUNT,           ///< Mailbox.msg_count, Mailbox.msg_unread
  ED_IND_TAGGED_COUNT,         ///< Mailbox.msg_tagged
  ED_IND_UNREAD_COUNT,         ///< Mailbox.msg_unread
  ED_IND_UNREAD_MAILBOXES,     ///< Mailbox, mutt_mailbox_check()
};

void                    index_shared_data_free(struct MuttWindow *win, void **ptr);
struct IndexSharedData *index_shared_data_new (void);

bool index_shared_data_is_cur_email(const struct IndexSharedData *shared, const struct Email *e);
void index_shared_data_set_mview   (struct IndexSharedData *shared, struct MailboxView *mv);
void index_shared_data_set_email   (struct IndexSharedData *shared, struct Email *e);

#endif /* MUTT_INDEX_SHARED_DATA_H */
