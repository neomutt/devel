/**
 * @file
 * Representation of a mailbox
 *
 * @authors
 * Copyright (C) 2019-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020-2022 Pietro Cerutti <gahr@gahr.ch>
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

#ifndef MUTT_CORE_MAILBOX_H
#define MUTT_CORE_MAILBOX_H

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "mutt/lib.h"

struct ConfigSubset;
struct Email;

/**
 * enum MailboxType - Supported mailbox formats
 */
enum MailboxType
{
  MUTT_MAILBOX_ANY = -2,   ///< Match any Mailbox type
  MUTT_MAILBOX_ERROR,      ///< Error occurred examining Mailbox
  MUTT_UNKNOWN,            ///< Mailbox wasn't recognised
  MUTT_MBOX,               ///< 'mbox' Mailbox type
  MUTT_MMDF,               ///< 'mmdf' Mailbox type
  MUTT_MH,                 ///< 'MH' Mailbox type
  MUTT_MAILDIR,            ///< 'Maildir' Mailbox type
  MUTT_NNTP,               ///< 'NNTP' (Usenet) Mailbox type
  MUTT_IMAP,               ///< 'IMAP' Mailbox type
  MUTT_NOTMUCH,            ///< 'Notmuch' (virtual) Mailbox type
  MUTT_POP,                ///< 'POP3' Mailbox type
  MUTT_COMPRESSED,         ///< Compressed file Mailbox type
};

/**
 * ACL Rights - These show permission to...
 */
typedef uint16_t AclFlags;          ///< Flags, e.g. #MUTT_ACL_ADMIN
#define MUTT_ACL_NO_FLAGS       0   ///< No flags are set
#define MUTT_ACL_ADMIN   (1 <<  0)  ///< Administer the account (get/set permissions)
#define MUTT_ACL_CREATE  (1 <<  1)  ///< Create a mailbox
#define MUTT_ACL_DELETE  (1 <<  2)  ///< Delete a message
#define MUTT_ACL_DELMX   (1 <<  3)  ///< Delete a mailbox
#define MUTT_ACL_EXPUNGE (1 <<  4)  ///< Expunge messages
#define MUTT_ACL_INSERT  (1 <<  5)  ///< Add/copy into the mailbox (used when editing a message)
#define MUTT_ACL_LOOKUP  (1 <<  6)  ///< Lookup mailbox (visible to 'list')
#define MUTT_ACL_POST    (1 <<  7)  ///< Post (submit messages to the server)
#define MUTT_ACL_READ    (1 <<  8)  ///< Read the mailbox
#define MUTT_ACL_SEEN    (1 <<  9)  ///< Change the 'seen' status of a message
#define MUTT_ACL_WRITE   (1 << 10)  ///< Write to a message (for flagging or linking threads)

#define MUTT_ACL_ALL    ((1 << 11) - 1)

/**
 * struct Mailbox - A mailbox
 */
struct Mailbox
{
  struct Buffer pathbuf;              ///< Path of the Mailbox
  char *realpath;                     ///< Used for duplicate detection, context comparison, and the sidebar
  char *name;                         ///< A short name for the Mailbox
  struct ConfigSubset *sub;           ///< Inherited config items
  off_t size;                         ///< Size of the Mailbox
  bool has_new;                       ///< Mailbox has new mail

  // These next three are only set when $mail_check_stats is set
  int msg_count;                      ///< Total number of messages
  int msg_unread;                     ///< Number of unread messages
  int msg_flagged;                    ///< Number of flagged messages

  int msg_new;                        ///< Number of new messages
  int msg_deleted;                    ///< Number of deleted messages
  int msg_tagged;                     ///< How many messages are tagged?

  struct Email **emails;              ///< Array of Emails
  int email_max;                      ///< Size of `emails` array
  int *v2r;                           ///< Mapping from virtual to real msgno
  int vcount;                         ///< The number of virtual messages

  bool notified;                      ///< User has been notified
  enum MailboxType type;              ///< Mailbox type
  bool newly_created;                 ///< Mbox or mmdf just popped into existence
  struct timespec last_visited;       ///< Time of last exit from this mailbox
  time_t last_checked;                ///< Last time we checked this mailbox for new mail

  const struct MxOps *mx_ops;         ///< MXAPI callback functions

  bool append                 : 1;    ///< Mailbox is opened in append mode
  bool changed                : 1;    ///< Mailbox has been modified
  bool dontwrite              : 1;    ///< Don't write the mailbox on close
  bool first_check_stats_done : 1;    ///< True when the check have been done at least one time
  bool notify_user            : 1;    ///< Notify the user of new mail
  bool peekonly               : 1;    ///< Just taking a glance, revert atime
  bool poll_new_mail          : 1;    ///< Check for new mail
  bool readonly               : 1;    ///< Don't allow changes to the mailbox
  bool verbose                : 1;    ///< Display status messages?

  AclFlags rights;                    ///< ACL bits, see #AclFlags

  void *compress_info;                ///< Compressed mbox module private data

  struct HashTable *id_hash;          ///< Hash Table: "message-id" -> Email
  struct HashTable *subj_hash;        ///< Hash Table: "subject" -> Email
  struct HashTable *label_hash;       ///< Hash Table: "x-labels" -> Email

  struct Account *account;            ///< Account that owns this Mailbox
  int opened;                         ///< Number of times mailbox is opened

  bool visible;                       ///< True if a result of "mailboxes"

  void *mdata;                        ///< Driver specific data

  /**
   * @defgroup mailbox_mdata_free Mailbox Private Data API
   *
   * mdata_free - Free the private data attached to the Mailbox
   * @param ptr Private data to be freed
   *
   * @pre ptr  is not NULL
   * @pre *ptr is not NULL
   */
  void (*mdata_free)(void **ptr);

  struct Notify *notify;              ///< Notifications: #NotifyMailbox, #EventMailbox

  int gen;                            ///< Generation number, for sorting
};

/**
 * ExpandoDataMailbox - Expando UIDs for Mailboxes
 *
 * @sa ED_MAILBOX, ExpandoDomain
 */
enum ExpandoDataMailbox
{
  ED_MBX_MAILBOX_NAME = 1,     ///< Mailbox, mailbox_path()
  ED_MBX_MESSAGE_COUNT,        ///< Mailbox.msg_count
  ED_MBX_PERCENTAGE,           ///< EmailFormatInfo.pager_progress
};

/**
 * struct MailboxNode - List of Mailboxes
 */
struct MailboxNode
{
  struct Mailbox *mailbox;           ///< Mailbox in the list
  STAILQ_ENTRY(MailboxNode) entries; ///< Linked list
};
STAILQ_HEAD(MailboxList, MailboxNode);

/**
 * enum NotifyMailbox - Types of Mailbox Event
 *
 * Observers of #NT_MAILBOX will be passed an #EventMailbox.
 *
 * @note Delete notifications are sent **before** the object is deleted.
 * @note Other notifications are sent **after** the event.
 */
enum NotifyMailbox
{
  NT_MAILBOX_ADD = 1,    ///< Mailbox has been added
  NT_MAILBOX_DELETE,     ///< Mailbox is about to be deleted
  NT_MAILBOX_DELETE_ALL, ///< All Mailboxes are about to be deleted
  NT_MAILBOX_CHANGE,     ///< Mailbox has been changed
  NT_MAILBOX_NEW_MAIL,   ///< Mailbox has new mail

  /* These don't really belong here as they are tied to GUI operations.
   * Eventually, they'll be eliminated. */
  NT_MAILBOX_INVALID,    ///< Email list was changed
  NT_MAILBOX_RESORT,     ///< Email list needs resorting
  NT_MAILBOX_UPDATE,     ///< Update internal tables
  NT_MAILBOX_UNTAG,      ///< Clear the 'last-tagged' pointer
};

/**
 * struct EventMailbox - An Event that happened to a Mailbox
 */
struct EventMailbox
{
  struct Mailbox *mailbox; ///< The Mailbox this Event relates to
};

void            mailbox_changed   (struct Mailbox *m, enum NotifyMailbox action);
struct Mailbox *mailbox_find      (const char *path);
struct Mailbox *mailbox_find_name (const char *name);
void            mailbox_free      (struct Mailbox **ptr);
int             mailbox_gen       (void);
struct Mailbox *mailbox_new       (void);
bool            mailbox_set_subset(struct Mailbox *m, struct ConfigSubset *sub);
void            mailbox_size_add  (struct Mailbox *m, const struct Email *e);
void            mailbox_size_sub  (struct Mailbox *m, const struct Email *e);
void            mailbox_update    (struct Mailbox *m);
void            mailbox_gc_add    (struct Email *e);
void            mailbox_gc_run    (void);

const char *mailbox_get_type_name(enum MailboxType type);

/**
 * mailbox_path - Get the Mailbox's path string
 * @param m Mailbox
 * @retval ptr Path string
 */
static inline const char *mailbox_path(const struct Mailbox *m) // LCOV_EXCL_LINE
{
  return buf_string(&m->pathbuf); // LCOV_EXCL_LINE
}

#endif /* MUTT_CORE_MAILBOX_H */
