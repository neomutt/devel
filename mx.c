/**
 * @file
 * Mailbox multiplexor
 *
 * @authors
 * Copyright (C) 1996-2002,2010,2013 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 1999-2003 Thomas Roessler <roessler@does-not-exist.org>
 * Copyright (C) 2016-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018 Mehdi Abaakouk <sileht@sileht.net>
 * Copyright (C) 2018-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Austin Ray <austin@austinray.io>
 * Copyright (C) 2020 Reto Brunner <reto@slightlybroken.com>
 * Copyright (C) 2023-2024 Dennis Schön <mail@dennis-schoen.de>
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
 * @page neo_mx Mailbox multiplexor
 *
 * Mailbox multiplexor
 */

#include "config.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "mx.h"
#include "compmbox/lib.h"
#include "imap/lib.h"
#include "key/lib.h"
#include "maildir/lib.h"
#include "mbox/lib.h"
#include "menu/lib.h"
#include "mh/lib.h"
#include "nntp/lib.h"
#include "pop/lib.h"
#include "question/lib.h"
#include "copy.h"
#include "external.h"
#include "globals.h"
#include "hook.h"
#include "mutt_header.h"
#include "mutt_logging.h"
#include "mutt_mailbox.h"
#include "muttlib.h"
#include "nntp/mdata.h" // IWYU pragma: keep
#include "protos.h"
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#endif

/// Lookup table of mailbox types
static const struct Mapping MboxTypeMap[] = {
  // clang-format off
  { "mbox",    MUTT_MBOX,    },
  { "mmdf",    MUTT_MMDF,    },
  { "mh",      MUTT_MH,      },
  { "maildir", MUTT_MAILDIR, },
  { NULL, 0, },
  // clang-format on
};

/// Data for the $mbox_type enumeration
const struct EnumDef MboxTypeDef = {
  "mbox_type",
  4,
  (struct Mapping *) &MboxTypeMap,
};

/**
 * MxOps - All the Mailbox backends
 */
static const struct MxOps *MxOps[] = {
  /* These mailboxes can be recognised by their Url scheme */
  &MxImapOps,
#ifdef USE_NOTMUCH
  &MxNotmuchOps,
#endif
  &MxPopOps,
  &MxNntpOps,

  /* Local mailboxes */
  &MxMaildirOps,
  &MxMboxOps,
  &MxMhOps,
  &MxMmdfOps,

  /* If everything else fails... */
  &MxCompOps,
  NULL,
};

/**
 * mx_get_ops - Get mailbox operations
 * @param type Mailbox type
 * @retval ptr  Mailbox function
 * @retval NULL Error
 */
const struct MxOps *mx_get_ops(enum MailboxType type)
{
  for (const struct MxOps **ops = MxOps; *ops; ops++)
    if ((*ops)->type == type)
      return *ops;

  return NULL;
}

/**
 * mutt_is_spool - Is this the spool_file?
 * @param str Name to check
 * @retval true It is the spool_file
 */
static bool mutt_is_spool(const char *str)
{
  const char *const c_spool_file = cs_subset_string(NeoMutt->sub, "spool_file");
  if (mutt_str_equal(str, c_spool_file))
    return true;

  struct Url *ua = url_parse(str);
  struct Url *ub = url_parse(c_spool_file);

  const bool is_spool = ua && ub && (ua->scheme == ub->scheme) &&
                        mutt_istr_equal(ua->host, ub->host) &&
                        mutt_istr_equal(ua->path, ub->path) &&
                        (!ua->user || !ub->user || mutt_str_equal(ua->user, ub->user));

  url_free(&ua);
  url_free(&ub);
  return is_spool;
}

/**
 * mx_access - Wrapper for access, checks permissions on a given mailbox
 * @param path  Path of mailbox
 * @param flags Flags, e.g. W_OK
 * @retval  0 Success, allowed
 * @retval <0 Failure, not allowed
 *
 * We may be interested in using ACL-style flags at some point, currently we
 * use the normal access() flags.
 */
int mx_access(const char *path, int flags)
{
  if (imap_path_probe(path, NULL) == MUTT_IMAP)
    return imap_access(path);

  return access(path, flags);
}

/**
 * mx_open_mailbox_append - Open a mailbox for appending
 * @param m     Mailbox
 * @param flags Flags, see #OpenMailboxFlags
 * @retval true Success
 * @retval false Failure
 */
static bool mx_open_mailbox_append(struct Mailbox *m, OpenMailboxFlags flags)
{
  if (!m)
    return false;

  struct stat st = { 0 };

  m->append = true;
  if ((m->type == MUTT_UNKNOWN) || (m->type == MUTT_MAILBOX_ERROR))
  {
    m->type = mx_path_probe(mailbox_path(m));

    if (m->type == MUTT_UNKNOWN)
    {
      if (flags & MUTT_APPEND)
      {
        m->type = MUTT_MAILBOX_ERROR;
      }
      else
      {
        mutt_error(_("%s is not a mailbox"), mailbox_path(m));
        return false;
      }
    }

    if (m->type == MUTT_MAILBOX_ERROR)
    {
      if (stat(mailbox_path(m), &st) == -1)
      {
        if (errno == ENOENT)
        {
          if (mutt_comp_can_append(m))
            m->type = MUTT_COMPRESSED;
          else
            m->type = cs_subset_enum(NeoMutt->sub, "mbox_type");
          flags |= MUTT_APPENDNEW;
        }
        else
        {
          mutt_perror("%s", mailbox_path(m));
          return false;
        }
      }
      else
      {
        return false;
      }
    }

    m->mx_ops = mx_get_ops(m->type);
  }

  if (!m->mx_ops || !m->mx_ops->mbox_open_append)
    return false;

  const bool rc = m->mx_ops->mbox_open_append(m, flags);
  m->opened++;
  return rc;
}

/**
 * mx_mbox_ac_link - Link a Mailbox to an existing or new Account
 * @param m Mailbox to link
 * @retval true Success
 * @retval false Failure
 */
bool mx_mbox_ac_link(struct Mailbox *m)
{
  if (!m)
    return false;

  if (m->account)
    return true;

  struct Account *a = mx_ac_find(m);
  const bool new_account = !a;
  if (new_account)
  {
    a = account_new(NULL, NeoMutt->sub);
    a->type = m->type;
  }
  if (!mx_ac_add(a, m))
  {
    if (new_account)
    {
      account_free(&a);
    }
    return false;
  }
  if (new_account)
  {
    neomutt_account_add(NeoMutt, a);
  }
  return true;
}

/**
 * mx_mbox_open - Open a mailbox and parse it
 * @param m     Mailbox to open
 * @param flags Flags, see #OpenMailboxFlags
 * @retval true Success
 * @retval false Error
 */
bool mx_mbox_open(struct Mailbox *m, OpenMailboxFlags flags)
{
  if (!m)
    return false;

  if ((m->type == MUTT_UNKNOWN) && (flags & MUTT_APPEND))
  {
    m->type = cs_subset_enum(NeoMutt->sub, "mbox_type");
    m->mx_ops = mx_get_ops(m->type);
  }

  const bool newly_linked_account = !m->account;
  if (newly_linked_account)
  {
    if (!mx_mbox_ac_link(m))
    {
      return false;
    }
  }

  m->verbose = !(flags & MUTT_QUIET);
  m->readonly = (flags & MUTT_READONLY);
  m->peekonly = (flags & MUTT_PEEK);

  if (flags & MUTT_APPEND)
  {
    if (!mx_open_mailbox_append(m, flags))
    {
      goto error;
    }
    return true;
  }

  if (m->opened > 0)
  {
    m->opened++;
    return true;
  }

  m->size = 0;
  m->msg_unread = 0;
  m->msg_flagged = 0;
  m->rights = MUTT_ACL_ALL;

  if (m->type == MUTT_UNKNOWN)
  {
    m->type = mx_path_probe(mailbox_path(m));
    m->mx_ops = mx_get_ops(m->type);
  }

  if ((m->type == MUTT_UNKNOWN) || (m->type == MUTT_MAILBOX_ERROR) || !m->mx_ops)
  {
    if (m->type == MUTT_MAILBOX_ERROR)
      mutt_perror("%s", mailbox_path(m));
    else if ((m->type == MUTT_UNKNOWN) || !m->mx_ops)
      mutt_error(_("%s is not a mailbox"), mailbox_path(m));
    goto error;
  }

  mutt_make_label_hash(m);

  /* if the user has a 'push' command in their .neomuttrc, or in a folder-hook,
   * it will cause the progress messages not to be displayed because
   * mutt_refresh() will think we are in the middle of a macro.  so set a
   * flag to indicate that we should really refresh the screen.  */
  OptForceRefresh = true;

  if (m->verbose)
    mutt_message(_("Reading %s..."), mailbox_path(m));

  // Clear out any existing emails
  for (int i = 0; i < m->email_max; i++)
  {
    email_free(&m->emails[i]);
  }

  m->msg_count = 0;
  m->msg_unread = 0;
  m->msg_flagged = 0;
  m->msg_new = 0;
  m->msg_deleted = 0;
  m->msg_tagged = 0;
  m->vcount = 0;

  enum MxOpenReturns rc = m->mx_ops->mbox_open(m);
  m->opened++;

  if ((rc == MX_OPEN_OK) || (rc == MX_OPEN_ABORT))
  {
    if ((flags & MUTT_NOSORT) == 0)
    {
      /* avoid unnecessary work since the mailbox is completely unthreaded
       * to begin with */
      OptSortSubthreads = false;
      OptNeedRescore = false;
    }
    if (m->verbose)
      mutt_clear_error();
    if (rc == MX_OPEN_ABORT)
    {
      mutt_error(_("Reading from %s interrupted..."), mailbox_path(m));
    }
  }
  else
  {
    goto error;
  }

  if (!m->peekonly)
    m->has_new = false;
  OptForceRefresh = false;

  return true;

error:
  mx_fastclose_mailbox(m, newly_linked_account);
  if (newly_linked_account)
    account_mailbox_remove(m->account, m);
  return false;
}

/**
 * mx_fastclose_mailbox - Free up memory associated with the Mailbox
 * @param m Mailbox
 * @param keep_account Make sure not to remove the mailbox's account
 */
void mx_fastclose_mailbox(struct Mailbox *m, bool keep_account)
{
  if (!m)
    return;

  m->opened--;
  if (m->opened != 0)
    return;

  /* never announce that a mailbox we've just left has new mail.
   * TODO: really belongs in mx_mbox_close, but this is a nice hook point */
  if (!m->peekonly)
    mutt_mailbox_set_notified(m);

  if (m->mx_ops)
    m->mx_ops->mbox_close(m);

  mutt_hash_free(&m->subj_hash);
  mutt_hash_free(&m->id_hash);
  mutt_hash_free(&m->label_hash);

  if (m->emails)
  {
    for (int i = 0; i < m->msg_count; i++)
    {
      if (!m->emails[i])
        break;
      email_free(&m->emails[i]);
    }
  }

  if (!m->visible)
  {
    mx_ac_remove(m, keep_account);
  }
}

/**
 * sync_mailbox - Save changes to disk
 * @param m Mailbox
 * @retval enum #MxStatus
 */
static enum MxStatus sync_mailbox(struct Mailbox *m)
{
  if (!m || !m->mx_ops || !m->mx_ops->mbox_sync)
    return MX_STATUS_ERROR;

  if (m->verbose)
  {
    /* L10N: Displayed before/as a mailbox is being synced */
    mutt_message(_("Writing %s..."), mailbox_path(m));
  }

  enum MxStatus rc = m->mx_ops->mbox_sync(m);
  if (rc != MX_STATUS_OK)
  {
    mutt_debug(LL_DEBUG2, "mbox_sync returned: %d\n", rc);
    if ((rc == MX_STATUS_ERROR) && m->verbose)
    {
      /* L10N: Displayed if a mailbox sync fails */
      mutt_error(_("Unable to write %s"), mailbox_path(m));
    }
  }

  return rc;
}

/**
 * trash_append - Move deleted mails to the trash folder
 * @param m Mailbox
 * @retval  0 Success
 * @retval -1 Failure
 */
static int trash_append(struct Mailbox *m)
{
  if (!m)
    return -1;

  struct stat st = { 0 };
  struct stat stc = { 0 };
  int rc;

  const bool c_maildir_trash = cs_subset_bool(NeoMutt->sub, "maildir_trash");
  const char *const c_trash = cs_subset_string(NeoMutt->sub, "trash");
  if (!c_trash || (m->msg_deleted == 0) || ((m->type == MUTT_MAILDIR) && c_maildir_trash))
  {
    return 0;
  }

  int delmsgcount = 0;
  int first_del = -1;
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    if (e->deleted && !e->purge)
    {
      if (first_del < 0)
        first_del = i;
      delmsgcount++;
    }
  }

  if (delmsgcount == 0)
    return 0; /* nothing to be done */

  /* avoid the "append messages" prompt */
  const bool c_confirm_append = cs_subset_bool(NeoMutt->sub, "confirm_append");
  cs_subset_str_native_set(NeoMutt->sub, "confirm_append", false, NULL);
  rc = mutt_save_confirm(c_trash, &st);
  cs_subset_str_native_set(NeoMutt->sub, "confirm_append", c_confirm_append, NULL);
  if (rc != 0)
  {
    /* L10N: Although we know the precise number of messages, we do not show it to the user.
       So feel free to use a "generic plural" as plural translation if your language has one. */
    mutt_error(ngettext("message not deleted", "messages not deleted", delmsgcount));
    return -1;
  }

  if ((lstat(mailbox_path(m), &stc) == 0) && (stc.st_ino == st.st_ino) &&
      (stc.st_dev == st.st_dev) && (stc.st_rdev == st.st_rdev))
  {
    return 0; /* we are in the trash folder: simple sync */
  }

  if ((m->type == MUTT_IMAP) && (imap_path_probe(c_trash, NULL) == MUTT_IMAP))
  {
    if (imap_fast_trash(m, c_trash) == 0)
      return 0;
  }

  struct Mailbox *m_trash = mx_path_resolve(c_trash);
  const bool old_append = m_trash->append;
  if (!mx_mbox_open(m_trash, MUTT_APPEND))
  {
    mutt_error(_("Can't open trash folder"));
    mailbox_free(&m_trash);
    return -1;
  }

  /* continue from initial scan above */
  for (int i = first_del; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    if (e->deleted && !e->purge)
    {
      if (mutt_append_message(m_trash, m, e, NULL, MUTT_CM_NO_FLAGS, CH_NO_FLAGS) == -1)
      {
        mx_mbox_close(m_trash);
        // L10N: Displayed if appending to $trash fails when syncing or closing a mailbox
        mutt_error(_("Unable to append to trash folder"));
        m_trash->append = old_append;
        mailbox_free(&m_trash);
        return -1;
      }
    }
  }

  mx_mbox_close(m_trash);
  m_trash->append = old_append;
  mailbox_free(&m_trash);

  return 0;
}

/**
 * mx_mbox_close - Save changes and close mailbox
 * @param m Mailbox
 * @retval enum #MxStatus
 *
 * @note The flag retvals come from a call to a backend sync function
 *
 * @note It's very important to ensure the mailbox is properly closed before
 *       free'ing the context.  For selected mailboxes, IMAP will cache the
 *       context inside connection->adata until imap_close_mailbox() removes
 *       it.  Readonly, dontwrite, and append mailboxes are guaranteed to call
 *       mx_fastclose_mailbox(), so for most of NeoMutt's code you won't see
 *       return value checks for temporary contexts.
 */
enum MxStatus mx_mbox_close(struct Mailbox *m)
{
  if (!m)
    return MX_STATUS_ERROR;

  const bool c_mail_check_recent = cs_subset_bool(NeoMutt->sub, "mail_check_recent");
  if (c_mail_check_recent && !m->peekonly)
    m->has_new = false;

  if (m->readonly || m->dontwrite || m->append || m->peekonly)
  {
    mx_fastclose_mailbox(m, false);
    return 0;
  }

  int i, read_msgs = 0;
  enum MxStatus rc = MX_STATUS_ERROR;
  enum QuadOption move_messages = MUTT_NO;
  enum QuadOption purge = MUTT_YES;
  struct Buffer *mbox = NULL;
  struct Buffer *buf = buf_pool_get();

  if ((m->msg_unread != 0) && (m->type == MUTT_NNTP))
  {
    struct NntpMboxData *mdata = m->mdata;

    if (mdata && mdata->adata && mdata->group)
    {
      enum QuadOption ans = query_quadoption(_("Mark all articles read?"),
                                             NeoMutt->sub, "catchup_newsgroup");
      if (ans == MUTT_ABORT)
        goto cleanup;
      if (ans == MUTT_YES)
        mutt_newsgroup_catchup(m, mdata->adata, mdata->group);
    }
  }

  const bool c_keep_flagged = cs_subset_bool(NeoMutt->sub, "keep_flagged");
  for (i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    if (!e->deleted && e->read && !(e->flagged && c_keep_flagged))
      read_msgs++;
  }

  /* don't need to move articles from newsgroup */
  if (m->type == MUTT_NNTP)
    read_msgs = 0;

  const enum QuadOption c_move = cs_subset_quad(NeoMutt->sub, "move");
  if ((read_msgs != 0) && (c_move != MUTT_NO))
  {
    bool is_spool;
    mbox = buf_pool_get();

    char *p = mutt_find_hook(MUTT_MBOX_HOOK, mailbox_path(m));
    if (p)
    {
      is_spool = true;
      buf_strcpy(mbox, p);
    }
    else
    {
      const char *const c_mbox = cs_subset_string(NeoMutt->sub, "mbox");
      buf_strcpy(mbox, c_mbox);
      is_spool = mutt_is_spool(mailbox_path(m)) && !mutt_is_spool(buf_string(mbox));
    }

    if (is_spool && !buf_is_empty(mbox))
    {
      buf_expand_path(mbox);
      buf_printf(buf,
                 /* L10N: The first argument is the number of read messages to be
                            moved, the second argument is the target mailbox. */
                 ngettext("Move %d read message to %s?", "Move %d read messages to %s?", read_msgs),
                 read_msgs, buf_string(mbox));
      move_messages = query_quadoption(buf_string(buf), NeoMutt->sub, "move");
      if (move_messages == MUTT_ABORT)
        goto cleanup;
    }
  }

  /* There is no point in asking whether or not to purge if we are
   * just marking messages as "trash".  */
  const bool c_maildir_trash = cs_subset_bool(NeoMutt->sub, "maildir_trash");
  if ((m->msg_deleted != 0) && !((m->type == MUTT_MAILDIR) && c_maildir_trash))
  {
    buf_printf(buf, ngettext("Purge %d deleted message?", "Purge %d deleted messages?", m->msg_deleted),
               m->msg_deleted);
    purge = query_quadoption(buf_string(buf), NeoMutt->sub, "delete");
    if (purge == MUTT_ABORT)
      goto cleanup;
  }

  const bool c_mark_old = cs_subset_bool(NeoMutt->sub, "mark_old");
  if (c_mark_old && !m->peekonly)
  {
    for (i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (!e->deleted && !e->old && !e->read)
        mutt_set_flag(m, e, MUTT_OLD, true, true);
    }
  }

  if (move_messages)
  {
    if (m->verbose)
      mutt_message(_("Moving read messages to %s..."), buf_string(mbox));

    /* try to use server-side copy first */
    i = 1;

    if ((m->type == MUTT_IMAP) && (imap_path_probe(buf_string(mbox), NULL) == MUTT_IMAP))
    {
      /* add messages for moving, and clear old tags, if any */
      struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
      for (i = 0; i < m->msg_count; i++)
      {
        struct Email *e = m->emails[i];
        if (!e)
          break;

        if (e->read && !e->deleted && !(e->flagged && c_keep_flagged))
        {
          e->tagged = true;
          ARRAY_ADD(&ea, e);
        }
        else
        {
          e->tagged = false;
        }
      }

      i = imap_copy_messages(m, &ea, buf_string(mbox), SAVE_MOVE);
      if (i == 0)
      {
        const bool c_delete_untag = cs_subset_bool(NeoMutt->sub, "delete_untag");
        if (c_delete_untag)
        {
          struct Email **ep = NULL;
          ARRAY_FOREACH(ep, &ea)
          {
            mutt_set_flag(m, *ep, MUTT_TAG, false, true);
          }
        }
      }
      ARRAY_FREE(&ea);
    }

    if (i == 0) /* success */
    {
      mutt_clear_error();
    }
    else if (i == -1) /* horrible error, bail */
    {
      goto cleanup;
    }
    else /* use regular append-copy mode */
    {
      struct Mailbox *m_read = mx_path_resolve(buf_string(mbox));
      if (!mx_mbox_open(m_read, MUTT_APPEND))
      {
        mailbox_free(&m_read);
        goto cleanup;
      }

      for (i = 0; i < m->msg_count; i++)
      {
        struct Email *e = m->emails[i];
        if (!e)
          break;
        if (e->read && !e->deleted && !(e->flagged && c_keep_flagged))
        {
          if (mutt_append_message(m_read, m, e, NULL, MUTT_CM_NO_FLAGS, CH_UPDATE_LEN) == 0)
          {
            mutt_set_flag(m, e, MUTT_DELETE, true, true);
            mutt_set_flag(m, e, MUTT_PURGE, true, true);
          }
          else
          {
            mx_mbox_close(m_read);
            goto cleanup;
          }
        }
      }

      mx_mbox_close(m_read);
    }
  }
  else if (!m->changed && (m->msg_deleted == 0))
  {
    if (m->verbose)
      mutt_message(_("Mailbox is unchanged"));
    if ((m->type == MUTT_MBOX) || (m->type == MUTT_MMDF))
      mbox_reset_atime(m, NULL);
    mx_fastclose_mailbox(m, false);
    rc = MX_STATUS_OK;
    goto cleanup;
  }

  /* copy mails to the trash before expunging */
  const char *const c_trash = cs_subset_string(NeoMutt->sub, "trash");
  const struct Mailbox *m_trash = mx_mbox_find(m->account, c_trash);
  if (purge && (m->msg_deleted != 0) && (m != m_trash))
  {
    if (trash_append(m) != 0)
      goto cleanup;
  }

  /* allow IMAP to preserve the deleted flag across sessions */
  if (m->type == MUTT_IMAP)
  {
    const enum MxStatus check = imap_sync_mailbox(m, (purge != MUTT_NO), true);
    if (check == MX_STATUS_ERROR)
    {
      rc = check;
      goto cleanup;
    }
  }
  else
  {
    if (purge == MUTT_NO)
    {
      for (i = 0; i < m->msg_count; i++)
      {
        struct Email *e = m->emails[i];
        if (!e)
          break;

        e->deleted = false;
        e->purge = false;
      }
      m->msg_deleted = 0;
    }

    if (m->changed || (m->msg_deleted != 0))
    {
      enum MxStatus check = sync_mailbox(m);
      if (check != MX_STATUS_OK)
      {
        rc = check;
        goto cleanup;
      }
    }
  }

  if (m->verbose)
  {
    if (move_messages)
    {
      mutt_message(_("%d kept, %d moved, %d deleted"),
                   m->msg_count - m->msg_deleted, read_msgs, m->msg_deleted);
    }
    else
    {
      mutt_message(_("%d kept, %d deleted"), m->msg_count - m->msg_deleted, m->msg_deleted);
    }
  }

  const bool c_save_empty = cs_subset_bool(NeoMutt->sub, "save_empty");
  if ((m->msg_count == m->msg_deleted) &&
      ((m->type == MUTT_MMDF) || (m->type == MUTT_MBOX)) &&
      !mutt_is_spool(mailbox_path(m)) && !c_save_empty)
  {
    mutt_file_unlink_empty(mailbox_path(m));
  }

  if ((purge == MUTT_YES) && (m->msg_deleted != 0))
  {
    for (i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (e->deleted && !e->read)
      {
        m->msg_unread--;
        if (!e->old)
          m->msg_new--;
      }
      if (e->deleted && e->flagged)
        m->msg_flagged--;
    }
  }

  mx_fastclose_mailbox(m, false);

  rc = MX_STATUS_OK;

cleanup:
  buf_pool_release(&mbox);
  buf_pool_release(&buf);
  return rc;
}

/**
 * mx_mbox_sync - Save changes to mailbox
 * @param[in]  m          Mailbox
 * @retval enum #MxStatus
 *
 * @note The flag retvals come from a call to a backend sync function
 */
enum MxStatus mx_mbox_sync(struct Mailbox *m)
{
  if (!m)
    return MX_STATUS_ERROR;

  enum MxStatus rc = MX_STATUS_OK;
  int purge = 1;
  int msgcount, deleted;

  if (m->dontwrite)
  {
    struct Buffer *buf = buf_pool_get();
    struct Buffer *tmp = buf_pool_get();

    if (km_expand_key(km_find_func(MENU_INDEX, OP_TOGGLE_WRITE), buf))
      buf_printf(tmp, _(" Press '%s' to toggle write"), buf_string(buf));
    else
      buf_addstr(tmp, _("Use 'toggle-write' to re-enable write"));

    mutt_error(_("Mailbox is marked unwritable. %s"), buf_string(tmp));

    buf_pool_release(&buf);
    buf_pool_release(&tmp);
    return MX_STATUS_ERROR;
  }
  else if (m->readonly)
  {
    mutt_error(_("Mailbox is read-only"));
    return MX_STATUS_ERROR;
  }

  if (!m->changed && (m->msg_deleted == 0))
  {
    if (m->verbose)
      mutt_message(_("Mailbox is unchanged"));
    return MX_STATUS_OK;
  }

  if (m->msg_deleted != 0)
  {
    char buf[128] = { 0 };

    snprintf(buf, sizeof(buf),
             ngettext("Purge %d deleted message?", "Purge %d deleted messages?", m->msg_deleted),
             m->msg_deleted);
    purge = query_quadoption(buf, NeoMutt->sub, "delete");
    if (purge == MUTT_ABORT)
      return MX_STATUS_ERROR;
    if (purge == MUTT_NO)
    {
      if (!m->changed)
        return MX_STATUS_OK; /* nothing to do! */
      /* let IMAP servers hold on to D flags */
      if (m->type != MUTT_IMAP)
      {
        for (int i = 0; i < m->msg_count; i++)
        {
          struct Email *e = m->emails[i];
          if (!e)
            break;
          e->deleted = false;
          e->purge = false;
        }
        m->msg_deleted = 0;
      }
    }
    mailbox_changed(m, NT_MAILBOX_UNTAG);
  }

  /* really only for IMAP - imap_sync_mailbox results in a call to
   * ctx_update_tables, so m->msg_deleted is 0 when it comes back */
  msgcount = m->msg_count;
  deleted = m->msg_deleted;

  const char *const c_trash = cs_subset_string(NeoMutt->sub, "trash");
  const struct Mailbox *m_trash = mx_mbox_find(m->account, c_trash);
  if (purge && (m->msg_deleted != 0) && (m != m_trash))
  {
    if (trash_append(m) != 0)
      return MX_STATUS_OK;
  }

  if (m->type == MUTT_IMAP)
    rc = imap_sync_mailbox(m, purge, false);
  else
    rc = sync_mailbox(m);
  if (rc != MX_STATUS_ERROR)
  {
    if ((m->type == MUTT_IMAP) && !purge)
    {
      if (m->verbose)
        mutt_message(_("Mailbox checkpointed"));
    }
    else
    {
      if (m->verbose)
        mutt_message(_("%d kept, %d deleted"), msgcount - deleted, deleted);
    }

    mutt_sleep(0);

    const bool c_save_empty = cs_subset_bool(NeoMutt->sub, "save_empty");
    if ((m->msg_count == m->msg_deleted) &&
        ((m->type == MUTT_MBOX) || (m->type == MUTT_MMDF)) &&
        !mutt_is_spool(mailbox_path(m)) && !c_save_empty)
    {
      unlink(mailbox_path(m));
      mx_fastclose_mailbox(m, false);
      return MX_STATUS_OK;
    }

    /* if we haven't deleted any messages, we don't need to resort
     * ... except for certain folder formats which need "unsorted"
     * sort order in order to synchronize folders.
     *
     * MH and maildir are safe.  mbox-style seems to need re-sorting,
     * at least with the new threading code.  */
    if (purge || ((m->type != MUTT_MAILDIR) && (m->type != MUTT_MH)))
    {
      /* IMAP does this automatically after handling EXPUNGE */
      if (m->type != MUTT_IMAP)
      {
        mailbox_changed(m, NT_MAILBOX_UPDATE);
        mailbox_changed(m, NT_MAILBOX_RESORT);
      }
    }
  }

  return rc;
}

/**
 * mx_msg_open_new - Open a new message
 * @param m     Destination mailbox
 * @param e     Message being copied (required for maildir support, because the filename depends on the message flags)
 * @param flags Flags, see #MsgOpenFlags
 * @retval ptr New Message
 */
struct Message *mx_msg_open_new(struct Mailbox *m, const struct Email *e, MsgOpenFlags flags)
{
  if (!m)
    return NULL;

  struct Address *p = NULL;
  struct Message *msg = NULL;

  if (!m->mx_ops || !m->mx_ops->msg_open_new)
  {
    mutt_debug(LL_DEBUG1, "function unimplemented for mailbox type %d\n", m->type);
    return NULL;
  }

  msg = message_new();
  msg->write = true;

  if (e)
  {
    msg->flags.flagged = e->flagged;
    msg->flags.replied = e->replied;
    msg->flags.read = e->read;
    msg->flags.draft = (flags & MUTT_SET_DRAFT);
    msg->received = e->received;
  }

  if (msg->received == 0)
    msg->received = mutt_date_now();

  if (m->mx_ops->msg_open_new(m, msg, e))
  {
    if (m->type == MUTT_MMDF)
      fputs(MMDF_SEP, msg->fp);

    if (((m->type == MUTT_MBOX) || (m->type == MUTT_MMDF)) && (flags & MUTT_ADD_FROM))
    {
      if (e)
      {
        p = TAILQ_FIRST(&e->env->return_path);
        if (!p)
          p = TAILQ_FIRST(&e->env->sender);
        if (!p)
          p = TAILQ_FIRST(&e->env->from);
      }

      // Use C locale for the date, so that day/month names are in English
      char buf[64] = { 0 };
      mutt_date_localtime_format_locale(buf, sizeof(buf), "%a %b %e %H:%M:%S %Y",
                                        msg->received, NeoMutt->time_c_locale);
      fprintf(msg->fp, "From %s %s\n", p ? buf_string(p->mailbox) : NONULL(Username), buf);
    }
  }
  else
  {
    message_free(&msg);
  }

  return msg;
}

/**
 * mx_mbox_check - Check for new mail - Wrapper for MxOps::mbox_check()
 * @param m          Mailbox
 * @retval enum #MxStatus
 */
enum MxStatus mx_mbox_check(struct Mailbox *m)
{
  if (!m || !m->mx_ops)
    return MX_STATUS_ERROR;

  const short c_mail_check = cs_subset_number(NeoMutt->sub, "mail_check");

  time_t t = mutt_date_now();
  if ((t - m->last_checked) < c_mail_check)
    return MX_STATUS_OK;

  m->last_checked = t;

  enum MxStatus rc = m->mx_ops->mbox_check(m);
  if ((rc == MX_STATUS_NEW_MAIL) || (rc == MX_STATUS_REOPENED))
    mailbox_changed(m, NT_MAILBOX_INVALID);
  if (rc == MX_STATUS_NEW_MAIL)
    mailbox_changed(m, NT_MAILBOX_NEW_MAIL);

  return rc;
}

/**
 * mx_msg_open - Return a stream pointer for a message
 * @param m Mailbox
 * @param e Email
 * @retval ptr  Message
 * @retval NULL Error
 */
struct Message *mx_msg_open(struct Mailbox *m, struct Email *e)
{
  if (!m || !e)
    return NULL;

  if (!m->mx_ops || !m->mx_ops->msg_open)
  {
    mutt_debug(LL_DEBUG1, "function not implemented for mailbox type %d\n", m->type);
    return NULL;
  }

  struct Message *msg = message_new();
  if (!m->mx_ops->msg_open(m, msg, e))
    message_free(&msg);

  return msg;
}

/**
 * mx_msg_commit - Commit a message to a folder - Wrapper for MxOps::msg_commit()
 * @param m   Mailbox
 * @param msg Message to commit
 * @retval  0 Success
 * @retval -1 Failure
 */
int mx_msg_commit(struct Mailbox *m, struct Message *msg)
{
  if (!m || !m->mx_ops || !m->mx_ops->msg_commit || !msg)
    return -1;

  if (!(msg->write && m->append))
  {
    mutt_debug(LL_DEBUG1, "msg->write = %d, m->append = %d\n", msg->write, m->append);
    return -1;
  }

  return m->mx_ops->msg_commit(m, msg);
}

/**
 * mx_msg_close - Close a message
 * @param[in]  m   Mailbox
 * @param[out] ptr Message to close
 * @retval  0 Success
 * @retval -1 Failure
 */
int mx_msg_close(struct Mailbox *m, struct Message **ptr)
{
  if (!m || !ptr || !*ptr)
    return 0;

  int rc = 0;
  struct Message *msg = *ptr;

  if (m->mx_ops && m->mx_ops->msg_close)
    rc = m->mx_ops->msg_close(m, msg);

  if (msg->path)
  {
    mutt_debug(LL_DEBUG1, "unlinking %s\n", msg->path);
    unlink(msg->path);
  }

  message_free(ptr);
  return rc;
}

/**
 * mx_alloc_memory - Create storage for the emails
 * @param m        Mailbox
 * @param req_size Space required
 */
void mx_alloc_memory(struct Mailbox *m, int req_size)
{
  if ((req_size + 1) <= m->email_max)
    return;

  // Step size to increase by
  // Larger mailboxes get a larger step (limited to 1000)
  const int grow = CLAMP(m->email_max, 25, 1000);

  // Sanity checks
  req_size = ROUND_UP(req_size + 1, grow);

  const size_t s = MAX(sizeof(struct Email *), sizeof(int));
  if ((req_size * s) < (m->email_max * s))
  {
    mutt_error("%s", strerror(ENOMEM));
    mutt_exit(1);
  }

  if (m->emails)
  {
    MUTT_MEM_REALLOC(&m->emails, req_size, struct Email *);
    MUTT_MEM_REALLOC(&m->v2r, req_size, int);
  }
  else
  {
    m->emails = MUTT_MEM_CALLOC(req_size, struct Email *);
    m->v2r = MUTT_MEM_CALLOC(req_size, int);
  }

  for (int i = m->email_max; i < req_size; i++)
  {
    m->emails[i] = NULL;
    m->v2r[i] = -1;
  }

  m->email_max = req_size;
}

/**
 * mx_path_is_empty - Is the mailbox empty
 * @param path Mailbox to check
 * @retval 1 Mailbox is empty
 * @retval 0 Mailbox contains mail
 * @retval -1 Error
 */
int mx_path_is_empty(struct Buffer *path)
{
  if (buf_is_empty(path))
    return -1;

  enum MailboxType type = mx_path_probe(buf_string(path));
  const struct MxOps *ops = mx_get_ops(type);
  if (!ops || !ops->path_is_empty)
    return -1;

  return ops->path_is_empty(path);
}

/**
 * mx_tags_edit - Start the tag editor of the mailbox
 * @param m      Mailbox
 * @param tags   Existing tags
 * @param buf    Buffer for the results
 * @retval -1 Error
 * @retval 0  No valid user input
 * @retval 1  Buffer set
 */
int mx_tags_edit(struct Mailbox *m, const char *tags, struct Buffer *buf)
{
  if (!m || !buf)
    return -1;

  if (m->mx_ops->tags_edit)
    return m->mx_ops->tags_edit(m, tags, buf);

  mutt_message(_("Folder doesn't support tagging, aborting"));
  return -1;
}

/**
 * mx_tags_commit - Save tags to the Mailbox - Wrapper for MxOps::tags_commit()
 * @param m    Mailbox
 * @param e    Email
 * @param tags Tags to save
 * @retval  0 Success
 * @retval -1 Failure
 */
int mx_tags_commit(struct Mailbox *m, struct Email *e, const char *tags)
{
  if (!m || !e || !tags)
    return -1;

  if (m->mx_ops->tags_commit)
    return m->mx_ops->tags_commit(m, e, tags);

  mutt_message(_("Folder doesn't support tagging, aborting"));
  return -1;
}

/**
 * mx_tags_is_supported - Return true if mailbox support tagging
 * @param m Mailbox
 * @retval true Tagging is supported
 */
bool mx_tags_is_supported(struct Mailbox *m)
{
  return m && m->mx_ops->tags_commit && m->mx_ops->tags_edit;
}

/**
 * mx_path_probe - Find a mailbox that understands a path
 * @param path Path to examine
 * @retval enum MailboxType, e.g. #MUTT_IMAP
 */
enum MailboxType mx_path_probe(const char *path)
{
  if (!path)
    return MUTT_UNKNOWN;

  enum MailboxType rc = MUTT_UNKNOWN;

  // First, search the non-local Mailbox types (is_local == false)
  for (const struct MxOps **ops = MxOps; *ops; ops++)
  {
    if ((*ops)->is_local)
      continue;
    rc = (*ops)->path_probe(path, NULL);
    if (rc != MUTT_UNKNOWN)
      return rc;
  }

  struct stat st = { 0 };
  if (stat(path, &st) != 0)
  {
    mutt_debug(LL_DEBUG1, "unable to stat %s: %s (errno %d)\n", path, strerror(errno), errno);
    return MUTT_UNKNOWN;
  }

  if (S_ISFIFO(st.st_mode))
  {
    mutt_error(_("Can't open %s: it is a pipe"), path);
    return MUTT_UNKNOWN;
  }

  // Next, search the local Mailbox types (is_local == true)
  for (const struct MxOps **ops = MxOps; *ops; ops++)
  {
    if (!(*ops)->is_local)
      continue;
    rc = (*ops)->path_probe(path, &st);
    if (rc != MUTT_UNKNOWN)
      return rc;
  }

  return rc;
}

/**
 * mx_path_canon - Canonicalise a mailbox path - Wrapper for MxOps::path_canon()
 */
int mx_path_canon(struct Buffer *path, const char *folder, enum MailboxType *type)
{
  if (buf_is_empty(path))
    return -1;

  for (size_t i = 0; i < 3; i++)
  {
    /* Look for !! ! - < > or ^ followed by / or NUL */
    if ((buf_at(path, 0) == '!') && (buf_at(path, 1) == '!'))
    {
      if (((buf_at(path, 2) == '/') || (buf_at(path, 2) == '\0')))
      {
        buf_inline_replace(path, 0, 2, LastFolder);
      }
    }
    else if ((buf_at(path, 0) == '+') || (buf_at(path, 0) == '='))
    {
      size_t folder_len = mutt_str_len(folder);
      if ((folder_len > 0) && (folder[folder_len - 1] != '/'))
      {
        path->data[0] = '/';
        buf_inline_replace(path, 0, 0, folder);
      }
      else
      {
        buf_inline_replace(path, 0, 1, folder);
      }
    }
    else if ((buf_at(path, 1) == '/') || (buf_at(path, 1) == '\0'))
    {
      if (buf_at(path, 0) == '!')
      {
        const char *const c_spool_file = cs_subset_string(NeoMutt->sub, "spool_file");
        buf_inline_replace(path, 0, 1, c_spool_file);
      }
      else if (buf_at(path, 0) == '-')
      {
        buf_inline_replace(path, 0, 1, LastFolder);
      }
      else if (buf_at(path, 0) == '<')
      {
        const char *const c_record = cs_subset_string(NeoMutt->sub, "record");
        buf_inline_replace(path, 0, 1, c_record);
      }
      else if (buf_at(path, 0) == '>')
      {
        const char *const c_mbox = cs_subset_string(NeoMutt->sub, "mbox");
        buf_inline_replace(path, 0, 1, c_mbox);
      }
      else if (buf_at(path, 0) == '^')
      {
        buf_inline_replace(path, 0, 1, CurrentFolder);
      }
      else if (buf_at(path, 0) == '~')
      {
        buf_inline_replace(path, 0, 1, HomeDir);
      }
    }
    else if (buf_at(path, 0) == '@')
    {
      /* elm compatibility, @ expands alias to user name */
      struct AddressList *al = alias_lookup(buf_string(path));
      if (!al || TAILQ_EMPTY(al))
        break;

      struct Email *e = email_new();
      e->env = mutt_env_new();
      mutt_addrlist_copy(&e->env->from, al, false);
      mutt_addrlist_copy(&e->env->to, al, false);
      mutt_default_save(path, e);
      email_free(&e);
      break;
    }
    else
    {
      break;
    }
  }

  // if (!folder) //XXX - use inherited version, or pass NULL to backend?
  //   return -1;

  enum MailboxType type2 = mx_path_probe(buf_string(path));
  if (type)
    *type = type2;
  const struct MxOps *ops = mx_get_ops(type2);
  if (!ops || !ops->path_canon)
    return -1;

  if (ops->path_canon(path) < 0)
  {
    mutt_path_canon(path, HomeDir, true);
  }

  return 0;
}

/**
 * mx_path_canon2 - Canonicalise the path to realpath
 * @param m      Mailbox
 * @param folder Path to canonicalise
 * @retval  0 Success
 * @retval -1 Failure
 */
int mx_path_canon2(struct Mailbox *m, const char *folder)
{
  if (!m)
    return -1;

  struct Buffer *path = buf_pool_get();

  if (m->realpath)
    buf_strcpy(path, m->realpath);
  else
    buf_strcpy(path, mailbox_path(m));

  int rc = mx_path_canon(path, folder, &m->type);

  mutt_str_replace(&m->realpath, buf_string(path));
  buf_pool_release(&path);

  if (rc >= 0)
  {
    m->mx_ops = mx_get_ops(m->type);
    buf_strcpy(&m->pathbuf, m->realpath);
  }

  return rc;
}

/**
 * mx_msg_padding_size - Bytes of padding between messages - Wrapper for MxOps::msg_padding_size()
 * @param m Mailbox
 * @retval num Number of bytes of padding
 *
 * mmdf and mbox add separators, which leads a small discrepancy when computing
 * vsize for a limited view.
 */
int mx_msg_padding_size(struct Mailbox *m)
{
  if (!m || !m->mx_ops || !m->mx_ops->msg_padding_size)
    return 0;

  return m->mx_ops->msg_padding_size(m);
}

/**
 * mx_ac_find - Find the Account owning a Mailbox
 * @param m Mailbox
 * @retval ptr  Account
 * @retval NULL None found
 */
struct Account *mx_ac_find(struct Mailbox *m)
{
  if (!m || !m->mx_ops || !m->realpath)
    return NULL;

  struct Account *np = NULL;
  TAILQ_FOREACH(np, &NeoMutt->accounts, entries)
  {
    if (np->type != m->type)
      continue;

    if (m->mx_ops->ac_owns_path(np, m->realpath))
      return np;
  }

  return NULL;
}

/**
 * mx_mbox_find - Find a Mailbox on an Account
 * @param a    Account to search
 * @param path Path to find
 * @retval ptr Mailbox
 */
struct Mailbox *mx_mbox_find(struct Account *a, const char *path)
{
  if (!a || !path)
    return NULL;

  struct MailboxNode *np = NULL;
  struct Url *url_p = NULL;
  struct Url *url_a = NULL;

  const bool use_url = (a->type == MUTT_IMAP);
  if (use_url)
  {
    url_p = url_parse(path);
    if (!url_p)
      goto done;
  }

  STAILQ_FOREACH(np, &a->mailboxes, entries)
  {
    if (!use_url)
    {
      if (mutt_str_equal(np->mailbox->realpath, path))
        return np->mailbox;
      continue;
    }

    url_free(&url_a);
    url_a = url_parse(np->mailbox->realpath);
    if (!url_a)
      continue;

    if (!mutt_istr_equal(url_a->host, url_p->host))
      continue;
    if (url_p->user && !mutt_istr_equal(url_a->user, url_p->user))
      continue;
    if (a->type == MUTT_IMAP)
    {
      if (imap_mxcmp(url_a->path, url_p->path) == 0)
        break;
    }
    else
    {
      if (mutt_str_equal(url_a->path, url_p->path))
        break;
    }
  }

done:
  url_free(&url_p);
  url_free(&url_a);

  if (!np)
    return NULL;
  return np->mailbox;
}

/**
 * mx_mbox_find2 - Find a Mailbox on an Account
 * @param path Path to find
 * @retval ptr  Mailbox
 * @retval NULL No match
 */
struct Mailbox *mx_mbox_find2(const char *path)
{
  if (!path)
    return NULL;

  struct Buffer *buf = buf_new(path);
  const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
  mx_path_canon(buf, c_folder, NULL);

  struct Account *np = NULL;
  TAILQ_FOREACH(np, &NeoMutt->accounts, entries)
  {
    struct Mailbox *m = mx_mbox_find(np, buf_string(buf));
    if (m)
    {
      buf_free(&buf);
      return m;
    }
  }

  buf_free(&buf);
  return NULL;
}

/**
 * mx_path_resolve - Get a Mailbox for a path
 * @param path Mailbox path
 * @retval ptr Mailbox
 *
 * If there isn't a Mailbox for the path, one will be created.
 */
struct Mailbox *mx_path_resolve(const char *path)
{
  if (!path)
    return NULL;

  struct Mailbox *m = mx_mbox_find2(path);
  if (m)
    return m;

  m = mailbox_new();
  buf_strcpy(&m->pathbuf, path);
  const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
  mx_path_canon2(m, c_folder);

  return m;
}

/**
 * mx_mbox_find_by_name_ac - Find a Mailbox with given name under an Account
 * @param a    Account to search
 * @param name Name to find
 * @retval ptr Mailbox
 */
static struct Mailbox *mx_mbox_find_by_name_ac(struct Account *a, const char *name)
{
  if (!a || !name)
    return NULL;

  struct MailboxNode *np = NULL;

  STAILQ_FOREACH(np, &a->mailboxes, entries)
  {
    if (mutt_str_equal(np->mailbox->name, name))
      return np->mailbox;
  }

  return NULL;
}

/**
 * mx_mbox_find_by_name - Find a Mailbox with given name
 * @param name Name to search
 * @retval ptr Mailbox
 */
static struct Mailbox *mx_mbox_find_by_name(const char *name)
{
  if (!name)
    return NULL;

  struct Account *np = NULL;
  TAILQ_FOREACH(np, &NeoMutt->accounts, entries)
  {
    struct Mailbox *m = mx_mbox_find_by_name_ac(np, name);
    if (m)
      return m;
  }

  return NULL;
}

/**
 * mx_resolve - Get a Mailbox from either a path or name
 * @param path_or_name Mailbox path or name
 * @retval ptr         Mailbox
 *
 * Order of resolving:
 *  1. Name
 *  2. Path
 */
struct Mailbox *mx_resolve(const char *path_or_name)
{
  if (!path_or_name)
    return NULL;

  // Order is name first because you can create a Mailbox from
  // a path, but can't from a name. So fallback behavior creates
  // a new Mailbox for us.
  struct Mailbox *m = mx_mbox_find_by_name(path_or_name);
  if (!m)
    m = mx_path_resolve(path_or_name);

  return m;
}

/**
 * mx_ac_add - Add a Mailbox to an Account - Wrapper for MxOps::ac_add()
 */
bool mx_ac_add(struct Account *a, struct Mailbox *m)
{
  if (!a || !m || !m->mx_ops || !m->mx_ops->ac_add)
    return false;

  return m->mx_ops->ac_add(a, m) && account_mailbox_add(a, m);
}

/**
 * mx_ac_remove - Remove a Mailbox from an Account and delete Account if empty
 * @param m Mailbox to remove
 * @param keep_account Make sure not to remove the mailbox's account
 * @retval  0 Success
 * @retval -1 Error
 *
 * @note The mailbox is NOT free'd
 */
int mx_ac_remove(struct Mailbox *m, bool keep_account)
{
  if (!m || !m->account)
    return -1;

  struct Account *a = m->account;
  account_mailbox_remove(m->account, m);
  if (!keep_account && STAILQ_EMPTY(&a->mailboxes))
  {
    neomutt_account_remove(NeoMutt, a);
  }
  return 0;
}

/**
 * mx_mbox_check_stats - Check the statistics for a mailbox - Wrapper for MxOps::mbox_check_stats()
 *
 * @note Emits: #NT_MAILBOX_CHANGE
 */
enum MxStatus mx_mbox_check_stats(struct Mailbox *m, uint8_t flags)
{
  if (!m)
    return MX_STATUS_ERROR;

  enum MxStatus rc = m->mx_ops->mbox_check_stats(m, flags);
  if (rc != MX_STATUS_ERROR)
  {
    mailbox_changed(m, NT_MAILBOX_CHANGE);
    if (rc == MX_STATUS_NEW_MAIL)
      mailbox_changed(m, NT_MAILBOX_NEW_MAIL);
  }

  return rc;
}

/**
 * mx_save_hcache - Save message to the header cache - Wrapper for MxOps::msg_save_hcache()
 * @param m Mailbox
 * @param e Email
 * @retval  0 Success
 * @retval -1 Failure
 *
 * Write a single header out to the header cache.
 */
int mx_save_hcache(struct Mailbox *m, struct Email *e)
{
  if (!m || !m->mx_ops || !m->mx_ops->msg_save_hcache || !e)
    return 0;

  return m->mx_ops->msg_save_hcache(m, e);
}

/**
 * mx_type - Return the type of the Mailbox
 * @param m Mailbox
 * @retval enum #MailboxType
 */
enum MailboxType mx_type(struct Mailbox *m)
{
  return m ? m->type : MUTT_MAILBOX_ERROR;
}

/**
 * mx_toggle_write - Toggle the mailbox's readonly flag
 * @param m Mailbox
 * @retval  0 Success
 * @retval -1 Error
 */
int mx_toggle_write(struct Mailbox *m)
{
  if (!m)
    return -1;

  if (m->readonly)
  {
    mutt_error(_("Can't toggle write on a readonly mailbox"));
    return -1;
  }

  if (m->dontwrite)
  {
    m->dontwrite = false;
    mutt_message(_("Changes to folder will be written on folder exit"));
  }
  else
  {
    m->dontwrite = true;
    mutt_message(_("Changes to folder will not be written"));
  }

  mailbox_changed(m, NT_MAILBOX_CHANGE);
  return 0;
}
