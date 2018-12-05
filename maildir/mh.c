/**
 * @file
 * MH local mailbox type
 *
 * @authors
 * Copyright (C) 1996-2002,2007,2009 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 1999-2005 Thomas Roessler <roessler@does-not-exist.org>
 * Copyright (C) 2010,2013 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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
 * @page maildir_mh MH local mailbox type
 *
 * MH local mailbox type
 */

#include "config.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "maildir_private.h"
#include "mutt/mutt.h"
#include "config/lib.h"
#include "email/lib.h"
#include "mutt.h"
#include "context.h"
#include "errno.h"
#include "globals.h"
#include "mailbox.h"
#include "monitor.h"
#include "muttlib.h"
#include "mx.h"

/**
 * mhs_alloc - Allocate more memory for sequences
 * @param mhs Existing sequences
 * @param i   Number required
 *
 * @note Memory is allocated in blocks of 128.
 */
static void mhs_alloc(struct MhSequences *mhs, int i)
{
  if ((i <= mhs->max) && mhs->flags)
    return;

  const int newmax = i + 128;
  int j = mhs->flags ? mhs->max + 1 : 0;
  mutt_mem_realloc(&mhs->flags, sizeof(mhs->flags[0]) * (newmax + 1));
  while (j <= newmax)
    mhs->flags[j++] = 0;

  mhs->max = newmax;
}

/**
 * mhs_free_sequences - Free some sequences
 * @param mhs Sequences to free
 */
void mhs_free_sequences(struct MhSequences *mhs)
{
  FREE(&mhs->flags);
}

/**
 * mhs_check - Get the flags for a given sequence
 * @param mhs Sequences
 * @param i   Index number required
 * @retval num Flags, e.g. #MH_SEQ_UNSEEN
 */
short mhs_check(struct MhSequences *mhs, int i)
{
  if (!mhs->flags || (i > mhs->max))
    return 0;
  else
    return mhs->flags[i];
}

/**
 * mhs_set - Set a flag for a given sequence
 * @param mhs Sequences
 * @param i   Index number
 * @param f   Flags, e.g. #MH_SEQ_UNSEEN
 * @retval num Resulting flags
 */
short mhs_set(struct MhSequences *mhs, int i, short f)
{
  mhs_alloc(mhs, i);
  mhs->flags[i] |= f;
  return mhs->flags[i];
}

/**
 * mhs_write_one_sequence - Write a flag sequence to a file
 * @param fp  File to write to
 * @param mhs Sequence list
 * @param f   Flag, e.g. MH_SEQ_UNSEEN
 * @param tag string tag, e.g. "unseen"
 */
static void mhs_write_one_sequence(FILE *fp, struct MhSequences *mhs, short f, const char *tag)
{
  fprintf(fp, "%s:", tag);

  int first = -1;
  int last = -1;

  for (int i = 0; i <= mhs->max; i++)
  {
    if ((mhs_check(mhs, i) & f))
    {
      if (first < 0)
        first = i;
      else
        last = i;
    }
    else if (first >= 0)
    {
      if (last < 0)
        fprintf(fp, " %d", first);
      else
        fprintf(fp, " %d-%d", first, last);

      first = -1;
      last = -1;
    }
  }

  if (first >= 0)
  {
    if (last < 0)
      fprintf(fp, " %d", first);
    else
      fprintf(fp, " %d-%d", first, last);
  }

  fputc('\n', fp);
}

/**
 * mh_update_sequences - Update sequence numbers
 * @param m Mailbox
 *
 * XXX we don't currently remove deleted messages from sequences we don't know.
 * Should we?
 */
void mh_update_sequences(struct Mailbox *m)
{
  FILE *ofp = NULL, *nfp = NULL;

  char sequences[PATH_MAX];
  char *tmpfname = NULL;
  char *buf = NULL;
  char *p = NULL;
  size_t s;
  int l = 0;
  int i;

  int unseen = 0;
  int flagged = 0;
  int replied = 0;

  char seq_unseen[STRING];
  char seq_replied[STRING];
  char seq_flagged[STRING];

  struct MhSequences mhs = { 0 };

  snprintf(seq_unseen, sizeof(seq_unseen), "%s:", NONULL(MhSeqUnseen));
  snprintf(seq_replied, sizeof(seq_replied), "%s:", NONULL(MhSeqReplied));
  snprintf(seq_flagged, sizeof(seq_flagged), "%s:", NONULL(MhSeqFlagged));

  if (mh_mkstemp(m, &nfp, &tmpfname) != 0)
  {
    /* error message? */
    return;
  }

  snprintf(sequences, sizeof(sequences), "%s/.mh_sequences", m->path);

  /* first, copy unknown sequences */
  ofp = fopen(sequences, "r");
  if (ofp)
  {
    while ((buf = mutt_file_read_line(buf, &s, ofp, &l, 0)))
    {
      if (mutt_str_startswith(buf, seq_unseen, CASE_MATCH) ||
          mutt_str_startswith(buf, seq_flagged, CASE_MATCH) ||
          mutt_str_startswith(buf, seq_replied, CASE_MATCH))
        continue;

      fprintf(nfp, "%s\n", buf);
    }
  }
  mutt_file_fclose(&ofp);

  /* now, update our unseen, flagged, and replied sequences */
  for (l = 0; l < m->msg_count; l++)
  {
    if (m->hdrs[l]->deleted)
      continue;

    p = strrchr(m->hdrs[l]->path, '/');
    if (p)
      p++;
    else
      p = m->hdrs[l]->path;

    if (mutt_str_atoi(p, &i) < 0)
      continue;

    if (!m->hdrs[l]->read)
    {
      mhs_set(&mhs, i, MH_SEQ_UNSEEN);
      unseen++;
    }
    if (m->hdrs[l]->flagged)
    {
      mhs_set(&mhs, i, MH_SEQ_FLAGGED);
      flagged++;
    }
    if (m->hdrs[l]->replied)
    {
      mhs_set(&mhs, i, MH_SEQ_REPLIED);
      replied++;
    }
  }

  /* write out the new sequences */
  if (unseen)
    mhs_write_one_sequence(nfp, &mhs, MH_SEQ_UNSEEN, NONULL(MhSeqUnseen));
  if (flagged)
    mhs_write_one_sequence(nfp, &mhs, MH_SEQ_FLAGGED, NONULL(MhSeqFlagged));
  if (replied)
    mhs_write_one_sequence(nfp, &mhs, MH_SEQ_REPLIED, NONULL(MhSeqReplied));

  mhs_free_sequences(&mhs);

  /* try to commit the changes - no guarantee here */
  mutt_file_fclose(&nfp);

  unlink(sequences);
  if (mutt_file_safe_rename(tmpfname, sequences) != 0)
  {
    /* report an error? */
    unlink(tmpfname);
  }

  FREE(&tmpfname);
}

/**
 * mh_read_token - Parse a number, or number range
 * @param t     String to parse
 * @param first First number
 * @param last  Last number (if a range, first number if not)
 * @retval  0 Success
 * @retval -1 Error
 */
static int mh_read_token(char *t, int *first, int *last)
{
  char *p = strchr(t, '-');
  if (p)
  {
    *p++ = '\0';
    if ((mutt_str_atoi(t, first) < 0) || (mutt_str_atoi(p, last) < 0))
      return -1;
  }
  else
  {
    if (mutt_str_atoi(t, first) < 0)
      return -1;
    *last = *first;
  }
  return 0;
}

/**
 * mh_read_sequences - Read a set of MH sequences
 * @param mhs  Existing sequences
 * @param path File to read from
 * @retval  0 Success
 * @retval -1 Error
 */
int mh_read_sequences(struct MhSequences *mhs, const char *path)
{
  int line = 1;
  char *buf = NULL;
  size_t sz = 0;

  short f;
  int first, last, rc = 0;

  char pathname[PATH_MAX];
  snprintf(pathname, sizeof(pathname), "%s/.mh_sequences", path);

  FILE *fp = fopen(pathname, "r");
  if (!fp)
    return 0; /* yes, ask callers to silently ignore the error */

  while ((buf = mutt_file_read_line(buf, &sz, fp, &line, 0)))
  {
    char *t = strtok(buf, " \t:");
    if (!t)
      continue;

    if (mutt_str_strcmp(t, MhSeqUnseen) == 0)
      f = MH_SEQ_UNSEEN;
    else if (mutt_str_strcmp(t, MhSeqFlagged) == 0)
      f = MH_SEQ_FLAGGED;
    else if (mutt_str_strcmp(t, MhSeqReplied) == 0)
      f = MH_SEQ_REPLIED;
    else /* unknown sequence */
      continue;

    while ((t = strtok(NULL, " \t:")))
    {
      if (mh_read_token(t, &first, &last) < 0)
      {
        mhs_free_sequences(mhs);
        rc = -1;
        goto out;
      }
      for (; first <= last; first++)
        mhs_set(mhs, first, f);
    }
  }

  rc = 0;

out:
  FREE(&buf);
  mutt_file_fclose(&fp);
  return rc;
}

/**
 * mh_sequences_changed - Has the mailbox changed
 * @param m Mailbox
 * @retval 1 mh_sequences last modification time is more recent than the last visit to this mailbox
 * @retval 0 modification time is older
 * @retval -1 Error
 */
static int mh_sequences_changed(struct Mailbox *m)
{
  char path[PATH_MAX];
  struct stat sb;

  if ((snprintf(path, sizeof(path), "%s/.mh_sequences", m->path) < sizeof(path)) &&
      (stat(path, &sb) == 0))
  {
    return (mutt_file_stat_timespec_compare(&sb, MUTT_STAT_MTIME, &m->last_visited) > 0);
  }
  return -1;
}

/**
 * mh_already_notified - Has the message changed
 * @param m     Mailbox
 * @param msgno Message number
 * @retval 1 Modification time on the message file is older than the last visit to this mailbox
 * @retval 0 Modification time on the message file is newer
 * @retval -1 Error
 */
static int mh_already_notified(struct Mailbox *m, int msgno)
{
  char path[PATH_MAX];
  struct stat sb;

  if ((snprintf(path, sizeof(path), "%s/%d", m->path, msgno) < sizeof(path)) &&
      (stat(path, &sb) == 0))
  {
    return (mutt_file_stat_timespec_compare(&sb, MUTT_STAT_MTIME, &m->last_visited) <= 0);
  }
  return -1;
}

/**
 * mh_valid_message - Is this a valid MH message filename
 * @param s Pathname to examine
 * @retval true name is valid
 * @retval false name is invalid
 *
 * Ignore the garbage files.  A valid MH message consists of only
 * digits.  Deleted message get moved to a filename with a comma before
 * it.
 */
bool mh_valid_message(const char *s)
{
  for (; *s; s++)
  {
    if (!isdigit((unsigned char) *s))
      return false;
  }
  return true;
}

/**
 * mh_mailbox - Check for new mail for a mh mailbox
 * @param m           Mailbox to check
 * @param check_stats Also count total, new, and flagged messages
 * @retval true if the mailbox has new mail
 */
bool mh_mailbox(struct Mailbox *m, bool check_stats)
{
  struct MhSequences mhs = { 0 };
  bool check_new = true;
  bool rc = false;
  DIR *dirp = NULL;
  struct dirent *de = NULL;

  /* when $mail_check_recent is set and the .mh_sequences file hasn't changed
   * since the last m visit, there is no "new mail" */
  if (MailCheckRecent && mh_sequences_changed(m) <= 0)
  {
    rc = false;
    check_new = false;
  }

  if (!(check_new || check_stats))
    return rc;

  if (mh_read_sequences(&mhs, m->path) < 0)
    return false;

  if (check_stats)
  {
    m->msg_count = 0;
    m->msg_unread = 0;
    m->msg_flagged = 0;
  }

  for (int i = mhs.max; i > 0; i--)
  {
    if (check_stats && (mhs_check(&mhs, i) & MH_SEQ_FLAGGED))
      m->msg_flagged++;
    if (mhs_check(&mhs, i) & MH_SEQ_UNSEEN)
    {
      if (check_stats)
        m->msg_unread++;
      if (check_new)
      {
        /* if the first unseen message we encounter was in the m during the
           last visit, don't notify about it */
        if (!MailCheckRecent || mh_already_notified(m, i) == 0)
        {
          m->has_new = true;
          rc = true;
        }
        /* Because we are traversing from high to low, we can stop
         * checking for new mail after the first unseen message.
         * Whether it resulted in "new mail" or not. */
        check_new = false;
        if (!check_stats)
          break;
      }
    }
  }
  mhs_free_sequences(&mhs);

  if (check_stats)
  {
    dirp = opendir(m->path);
    if (dirp)
    {
      while ((de = readdir(dirp)))
      {
        if (*de->d_name == '.')
          continue;
        if (mh_valid_message(de->d_name))
          m->msg_count++;
      }
      closedir(dirp);
    }
  }

  return rc;
}

/**
 * mh_update_maildir - Update our record of flags
 * @param md  Maildir to update
 * @param mhs Sequences
 */
void mh_update_maildir(struct Maildir *md, struct MhSequences *mhs)
{
  int i;

  for (; md; md = md->next)
  {
    char *p = strrchr(md->email->path, '/');
    if (p)
      p++;
    else
      p = md->email->path;

    if (mutt_str_atoi(p, &i) < 0)
      continue;
    short f = mhs_check(mhs, i);

    md->email->read = (f & MH_SEQ_UNSEEN) ? false : true;
    md->email->flagged = (f & MH_SEQ_FLAGGED) ? true : false;
    md->email->replied = (f & MH_SEQ_REPLIED) ? true : false;
  }
}

/**
 * mh_sync_message - Sync an email to an MH folder
 * @param m     Mailbox
 * @param msgno Index number
 * @retval  0 Success
 * @retval -1 Error
 */
int mh_sync_message(struct Mailbox *m, int msgno)
{
  if (!m || !m->hdrs)
    return -1;

  struct Email *e = m->hdrs[msgno];

  if (e->attach_del || e->xlabel_changed ||
      (e->env && (e->env->refs_changed || e->env->irt_changed)))
  {
    if (mh_rewrite_message(m, msgno) != 0)
      return -1;
  }

  return 0;
}

/**
 * mh_mbox_open - Implements MxOps::mbox_open()
 */
static int mh_mbox_open(struct Mailbox *m, struct Context *ctx)
{
  return mh_read_dir(m, NULL);
}

/**
 * mh_mbox_open_append - Implements MxOps::mbox_open_append()
 */
static int mh_mbox_open_append(struct Mailbox *m, int flags)
{
  if (!m)
    return -1;

  if (!(flags & MUTT_APPENDNEW))
  {
    return 0;
  }

  if (mkdir(m->path, S_IRWXU))
  {
    mutt_perror(m->path);
    return -1;
  }

  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s/.mh_sequences", m->path);
  const int i = creat(tmp, S_IRWXU);
  if (i == -1)
  {
    mutt_perror(tmp);
    rmdir(m->path);
    return -1;
  }
  close(i);

  return 0;
}

/**
 * mh_mbox_check - Implements MxOps::mbox_check()
 *
 * This function handles arrival of new mail and reopening of mh/maildir
 * folders. Things are getting rather complex because we don't have a
 * well-defined "mailbox order", so the tricks from mbox.c and mx.c won't work
 * here.
 *
 * Don't change this code unless you _really_ understand what happens.
 */
int mh_mbox_check(struct Context *ctx, int *index_hint)
{
  if (!ctx || !ctx->mailbox)
    return -1;

  struct Mailbox *m = ctx->mailbox;

  char buf[PATH_MAX];
  struct stat st, st_cur;
  bool modified = false, occult = false, flags_changed = false;
  int num_new = 0;
  struct Maildir *md = NULL, *p = NULL;
  struct Maildir **last = NULL;
  struct MhSequences mhs = { 0 };
  int count = 0;
  struct Hash *fnames = NULL;
  struct MaildirMboxData *mdata = maildir_mdata_get(m);

  if (!CheckNew)
    return 0;

  mutt_str_strfcpy(buf, m->path, sizeof(buf));
  if (stat(buf, &st) == -1)
    return -1;

  /* create .mh_sequences when there isn't one. */
  snprintf(buf, sizeof(buf), "%s/.mh_sequences", m->path);
  int i = stat(buf, &st_cur);
  if ((i == -1) && (errno == ENOENT))
  {
    char *tmp = NULL;
    FILE *fp = NULL;

    if (mh_mkstemp(m, &fp, &tmp) == 0)
    {
      mutt_file_fclose(&fp);
      if (mutt_file_safe_rename(tmp, buf) == -1)
        unlink(tmp);
      FREE(&tmp);
    }
  }

  if (i == -1 && stat(buf, &st_cur) == -1)
    modified = true;

  if ((mutt_file_stat_timespec_compare(&st, MUTT_STAT_MTIME, &m->mtime) > 0) ||
      (mutt_file_stat_timespec_compare(&st_cur, MUTT_STAT_MTIME, &mdata->mtime_cur) > 0))
  {
    modified = true;
  }

  if (!modified)
    return 0;

    /* Update the modification times on the mailbox.
     *
     * The monitor code notices changes in the open mailbox too quickly.
     * In practice, this sometimes leads to all the new messages not being
     * noticed during the SAME group of mtime stat updates.  To work around
     * the problem, don't update the stat times for a monitor caused check. */
#ifdef USE_INOTIFY
  if (MonitorContextChanged)
    MonitorContextChanged = 0;
  else
#endif
  {
    mutt_file_get_stat_timespec(&mdata->mtime_cur, &st_cur, MUTT_STAT_MTIME);
    mutt_file_get_stat_timespec(&m->mtime, &st, MUTT_STAT_MTIME);
  }

  md = NULL;
  last = &md;

  maildir_parse_dir(m, &last, NULL, &count, NULL);
  maildir_delayed_parsing(m, &md, NULL);

  if (mh_read_sequences(&mhs, m->path) < 0)
    return -1;
  mh_update_maildir(md, &mhs);
  mhs_free_sequences(&mhs);

  /* check for modifications and adjust flags */
  fnames = mutt_hash_new(count, 0);

  for (p = md; p; p = p->next)
  {
    /* the hash key must survive past the header, which is freed below. */
    p->canon_fname = mutt_str_strdup(p->email->path);
    mutt_hash_insert(fnames, p->canon_fname, p);
  }

  for (i = 0; i < m->msg_count; i++)
  {
    m->hdrs[i]->active = false;

    p = mutt_hash_find(fnames, m->hdrs[i]->path);
    if (p && p->email && mutt_email_cmp_strict(m->hdrs[i], p->email))
    {
      m->hdrs[i]->active = true;
      /* found the right message */
      if (!m->hdrs[i]->changed)
        if (maildir_update_flags(ctx->mailbox, m->hdrs[i], p->email))
          flags_changed = true;

      mutt_email_free(&p->email);
    }
    else /* message has disappeared */
      occult = true;
  }

  /* destroy the file name hash */

  mutt_hash_destroy(&fnames);

  /* If we didn't just get new mail, update the tables. */
  if (occult)
    maildir_update_tables(ctx, index_hint);

  /* Incorporate new messages */
  num_new = maildir_move_to_context(m, &md);
  if (num_new > 0)
    mx_update_context(ctx);

  if (occult)
    return MUTT_REOPENED;
  if (num_new > 0)
    return MUTT_NEW_MAIL;
  if (flags_changed)
    return MUTT_FLAGS;
  return 0;
}

/**
 * mh_msg_open - Implements MxOps::msg_open()
 */
static int mh_msg_open(struct Mailbox *m, struct Message *msg, int msgno)
{
  if (!m)
    return -1;
  return maildir_mh_open_message(m, msg, msgno, false);
}

/**
 * mh_msg_open_new - Implements MxOps::msg_open_new()
 *
 * Open a new (temporary) message in an MH folder.
 */
static int mh_msg_open_new(struct Mailbox *m, struct Message *msg, struct Email *e)
{
  if (!m || !msg)
    return -1;
  return mh_mkstemp(m, &msg->fp, &msg->path);
}

/**
 * mh_msg_commit - Implements MxOps::msg_commit()
 */
static int mh_msg_commit(struct Mailbox *m, struct Message *msg)
{
  if (!m)
    return -1;

  return mh_commit_msg(m, msg, NULL, true);
}

/**
 * mh_path_probe - Is this an mh mailbox? - Implements MxOps::path_probe()
 */
enum MailboxType mh_path_probe(const char *path, const struct stat *st)
{
  if (!path)
    return MUTT_UNKNOWN;

  if (!st || !S_ISDIR(st->st_mode))
    return MUTT_UNKNOWN;

  char tmp[PATH_MAX];

  snprintf(tmp, sizeof(tmp), "%s/.mh_sequences", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  snprintf(tmp, sizeof(tmp), "%s/.xmhcache", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  snprintf(tmp, sizeof(tmp), "%s/.mew_cache", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  snprintf(tmp, sizeof(tmp), "%s/.mew-cache", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  snprintf(tmp, sizeof(tmp), "%s/.sylpheed_cache", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  /* ok, this isn't an mh folder, but mh mode can be used to read
   * Usenet news from the spool.  */

  snprintf(tmp, sizeof(tmp), "%s/.overview", path);
  if (access(tmp, F_OK) == 0)
    return MUTT_MH;

  return MUTT_UNKNOWN;
}

// clang-format off
/**
 * struct mx_mh_ops - MH mailbox - Implements ::MxOps
 */
struct MxOps mx_mh_ops = {
  .magic            = MUTT_MH,
  .name             = "mh",
  .ac_find          = maildir_ac_find,
  .ac_add           = maildir_ac_add,
  .mbox_open        = mh_mbox_open,
  .mbox_open_append = mh_mbox_open_append,
  .mbox_check       = mh_mbox_check,
  .mbox_sync        = mh_mbox_sync,
  .mbox_close       = mh_mbox_close,
  .msg_open         = mh_msg_open,
  .msg_open_new     = mh_msg_open_new,
  .msg_commit       = mh_msg_commit,
  .msg_close        = mh_msg_close,
  .msg_padding_size = NULL,
  .tags_edit        = NULL,
  .tags_commit      = NULL,
  .path_probe       = mh_path_probe,
  .path_canon       = maildir_path_canon,
  .path_pretty      = maildir_path_pretty,
  .path_parent      = maildir_path_parent,
};
// clang-format on
