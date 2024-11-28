/**
 * @file
 * Read/parse/write an NNTP config file of subscribed newsgroups
 *
 * @authors
 * Copyright (C) 2016-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2019 Ian Zimmerman <itz@no-use.mooo.com>
 * Copyright (C) 2022 Ramkumar Ramachandra <r@artagnon.com>
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
 * @page nntp_newsrc Read/write a file of subscribed newsgroups
 *
 * Read/parse/write an NNTP config file of subscribed newsgroups
 */

#include "config.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "conn/lib.h"
#include "mutt.h"
#include "lib.h"
#include "bcache/lib.h"
#include "expando/lib.h"
#include "adata.h"
#include "edata.h"
#include "expando_newsrc.h"
#include "globals.h"
#include "mdata.h"
#include "mutt_logging.h"
#include "mutt_socket.h"
#include "muttlib.h"
#include "protos.h"
#ifdef USE_HCACHE
#include "hcache/lib.h"
#endif

struct BodyCache;

/**
 * mdata_find - Find NntpMboxData for given newsgroup or add it
 * @param adata NNTP server
 * @param group Newsgroup
 * @retval ptr  NNTP data
 * @retval NULL Error
 */
static struct NntpMboxData *mdata_find(struct NntpAccountData *adata, const char *group)
{
  struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
  if (mdata)
    return mdata;

  size_t len = strlen(group) + 1;
  /* create NntpMboxData structure and add it to hash */
  mdata = mutt_mem_calloc(1, sizeof(struct NntpMboxData) + len);
  mdata->group = (char *) mdata + sizeof(struct NntpMboxData);
  mutt_str_copy(mdata->group, group, len);
  mdata->adata = adata;
  mdata->deleted = true;
  mutt_hash_insert(adata->groups_hash, mdata->group, mdata);

  /* add NntpMboxData to list */
  if (adata->groups_num >= adata->groups_max)
  {
    adata->groups_max *= 2;
    MUTT_MEM_REALLOC(&adata->groups_list, adata->groups_max, struct NntpMboxData *);
  }
  adata->groups_list[adata->groups_num++] = mdata;

  return mdata;
}

/**
 * nntp_acache_free - Remove all temporarily cache files
 * @param mdata NNTP Mailbox data
 */
void nntp_acache_free(struct NntpMboxData *mdata)
{
  for (int i = 0; i < NNTP_ACACHE_LEN; i++)
  {
    if (mdata->acache[i].path)
    {
      unlink(mdata->acache[i].path);
      FREE(&mdata->acache[i].path);
    }
  }
}

/**
 * nntp_newsrc_close - Unlock and close .newsrc file
 * @param adata NNTP server
 */
void nntp_newsrc_close(struct NntpAccountData *adata)
{
  if (!adata->fp_newsrc)
    return;

  mutt_debug(LL_DEBUG1, "Unlocking %s\n", adata->newsrc_file);
  mutt_file_unlock(fileno(adata->fp_newsrc));
  mutt_file_fclose(&adata->fp_newsrc);
}

/**
 * nntp_group_unread_stat - Count number of unread articles using .newsrc data
 * @param mdata NNTP Mailbox data
 */
void nntp_group_unread_stat(struct NntpMboxData *mdata)
{
  mdata->unread = 0;
  if ((mdata->last_message == 0) ||
      (mdata->first_message > mdata->last_message) || !mdata->newsrc_ent)
  {
    return;
  }

  mdata->unread = mdata->last_message - mdata->first_message + 1;
  for (unsigned int i = 0; i < mdata->newsrc_len; i++)
  {
    anum_t first = mdata->newsrc_ent[i].first;
    if (first < mdata->first_message)
      first = mdata->first_message;
    anum_t last = mdata->newsrc_ent[i].last;
    if (last > mdata->last_message)
      last = mdata->last_message;
    if (first <= last)
      mdata->unread -= last - first + 1;
  }
}

/**
 * nntp_newsrc_parse - Parse .newsrc file
 * @param adata NNTP server
 * @retval  0 Not changed
 * @retval  1 Parsed
 * @retval -1 Error
 */
int nntp_newsrc_parse(struct NntpAccountData *adata)
{
  if (!adata)
    return -1;

  char *line = NULL;
  struct stat st = { 0 };

  if (adata->fp_newsrc)
  {
    /* if we already have a handle, close it and reopen */
    mutt_file_fclose(&adata->fp_newsrc);
  }
  else
  {
    /* if file doesn't exist, create it */
    adata->fp_newsrc = mutt_file_fopen(adata->newsrc_file, "a");
    mutt_file_fclose(&adata->fp_newsrc);
  }

  /* open .newsrc */
  adata->fp_newsrc = mutt_file_fopen(adata->newsrc_file, "r");
  if (!adata->fp_newsrc)
  {
    mutt_perror("%s", adata->newsrc_file);
    return -1;
  }

  /* lock it */
  mutt_debug(LL_DEBUG1, "Locking %s\n", adata->newsrc_file);
  if (mutt_file_lock(fileno(adata->fp_newsrc), false, true))
  {
    mutt_file_fclose(&adata->fp_newsrc);
    return -1;
  }

  if (stat(adata->newsrc_file, &st) != 0)
  {
    mutt_perror("%s", adata->newsrc_file);
    nntp_newsrc_close(adata);
    return -1;
  }

  if ((adata->size == st.st_size) && (adata->mtime == st.st_mtime))
    return 0;

  adata->size = st.st_size;
  adata->mtime = st.st_mtime;
  adata->newsrc_modified = true;
  mutt_debug(LL_DEBUG1, "Parsing %s\n", adata->newsrc_file);

  /* .newsrc has been externally modified or hasn't been loaded yet */
  for (unsigned int i = 0; i < adata->groups_num; i++)
  {
    struct NntpMboxData *mdata = adata->groups_list[i];
    if (!mdata)
      continue;

    mdata->subscribed = false;
    mdata->newsrc_len = 0;
    FREE(&mdata->newsrc_ent);
  }

  line = MUTT_MEM_MALLOC(st.st_size + 1, char);
  while (st.st_size && fgets(line, st.st_size + 1, adata->fp_newsrc))
  {
    char *b = NULL, *h = NULL;
    unsigned int j = 1;
    bool subs = false;

    /* find end of newsgroup name */
    char *p = strpbrk(line, ":!");
    if (!p)
      continue;

    /* ":" - subscribed, "!" - unsubscribed */
    if (*p == ':')
      subs = true;
    *p++ = '\0';

    /* get newsgroup data */
    struct NntpMboxData *mdata = mdata_find(adata, line);
    FREE(&mdata->newsrc_ent);

    /* count number of entries */
    b = p;
    while (*b)
      if (*b++ == ',')
        j++;
    mdata->newsrc_ent = MUTT_MEM_CALLOC(j, struct NewsrcEntry);
    mdata->subscribed = subs;

    /* parse entries */
    j = 0;
    while (p)
    {
      b = p;

      /* find end of entry */
      p = strchr(p, ',');
      if (p)
        *p++ = '\0';

      /* first-last or single number */
      h = strchr(b, '-');
      if (h)
        *h++ = '\0';
      else
        h = b;

      if ((sscanf(b, ANUM_FMT, &mdata->newsrc_ent[j].first) == 1) &&
          (sscanf(h, ANUM_FMT, &mdata->newsrc_ent[j].last) == 1))
      {
        j++;
      }
    }
    if (j == 0)
    {
      mdata->newsrc_ent[j].first = 1;
      mdata->newsrc_ent[j].last = 0;
      j++;
    }
    if (mdata->last_message == 0)
      mdata->last_message = mdata->newsrc_ent[j - 1].last;
    mdata->newsrc_len = j;
    MUTT_MEM_REALLOC(&mdata->newsrc_ent, j, struct NewsrcEntry);
    nntp_group_unread_stat(mdata);
    mutt_debug(LL_DEBUG2, "%s\n", mdata->group);
  }
  FREE(&line);
  return 1;
}

/**
 * nntp_newsrc_gen_entries - Generate array of .newsrc entries
 * @param m Mailbox
 */
void nntp_newsrc_gen_entries(struct Mailbox *m)
{
  if (!m)
    return;

  struct NntpMboxData *mdata = m->mdata;
  anum_t last = 0, first = 1;
  bool series;
  unsigned int entries;

  const enum EmailSortType c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  if (c_sort != EMAIL_SORT_UNSORTED)
  {
    cs_subset_str_native_set(NeoMutt->sub, "sort", EMAIL_SORT_UNSORTED, NULL);
    mailbox_changed(m, NT_MAILBOX_RESORT);
  }

  entries = mdata->newsrc_len;
  if (!entries)
  {
    entries = 5;
    mdata->newsrc_ent = MUTT_MEM_CALLOC(entries, struct NewsrcEntry);
  }

  /* Set up to fake initial sequence from 1 to the article before the
   * first article in our list */
  mdata->newsrc_len = 0;
  series = true;
  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;

    /* search for first unread */
    if (series)
    {
      /* We don't actually check sequential order, since we mark
       * "missing" entries as read/deleted */
      last = nntp_edata_get(e)->article_num;
      if ((last >= mdata->first_message) && !e->deleted && !e->read)
      {
        if (mdata->newsrc_len >= entries)
        {
          entries *= 2;
          MUTT_MEM_REALLOC(&mdata->newsrc_ent, entries, struct NewsrcEntry);
        }
        mdata->newsrc_ent[mdata->newsrc_len].first = first;
        mdata->newsrc_ent[mdata->newsrc_len].last = last - 1;
        mdata->newsrc_len++;
        series = false;
      }
    }
    else
    {
      /* search for first read */
      if (e->deleted || e->read)
      {
        first = last + 1;
        series = true;
      }
      last = nntp_edata_get(e)->article_num;
    }
  }

  if (series && (first <= mdata->last_loaded))
  {
    if (mdata->newsrc_len >= entries)
    {
      entries++;
      MUTT_MEM_REALLOC(&mdata->newsrc_ent, entries, struct NewsrcEntry);
    }
    mdata->newsrc_ent[mdata->newsrc_len].first = first;
    mdata->newsrc_ent[mdata->newsrc_len].last = mdata->last_loaded;
    mdata->newsrc_len++;
  }
  MUTT_MEM_REALLOC(&mdata->newsrc_ent, mdata->newsrc_len, struct NewsrcEntry);

  if (c_sort != EMAIL_SORT_UNSORTED)
  {
    cs_subset_str_native_set(NeoMutt->sub, "sort", c_sort, NULL);
    mailbox_changed(m, NT_MAILBOX_RESORT);
  }
}

/**
 * update_file - Update file with new contents
 * @param filename File to update
 * @param buf      New context
 * @retval  0 Success
 * @retval -1 Failure
 */
static int update_file(char *filename, char *buf)
{
  FILE *fp = NULL;
  char tempfile[PATH_MAX] = { 0 };
  int rc = -1;

  while (true)
  {
    snprintf(tempfile, sizeof(tempfile), "%s.tmp", filename);
    fp = mutt_file_fopen(tempfile, "w");
    if (!fp)
    {
      mutt_perror("%s", tempfile);
      *tempfile = '\0';
      break;
    }
    if (fputs(buf, fp) == EOF)
    {
      mutt_perror("%s", tempfile);
      break;
    }
    if (mutt_file_fclose(&fp) == EOF)
    {
      mutt_perror("%s", tempfile);
      fp = NULL;
      break;
    }
    fp = NULL;
    if (rename(tempfile, filename) < 0)
    {
      mutt_perror("%s", filename);
      break;
    }
    *tempfile = '\0';
    rc = 0;
    break;
  }
  mutt_file_fclose(&fp);

  if (*tempfile)
    unlink(tempfile);
  return rc;
}

/**
 * nntp_newsrc_update - Update .newsrc file
 * @param adata NNTP server
 * @retval  0 Success
 * @retval -1 Failure
 */
int nntp_newsrc_update(struct NntpAccountData *adata)
{
  if (!adata)
    return -1;

  int rc = -1;

  size_t buflen = 10240;
  char *buf = MUTT_MEM_CALLOC(buflen, char);
  size_t off = 0;

  /* we will generate full newsrc here */
  for (unsigned int i = 0; i < adata->groups_num; i++)
  {
    struct NntpMboxData *mdata = adata->groups_list[i];

    if (!mdata || !mdata->newsrc_ent)
      continue;

    /* write newsgroup name */
    if ((off + strlen(mdata->group) + 3) > buflen)
    {
      buflen *= 2;
      MUTT_MEM_REALLOC(&buf, buflen, char);
    }
    snprintf(buf + off, buflen - off, "%s%c ", mdata->group, mdata->subscribed ? ':' : '!');
    off += strlen(buf + off);

    /* write entries */
    for (unsigned int j = 0; j < mdata->newsrc_len; j++)
    {
      if ((off + 1024) > buflen)
      {
        buflen *= 2;
        MUTT_MEM_REALLOC(&buf, buflen, char);
      }
      if (j)
        buf[off++] = ',';
      if (mdata->newsrc_ent[j].first == mdata->newsrc_ent[j].last)
      {
        snprintf(buf + off, buflen - off, ANUM_FMT, mdata->newsrc_ent[j].first);
      }
      else if (mdata->newsrc_ent[j].first < mdata->newsrc_ent[j].last)
      {
        snprintf(buf + off, buflen - off, ANUM_FMT "-" ANUM_FMT,
                 mdata->newsrc_ent[j].first, mdata->newsrc_ent[j].last);
      }
      off += strlen(buf + off);
    }
    buf[off++] = '\n';
  }
  buf[off] = '\0';

  /* newrc being fully rewritten */
  mutt_debug(LL_DEBUG1, "Updating %s\n", adata->newsrc_file);
  if (adata->newsrc_file && (update_file(adata->newsrc_file, buf) == 0))
  {
    struct stat st = { 0 };

    rc = stat(adata->newsrc_file, &st);
    if (rc == 0)
    {
      adata->size = st.st_size;
      adata->mtime = st.st_mtime;
    }
    else
    {
      mutt_perror("%s", adata->newsrc_file);
    }
  }
  FREE(&buf);
  return rc;
}

/**
 * cache_expand - Make fully qualified cache file name
 * @param dst    Buffer for filename
 * @param dstlen Length of buffer
 * @param cac    Account
 * @param src    Path to add to the URL
 */
static void cache_expand(char *dst, size_t dstlen, struct ConnAccount *cac, const char *src)
{
  char file[PATH_MAX] = { 0 };

  /* server subdirectory */
  struct Url url = { 0 };
  account_to_url(cac, &url);
  url.path = mutt_str_dup(src);
  url_tostring(&url, file, sizeof(file), U_PATH);
  FREE(&url.path);

  /* remove trailing slash */
  char *c = file + strlen(file) - 1;
  if (*c == '/')
    *c = '\0';

  struct Buffer *tmp = buf_pool_get();
  buf_addstr(tmp, file);
  mutt_encode_path(tmp, file);

  const char *const c_news_cache_dir = cs_subset_path(NeoMutt->sub, "news_cache_dir");
  snprintf(dst, dstlen, "%s/%s", c_news_cache_dir, buf_string(tmp));

  buf_pool_release(&tmp);
}

/**
 * nntp_expand_path - Make fully qualified url from newsgroup name
 * @param buf    Buffer for the result
 * @param buflen Length of buffer
 * @param cac    Account to serialise
 */
void nntp_expand_path(char *buf, size_t buflen, struct ConnAccount *cac)
{
  struct Url url = { 0 };

  account_to_url(cac, &url);
  url.path = mutt_str_dup(buf);
  url_tostring(&url, buf, buflen, U_NO_FLAGS);
  FREE(&url.path);
}

/**
 * nntp_add_group - Parse newsgroup
 * @param line String to parse
 * @param data NNTP data
 * @retval 0 Always
 */
int nntp_add_group(char *line, void *data)
{
  struct NntpAccountData *adata = data;
  struct NntpMboxData *mdata = NULL;
  char group[1024] = { 0 };
  char desc[8192] = { 0 };
  char mod = '\0';
  anum_t first = 0, last = 0;

  if (!adata || !line)
    return 0;

  /* These sscanf limits must match the sizes of the group and desc arrays */
  if (sscanf(line, "%1023s " ANUM_FMT " " ANUM_FMT " %c %8191[^\n]", group,
             &last, &first, &mod, desc) < 4)
  {
    mutt_debug(LL_DEBUG2, "Can't parse server line: %s\n", line);
    return 0;
  }

  mdata = mdata_find(adata, group);
  mdata->deleted = false;
  mdata->first_message = first;
  mdata->last_message = last;
  mdata->allowed = (mod == 'y') || (mod == 'm');
  mutt_str_replace(&mdata->desc, desc);
  if (mdata->newsrc_ent || (mdata->last_cached != 0))
    nntp_group_unread_stat(mdata);
  else if (mdata->last_message && (mdata->first_message <= mdata->last_message))
    mdata->unread = mdata->last_message - mdata->first_message + 1;
  else
    mdata->unread = 0;
  return 0;
}

/**
 * active_get_cache - Load list of all newsgroups from cache
 * @param adata NNTP server
 * @retval  0 Success
 * @retval -1 Failure
 */
static int active_get_cache(struct NntpAccountData *adata)
{
  char buf[8192] = { 0 };
  char file[4096] = { 0 };
  time_t t = 0;

  cache_expand(file, sizeof(file), &adata->conn->account, ".active");
  mutt_debug(LL_DEBUG1, "Parsing %s\n", file);
  FILE *fp = mutt_file_fopen(file, "r");
  if (!fp)
    return -1;

  if (!fgets(buf, sizeof(buf), fp) || (sscanf(buf, "%jd%4095s", &t, file) != 1) || (t == 0))
  {
    mutt_file_fclose(&fp);
    return -1;
  }
  adata->newgroups_time = t;

  mutt_message(_("Loading list of groups from cache..."));
  while (fgets(buf, sizeof(buf), fp))
    nntp_add_group(buf, adata);
  nntp_add_group(NULL, NULL);
  mutt_file_fclose(&fp);
  mutt_clear_error();
  return 0;
}

/**
 * nntp_active_save_cache - Save list of all newsgroups to cache
 * @param adata NNTP server
 * @retval  0 Success
 * @retval -1 Failure
 */
int nntp_active_save_cache(struct NntpAccountData *adata)
{
  if (!adata->cacheable)
    return 0;

  size_t buflen = 10240;
  char *buf = MUTT_MEM_CALLOC(buflen, char);
  snprintf(buf, buflen, "%lu\n", (unsigned long) adata->newgroups_time);
  size_t off = strlen(buf);

  for (unsigned int i = 0; i < adata->groups_num; i++)
  {
    struct NntpMboxData *mdata = adata->groups_list[i];

    if (!mdata || mdata->deleted)
      continue;

    if ((off + strlen(mdata->group) + (mdata->desc ? strlen(mdata->desc) : 0) + 50) > buflen)
    {
      buflen *= 2;
      MUTT_MEM_REALLOC(&buf, buflen, char);
    }
    snprintf(buf + off, buflen - off, "%s " ANUM_FMT " " ANUM_FMT " %c%s%s\n",
             mdata->group, mdata->last_message, mdata->first_message,
             mdata->allowed ? 'y' : 'n', mdata->desc ? " " : "",
             mdata->desc ? mdata->desc : "");
    off += strlen(buf + off);
  }

  char file[PATH_MAX] = { 0 };
  cache_expand(file, sizeof(file), &adata->conn->account, ".active");
  mutt_debug(LL_DEBUG1, "Updating %s\n", file);
  int rc = update_file(file, buf);
  FREE(&buf);
  return rc;
}

#ifdef USE_HCACHE
/**
 * nntp_hcache_namer - Compose hcache file names - Implements ::hcache_namer_t - @ingroup hcache_namer_api
 */
static void nntp_hcache_namer(const char *path, struct Buffer *dest)
{
  buf_printf(dest, "%s.hcache", path);

  /* Strip out any directories in the path */
  char *first = strchr(buf_string(dest), '/');
  char *last = strrchr(buf_string(dest), '/');
  if (first && last && (last > first))
  {
    memmove(first, last, strlen(last) + 1);
  }
}

/**
 * nntp_hcache_open - Open newsgroup hcache
 * @param mdata NNTP Mailbox data
 * @retval ptr  Header cache
 * @retval NULL Error
 */
struct HeaderCache *nntp_hcache_open(struct NntpMboxData *mdata)
{
  struct Url url = { 0 };
  char file[PATH_MAX] = { 0 };

  const bool c_save_unsubscribed = cs_subset_bool(NeoMutt->sub, "save_unsubscribed");
  if (!mdata->adata || !mdata->adata->cacheable || !mdata->adata->conn || !mdata->group ||
      !(mdata->newsrc_ent || mdata->subscribed || c_save_unsubscribed))
  {
    return NULL;
  }

  account_to_url(&mdata->adata->conn->account, &url);
  url.path = mdata->group;
  url_tostring(&url, file, sizeof(file), U_PATH);
  const char *const c_news_cache_dir = cs_subset_path(NeoMutt->sub, "news_cache_dir");
  return hcache_open(c_news_cache_dir, file, nntp_hcache_namer, true);
}

/**
 * nntp_hcache_update - Remove stale cached headers
 * @param mdata NNTP Mailbox data
 * @param hc    Header cache
 */
void nntp_hcache_update(struct NntpMboxData *mdata, struct HeaderCache *hc)
{
  if (!hc)
    return;

  char buf[32] = { 0 };
  bool old = false;
  anum_t first = 0, last = 0;

  /* fetch previous values of first and last */
  char *hdata = hcache_fetch_raw_str(hc, "index", 5);
  if (hdata)
  {
    mutt_debug(LL_DEBUG2, "hcache_fetch_email index: %s\n", hdata);
    if (sscanf(hdata, ANUM_FMT " " ANUM_FMT, &first, &last) == 2)
    {
      old = true;
      mdata->last_cached = last;

      /* clean removed headers from cache */
      for (anum_t current = first; current <= last; current++)
      {
        if ((current >= mdata->first_message) && (current <= mdata->last_message))
          continue;

        snprintf(buf, sizeof(buf), ANUM_FMT, current);
        mutt_debug(LL_DEBUG2, "hcache_delete_email %s\n", buf);
        hcache_delete_email(hc, buf, strlen(buf));
      }
    }
    FREE(&hdata);
  }

  /* store current values of first and last */
  if (!old || (mdata->first_message != first) || (mdata->last_message != last))
  {
    snprintf(buf, sizeof(buf), ANUM_FMT " " ANUM_FMT, mdata->first_message,
             mdata->last_message);
    mutt_debug(LL_DEBUG2, "hcache_store_email index: %s\n", buf);
    hcache_store_raw(hc, "index", 5, buf, strlen(buf) + 1);
  }
}
#endif

/**
 * nntp_bcache_delete - Delete an entry from the message cache - Implements ::bcache_list_t - @ingroup bcache_list_api
 * @retval 0 Always
 */
static int nntp_bcache_delete(const char *id, struct BodyCache *bcache, void *data)
{
  struct NntpMboxData *mdata = data;
  anum_t anum = 0;
  char c = '\0';

  if (!mdata || (sscanf(id, ANUM_FMT "%c", &anum, &c) != 1) ||
      (anum < mdata->first_message) || (anum > mdata->last_message))
  {
    if (mdata)
      mutt_debug(LL_DEBUG2, "mutt_bcache_del %s\n", id);
    mutt_bcache_del(bcache, id);
  }
  return 0;
}

/**
 * nntp_bcache_update - Remove stale cached messages
 * @param mdata NNTP Mailbox data
 */
void nntp_bcache_update(struct NntpMboxData *mdata)
{
  mutt_bcache_list(mdata->bcache, nntp_bcache_delete, mdata);
}

/**
 * nntp_delete_group_cache - Remove hcache and bcache of newsgroup
 * @param mdata NNTP Mailbox data
 */
void nntp_delete_group_cache(struct NntpMboxData *mdata)
{
  if (!mdata || !mdata->adata || !mdata->adata->cacheable)
    return;

#ifdef USE_HCACHE
  struct Buffer *file = buf_pool_get();
  nntp_hcache_namer(mdata->group, file);
  cache_expand(file->data, file->dsize, &mdata->adata->conn->account, buf_string(file));
  unlink(buf_string(file));
  mdata->last_cached = 0;
  mutt_debug(LL_DEBUG2, "%s\n", buf_string(file));
  buf_pool_release(&file);
#endif

  if (!mdata->bcache)
  {
    mdata->bcache = mutt_bcache_open(&mdata->adata->conn->account, mdata->group);
  }
  if (mdata->bcache)
  {
    mutt_debug(LL_DEBUG2, "%s/*\n", mdata->group);
    mutt_bcache_list(mdata->bcache, nntp_bcache_delete, NULL);
    mutt_bcache_close(&mdata->bcache);
  }
}

/**
 * nntp_clear_cache - Clear the NNTP cache
 * @param adata NNTP server
 *
 * Remove hcache and bcache of all unexistent and unsubscribed newsgroups
 */
void nntp_clear_cache(struct NntpAccountData *adata)
{
  if (!adata || !adata->cacheable)
    return;

  struct dirent *de = NULL;
  DIR *dir = NULL;
  struct Buffer *cache = buf_pool_get();
  struct Buffer *file = buf_pool_get();

  cache_expand(cache->data, cache->dsize, &adata->conn->account, NULL);
  dir = mutt_file_opendir(buf_string(cache), MUTT_OPENDIR_NONE);
  if (!dir)
    goto done;

  buf_addch(cache, '/');
  const bool c_save_unsubscribed = cs_subset_bool(NeoMutt->sub, "save_unsubscribed");

  while ((de = readdir(dir)))
  {
    char *group = de->d_name;
    if (mutt_str_equal(group, ".") || mutt_str_equal(group, ".."))
      continue;

    buf_printf(file, "%s%s", buf_string(cache), group);
    struct stat st = { 0 };
    if (stat(buf_string(file), &st) != 0)
      continue;

#ifdef USE_HCACHE
    if (S_ISREG(st.st_mode))
    {
      char *ext = group + strlen(group) - 7;
      if ((strlen(group) < 8) || !mutt_str_equal(ext, ".hcache"))
        continue;
      *ext = '\0';
    }
    else
#endif
        if (!S_ISDIR(st.st_mode))
      continue;

    struct NntpMboxData tmp_mdata = { 0 };
    struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
    if (!mdata)
    {
      mdata = &tmp_mdata;
      mdata->adata = adata;
      mdata->group = group;
      mdata->bcache = NULL;
    }
    else if (mdata->newsrc_ent || mdata->subscribed || c_save_unsubscribed)
    {
      continue;
    }

    nntp_delete_group_cache(mdata);
    if (S_ISDIR(st.st_mode))
    {
      rmdir(buf_string(file));
      mutt_debug(LL_DEBUG2, "%s\n", buf_string(file));
    }
  }
  closedir(dir);

done:
  buf_pool_release(&cache);
  buf_pool_release(&file);
}

/**
 * nntp_get_field - Get connection login credentials - Implements ConnAccount::get_field() - @ingroup conn_account_get_field
 */
static const char *nntp_get_field(enum ConnAccountField field, void *gf_data)
{
  switch (field)
  {
    case MUTT_CA_LOGIN:
    case MUTT_CA_USER:
      return cs_subset_string(NeoMutt->sub, "nntp_user");
    case MUTT_CA_PASS:
      return cs_subset_string(NeoMutt->sub, "nntp_pass");
    case MUTT_CA_OAUTH_CMD:
    case MUTT_CA_HOST:
    default:
      return NULL;
  }
}

/**
 * nntp_select_server - Open a connection to an NNTP server
 * @param m          Mailbox
 * @param server     Server URL
 * @param leave_lock Leave the server locked?
 * @retval ptr  NNTP server
 * @retval NULL Error
 *
 * Automatically loads a newsrc into memory, if necessary.  Checks the
 * size/mtime of a newsrc file, if it doesn't match, load again.  Hmm, if a
 * system has broken mtimes, this might mean the file is reloaded every time,
 * which we'd have to fix.
 *
 * @sa $newsrc
 */
struct NntpAccountData *nntp_select_server(struct Mailbox *m, const char *server, bool leave_lock)
{
  char file[PATH_MAX] = { 0 };
  int rc;
  struct ConnAccount cac = { { 0 } };
  struct NntpAccountData *adata = NULL;
  struct Connection *conn = NULL;

  if (!server || (*server == '\0'))
  {
    mutt_error(_("No news server defined"));
    return NULL;
  }

  /* create account from news server url */
  cac.flags = 0;
  cac.port = NNTP_PORT;
  cac.type = MUTT_ACCT_TYPE_NNTP;
  cac.service = "nntp";
  cac.get_field = nntp_get_field;

  snprintf(file, sizeof(file), "%s%s", strstr(server, "://") ? "" : "news://", server);
  struct Url *url = url_parse(file);
  if (!url || (url->path && *url->path) ||
      !((url->scheme == U_NNTP) || (url->scheme == U_NNTPS)) || !url->host ||
      (account_from_url(&cac, url) < 0))
  {
    url_free(&url);
    mutt_error(_("%s is an invalid news server specification"), server);
    return NULL;
  }
  if (url->scheme == U_NNTPS)
  {
    cac.flags |= MUTT_ACCT_SSL;
    cac.port = NNTP_SSL_PORT;
  }
  url_free(&url);

  // If nntp_user and nntp_pass are specified in the config, use them to find the connection
  const char *user = NULL;
  const char *pass = NULL;
  if ((user = cac.get_field(MUTT_CA_USER, NULL)))
  {
    mutt_str_copy(cac.user, user, sizeof(cac.user));
    cac.flags |= MUTT_ACCT_USER;
  }
  if ((pass = cac.get_field(MUTT_CA_PASS, NULL)))
  {
    mutt_str_copy(cac.pass, pass, sizeof(cac.pass));
    cac.flags |= MUTT_ACCT_PASS;
  }

  /* find connection by account */
  conn = mutt_conn_find(&cac);
  if (!conn)
    return NULL;
  if (!(conn->account.flags & MUTT_ACCT_USER) && cac.flags & MUTT_ACCT_USER)
  {
    conn->account.flags |= MUTT_ACCT_USER;
    conn->account.user[0] = '\0';
  }

  /* new news server */
  adata = nntp_adata_new(conn);

  rc = nntp_open_connection(adata);

  /* try to create cache directory and enable caching */
  adata->cacheable = false;
  const char *const c_news_cache_dir = cs_subset_path(NeoMutt->sub, "news_cache_dir");
  if ((rc >= 0) && c_news_cache_dir)
  {
    cache_expand(file, sizeof(file), &conn->account, NULL);
    if (mutt_file_mkdir(file, S_IRWXU) < 0)
    {
      mutt_error(_("Can't create %s: %s"), file, strerror(errno));
    }
    adata->cacheable = true;
  }

  /* load .newsrc */
  if (rc >= 0)
  {
    struct ExpandoRenderData NntpRenderData[] = {
      // clang-format off
      { ED_NNTP, NntpRenderCallbacks, adata, MUTT_FORMAT_NO_FLAGS },
      { -1, NULL, NULL, 0 },
      // clang-format on
    };

    const struct Expando *c_newsrc = cs_subset_expando(NeoMutt->sub, "newsrc");
    struct Buffer *buf = buf_pool_get();
    expando_filter(c_newsrc, NntpRenderCallbacks, adata, MUTT_FORMAT_NO_FLAGS,
                   buf->dsize, EnvList, buf);
    buf_expand_path(buf);
    adata->newsrc_file = buf_strdup(buf);
    buf_pool_release(&buf);
    rc = nntp_newsrc_parse(adata);
  }
  if (rc >= 0)
  {
    /* try to load list of newsgroups from cache */
    if (adata->cacheable && (active_get_cache(adata) == 0))
    {
      rc = nntp_check_new_groups(m, adata);
    }
    else
    {
      /* load list of newsgroups from server */
      rc = nntp_active_fetch(adata, false);
    }
  }

  if (rc >= 0)
    nntp_clear_cache(adata);

#ifdef USE_HCACHE
  /* check cache files */
  if ((rc >= 0) && adata->cacheable)
  {
    struct dirent *de = NULL;
    DIR *dir = mutt_file_opendir(file, MUTT_OPENDIR_NONE);

    if (dir)
    {
      while ((de = readdir(dir)))
      {
        struct HeaderCache *hc = NULL;
        char *group = de->d_name;

        char *p = group + strlen(group) - 7;
        if ((strlen(group) < 8) || !mutt_str_equal(p, ".hcache"))
          continue;
        *p = '\0';
        struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
        if (!mdata)
          continue;

        hc = nntp_hcache_open(mdata);
        if (!hc)
          continue;

        /* fetch previous values of first and last */
        char *hdata = hcache_fetch_raw_str(hc, "index", 5);
        if (hdata)
        {
          anum_t first = 0, last = 0;

          if (sscanf(hdata, ANUM_FMT " " ANUM_FMT, &first, &last) == 2)
          {
            if (mdata->deleted)
            {
              mdata->first_message = first;
              mdata->last_message = last;
            }
            if ((last >= mdata->first_message) && (last <= mdata->last_message))
            {
              mdata->last_cached = last;
              mutt_debug(LL_DEBUG2, "%s last_cached=" ANUM_FMT "\n", mdata->group, last);
            }
          }
          FREE(&hdata);
        }
        hcache_close(&hc);
      }
      closedir(dir);
    }
  }
#endif

  if ((rc < 0) || !leave_lock)
    nntp_newsrc_close(adata);

  if (rc < 0)
  {
    mutt_hash_free(&adata->groups_hash);
    FREE(&adata->groups_list);
    FREE(&adata->newsrc_file);
    FREE(&adata->authenticators);
    FREE(&adata);
    mutt_socket_close(conn);
    FREE(&conn);
    return NULL;
  }

  return adata;
}

/**
 * nntp_article_status - Get status of articles from .newsrc
 * @param m       Mailbox
 * @param e       Email
 * @param group   Newsgroup
 * @param anum    Article number
 *
 * Full status flags are not supported by nntp, but we can fake some of them:
 * Read = a read message number is in the .newsrc
 * New = not read and not cached
 * Old = not read but cached
 */
void nntp_article_status(struct Mailbox *m, struct Email *e, char *group, anum_t anum)
{
  struct NntpMboxData *mdata = m->mdata;

  if (group)
    mdata = mutt_hash_find(mdata->adata->groups_hash, group);

  if (!mdata)
    return;

  for (unsigned int i = 0; i < mdata->newsrc_len; i++)
  {
    if ((anum >= mdata->newsrc_ent[i].first) && (anum <= mdata->newsrc_ent[i].last))
    {
      /* can't use mutt_set_flag() because mview_update() didn't get called yet */
      e->read = true;
      return;
    }
  }

  /* article was not cached yet, it's new */
  if (anum > mdata->last_cached)
    return;

  /* article isn't read but cached, it's old */
  const bool c_mark_old = cs_subset_bool(NeoMutt->sub, "mark_old");
  if (c_mark_old)
    e->old = true;
}

/**
 * mutt_newsgroup_subscribe - Subscribe newsgroup
 * @param adata NNTP server
 * @param group Newsgroup
 * @retval ptr  NNTP data
 * @retval NULL Error
 */
struct NntpMboxData *mutt_newsgroup_subscribe(struct NntpAccountData *adata, char *group)
{
  if (!adata || !adata->groups_hash || !group || (*group == '\0'))
    return NULL;

  struct NntpMboxData *mdata = mdata_find(adata, group);
  mdata->subscribed = true;
  if (!mdata->newsrc_ent)
  {
    mdata->newsrc_ent = MUTT_MEM_CALLOC(1, struct NewsrcEntry);
    mdata->newsrc_len = 1;
    mdata->newsrc_ent[0].first = 1;
    mdata->newsrc_ent[0].last = 0;
  }
  return mdata;
}

/**
 * mutt_newsgroup_unsubscribe - Unsubscribe newsgroup
 * @param adata NNTP server
 * @param group Newsgroup
 * @retval ptr  NNTP data
 * @retval NULL Error
 */
struct NntpMboxData *mutt_newsgroup_unsubscribe(struct NntpAccountData *adata, char *group)
{
  if (!adata || !adata->groups_hash || !group || (*group == '\0'))
    return NULL;

  struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
  if (!mdata)
    return NULL;

  mdata->subscribed = false;
  const bool c_save_unsubscribed = cs_subset_bool(NeoMutt->sub, "save_unsubscribed");
  if (!c_save_unsubscribed)
  {
    mdata->newsrc_len = 0;
    FREE(&mdata->newsrc_ent);
  }
  return mdata;
}

/**
 * mutt_newsgroup_catchup - Catchup newsgroup
 * @param m     Mailbox
 * @param adata NNTP server
 * @param group Newsgroup
 * @retval ptr  NNTP data
 * @retval NULL Error
 */
struct NntpMboxData *mutt_newsgroup_catchup(struct Mailbox *m,
                                            struct NntpAccountData *adata, char *group)
{
  if (!adata || !adata->groups_hash || !group || (*group == '\0'))
    return NULL;

  struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
  if (!mdata)
    return NULL;

  if (mdata->newsrc_ent)
  {
    MUTT_MEM_REALLOC(&mdata->newsrc_ent, 1, struct NewsrcEntry);
    mdata->newsrc_len = 1;
    mdata->newsrc_ent[0].first = 1;
    mdata->newsrc_ent[0].last = mdata->last_message;
  }
  mdata->unread = 0;
  if (m && (m->mdata == mdata))
  {
    for (unsigned int i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      mutt_set_flag(m, e, MUTT_READ, true, true);
    }
  }
  return mdata;
}

/**
 * mutt_newsgroup_uncatchup - Uncatchup newsgroup
 * @param m     Mailbox
 * @param adata NNTP server
 * @param group Newsgroup
 * @retval ptr  NNTP data
 * @retval NULL Error
 */
struct NntpMboxData *mutt_newsgroup_uncatchup(struct Mailbox *m,
                                              struct NntpAccountData *adata, char *group)
{
  if (!adata || !adata->groups_hash || !group || (*group == '\0'))
    return NULL;

  struct NntpMboxData *mdata = mutt_hash_find(adata->groups_hash, group);
  if (!mdata)
    return NULL;

  if (mdata->newsrc_ent)
  {
    MUTT_MEM_REALLOC(&mdata->newsrc_ent, 1, struct NewsrcEntry);
    mdata->newsrc_len = 1;
    mdata->newsrc_ent[0].first = 1;
    mdata->newsrc_ent[0].last = mdata->first_message - 1;
  }
  if (m && (m->mdata == mdata))
  {
    mdata->unread = m->msg_count;
    for (unsigned int i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      mutt_set_flag(m, e, MUTT_READ, false, true);
    }
  }
  else
  {
    mdata->unread = mdata->last_message;
    if (mdata->newsrc_ent)
      mdata->unread -= mdata->newsrc_ent[0].last;
  }
  return mdata;
}

/**
 * nntp_mailbox - Get first newsgroup with new messages
 * @param m       Mailbox
 * @param buf     Buffer for result
 * @param buflen  Length of buffer
 */
void nntp_mailbox(struct Mailbox *m, char *buf, size_t buflen)
{
  if (!m)
    return;

  for (unsigned int i = 0; i < CurrentNewsSrv->groups_num; i++)
  {
    struct NntpMboxData *mdata = CurrentNewsSrv->groups_list[i];

    if (!mdata || !mdata->subscribed || !mdata->unread)
      continue;

    if ((m->type == MUTT_NNTP) &&
        mutt_str_equal(mdata->group, ((struct NntpMboxData *) m->mdata)->group))
    {
      unsigned int unread = 0;

      for (unsigned int j = 0; j < m->msg_count; j++)
      {
        struct Email *e = m->emails[j];
        if (!e)
          break;
        if (!e->read && !e->deleted)
          unread++;
      }
      if (unread == 0)
        continue;
    }
    mutt_str_copy(buf, mdata->group, buflen);
    break;
  }
}
