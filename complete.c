/**
 * @file
 * String auto-completion routines
 *
 * @authors
 * Copyright (C) 1996-2000,2007 Michael R. Elkins <me@mutt.org>
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

#include "config.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include "globals.h"
#include "lib/lib.h"
#include "options.h"
#include "protos.h"
#ifdef USE_IMAP
#include "imap/imap.h"
#include "mailbox.h"
#endif
#ifdef USE_NNTP
#include "nntp.h"
#endif

/**
 * mutt_complete - Attempt to complete a partial pathname
 * @param s    Buffer containing pathname
 * @param slen Buffer length
 * @retval 0 if ok
 * @retval -1 if no matches
 *
 * Given a partial pathname, fill in as much of the rest of the path as is
 * unique.
 */
int mutt_complete(char *s, size_t slen)
{
  char *p = NULL;
  DIR *dirp = NULL;
  struct dirent *de = NULL;
  int i, init = 0;
  size_t len;
  char dirpart[_POSIX_PATH_MAX], exp_dirpart[_POSIX_PATH_MAX];
  char filepart[_POSIX_PATH_MAX];
#ifdef USE_IMAP
  char imap_path[LONG_STRING];
#endif

  mutt_debug(2, "mutt_complete: completing %s\n", s);

#ifdef USE_NNTP
  if (option(OPT_NEWS))
  {
    struct NntpServer *nserv = CurrentNewsSrv;
    unsigned int n = 0;

    strfcpy(filepart, s, sizeof(filepart));

    /* special case to handle when there is no filepart yet
     * find the first subscribed newsgroup */
    len = mutt_strlen(filepart);
    if (len == 0)
    {
      for (; n < nserv->groups_num; n++)
      {
        struct NntpData *nntp_data = nserv->groups_list[n];

        if (nntp_data && nntp_data->subscribed)
        {
          strfcpy(filepart, nntp_data->group, sizeof(filepart));
          init = 1;
          n++;
          break;
        }
      }
    }

    for (; n < nserv->groups_num; n++)
    {
      struct NntpData *nntp_data = nserv->groups_list[n];

      if (nntp_data && nntp_data->subscribed &&
          (mutt_strncmp(nntp_data->group, filepart, len) == 0))
      {
        if (init)
        {
          for (i = 0; filepart[i] && nntp_data->group[i]; i++)
          {
            if (filepart[i] != nntp_data->group[i])
            {
              filepart[i] = 0;
              break;
            }
          }
          filepart[i] = 0;
        }
        else
        {
          strfcpy(filepart, nntp_data->group, sizeof(filepart));
          init = 1;
        }
      }
    }

    strfcpy(s, filepart, slen);
    return (init ? 0 : -1);
  }
#endif

#ifdef USE_IMAP
  /* we can use '/' as a delimiter, imap_complete rewrites it */
  if (*s == '=' || *s == '+' || *s == '!')
  {
    if (*s == '!')
      p = NONULL(SpoolFile);
    else
      p = NONULL(Maildir);

    mutt_concat_path(imap_path, p, s + 1, sizeof(imap_path));
  }
  else
    strfcpy(imap_path, s, sizeof(imap_path));

  if (mx_is_imap(imap_path))
    return imap_complete(s, slen, imap_path);
#endif

  if (*s == '=' || *s == '+' || *s == '!')
  {
    dirpart[0] = *s;
    dirpart[1] = 0;
    if (*s == '!')
      strfcpy(exp_dirpart, NONULL(SpoolFile), sizeof(exp_dirpart));
    else
      strfcpy(exp_dirpart, NONULL(Maildir), sizeof(exp_dirpart));
    if ((p = strrchr(s, '/')))
    {
      char buf[_POSIX_PATH_MAX];
      if (mutt_concatn_path(buf, sizeof(buf), exp_dirpart, strlen(exp_dirpart),
                            s + 1, (size_t)(p - s - 1)) == NULL)
      {
        return -1;
      }
      strfcpy(exp_dirpart, buf, sizeof(exp_dirpart));
      mutt_substrcpy(dirpart, s, p + 1, sizeof(dirpart));
      strfcpy(filepart, p + 1, sizeof(filepart));
    }
    else
      strfcpy(filepart, s + 1, sizeof(filepart));
    dirp = opendir(exp_dirpart);
  }
  else
  {
    if ((p = strrchr(s, '/')))
    {
      if (p == s) /* absolute path */
      {
        p = s + 1;
        strfcpy(dirpart, "/", sizeof(dirpart));
        exp_dirpart[0] = 0;
        strfcpy(filepart, p, sizeof(filepart));
        dirp = opendir(dirpart);
      }
      else
      {
        mutt_substrcpy(dirpart, s, p, sizeof(dirpart));
        strfcpy(filepart, p + 1, sizeof(filepart));
        strfcpy(exp_dirpart, dirpart, sizeof(exp_dirpart));
        mutt_expand_path(exp_dirpart, sizeof(exp_dirpart));
        dirp = opendir(exp_dirpart);
      }
    }
    else
    {
      /* no directory name, so assume current directory. */
      dirpart[0] = 0;
      strfcpy(filepart, s, sizeof(filepart));
      dirp = opendir(".");
    }
  }

  if (!dirp)
  {
    mutt_debug(1, "mutt_complete(): %s: %s (errno %d).\n", exp_dirpart,
               strerror(errno), errno);
    return -1;
  }

  /*
   * special case to handle when there is no filepart yet.  find the first
   * file/directory which is not ``.'' or ``..''
   */
  if ((len = mutt_strlen(filepart)) == 0)
  {
    while ((de = readdir(dirp)) != NULL)
    {
      if ((mutt_strcmp(".", de->d_name) != 0) && (mutt_strcmp("..", de->d_name) != 0))
      {
        strfcpy(filepart, de->d_name, sizeof(filepart));
        init++;
        break;
      }
    }
  }

  while ((de = readdir(dirp)) != NULL)
  {
    if (mutt_strncmp(de->d_name, filepart, len) == 0)
    {
      if (init)
      {
        for (i = 0; filepart[i] && de->d_name[i]; i++)
        {
          if (filepart[i] != de->d_name[i])
          {
            filepart[i] = 0;
            break;
          }
        }
        filepart[i] = 0;
      }
      else
      {
        char buf[_POSIX_PATH_MAX];
        struct stat st;

        strfcpy(filepart, de->d_name, sizeof(filepart));

        /* check to see if it is a directory */
        if (dirpart[0])
        {
          strfcpy(buf, exp_dirpart, sizeof(buf));
          strfcpy(buf + strlen(buf), "/", sizeof(buf) - strlen(buf));
        }
        else
          buf[0] = 0;
        strfcpy(buf + strlen(buf), filepart, sizeof(buf) - strlen(buf));
        if (stat(buf, &st) != -1 && (st.st_mode & S_IFDIR))
          strfcpy(filepart + strlen(filepart), "/", sizeof(filepart) - strlen(filepart));
        init = 1;
      }
    }
  }
  closedir(dirp);

  if (dirpart[0])
  {
    strfcpy(s, dirpart, slen);
    if ((mutt_strcmp("/", dirpart) != 0) && dirpart[0] != '=' && dirpart[0] != '+')
      strfcpy(s + strlen(s), "/", slen - strlen(s));
    strfcpy(s + strlen(s), filepart, slen - strlen(s));
  }
  else
    strfcpy(s, filepart, slen);

  return (init ? 0 : -1);
}
