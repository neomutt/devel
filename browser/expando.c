/**
 * @file
 * Browser Expando definitions
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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
 * @page browser_expando Browser Expando definitions
 *
 * Browser Expando definitions
 */

#include "config.h"
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "expando.h"
#include "lib.h"
#include "expando/lib.h"
#include "muttlib.h"

/**
 * folder_date - Browser: Last modified - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_date(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return;

  static const time_t one_year = 31536000;
  const char *t_fmt = ((mutt_date_now() - folder->ff->mtime) < one_year) ?
                          "%b %d %H:%M" :
                          "%b %d  %Y";

  char tmp[128] = { 0 };

  mutt_date_localtime_format(tmp, sizeof(tmp), t_fmt, folder->ff->mtime);

  buf_strcpy(buf, tmp);
}

/**
 * folder_date_num - Browser: Last modified - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_date_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return 0;

  return folder->ff->mtime;
}

/**
 * folder_date_format - Browser: Last modified ($date_format) - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_date_format(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return;

  char tmp[128] = { 0 };
  bool use_c_locale = false;
  const char *const c_date_format = cs_subset_string(NeoMutt->sub, "date_format");
  const char *t_fmt = NONULL(c_date_format);
  if (*t_fmt == '!')
  {
    t_fmt++;
    use_c_locale = true;
  }

  if (use_c_locale)
  {
    mutt_date_localtime_format_locale(tmp, sizeof(tmp), t_fmt,
                                      folder->ff->mtime, NeoMutt->time_c_locale);
  }
  else
  {
    mutt_date_localtime_format(tmp, sizeof(tmp), t_fmt, folder->ff->mtime);
  }

  buf_strcpy(buf, tmp);
}

/**
 * folder_date_format_num - Browser: Last modified ($date_format) - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_date_format_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return 0;

  return folder->ff->mtime;
}

/**
 * folder_date_strf - Browser: Last modified (strftime) - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_date_strf(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  if (!folder->ff->local)
    return;

  bool use_c_locale = false;
  const char *text = node->text;
  if (*text == '!')
  {
    use_c_locale = true;
    text++;
  }

  char tmp[128] = { 0 };
  struct tm tm = mutt_date_localtime(folder->ff->mtime);

  if (use_c_locale)
  {
    strftime_l(tmp, sizeof(tmp), text, &tm, NeoMutt->time_c_locale);
  }
  else
  {
    strftime(tmp, sizeof(tmp), text, &tm);
  }

  buf_strcpy(buf, tmp);
}

/**
 * folder_date_strf_num - Browser: Last modified (strftime) - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_date_strf_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  if (!folder->ff->local)
    return 0;

  return folder->ff->mtime;
}

/**
 * folder_description - Browser: Description - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_description(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  const char *s = NULL;
  if (folder->ff->desc)
    s = folder->ff->desc;
  else
    s = folder->ff->name;

  buf_printf(buf, "%s%s", s,
             folder->ff->local ?
                 (S_ISLNK(folder->ff->mode) ?
                      "@" :
                      (S_ISDIR(folder->ff->mode) ?
                           "/" :
                           (((folder->ff->mode & S_IXUSR) != 0) ? "*" : ""))) :
                 "");
}

/**
 * folder_filename - Browser: Filename - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_filename(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  const char *s = NONULL(folder->ff->name);

  buf_printf(buf, "%s%s", s,
             folder->ff->local ?
                 (S_ISLNK(folder->ff->mode) ?
                      "@" :
                      (S_ISDIR(folder->ff->mode) ?
                           "/" :
                           (((folder->ff->mode & S_IXUSR) != 0) ? "*" : ""))) :
                 "");
}

/**
 * folder_file_group - Browser: Group name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_file_group(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return;

  struct group *gr = getgrgid(folder->ff->gid);
  if (gr)
  {
    buf_addstr(buf, gr->gr_name);
  }
  else
  {
    buf_printf(buf, "%u", folder->ff->gid);
  }
}

/**
 * folder_file_mode - Browser: File permissions - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_file_mode(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  if (folder->ff->local)
  {
    buf_printf(buf, "%c%c%c%c%c%c%c%c%c%c",
               S_ISDIR(folder->ff->mode) ? 'd' : (S_ISLNK(folder->ff->mode) ? 'l' : '-'),
               ((folder->ff->mode & S_IRUSR) != 0) ? 'r' : '-',
               ((folder->ff->mode & S_IWUSR) != 0) ? 'w' : '-',
               ((folder->ff->mode & S_ISUID) != 0) ? 's' :
               ((folder->ff->mode & S_IXUSR) != 0) ? 'x' :
                                                     '-',
               ((folder->ff->mode & S_IRGRP) != 0) ? 'r' : '-',
               ((folder->ff->mode & S_IWGRP) != 0) ? 'w' : '-',
               ((folder->ff->mode & S_ISGID) != 0) ? 's' :
               ((folder->ff->mode & S_IXGRP) != 0) ? 'x' :
                                                     '-',
               ((folder->ff->mode & S_IROTH) != 0) ? 'r' : '-',
               ((folder->ff->mode & S_IWOTH) != 0) ? 'w' : '-',
               ((folder->ff->mode & S_ISVTX) != 0) ? 't' :
               ((folder->ff->mode & S_IXOTH) != 0) ? 'x' :
                                                     '-');
  }
  else if (folder->ff->imap)
  {
    /* mark folders with subfolders AND mail */
    buf_printf(buf, "IMAP %c", (folder->ff->inferiors && folder->ff->selectable) ? '+' : ' ');
  }
}

/**
 * folder_file_owner - Browser: Owner name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_file_owner(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return;

  struct passwd *pw = getpwuid(folder->ff->uid);
  if (pw)
  {
    buf_addstr(buf, pw->pw_name);
  }
  else
  {
    buf_printf(buf, "%u", folder->ff->uid);
  }
}

/**
 * folder_file_size - Browser: Size in bytes - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_file_size(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  mutt_str_pretty_size(buf, folder->ff->size);
}

/**
 * folder_file_size_num - Browser: Size in bytes - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_file_size_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;
  return folder->ff->size;
}

/**
 * folder_hard_links - Browser: Hard links - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_hard_links(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->local)
    return;

  buf_add_printf(buf, "%d", (int) folder->ff->nlink);
}

/**
 * folder_hard_links_num - Browser: Hard links - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_hard_links_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  if (folder->ff->local)
    return folder->ff->nlink;

  return 0;
}

/**
 * folder_message_count - Browser: Number of messages - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_message_count(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->has_mailbox)
    return;

  buf_add_printf(buf, "%d", folder->ff->msg_count);
}

/**
 * folder_message_count_num - Browser: Number of messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_message_count_num(const struct ExpandoNode *node, void *data,
                                     MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  if (folder->ff->has_mailbox)
    return folder->ff->msg_count;

  return 0;
}

/**
 * folder_new_mail - Browser: New mail flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_new_mail(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = folder->ff->has_new_mail ? "N" : " ";
  buf_strcpy(buf, s);
}

/**
 * folder_new_mail_num - Browser: New mail flag - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_new_mail_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;
  return folder->ff->has_new_mail;
}

/**
 * folder_notify_num - Browser: Alert for new mail - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_notify_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  return folder->ff->notify_user;
}

/**
 * folder_number_num - Browser: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_number_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  return folder->num + 1;
}

/**
 * folder_poll_num - Browser: Poll for new mail - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_poll_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  return folder->ff->poll_new_mail;
}

/**
 * folder_tagged - Browser: Is Tagged - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_tagged(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = folder->ff->tagged ? "*" : " ";
  buf_strcpy(buf, s);
}

/**
 * folder_tagged_num - Browser: Is Tagged - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_tagged_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct Folder *folder = data;
  return folder->ff->tagged;
}

/**
 * folder_unread_count - Browser: Number of unread messages - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void folder_unread_count(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct Folder *folder = data;
  if (!folder->ff->has_mailbox)
    return;

  buf_add_printf(buf, "%d", folder->ff->msg_unread);
}

/**
 * folder_unread_count_num - Browser: Number of unread messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long folder_unread_count_num(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags)
{
  const struct Folder *folder = data;

  if (folder->ff->has_mailbox)
    return folder->ff->msg_unread;

  return 0;
}

/**
 * global_padding_space - Fixed whitespace - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void global_padding_space(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  buf_addstr(buf, " ");
}

/**
 * FolderRenderCallbacks1 - Callbacks for Browser Expandos
 *
 * @sa FolderFormatDef, ExpandoDataFolder, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback FolderRenderCallbacks1[] = {
  // clang-format off
  { ED_FOLDER, ED_FOL_DATE,          folder_date,          folder_date_num },
  { ED_FOLDER, ED_FOL_DATE_FORMAT,   folder_date_format,   folder_date_format_num },
  { ED_FOLDER, ED_FOL_DATE_STRF,     folder_date_strf,     folder_date_strf_num },
  { ED_FOLDER, ED_FOL_DESCRIPTION,   folder_description,   NULL },
  { ED_FOLDER, ED_FOL_FILENAME,      folder_filename,      NULL },
  { ED_FOLDER, ED_FOL_FILE_GROUP,    folder_file_group,    NULL },
  { ED_FOLDER, ED_FOL_FILE_MODE,     folder_file_mode,     NULL },
  { ED_FOLDER, ED_FOL_FILE_OWNER,    folder_file_owner,    NULL },
  { ED_FOLDER, ED_FOL_FILE_SIZE,     folder_file_size,     folder_file_size_num },
  { ED_FOLDER, ED_FOL_HARD_LINKS,    folder_hard_links,    folder_hard_links_num },
  { ED_FOLDER, ED_FOL_MESSAGE_COUNT, folder_message_count, folder_message_count_num },
  { ED_FOLDER, ED_FOL_NEW_MAIL,      folder_new_mail,      folder_new_mail_num },
  { ED_FOLDER, ED_FOL_NOTIFY,        NULL,                 folder_notify_num },
  { ED_FOLDER, ED_FOL_NUMBER,        NULL,                 folder_number_num },
  { ED_FOLDER, ED_FOL_POLL,          NULL,                 folder_poll_num },
  { ED_FOLDER, ED_FOL_TAGGED,        folder_tagged,        folder_tagged_num },
  { ED_FOLDER, ED_FOL_UNREAD_COUNT,  folder_unread_count,  folder_unread_count_num },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * FolderRenderCallbacks2 - Callbacks for Browser Expandos
 *
 * @sa FolderFormatDef, ExpandoDataFolder, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback FolderRenderCallbacks2[] = {
  // clang-format off
  { ED_GLOBAL, ED_GLO_PADDING_SPACE, global_padding_space, NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
