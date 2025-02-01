/**
 * @file
 * Functions to parse commands in a config file
 *
 * @authors
 * Copyright (C) 1996-2002,2007,2010,2012-2013,2016 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2004 g10 Code GmbH
 * Copyright (C) 2019-2025 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Aditya De Saha <adityadesaha@gmail.com>
 * Copyright (C) 2020 Matthew Hughes <matthewhughes934@gmail.com>
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
 * Copyright (C) 2020-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2022 Marco Sirabella <marco@sirabella.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page neo_commands Functions to parse commands in a config file
 *
 * Functions to parse commands in a config file
 */

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "commands.h"
#include "attach/lib.h"
#include "color/lib.h"
#include "imap/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "pager/lib.h"
#include "parse/lib.h"
#include "pfile/lib.h"
#include "spager/lib.h"
#include "store/lib.h"
#include "alternates.h"
#include "globals.h"
#include "muttlib.h"
#include "mx.h"
#include "score.h"
#include "version.h"
#ifdef USE_INOTIFY
#include "monitor.h"
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#endif
#ifdef USE_DEBUG_COLOR
#include "debug/lib.h"
#endif

/// LIFO designed to contain the list of config files that have been sourced and
/// avoid cyclic sourcing.
static struct ListHead MuttrcStack = STAILQ_HEAD_INITIALIZER(MuttrcStack);

#define MAX_ERRS 128

/**
 * enum TriBool - Tri-state boolean
 */
enum TriBool
{
  TB_UNSET = -1, ///< Value hasn't been set
  TB_FALSE,      ///< Value is false
  TB_TRUE,       ///< Value is true
};

/**
 * enum GroupState - Type of email address group
 */
enum GroupState
{
  GS_NONE, ///< Group is missing an argument
  GS_RX,   ///< Entry is a regular expression
  GS_ADDR, ///< Entry is an address
};

/**
 * is_function - Is the argument a neomutt function?
 * @param name  Command name to be searched for
 * @retval true  Function found
 * @retval false Function not found
 */
static bool is_function(const char *name)
{
  for (size_t i = 0; MenuNames[i].name; i++)
  {
    const struct MenuFuncOp *fns = km_get_table(MenuNames[i].value);
    if (!fns)
      continue;

    for (int j = 0; fns[j].name; j++)
      if (mutt_str_equal(name, fns[j].name))
        return true;
  }
  return false;
}

/**
 * is_color_object - Is the argument a neomutt colour?
 * @param name  Colour name to be searched for
 * @retval true  Function found
 * @retval false Function not found
 */
static bool is_color_object(const char *name)
{
  int cid = mutt_map_get_value(name, ColorFields);

  return (cid > 0);
}

/**
 * parse_grouplist - Parse a group context
 * @param gl   GroupList to add to
 * @param buf  Temporary Buffer space
 * @param s    Buffer containing string to be parsed
 * @param err  Buffer for error messages
 * @retval  0 Success
 * @retval -1 Error
 */
int parse_grouplist(struct GroupList *gl, struct Buffer *buf, struct Buffer *s,
                    struct Buffer *err)
{
  while (mutt_istr_equal(buf->data, "-group"))
  {
    if (!MoreArgs(s))
    {
      buf_strcpy(err, _("-group: no group name"));
      return -1;
    }

    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    mutt_grouplist_add(gl, mutt_pattern_group(buf->data));

    if (!MoreArgs(s))
    {
      buf_strcpy(err, _("out of arguments"));
      return -1;
    }

    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
  }

  return 0;
}

/**
 * parse_rc_line_cwd - Parse and run a muttrc line in a relative directory
 * @param line   Line to be parsed
 * @param cwd    File relative where to run the line
 * @param err    Where to write error messages
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 */
enum CommandResult parse_rc_line_cwd(const char *line, char *cwd, struct Buffer *err)
{
  mutt_list_insert_head(&MuttrcStack, mutt_str_dup(NONULL(cwd)));

  enum CommandResult ret = parse_rc_line(line, err);

  struct ListNode *np = STAILQ_FIRST(&MuttrcStack);
  STAILQ_REMOVE_HEAD(&MuttrcStack, entries);
  FREE(&np->data);
  FREE(&np);

  return ret;
}

/**
 * mutt_get_sourced_cwd - Get the current file path that is being parsed
 * @retval ptr File path that is being parsed or cwd at runtime
 *
 * @note Caller is responsible for freeing returned string
 */
char *mutt_get_sourced_cwd(void)
{
  struct ListNode *np = STAILQ_FIRST(&MuttrcStack);
  if (np && np->data)
    return mutt_str_dup(np->data);

  // stack is empty, return our own dummy file relative to cwd
  struct Buffer *cwd = buf_pool_get();
  mutt_path_getcwd(cwd);
  buf_addstr(cwd, "/dummy.rc");
  char *ret = buf_strdup(cwd);
  buf_pool_release(&cwd);
  return ret;
}

/**
 * source_rc - Read an initialization file
 * @param rcfile_path Path to initialization file
 * @param err         Buffer for error messages
 * @retval <0 NeoMutt should pause to let the user know
 */
int source_rc(const char *rcfile_path, struct Buffer *err)
{
  int lineno = 0, rc = 0, warnings = 0;
  enum CommandResult line_rc;
  struct Buffer *token = NULL, *linebuf = NULL;
  char *line = NULL;
  char *currentline = NULL;
  char rcfile[PATH_MAX + 1] = { 0 };
  size_t linelen = 0;
  pid_t pid;

  mutt_str_copy(rcfile, rcfile_path, sizeof(rcfile));

  size_t rcfilelen = mutt_str_len(rcfile);
  if (rcfilelen == 0)
    return -1;

  bool ispipe = rcfile[rcfilelen - 1] == '|';

  if (!ispipe)
  {
    struct ListNode *np = STAILQ_FIRST(&MuttrcStack);
    if (!mutt_path_to_absolute(rcfile, np ? NONULL(np->data) : ""))
    {
      mutt_error(_("Error: Can't build path of '%s'"), rcfile_path);
      return -1;
    }

    STAILQ_FOREACH(np, &MuttrcStack, entries)
    {
      if (mutt_str_equal(np->data, rcfile))
      {
        break;
      }
    }
    if (np)
    {
      mutt_error(_("Error: Cyclic sourcing of configuration file '%s'"), rcfile);
      return -1;
    }

    mutt_list_insert_head(&MuttrcStack, mutt_str_dup(rcfile));
  }

  mutt_debug(LL_DEBUG2, "Reading configuration file '%s'\n", rcfile);

  FILE *fp = mutt_open_read(rcfile, &pid);
  if (!fp)
  {
    buf_printf(err, "%s: %s", rcfile, strerror(errno));
    return -1;
  }

  token = buf_pool_get();
  linebuf = buf_pool_get();

  const char *const c_config_charset = cs_subset_string(NeoMutt->sub, "config_charset");
  const char *const c_charset = cc_charset();
  while ((line = mutt_file_read_line(line, &linelen, fp, &lineno, MUTT_RL_CONT)) != NULL)
  {
    const bool conv = c_config_charset && c_charset;
    if (conv)
    {
      currentline = mutt_str_dup(line);
      if (!currentline)
        continue;
      mutt_ch_convert_string(&currentline, c_config_charset, c_charset, MUTT_ICONV_NO_FLAGS);
    }
    else
    {
      currentline = line;
    }

    buf_strcpy(linebuf, currentline);

    buf_reset(err);
    line_rc = parse_rc_buffer(linebuf, token, err);
    if (line_rc == MUTT_CMD_ERROR)
    {
      mutt_error("%s:%d: %s", rcfile, lineno, buf_string(err));
      if (--rc < -MAX_ERRS)
      {
        if (conv)
          FREE(&currentline);
        break;
      }
    }
    else if (line_rc == MUTT_CMD_WARNING)
    {
      /* Warning */
      mutt_warning("%s:%d: %s", rcfile, lineno, buf_string(err));
      warnings++;
    }
    else if (line_rc == MUTT_CMD_FINISH)
    {
      if (conv)
        FREE(&currentline);
      break; /* Found "finish" command */
    }
    else
    {
      if (rc < 0)
        rc = -1;
    }
    if (conv)
      FREE(&currentline);
  }

  FREE(&line);
  mutt_file_fclose(&fp);
  if (pid != -1)
    filter_wait(pid);

  if (rc)
  {
    /* the neomuttrc source keyword */
    buf_reset(err);
    buf_printf(err, (rc >= -MAX_ERRS) ? _("source: errors in %s") : _("source: reading aborted due to too many errors in %s"),
               rcfile);
    rc = -1;
  }
  else
  {
    /* Don't alias errors with warnings */
    if (warnings > 0)
    {
      buf_printf(err, ngettext("source: %d warning in %s", "source: %d warnings in %s", warnings),
                 warnings, rcfile);
      rc = -2;
    }
  }

  if (!ispipe && !STAILQ_EMPTY(&MuttrcStack))
  {
    struct ListNode *np = STAILQ_FIRST(&MuttrcStack);
    STAILQ_REMOVE_HEAD(&MuttrcStack, entries);
    FREE(&np->data);
    FREE(&np);
  }

  buf_pool_release(&token);
  buf_pool_release(&linebuf);
  return rc;
}

/**
 * parse_cd - Parse the 'cd' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_cd(struct Buffer *buf, struct Buffer *s,
                                   intptr_t data, struct Buffer *err)
{
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);
  buf_expand_path(buf);
  if (buf_is_empty(buf))
  {
    if (HomeDir)
    {
      buf_strcpy(buf, HomeDir);
    }
    else
    {
      buf_printf(err, _("%s: too few arguments"), "cd");
      return MUTT_CMD_ERROR;
    }
  }

  if (chdir(buf_string(buf)) != 0)
  {
    buf_printf(err, "cd: %s", strerror(errno));
    return MUTT_CMD_ERROR;
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_echo - Parse the 'echo' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_echo(struct Buffer *buf, struct Buffer *s,
                                     intptr_t data, struct Buffer *err)
{
  if (!MoreArgs(s))
  {
    buf_printf(err, _("%s: too few arguments"), "echo");
    return MUTT_CMD_WARNING;
  }
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);
  OptForceRefresh = true;
  mutt_message("%s", buf->data);
  OptForceRefresh = false;
  mutt_sleep(0);

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_finish - Parse the 'finish' command - Implements Command::parse() - @ingroup command_parse
 * @retval  #MUTT_CMD_FINISH Stop processing the current file
 * @retval  #MUTT_CMD_WARNING Failed
 *
 * If the 'finish' command is found, we should stop reading the current file.
 */
static enum CommandResult parse_finish(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  if (MoreArgs(s))
  {
    buf_printf(err, _("%s: too many arguments"), "finish");
    return MUTT_CMD_WARNING;
  }

  return MUTT_CMD_FINISH;
}

/**
 * parse_group - Parse the 'group' and 'ungroup' commands - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_group(struct Buffer *buf, struct Buffer *s,
                                      intptr_t data, struct Buffer *err)
{
  struct GroupList gl = STAILQ_HEAD_INITIALIZER(gl);
  enum GroupState gstate = GS_NONE;

  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    if (parse_grouplist(&gl, buf, s, err) == -1)
      goto bail;

    if ((data == MUTT_UNGROUP) && mutt_istr_equal(buf->data, "*"))
    {
      mutt_grouplist_clear(&gl);
      goto out;
    }

    if (mutt_istr_equal(buf->data, "-rx"))
    {
      gstate = GS_RX;
    }
    else if (mutt_istr_equal(buf->data, "-addr"))
    {
      gstate = GS_ADDR;
    }
    else
    {
      switch (gstate)
      {
        case GS_NONE:
          buf_printf(err, _("%sgroup: missing -rx or -addr"),
                     (data == MUTT_UNGROUP) ? "un" : "");
          goto warn;

        case GS_RX:
          if ((data == MUTT_GROUP) &&
              (mutt_grouplist_add_regex(&gl, buf->data, REG_ICASE, err) != 0))
          {
            goto bail;
          }
          else if ((data == MUTT_UNGROUP) &&
                   (mutt_grouplist_remove_regex(&gl, buf->data) < 0))
          {
            goto bail;
          }
          break;

        case GS_ADDR:
        {
          char *estr = NULL;
          struct AddressList al = TAILQ_HEAD_INITIALIZER(al);
          mutt_addrlist_parse2(&al, buf->data);
          if (TAILQ_EMPTY(&al))
            goto bail;
          if (mutt_addrlist_to_intl(&al, &estr))
          {
            buf_printf(err, _("%sgroup: warning: bad IDN '%s'"),
                       (data == 1) ? "un" : "", estr);
            mutt_addrlist_clear(&al);
            FREE(&estr);
            goto bail;
          }
          if (data == MUTT_GROUP)
            mutt_grouplist_add_addrlist(&gl, &al);
          else if (data == MUTT_UNGROUP)
            mutt_grouplist_remove_addrlist(&gl, &al);
          mutt_addrlist_clear(&al);
          break;
        }
      }
    }
  } while (MoreArgs(s));

out:
  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_SUCCESS;

bail:
  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_ERROR;

warn:
  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_WARNING;
}

/**
 * parse_ifdef - Parse the 'ifdef' and 'ifndef' commands - Implements Command::parse() - @ingroup command_parse
 *
 * The 'ifdef' command allows conditional elements in the config file.
 * If a given variable, function, command or compile-time symbol exists, then
 * read the rest of the line of config commands.
 * e.g.
 *      ifdef sidebar source ~/.neomutt/sidebar.rc
 *
 * If (data == 1) then it means use the 'ifndef' (if-not-defined) command.
 * e.g.
 *      ifndef imap finish
 */
static enum CommandResult parse_ifdef(struct Buffer *buf, struct Buffer *s,
                                      intptr_t data, struct Buffer *err)
{
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);

  if (buf_is_empty(buf))
  {
    buf_printf(err, _("%s: too few arguments"), (data ? "ifndef" : "ifdef"));
    return MUTT_CMD_WARNING;
  }

  // is the item defined as:
  bool res = cs_subset_lookup(NeoMutt->sub, buf->data) // a variable?
             || feature_enabled(buf->data)             // a compiled-in feature?
             || is_function(buf->data)                 // a function?
             || command_get(buf->data)                 // a command?
             || is_color_object(buf->data)             // a color?
#ifdef USE_HCACHE
             || store_is_valid_backend(buf->data) // a store? (database)
#endif
             || mutt_str_getenv(buf->data); // an environment variable?

  if (!MoreArgs(s))
  {
    buf_printf(err, _("%s: too few arguments"), (data ? "ifndef" : "ifdef"));
    return MUTT_CMD_WARNING;
  }
  parse_extract_token(buf, s, TOKEN_SPACE);

  /* ifdef KNOWN_SYMBOL or ifndef UNKNOWN_SYMBOL */
  if ((res && (data == 0)) || (!res && (data == 1)))
  {
    enum CommandResult rc = parse_rc_line(buf->data, err);
    if (rc == MUTT_CMD_ERROR)
    {
      mutt_error(_("Error: %s"), buf_string(err));
      return MUTT_CMD_ERROR;
    }
    return rc;
  }
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_ignore - Parse the 'ignore' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_ignore(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    remove_from_stailq(&UnIgnore, buf->data);
    add_to_stailq(&Ignore, buf->data);
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_lists - Parse the 'lists' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_lists(struct Buffer *buf, struct Buffer *s,
                                      intptr_t data, struct Buffer *err)
{
  struct GroupList gl = STAILQ_HEAD_INITIALIZER(gl);

  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    if (parse_grouplist(&gl, buf, s, err) == -1)
      goto bail;

    mutt_regexlist_remove(&UnMailLists, buf->data);

    if (mutt_regexlist_add(&MailLists, buf->data, REG_ICASE, err) != 0)
      goto bail;

    if (mutt_grouplist_add_regex(&gl, buf->data, REG_ICASE, err) != 0)
      goto bail;
  } while (MoreArgs(s));

  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_SUCCESS;

bail:
  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_ERROR;
}

/**
 * mailbox_add - Add a new Mailbox
 * @param folder  Path to use for '+' abbreviations
 * @param mailbox Mailbox to add
 * @param label   Descriptive label
 * @param poll    Enable mailbox polling?
 * @param notify  Enable mailbox notification?
 * @param err     Buffer for error messages
 * @retval #CommandResult Result e.g. #MUTT_CMD_SUCCESS
 */
static enum CommandResult mailbox_add(const char *folder, const char *mailbox,
                                      const char *label, enum TriBool poll,
                                      enum TriBool notify, struct Buffer *err)
{
  mutt_debug(LL_DEBUG1, "Adding mailbox: '%s' label '%s', poll %s, notify %s\n",
             mailbox, label ? label : "[NONE]",
             (poll == TB_UNSET) ? "[UNSPECIFIED]" :
             (poll == TB_TRUE)  ? "true" :
                                  "false",
             (notify == TB_UNSET) ? "[UNSPECIFIED]" :
             (notify == TB_TRUE)  ? "true" :
                                    "false");
  struct Mailbox *m = mailbox_new();

  buf_strcpy(&m->pathbuf, mailbox);
  /* int rc = */ mx_path_canon2(m, folder);

  if (m->type <= MUTT_UNKNOWN)
  {
    buf_printf(err, "Unknown Mailbox: %s", m->realpath);
    mailbox_free(&m);
    return MUTT_CMD_ERROR;
  }

  bool new_account = false;
  struct Account *a = mx_ac_find(m);
  if (!a)
  {
    a = account_new(NULL, NeoMutt->sub);
    a->type = m->type;
    new_account = true;
  }

  if (!new_account)
  {
    struct Mailbox *m_old = mx_mbox_find(a, m->realpath);
    if (m_old)
    {
      if (!m_old->visible)
      {
        m_old->visible = true;
        m_old->gen = mailbox_gen();
      }

      if (label)
        mutt_str_replace(&m_old->name, label);

      if (notify != TB_UNSET)
        m_old->notify_user = notify;

      if (poll != TB_UNSET)
        m_old->poll_new_mail = poll;

      struct EventMailbox ev_m = { m_old };
      notify_send(m_old->notify, NT_MAILBOX, NT_MAILBOX_CHANGE, &ev_m);

      mailbox_free(&m);
      return MUTT_CMD_SUCCESS;
    }
  }

  if (label)
    m->name = mutt_str_dup(label);

  if (notify != TB_UNSET)
    m->notify_user = notify;

  if (poll != TB_UNSET)
    m->poll_new_mail = poll;

  if (!mx_ac_add(a, m))
  {
    mailbox_free(&m);
    if (new_account)
    {
      cs_subset_free(&a->sub);
      FREE(&a->name);
      notify_free(&a->notify);
      FREE(&a);
    }
    return MUTT_CMD_SUCCESS;
  }

  if (new_account)
  {
    neomutt_account_add(NeoMutt, a);
  }

  // this is finally a visible mailbox in the sidebar and mailboxes list
  m->visible = true;

#ifdef USE_INOTIFY
  mutt_monitor_add(m);
#endif

  return MUTT_CMD_SUCCESS;
}

/**
 * mailbox_add_simple - Add a new Mailbox
 * @param mailbox Mailbox to add
 * @param err     Buffer for error messages
 * @retval true Success
 */
bool mailbox_add_simple(const char *mailbox, struct Buffer *err)
{
  enum CommandResult rc = mailbox_add("", mailbox, NULL, TB_UNSET, TB_UNSET, err);

  return (rc == MUTT_CMD_SUCCESS);
}

/**
 * parse_mailboxes - Parse the 'mailboxes' command - Implements Command::parse() - @ingroup command_parse
 *
 * This is also used by 'virtual-mailboxes'.
 */
enum CommandResult parse_mailboxes(struct Buffer *buf, struct Buffer *s,
                                   intptr_t data, struct Buffer *err)
{
  enum CommandResult rc = MUTT_CMD_WARNING;

  struct Buffer *label = buf_pool_get();
  struct Buffer *mailbox = buf_pool_get();

  const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
  while (MoreArgs(s))
  {
    bool label_set = false;
    enum TriBool notify = TB_UNSET;
    enum TriBool poll = TB_UNSET;

    do
    {
      // Start by handling the options
      parse_extract_token(buf, s, TOKEN_NO_FLAGS);

      if (mutt_str_equal(buf_string(buf), "-label"))
      {
        if (!MoreArgs(s))
        {
          buf_printf(err, _("%s: too few arguments"), "mailboxes -label");
          goto done;
        }

        parse_extract_token(label, s, TOKEN_NO_FLAGS);
        label_set = true;
      }
      else if (mutt_str_equal(buf_string(buf), "-nolabel"))
      {
        buf_reset(label);
        label_set = true;
      }
      else if (mutt_str_equal(buf_string(buf), "-notify"))
      {
        notify = TB_TRUE;
      }
      else if (mutt_str_equal(buf_string(buf), "-nonotify"))
      {
        notify = TB_FALSE;
      }
      else if (mutt_str_equal(buf_string(buf), "-poll"))
      {
        poll = TB_TRUE;
      }
      else if (mutt_str_equal(buf_string(buf), "-nopoll"))
      {
        poll = TB_FALSE;
      }
      else if ((data & MUTT_NAMED) && !label_set)
      {
        if (!MoreArgs(s))
        {
          buf_printf(err, _("%s: too few arguments"), "named-mailboxes");
          goto done;
        }

        buf_copy(label, buf);
        label_set = true;
      }
      else
      {
        buf_copy(mailbox, buf);
        break;
      }
    } while (MoreArgs(s));

    if (buf_is_empty(mailbox))
    {
      buf_printf(err, _("%s: too few arguments"), "mailboxes");
      goto done;
    }

    rc = mailbox_add(c_folder, buf_string(mailbox),
                     label_set ? buf_string(label) : NULL, poll, notify, err);
    if (rc != MUTT_CMD_SUCCESS)
      goto done;

    buf_reset(label);
    buf_reset(mailbox);
  }

  rc = MUTT_CMD_SUCCESS;

done:
  buf_pool_release(&label);
  buf_pool_release(&mailbox);
  return rc;
}

/**
 * parse_my_hdr - Parse the 'my_hdr' command - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult parse_my_hdr(struct Buffer *buf, struct Buffer *s,
                                intptr_t data, struct Buffer *err)
{
  parse_extract_token(buf, s, TOKEN_SPACE | TOKEN_QUOTE);
  char *p = strpbrk(buf->data, ": \t");
  if (!p || (*p != ':'))
  {
    buf_strcpy(err, _("invalid header field"));
    return MUTT_CMD_WARNING;
  }

  struct EventHeader ev_h = { buf->data };
  struct ListNode *n = header_find(&UserHeader, buf->data);

  if (n)
  {
    header_update(n, buf->data);
    mutt_debug(LL_NOTIFY, "NT_HEADER_CHANGE: %s\n", buf->data);
    notify_send(NeoMutt->notify, NT_HEADER, NT_HEADER_CHANGE, &ev_h);
  }
  else
  {
    header_add(&UserHeader, buf->data);
    mutt_debug(LL_NOTIFY, "NT_HEADER_ADD: %s\n", buf->data);
    notify_send(NeoMutt->notify, NT_HEADER, NT_HEADER_ADD, &ev_h);
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * set_dump - Dump list of config variables into a file/pager
 * @param flags Which config to dump, e.g. #GEL_CHANGED_CONFIG
 * @param err   Buffer for error message
 * @return num See #CommandResult
 *
 * FIXME: Move me into parse/set.c.  Note: this function currently depends on
 * pager, which is the reason it is not included in the parse library.
 */
enum CommandResult set_dump(enum GetElemListFlags flags, struct Buffer *err)
{
  struct PagedFile *pf = paged_file_new(NULL);

  struct Buffer *value = buf_pool_get();
  struct Buffer *tmp = buf_pool_get();

  struct HashElemArray hea = get_elem_list(NeoMutt->sub->cs, flags);
  struct HashElem **hep = NULL;
  struct HashElem *he = NULL;
  const struct ConfigDef *cdef = NULL;
  int type;

  // measure the width of the config names
  int width = 0;
  ARRAY_FOREACH(hep, &hea)
  {
    he = *hep;
    if (he->type & D_INTERNAL_DEPRECATED)
      continue;
    type = CONFIG_TYPE(he->type);
    if (type == DT_SYNONYM)
      continue;

    cdef = he->data;
    width = MAX(width, mutt_str_len(cdef->name));
  }

  int len;
  ARRAY_FOREACH(hep, &hea)
  {
    he = *hep;
    if (he->type & D_INTERNAL_DEPRECATED)
      continue;
    type = CONFIG_TYPE(he->type);
    if (type == DT_SYNONYM)
      continue;

    cdef = he->data;

    struct PagedLine *pl = paged_file_new_line(pf);

    // set config =
    paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, "set");
    paged_line_add_text(pl, " ");
    len = paged_line_add_colored_text(pl, MT_COLOR_IDENTIFIER, cdef->name);
    buf_printf(tmp, "%*s", width - len + 1, "");
    paged_line_add_text(pl, buf_string(tmp));
    paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, "=");
    paged_line_add_text(pl, " ");

    buf_reset(value);
    cs_subset_he_string_get(NeoMutt->sub, he, value);

    if (((type == DT_PATH) || IS_MAILBOX(he->type)) && (value->data[0] == '/'))
      mutt_pretty_mailbox(value->data, value->dsize);

    // Quote/escape the values of config options NOT of these types
    if ((type != DT_BOOL) && (type != DT_NUMBER) && (type != DT_LONG) &&
        (type != DT_QUAD) && (type != DT_ENUM) && (type != DT_SORT))
    {
      buf_reset(tmp);
      pretty_var(value->data, tmp);
      buf_strcpy(value, tmp->data);
    }

    int cid;
    if ((type == DT_BOOL) || (type == DT_ENUM) || (type == DT_QUAD) || (type == DT_SORT))
      cid = MT_COLOR_ENUM;
    else if ((type == DT_LONG) || (type == DT_NUMBER))
      cid = MT_COLOR_NUMBER;
    else
      cid = MT_COLOR_STRING;

    paged_line_add_colored_text(pl, cid, buf_string(value));
    paged_line_add_newline(pl);
  }
  ARRAY_FREE(&hea);

  // Apply striping
  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, &pf->lines)
  {
    if ((ARRAY_FOREACH_IDX_pl % 2) == 0)
      pl->cid = MT_COLOR_STRIPE_ODD;
    else
      pl->cid = MT_COLOR_STRIPE_EVEN;
  }

#ifdef USE_DEBUG_SPAGER
  dump_spager(pf);
#endif
  const char *banner = (flags == GEL_ALL_CONFIG) ? "set all" : "set";
  dlg_spager(pf, banner, NeoMutt->sub);

  buf_pool_release(&value);
  buf_pool_release(&tmp);
  paged_file_free(&pf);

  return MUTT_CMD_SUCCESS;
}

/**
 * envlist_sort - Compare two environment strings - Implements ::sort_t - @ingroup sort_api
 */
static int envlist_sort(const void *a, const void *b, void *sdata)
{
  return strcmp(*(const char **) a, *(const char **) b);
}

/**
 * parse_setenv - Parse the 'setenv' and 'unsetenv' commands - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_setenv(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  char **envp = EnvList;

  bool query = false;
  bool prefix = false;
  bool unset = (data == MUTT_SET_UNSET);

  if (!MoreArgs(s))
  {
    if (!StartupComplete)
    {
      buf_printf(err, _("%s: too few arguments"), "setenv");
      return MUTT_CMD_WARNING;
    }

    struct Buffer *tempfile = buf_pool_get();
    buf_mktemp(tempfile);

    FILE *fp_out = mutt_file_fopen(buf_string(tempfile), "w");
    if (!fp_out)
    {
      // L10N: '%s' is the file name of the temporary file
      buf_printf(err, _("Could not create temporary file %s"), buf_string(tempfile));
      buf_pool_release(&tempfile);
      return MUTT_CMD_ERROR;
    }

    int count = 0;
    for (char **env = EnvList; *env; env++)
      count++;

    mutt_qsort_r(EnvList, count, sizeof(char *), envlist_sort, NULL);

    for (char **env = EnvList; *env; env++)
      fprintf(fp_out, "%s\n", *env);

    mutt_file_fclose(&fp_out);

    struct PagerData pdata = { 0 };
    struct PagerView pview = { &pdata };

    pdata.fname = buf_string(tempfile);

    pview.banner = "setenv";
    pview.flags = MUTT_PAGER_NO_FLAGS;
    pview.mode = PAGER_MODE_OTHER;

    mutt_do_pager(&pview, NULL);
    buf_pool_release(&tempfile);

    return MUTT_CMD_SUCCESS;
  }

  if (*s->dptr == '?')
  {
    query = true;
    prefix = true;

    if (unset)
    {
      buf_printf(err, _("Can't query option with the '%s' command"), "unsetenv");
      return MUTT_CMD_WARNING;
    }

    s->dptr++;
  }

  /* get variable name */
  parse_extract_token(buf, s, TOKEN_EQUAL | TOKEN_QUESTION);

  if (*s->dptr == '?')
  {
    if (unset)
    {
      buf_printf(err, _("Can't query option with the '%s' command"), "unsetenv");
      return MUTT_CMD_WARNING;
    }

    if (prefix)
    {
      buf_printf(err, _("Can't use a prefix when querying a variable"));
      return MUTT_CMD_WARNING;
    }

    query = true;
    s->dptr++;
  }

  if (query)
  {
    bool found = false;
    while (envp && *envp)
    {
      /* This will display all matches for "^QUERY" */
      if (mutt_str_startswith(*envp, buf->data))
      {
        if (!found)
        {
          mutt_endwin();
          found = true;
        }
        puts(*envp);
      }
      envp++;
    }

    if (found)
    {
      mutt_any_key_to_continue(NULL);
      return MUTT_CMD_SUCCESS;
    }

    buf_printf(err, _("%s is unset"), buf->data);
    return MUTT_CMD_WARNING;
  }

  if (unset)
  {
    if (!envlist_unset(&EnvList, buf->data))
    {
      buf_printf(err, _("%s is unset"), buf->data);
      return MUTT_CMD_WARNING;
    }
    return MUTT_CMD_SUCCESS;
  }

  /* set variable */

  if (*s->dptr == '=')
  {
    s->dptr++;
    SKIPWS(s->dptr);
  }

  if (!MoreArgs(s))
  {
    buf_printf(err, _("%s: too few arguments"), "setenv");
    return MUTT_CMD_WARNING;
  }

  char *name = mutt_str_dup(buf->data);
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);
  envlist_set(&EnvList, name, buf->data, true);
  FREE(&name);

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_source - Parse the 'source' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_source(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  struct Buffer *path = buf_pool_get();

  do
  {
    if (parse_extract_token(buf, s, TOKEN_BACKTICK_VARS) != 0)
    {
      buf_printf(err, _("source: error at %s"), s->dptr);
      buf_pool_release(&path);
      return MUTT_CMD_ERROR;
    }
    buf_copy(path, buf);
    buf_expand_path(path);

    if (source_rc(buf_string(path), err) < 0)
    {
      buf_printf(err, _("source: file %s could not be sourced"), buf_string(path));
      buf_pool_release(&path);
      return MUTT_CMD_ERROR;
    }

  } while (MoreArgs(s));

  buf_pool_release(&path);

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_nospam - Parse the 'nospam' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_nospam(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  if (!MoreArgs(s))
  {
    buf_printf(err, _("%s: too few arguments"), "nospam");
    return MUTT_CMD_ERROR;
  }

  // Extract the first token, a regex or "*"
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);

  if (MoreArgs(s))
  {
    buf_printf(err, _("%s: too many arguments"), "finish");
    return MUTT_CMD_ERROR;
  }

  // "*" is special - clear both spam and nospam lists
  if (mutt_str_equal(buf_string(buf), "*"))
  {
    mutt_replacelist_free(&SpamList);
    mutt_regexlist_free(&NoSpamList);
    return MUTT_CMD_SUCCESS;
  }

  // If it's on the spam list, just remove it
  if (mutt_replacelist_remove(&SpamList, buf_string(buf)) != 0)
    return MUTT_CMD_SUCCESS;

  // Otherwise, add it to the nospam list
  if (mutt_regexlist_add(&NoSpamList, buf_string(buf), REG_ICASE, err) != 0)
    return MUTT_CMD_ERROR;

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_spam - Parse the 'spam' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_spam(struct Buffer *buf, struct Buffer *s,
                                     intptr_t data, struct Buffer *err)
{
  if (!MoreArgs(s))
  {
    buf_printf(err, _("%s: too few arguments"), "spam");
    return MUTT_CMD_ERROR;
  }

  // Extract the first token, a regex
  parse_extract_token(buf, s, TOKEN_NO_FLAGS);

  // If there's a second parameter, it's a template for the spam tag
  if (MoreArgs(s))
  {
    struct Buffer *templ = buf_pool_get();
    parse_extract_token(templ, s, TOKEN_NO_FLAGS);

    // Add to the spam list
    int rc = mutt_replacelist_add(&SpamList, buf_string(buf), buf_string(templ), err);
    buf_pool_release(&templ);
    if (rc != 0)
      return MUTT_CMD_ERROR;
  }
  else
  {
    // If not, try to remove from the nospam list
    mutt_regexlist_remove(&NoSpamList, buf_string(buf));
  }

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_stailq - Parse a list command - Implements Command::parse() - @ingroup command_parse
 *
 * This is used by 'alternative_order', 'auto_view' and several others.
 */
static enum CommandResult parse_stailq(struct Buffer *buf, struct Buffer *s,
                                       intptr_t data, struct Buffer *err)
{
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    add_to_stailq((struct ListHead *) data, buf->data);
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_subscribe - Parse the 'subscribe' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_subscribe(struct Buffer *buf, struct Buffer *s,
                                          intptr_t data, struct Buffer *err)
{
  struct GroupList gl = STAILQ_HEAD_INITIALIZER(gl);

  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    if (parse_grouplist(&gl, buf, s, err) == -1)
      goto bail;

    mutt_regexlist_remove(&UnMailLists, buf->data);
    mutt_regexlist_remove(&UnSubscribedLists, buf->data);

    if (mutt_regexlist_add(&MailLists, buf->data, REG_ICASE, err) != 0)
      goto bail;
    if (mutt_regexlist_add(&SubscribedLists, buf->data, REG_ICASE, err) != 0)
      goto bail;
    if (mutt_grouplist_add_regex(&gl, buf->data, REG_ICASE, err) != 0)
      goto bail;
  } while (MoreArgs(s));

  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_SUCCESS;

bail:
  mutt_grouplist_destroy(&gl);
  return MUTT_CMD_ERROR;
}

/**
 * parse_subscribe_to - Parse the 'subscribe-to' command - Implements Command::parse() - @ingroup command_parse
 *
 * The 'subscribe-to' command allows to subscribe to an IMAP-Mailbox.
 * Patterns are not supported.
 * Use it as follows: subscribe-to =folder
 */
enum CommandResult parse_subscribe_to(struct Buffer *buf, struct Buffer *s,
                                      intptr_t data, struct Buffer *err)
{
  if (!buf || !s || !err)
    return MUTT_CMD_ERROR;

  buf_reset(err);

  if (MoreArgs(s))
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    if (MoreArgs(s))
    {
      buf_printf(err, _("%s: too many arguments"), "subscribe-to");
      return MUTT_CMD_WARNING;
    }

    if (!buf_is_empty(buf))
    {
      /* Expand and subscribe */
      buf_expand_path(buf);
      if (imap_subscribe(buf_string(buf), true) == 0)
      {
        mutt_message(_("Subscribed to %s"), buf->data);
        return MUTT_CMD_SUCCESS;
      }

      buf_printf(err, _("Could not subscribe to %s"), buf->data);
      return MUTT_CMD_ERROR;
    }

    mutt_debug(LL_DEBUG1, "Corrupted buffer\n");
    return MUTT_CMD_ERROR;
  }

  buf_addstr(err, _("No folder specified"));
  return MUTT_CMD_WARNING;
}

/**
 * parse_tag_formats - Parse the 'tag-formats' command - Implements Command::parse() - @ingroup command_parse
 *
 * Parse config like: `tag-formats pgp GP`
 *
 * @note This maps format -> tag
 */
static enum CommandResult parse_tag_formats(struct Buffer *buf, struct Buffer *s,
                                            intptr_t data, struct Buffer *err)
{
  if (!s)
    return MUTT_CMD_ERROR;

  struct Buffer *tagbuf = buf_pool_get();
  struct Buffer *fmtbuf = buf_pool_get();

  while (MoreArgs(s))
  {
    parse_extract_token(tagbuf, s, TOKEN_NO_FLAGS);
    const char *tag = buf_string(tagbuf);
    if (*tag == '\0')
      continue;

    parse_extract_token(fmtbuf, s, TOKEN_NO_FLAGS);
    const char *fmt = buf_string(fmtbuf);

    /* avoid duplicates */
    const char *tmp = mutt_hash_find(TagFormats, fmt);
    if (tmp)
    {
      mutt_warning(_("tag format '%s' already registered as '%s'"), fmt, tmp);
      continue;
    }

    mutt_hash_insert(TagFormats, fmt, mutt_str_dup(tag));
  }

  buf_pool_release(&tagbuf);
  buf_pool_release(&fmtbuf);
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_tag_transforms - Parse the 'tag-transforms' command - Implements Command::parse() - @ingroup command_parse
 *
 * Parse config like: `tag-transforms pgp P`
 *
 * @note This maps tag -> transform
 */
static enum CommandResult parse_tag_transforms(struct Buffer *buf, struct Buffer *s,
                                               intptr_t data, struct Buffer *err)
{
  if (!s)
    return MUTT_CMD_ERROR;

  struct Buffer *tagbuf = buf_pool_get();
  struct Buffer *trnbuf = buf_pool_get();

  while (MoreArgs(s))
  {
    parse_extract_token(tagbuf, s, TOKEN_NO_FLAGS);
    const char *tag = buf_string(tagbuf);
    if (*tag == '\0')
      continue;

    parse_extract_token(trnbuf, s, TOKEN_NO_FLAGS);
    const char *trn = buf_string(trnbuf);

    /* avoid duplicates */
    const char *tmp = mutt_hash_find(TagTransforms, tag);
    if (tmp)
    {
      mutt_warning(_("tag transform '%s' already registered as '%s'"), tag, tmp);
      continue;
    }

    mutt_hash_insert(TagTransforms, tag, mutt_str_dup(trn));
  }

  buf_pool_release(&tagbuf);
  buf_pool_release(&trnbuf);
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unignore - Parse the 'unignore' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_unignore(struct Buffer *buf, struct Buffer *s,
                                         intptr_t data, struct Buffer *err)
{
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    /* don't add "*" to the unignore list */
    if (!mutt_str_equal(buf->data, "*"))
      add_to_stailq(&UnIgnore, buf->data);

    remove_from_stailq(&Ignore, buf->data);
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unlists - Parse the 'unlists' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_unlists(struct Buffer *buf, struct Buffer *s,
                                        intptr_t data, struct Buffer *err)
{
  mutt_hash_free(&AutoSubscribeCache);
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    mutt_regexlist_remove(&SubscribedLists, buf->data);
    mutt_regexlist_remove(&MailLists, buf->data);

    if (!mutt_str_equal(buf->data, "*") &&
        (mutt_regexlist_add(&UnMailLists, buf->data, REG_ICASE, err) != 0))
    {
      return MUTT_CMD_ERROR;
    }
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * do_unmailboxes - Remove a Mailbox from the Sidebar/notifications
 * @param m Mailbox to `unmailboxes`
 */
static void do_unmailboxes(struct Mailbox *m)
{
#ifdef USE_INOTIFY
  if (m->poll_new_mail)
    mutt_monitor_remove(m);
#endif
  m->visible = false;
  m->gen = -1;
  if (m->opened)
  {
    struct EventMailbox ev_m = { NULL };
    mutt_debug(LL_NOTIFY, "NT_MAILBOX_CHANGE: NULL\n");
    notify_send(NeoMutt->notify, NT_MAILBOX, NT_MAILBOX_CHANGE, &ev_m);
  }
  else
  {
    account_mailbox_remove(m->account, m);
    mailbox_free(&m);
  }
}

/**
 * do_unmailboxes_star - Remove all Mailboxes from the Sidebar/notifications
 */
static void do_unmailboxes_star(void)
{
  struct MailboxList ml = STAILQ_HEAD_INITIALIZER(ml);
  neomutt_mailboxlist_get_all(&ml, NeoMutt, MUTT_MAILBOX_ANY);
  struct MailboxNode *np = NULL;
  struct MailboxNode *nptmp = NULL;
  STAILQ_FOREACH_SAFE(np, &ml, entries, nptmp)
  {
    do_unmailboxes(np->mailbox);
  }
  neomutt_mailboxlist_clear(&ml);
}

/**
 * parse_unmailboxes - Parse the 'unmailboxes' command - Implements Command::parse() - @ingroup command_parse
 *
 * This is also used by 'unvirtual-mailboxes'
 */
enum CommandResult parse_unmailboxes(struct Buffer *buf, struct Buffer *s,
                                     intptr_t data, struct Buffer *err)
{
  while (MoreArgs(s))
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    if (mutt_str_equal(buf->data, "*"))
    {
      do_unmailboxes_star();
      return MUTT_CMD_SUCCESS;
    }

    buf_expand_path(buf);

    struct Account *a = NULL;
    TAILQ_FOREACH(a, &NeoMutt->accounts, entries)
    {
      struct Mailbox *m = mx_mbox_find(a, buf_string(buf));
      if (m)
      {
        do_unmailboxes(m);
        break;
      }
    }
  }
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unmy_hdr - Parse the 'unmy_hdr' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_unmy_hdr(struct Buffer *buf, struct Buffer *s,
                                         intptr_t data, struct Buffer *err)
{
  struct ListNode *np = NULL, *tmp = NULL;
  size_t l;

  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    if (mutt_str_equal("*", buf->data))
    {
      /* Clear all headers, send a notification for each header */
      STAILQ_FOREACH(np, &UserHeader, entries)
      {
        mutt_debug(LL_NOTIFY, "NT_HEADER_DELETE: %s\n", np->data);
        struct EventHeader ev_h = { np->data };
        notify_send(NeoMutt->notify, NT_HEADER, NT_HEADER_DELETE, &ev_h);
      }
      mutt_list_free(&UserHeader);
      continue;
    }

    l = mutt_str_len(buf->data);
    if (buf->data[l - 1] == ':')
      l--;

    STAILQ_FOREACH_SAFE(np, &UserHeader, entries, tmp)
    {
      if (mutt_istrn_equal(buf->data, np->data, l) && (np->data[l] == ':'))
      {
        mutt_debug(LL_NOTIFY, "NT_HEADER_DELETE: %s\n", np->data);
        struct EventHeader ev_h = { np->data };
        notify_send(NeoMutt->notify, NT_HEADER, NT_HEADER_DELETE, &ev_h);

        header_free(&UserHeader, np);
      }
    }
  } while (MoreArgs(s));
  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unstailq - Parse an unlist command - Implements Command::parse() - @ingroup command_parse
 *
 * This is used by 'unalternative_order', 'unauto_view' and several others.
 */
static enum CommandResult parse_unstailq(struct Buffer *buf, struct Buffer *s,
                                         intptr_t data, struct Buffer *err)
{
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    /* Check for deletion of entire list */
    if (mutt_str_equal(buf->data, "*"))
    {
      mutt_list_free((struct ListHead *) data);
      break;
    }
    remove_from_stailq((struct ListHead *) data, buf->data);
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unsubscribe - Parse the 'unsubscribe' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_unsubscribe(struct Buffer *buf, struct Buffer *s,
                                            intptr_t data, struct Buffer *err)
{
  mutt_hash_free(&AutoSubscribeCache);
  do
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);
    mutt_regexlist_remove(&SubscribedLists, buf->data);

    if (!mutt_str_equal(buf->data, "*") &&
        (mutt_regexlist_add(&UnSubscribedLists, buf->data, REG_ICASE, err) != 0))
    {
      return MUTT_CMD_ERROR;
    }
  } while (MoreArgs(s));

  return MUTT_CMD_SUCCESS;
}

/**
 * parse_unsubscribe_from - Parse the 'unsubscribe-from' command - Implements Command::parse() - @ingroup command_parse
 *
 * The 'unsubscribe-from' command allows to unsubscribe from an IMAP-Mailbox.
 * Patterns are not supported.
 * Use it as follows: unsubscribe-from =folder
 */
enum CommandResult parse_unsubscribe_from(struct Buffer *buf, struct Buffer *s,
                                          intptr_t data, struct Buffer *err)
{
  if (!buf || !s || !err)
    return MUTT_CMD_ERROR;

  if (MoreArgs(s))
  {
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

    if (MoreArgs(s))
    {
      buf_printf(err, _("%s: too many arguments"), "unsubscribe-from");
      return MUTT_CMD_WARNING;
    }

    if (buf->data && (*buf->data != '\0'))
    {
      /* Expand and subscribe */
      buf_expand_path(buf);
      if (imap_subscribe(buf_string(buf), false) == 0)
      {
        mutt_message(_("Unsubscribed from %s"), buf->data);
        return MUTT_CMD_SUCCESS;
      }

      buf_printf(err, _("Could not unsubscribe from %s"), buf->data);
      return MUTT_CMD_ERROR;
    }

    mutt_debug(LL_DEBUG1, "Corrupted buffer\n");
    return MUTT_CMD_ERROR;
  }

  buf_addstr(err, _("No folder specified"));
  return MUTT_CMD_WARNING;
}

/**
 * parse_version - Parse the 'version' command - Implements Command::parse() - @ingroup command_parse
 */
static enum CommandResult parse_version(struct Buffer *buf, struct Buffer *s,
                                        intptr_t data, struct Buffer *err)
{
  // silently ignore 'version' if it's in a config file
  if (!StartupComplete)
    return MUTT_CMD_SUCCESS;

  struct PagedFile *pf = paged_file_new(NULL);
  print_version(pf, 0);
  dlg_spager(pf, "version", NeoMutt->sub);
  paged_file_free(&pf);

  return MUTT_CMD_SUCCESS;
}

/**
 * source_stack_cleanup - Free memory from the stack used for the source command
 */
void source_stack_cleanup(void)
{
  mutt_list_free(&MuttrcStack);
}

/**
 * MuttCommands - General NeoMutt Commands
 */
static const struct Command MuttCommands[] = {
  // clang-format off
  { "alias",               parse_alias,            0 },
  { "alternates",          parse_alternates,       0 },
  { "alternative_order",   parse_stailq,           IP &AlternativeOrderList },
  { "attachments",         parse_attachments,      0 },
  { "auto_view",           parse_stailq,           IP &AutoViewList },
  { "bind",                parse_bind,             0 },
  { "cd",                  parse_cd,               0 },
  { "color",               parse_color,            0 },
  { "echo",                parse_echo,             0 },
  { "exec",                parse_exec,             0 },
  { "finish",              parse_finish,           0 },
  { "group",               parse_group,            MUTT_GROUP },
  { "hdr_order",           parse_stailq,           IP &HeaderOrderList },
  { "ifdef",               parse_ifdef,            0 },
  { "ifndef",              parse_ifdef,            1 },
  { "ignore",              parse_ignore,           0 },
  { "lists",               parse_lists,            0 },
  { "macro",               parse_macro,            1 },
  { "mailboxes",           parse_mailboxes,        0 },
  { "mailto_allow",        parse_stailq,           IP &MailToAllow },
  { "mime_lookup",         parse_stailq,           IP &MimeLookupList },
  { "mono",                parse_mono,             0 },
  { "my_hdr",              parse_my_hdr,           0 },
  { "named-mailboxes",     parse_mailboxes,        MUTT_NAMED },
  { "nospam",              parse_nospam,           0 },
  { "push",                parse_push,             0 },
  { "reset",               parse_set,              MUTT_SET_RESET },
  { "score",               parse_score,            0 },
  { "set",                 parse_set,              MUTT_SET_SET },
  { "setenv",              parse_setenv,           MUTT_SET_SET },
  { "source",              parse_source,           0 },
  { "spam",                parse_spam,             0 },
  { "subjectrx",           parse_subjectrx_list,   0 },
  { "subscribe",           parse_subscribe,        0 },
  { "tag-formats",         parse_tag_formats,      0 },
  { "tag-transforms",      parse_tag_transforms,   0 },
  { "toggle",              parse_set,              MUTT_SET_INV },
  { "unalias",             parse_unalias,          0 },
  { "unalternates",        parse_unalternates,     0 },
  { "unalternative_order", parse_unstailq,         IP &AlternativeOrderList },
  { "unattachments",       parse_unattachments,    0 },
  { "unauto_view",         parse_unstailq,         IP &AutoViewList },
  { "unbind",              parse_unbind,           MUTT_UNBIND },
  { "uncolor",             parse_uncolor,          0 },
  { "ungroup",             parse_group,            MUTT_UNGROUP },
  { "unhdr_order",         parse_unstailq,         IP &HeaderOrderList },
  { "unignore",            parse_unignore,         0 },
  { "unlists",             parse_unlists,          0 },
  { "unmacro",             parse_unbind,           MUTT_UNMACRO },
  { "unmailboxes",         parse_unmailboxes,      0 },
  { "unmailto_allow",      parse_unstailq,         IP &MailToAllow },
  { "unmime_lookup",       parse_unstailq,         IP &MimeLookupList },
  { "unmono",              parse_unmono,           0 },
  { "unmy_hdr",            parse_unmy_hdr,         0 },
  { "unscore",             parse_unscore,          0 },
  { "unset",               parse_set,              MUTT_SET_UNSET },
  { "unsetenv",            parse_setenv,           MUTT_SET_UNSET },
  { "unsubjectrx",         parse_unsubjectrx_list, 0 },
  { "unsubscribe",         parse_unsubscribe,      0 },
  { "version",             parse_version,          0 },
  // clang-format on
};

/**
 * commands_init - Initialize commands array and register default commands
 */
void commands_init(void)
{
  commands_register(MuttCommands, mutt_array_size(MuttCommands));
}
