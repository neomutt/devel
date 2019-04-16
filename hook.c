/**
 * @file
 * Parse and execute user-defined hooks
 *
 * @authors
 * Copyright (C) 1996-2002,2004,2007 Michael R. Elkins <me@mutt.org>, and others
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
 * @page hook Parse and execute user-defined hooks
 *
 * Parse and execute user-defined hooks
 */

#include "config.h"
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mutt/mutt.h"
#include "email/lib.h"
#include "mutt.h"
#include "hook.h"
#include "address/lib.h"
#include "alias.h"
#include "context.h"
#include "globals.h"
#include "hdrline.h"
#include "mutt_attach.h"
#include "mutt_commands.h"
#include "muttlib.h"
#include "mx.h"
#include "ncrypt/ncrypt.h"
#include "pattern.h"
#ifdef USE_COMPRESSED
#include "compress.h"
#endif

struct Context;

/* These Config Variables are only used in hook.c */
char *C_DefaultHook; ///< Config: Pattern to use for hooks that only have a simple regex
bool C_ForceName; ///< Config: Save outgoing mail in a folder of their name
bool C_SaveName; ///< Config: Save outgoing message to mailbox of recipient's name if it exists

/**
 * struct Hook - A list of user hooks
 */
struct Hook
{
  HookFlags type;              ///< Hook type
  struct Regex regex;          ///< Regular expression
  char *command;               ///< Filename, command or pattern to execute
  struct PatternHead *pattern; ///< Used for fcc,save,send-hook
  TAILQ_ENTRY(Hook) entries;
};
static TAILQ_HEAD(, Hook) Hooks = TAILQ_HEAD_INITIALIZER(Hooks);

static HookFlags current_hook_type = MUTT_HOOK_NO_FLAGS;

/**
 * mutt_parse_hook - Parse the 'hook' family of commands - Implements ::command_t
 *
 * This is used by 'account-hook', 'append-hook' and many more.
 */
enum CommandResult mutt_parse_hook(struct Buffer *buf, struct Buffer *s,
                                   unsigned long data, struct Buffer *err)
{
  struct Hook *ptr = NULL;
  struct Buffer cmd, pattern;
  int rc;
  bool not = false, warning = false;
  regex_t *rx = NULL;
  struct PatternHead *pat = NULL;
  char path[PATH_MAX];

  mutt_buffer_init(&pattern);
  mutt_buffer_init(&cmd);

  if (~data & MUTT_GLOBAL_HOOK) /* NOT a global hook */
  {
    if (*s->dptr == '!')
    {
      s->dptr++;
      SKIPWS(s->dptr);
      not = true;
    }

    mutt_extract_token(&pattern, s, MUTT_TOKEN_NO_FLAGS);

    if (!MoreArgs(s))
    {
      mutt_buffer_printf(err, _("%s: too few arguments"), buf->data);
      goto warn;
    }
  }

  mutt_extract_token(&cmd, s,
                     (data & (MUTT_FOLDER_HOOK | MUTT_SEND_HOOK | MUTT_SEND2_HOOK |
                              MUTT_ACCOUNT_HOOK | MUTT_REPLY_HOOK)) ?
                         MUTT_TOKEN_SPACE :
                         MUTT_TOKEN_NO_FLAGS);

  if (!cmd.data)
  {
    mutt_buffer_printf(err, _("%s: too few arguments"), buf->data);
    goto warn;
  }

  if (MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too many arguments"), buf->data);
    goto warn;
  }

  if (data & (MUTT_FOLDER_HOOK | MUTT_MBOX_HOOK))
  {
    /* Accidentally using the ^ mailbox shortcut in the .neomuttrc is a
     * common mistake */
    if ((*pattern.data == '^') && (!CurrentFolder))
    {
      mutt_buffer_strcpy(err, _("current mailbox shortcut '^' is unset"));
      goto error;
    }

    mutt_str_strfcpy(path, pattern.data, sizeof(path));
    mutt_expand_path_regex(path, sizeof(path), true);

    /* Check for other mailbox shortcuts that expand to the empty string.
     * This is likely a mistake too */
    if (!*path && *pattern.data)
    {
      mutt_buffer_strcpy(err, _("mailbox shortcut expanded to empty regex"));
      goto error;
    }

    FREE(&pattern.data);
    mutt_buffer_init(&pattern);
    pattern.data = mutt_str_strdup(path);
  }
#ifdef USE_COMPRESSED
  else if (data & (MUTT_APPEND_HOOK | MUTT_OPEN_HOOK | MUTT_CLOSE_HOOK))
  {
    if (mutt_comp_valid_command(cmd.data) == 0)
    {
      mutt_buffer_strcpy(err, _("badly formatted cmd string"));
      return MUTT_CMD_ERROR;
    }
  }
#endif
  else if (C_DefaultHook && (~data & MUTT_GLOBAL_HOOK) &&
           !(data & (MUTT_CHARSET_HOOK | MUTT_ICONV_HOOK | MUTT_ACCOUNT_HOOK)) &&
           (!WithCrypto || !(data & MUTT_CRYPT_HOOK)))
  {
    char tmp[8192];

    /* At this stage remain only message-hooks, reply-hooks, send-hooks,
     * send2-hooks, save-hooks, and fcc-hooks: All those allowing full
     * patterns. If given a simple regex, we expand $default_hook.  */
    mutt_str_strfcpy(tmp, pattern.data, sizeof(tmp));
    mutt_check_simple(tmp, sizeof(tmp), C_DefaultHook);
    FREE(&pattern.data);
    mutt_buffer_init(&pattern);
    pattern.data = mutt_str_strdup(tmp);
  }

  if (data & (MUTT_MBOX_HOOK | MUTT_SAVE_HOOK | MUTT_FCC_HOOK))
  {
    mutt_str_strfcpy(path, cmd.data, sizeof(path));
    mutt_expand_path(path, sizeof(path));
    FREE(&cmd.data);
    mutt_buffer_init(&cmd);
    cmd.data = mutt_str_strdup(path);
  }

  /* check to make sure that a matching hook doesn't already exist */
  TAILQ_FOREACH(ptr, &Hooks, entries)
  {
    if (data & MUTT_GLOBAL_HOOK)
    {
      /* Ignore duplicate global hooks */
      if (mutt_str_strcmp(ptr->command, cmd.data) == 0)
      {
        FREE(&cmd.data);
        return MUTT_CMD_SUCCESS;
      }
    }
    else if ((ptr->type == data) && (ptr->regex.not == not) &&
             (mutt_str_strcmp(pattern.data, ptr->regex.pattern) == 0))
    {
      if (data & (MUTT_FOLDER_HOOK | MUTT_SEND_HOOK | MUTT_SEND2_HOOK | MUTT_MESSAGE_HOOK |
                  MUTT_ACCOUNT_HOOK | MUTT_REPLY_HOOK | MUTT_CRYPT_HOOK |
                  MUTT_TIMEOUT_HOOK | MUTT_STARTUP_HOOK | MUTT_SHUTDOWN_HOOK))
      {
        /* these hooks allow multiple commands with the same
         * pattern, so if we've already seen this pattern/cmd pair, just
         * ignore it instead of creating a duplicate */
        if (mutt_str_strcmp(ptr->command, cmd.data) == 0)
        {
          FREE(&cmd.data);
          FREE(&pattern.data);
          return MUTT_CMD_SUCCESS;
        }
      }
      else
      {
        /* other hooks only allow one cmd per pattern, so update the
         * entry with the new cmd.  this currently does not change the
         * order of execution of the hooks, which i think is desirable since
         * a common action to perform is to change the default (.) entry
         * based upon some other information. */
        FREE(&ptr->command);
        ptr->command = cmd.data;
        FREE(&pattern.data);
        return MUTT_CMD_SUCCESS;
      }
    }
  }

  if (data & (MUTT_CHARSET_HOOK | MUTT_ICONV_HOOK))
  {
    /* These are managed separately by the charset code */
    enum LookupType type = (data & MUTT_CHARSET_HOOK) ? MUTT_LOOKUP_CHARSET : MUTT_LOOKUP_ICONV;
    if (!mutt_ch_lookup_add(type, pattern.data, cmd.data, err))
      goto error;
    FREE(&pattern.data);
    FREE(&cmd.data);
    return MUTT_CMD_SUCCESS;
  }
  else if (data & (MUTT_SEND_HOOK | MUTT_SEND2_HOOK | MUTT_SAVE_HOOK |
                   MUTT_FCC_HOOK | MUTT_MESSAGE_HOOK | MUTT_REPLY_HOOK))
  {
    pat = mutt_pattern_comp(
        pattern.data,
        (data & (MUTT_SEND_HOOK | MUTT_SEND2_HOOK | MUTT_FCC_HOOK)) ? 0 : MUTT_FULL_MSG, err);
    if (!pat)
      goto error;
  }
  else if (~data & MUTT_GLOBAL_HOOK) /* NOT a global hook */
  {
    /* Hooks not allowing full patterns: Check syntax of regex */
    rx = mutt_mem_malloc(sizeof(regex_t));
    rc = REG_COMP(rx, NONULL(pattern.data), ((data & MUTT_CRYPT_HOOK) ? REG_ICASE : 0));
    if (rc != 0)
    {
      regerror(rc, rx, err->data, err->dsize);
      FREE(&rx);
      goto error;
    }
  }

  ptr = mutt_mem_calloc(1, sizeof(struct Hook));
  ptr->type = data;
  ptr->command = cmd.data;
  ptr->pattern = pat;
  ptr->regex.pattern = pattern.data;
  ptr->regex.regex = rx;
  ptr->regex.not = not;
  TAILQ_INSERT_TAIL(&Hooks, ptr, entries);
  return MUTT_CMD_SUCCESS;

warn:
  warning = true;
error:
  if (~data & MUTT_GLOBAL_HOOK) /* NOT a global hook */
    FREE(&pattern.data);
  FREE(&cmd.data);
  return (warning ? MUTT_CMD_WARNING : MUTT_CMD_ERROR);
}

/**
 * delete_hook - Delete a Hook
 * @param h Hook to delete
 */
static void delete_hook(struct Hook *h)
{
  FREE(&h->command);
  FREE(&h->regex.pattern);
  if (h->regex.regex)
  {
    regfree(h->regex.regex);
    FREE(&h->regex.regex);
  }
  mutt_pattern_free(&h->pattern);
  FREE(&h);
}

/**
 * mutt_delete_hooks - Delete matching hooks
 * @param type Hook type to delete, see #HookFlags
 *
 * If 0 is passed, all the hooks will be deleted.
 */
void mutt_delete_hooks(HookFlags type)
{
  struct Hook *h = NULL;
  struct Hook *tmp = NULL;

  TAILQ_FOREACH_SAFE(h, &Hooks, entries, tmp)
  {
    if ((type == 0) || (type == h->type))
    {
      TAILQ_REMOVE(&Hooks, h, entries);
      delete_hook(h);
    }
  }
}

/**
 * mutt_parse_unhook - Parse the 'unhook' command - Implements ::command_t
 */
enum CommandResult mutt_parse_unhook(struct Buffer *buf, struct Buffer *s,
                                     unsigned long data, struct Buffer *err)
{
  while (MoreArgs(s))
  {
    mutt_extract_token(buf, s, MUTT_TOKEN_NO_FLAGS);
    if (mutt_str_strcmp("*", buf->data) == 0)
    {
      if (current_hook_type)
      {
        mutt_buffer_printf(err, "%s", _("unhook: Can't do unhook * from within a hook"));
        return MUTT_CMD_WARNING;
      }
      mutt_delete_hooks(MUTT_HOOK_NO_FLAGS);
      mutt_ch_lookup_remove();
    }
    else
    {
      int type = mutt_get_hook_type(buf->data);

      if (!type)
      {
        mutt_buffer_printf(err, _("unhook: unknown hook type: %s"), buf->data);
        return MUTT_CMD_ERROR;
      }
      if (type & (MUTT_CHARSET_HOOK | MUTT_ICONV_HOOK))
      {
        mutt_ch_lookup_remove();
        return MUTT_CMD_SUCCESS;
      }
      if (current_hook_type == type)
      {
        mutt_buffer_printf(err, _("unhook: Can't delete a %s from within a %s"),
                           buf->data, buf->data);
        return MUTT_CMD_WARNING;
      }
      mutt_delete_hooks(type);
    }
  }
  return MUTT_CMD_SUCCESS;
}

/**
 * mutt_folder_hook - Perform a folder hook
 * @param path Path to potentially match
 * @param desc Description to potentially match
 */
void mutt_folder_hook(const char *path, const char *desc)
{
  if (!path && !desc)
    return;

  struct Hook *tmp = NULL;
  struct Buffer *err = mutt_buffer_pool_get();
  struct Buffer *token = mutt_buffer_pool_get();

  current_hook_type = MUTT_FOLDER_HOOK;

  TAILQ_FOREACH(tmp, &Hooks, entries)
  {
    if (!tmp->command)
      continue;

    if (!(tmp->type & MUTT_FOLDER_HOOK))
      continue;

    if ((path && (regexec(tmp->regex.regex, path, 0, NULL, 0) == 0) ^ tmp->regex.not) ||
        (desc && (regexec(tmp->regex.regex, desc, 0, NULL, 0) == 0) ^ tmp->regex.not))
    {
      if (mutt_parse_rc_line(tmp->command, token, err) == MUTT_CMD_ERROR)
      {
        mutt_error("%s", mutt_b2s(err));
        break;
      }
    }
  }
  mutt_buffer_pool_release(&token);
  mutt_buffer_pool_release(&err);

  current_hook_type = 0;
}

/**
 * mutt_find_hook - Find a matching hook
 * @param type Hook type, see #HookFlags
 * @param pat  Pattern to match
 * @retval ptr Command string
 *
 * @note The returned string must not be freed.
 */
char *mutt_find_hook(HookFlags type, const char *pat)
{
  struct Hook *tmp = NULL;

  TAILQ_FOREACH(tmp, &Hooks, entries)
  {
    if (tmp->type & type)
    {
      if (regexec(tmp->regex.regex, pat, 0, NULL, 0) == 0)
        return tmp->command;
    }
  }
  return NULL;
}

/**
 * mutt_message_hook - Perform a message hook
 * @param m   Mailbox Context
 * @param e   Email
 * @param type Hook type, see #HookFlags
 */
void mutt_message_hook(struct Mailbox *m, struct Email *e, HookFlags type)
{
  struct Hook *hook = NULL;
  struct PatternCache cache = { 0 };
  struct Buffer *err = mutt_buffer_pool_get();
  struct Buffer *token = mutt_buffer_pool_get();

  current_hook_type = type;

  TAILQ_FOREACH(hook, &Hooks, entries)
  {
    if (!hook->command)
      continue;

    if (hook->type & type)
    {
      if ((mutt_pattern_exec(SLIST_FIRST(hook->pattern), 0, m, e, &cache) > 0) ^
          hook->regex.not)
      {
        if (mutt_parse_rc_line(hook->command, token, err) == MUTT_CMD_ERROR)
        {
          mutt_buffer_pool_release(&token);
          mutt_error("%s", mutt_b2s(err));
          current_hook_type = 0;
          mutt_buffer_pool_release(&err);

          return;
        }
        /* Executing arbitrary commands could affect the pattern results,
         * so the cache has to be wiped */
        memset(&cache, 0, sizeof(cache));
      }
    }
  }
  mutt_buffer_pool_release(&token);
  mutt_buffer_pool_release(&err);

  current_hook_type = 0;
}

/**
 * addr_hook - Perform an address hook (get a path)
 * @param path    Buffer for path
 * @param pathlen Length of buffer
 * @param type    Hook type, see #HookFlags
 * @param ctx     Mailbox Context
 * @param e       Email
 * @retval  0 Success
 * @retval -1 Failure
 */
static int addr_hook(char *path, size_t pathlen, HookFlags type,
                     struct Context *ctx, struct Email *e)
{
  struct Hook *hook = NULL;
  struct PatternCache cache = { 0 };

  /* determine if a matching hook exists */
  TAILQ_FOREACH(hook, &Hooks, entries)
  {
    if (!hook->command)
      continue;

    if (hook->type & type)
    {
      struct Mailbox *m = ctx ? ctx->mailbox : NULL;
      if ((mutt_pattern_exec(SLIST_FIRST(hook->pattern), 0, m, e, &cache) > 0) ^
          hook->regex.not)
      {
        mutt_make_string_flags(path, pathlen, hook->command, ctx, m, e, MUTT_FORMAT_PLAIN);
        return 0;
      }
    }
  }

  return -1;
}

/**
 * mutt_default_save - Find the default save path for an email
 * @param path    Buffer for the path
 * @param pathlen Length of buffer
 * @param e       Email
 */
void mutt_default_save(char *path, size_t pathlen, struct Email *e)
{
  *path = '\0';
  if (addr_hook(path, pathlen, MUTT_SAVE_HOOK, Context, e) == 0)
    return;

  struct Address *addr = NULL;
  struct Envelope *env = e->env;
  bool from_me = mutt_addr_is_user(env->from);

  if (!from_me && env->reply_to && env->reply_to->mailbox)
    addr = env->reply_to;
  else if (!from_me && env->from && env->from->mailbox)
    addr = env->from;
  else if (env->to && env->to->mailbox)
    addr = env->to;
  else if (env->cc && env->cc->mailbox)
    addr = env->cc;
  else
    addr = NULL;
  if (addr)
  {
    char tmp[PATH_MAX];
    mutt_safe_path(tmp, sizeof(tmp), addr);
    snprintf(path, pathlen, "=%s", tmp);
  }
}

/**
 * mutt_select_fcc - Select the FCC path for an email
 * @param path    Buffer for the path
 * @param pathlen Length of the buffer
 * @param e       Email
 */
void mutt_select_fcc(char *path, size_t pathlen, struct Email *e)
{
  if (addr_hook(path, pathlen, MUTT_FCC_HOOK, NULL, e) != 0)
  {
    struct Envelope *env = e->env;
    if ((C_SaveName || C_ForceName) && (env->to || env->cc || env->bcc))
    {
      struct Address *addr = env->to ? env->to : (env->cc ? env->cc : env->bcc);
      char buf[PATH_MAX];
      mutt_safe_path(buf, sizeof(buf), addr);
      mutt_path_concat(path, NONULL(C_Folder), buf, pathlen);
      if (!C_ForceName && (mx_access(path, W_OK) != 0))
        mutt_str_strfcpy(path, C_Record, pathlen);
    }
    else
      mutt_str_strfcpy(path, C_Record, pathlen);
  }
  mutt_pretty_mailbox(path, pathlen);
}

/**
 * list_hook - Find hook strings matching
 * @param[out] matches List of hook strings
 * @param[in]  match   String to match
 * @param[in]  hook    Hook type, see #HookFlags
 */
static void list_hook(struct ListHead *matches, const char *match, HookFlags hook)
{
  struct Hook *tmp = NULL;

  TAILQ_FOREACH(tmp, &Hooks, entries)
  {
    if ((tmp->type & hook) &&
        ((match && (regexec(tmp->regex.regex, match, 0, NULL, 0) == 0)) ^
         tmp->regex.not))
    {
      mutt_list_insert_tail(matches, mutt_str_strdup(tmp->command));
    }
  }
}

/**
 * mutt_crypt_hook - Find crypto hooks for an Address
 * @param[out] list List of keys
 * @param[in]  addr Address to match
 *
 * The crypt-hook associates keys with addresses.
 */
void mutt_crypt_hook(struct ListHead *list, struct Address *addr)
{
  list_hook(list, addr->mailbox, MUTT_CRYPT_HOOK);
}

#ifdef USE_SOCKET
/**
 * mutt_account_hook - Perform an account hook
 * @param url Account URL to match
 */
void mutt_account_hook(const char *url)
{
  /* parsing commands with URLs in an account hook can cause a recursive
   * call. We just skip processing if this occurs. Typically such commands
   * belong in a folder-hook -- perhaps we should warn the user. */
  static bool inhook = false;

  struct Hook *hook = NULL;
  struct Buffer *err = mutt_buffer_pool_get();
  struct Buffer *token = mutt_buffer_pool_get();

  if (inhook)
    return;

  TAILQ_FOREACH(hook, &Hooks, entries)
  {
    if (!(hook->command && (hook->type & MUTT_ACCOUNT_HOOK)))
      continue;

    if ((regexec(hook->regex.regex, url, 0, NULL, 0) == 0) ^ hook->regex.not)
    {
      inhook = true;

      if (mutt_parse_rc_line(hook->command, token, err) == MUTT_CMD_ERROR)
      {
        mutt_buffer_pool_release(&token);
        mutt_error("%s", mutt_b2s(err));
        mutt_buffer_pool_release(&err);

        inhook = false;
        return;
      }

      inhook = false;
    }
  }

  mutt_buffer_pool_release(&token);
  mutt_buffer_pool_release(&err);
}
#endif

/**
 * mutt_timeout_hook - Execute any timeout hooks
 *
 * The user can configure hooks to be run on timeout.
 * This function finds all the matching hooks and executes them.
 */
void mutt_timeout_hook(void)
{
  struct Hook *hook = NULL;
  struct Buffer token;
  struct Buffer err;
  char buf[256];

  mutt_buffer_init(&err);
  err.data = buf;
  err.dsize = sizeof(buf);
  mutt_buffer_init(&token);

  TAILQ_FOREACH(hook, &Hooks, entries)
  {
    if (!(hook->command && (hook->type & MUTT_TIMEOUT_HOOK)))
      continue;

    if (mutt_parse_rc_line(hook->command, &token, &err) == MUTT_CMD_ERROR)
    {
      mutt_error("%s", err.data);
      mutt_buffer_reset(&err);

      /* The hooks should be independent of each other, so even though this on
       * failed, we'll carry on with the others. */
    }
  }
  FREE(&token.data);

  /* Delete temporary attachment files */
  mutt_unlink_temp_attachments();
}

/**
 * mutt_startup_shutdown_hook - Execute any startup/shutdown hooks
 * @param type Hook type: #MUTT_STARTUP_HOOK or #MUTT_SHUTDOWN_HOOK
 *
 * The user can configure hooks to be run on startup/shutdown.
 * This function finds all the matching hooks and executes them.
 */
void mutt_startup_shutdown_hook(HookFlags type)
{
  struct Hook *hook = NULL;
  struct Buffer token = { 0 };
  struct Buffer err = { 0 };
  char buf[256];

  err.data = buf;
  err.dsize = sizeof(buf);
  mutt_buffer_init(&token);

  TAILQ_FOREACH(hook, &Hooks, entries)
  {
    if (!(hook->command && (hook->type & type)))
      continue;

    if (mutt_parse_rc_line(hook->command, &token, &err) == MUTT_CMD_ERROR)
    {
      mutt_error("%s", err.data);
      mutt_buffer_reset(&err);
    }
  }
  FREE(&token.data);
}
