/**
 * @file
 * Compressed mbox local mailbox type
 *
 * @authors
 * Copyright (C) 2016-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2019-2021 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Reto Brunner <reto@slightlybroken.com>
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
 * @page compmbox_compress Compressed mailbox functions
 *
 * Compressed mbox local mailbox type
 *
 * @note
 * Any references to compressed files also apply to encrypted files.
 * - mailbox->path     == plaintext file
 * - mailbox->realpath == compressed file
 *
 * Implementation: #MxCompOps
 */

#include "config.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "expando/lib.h"
#include "expando.h"
#include "globals.h"
#include "hook.h"
#include "mx.h"
#include "protos.h"

struct Email;

/**
 * CompCommands - Compression Commands
 */
static const struct Command CompCommands[] = {
  // clang-format off
  { "append-hook", mutt_parse_hook, MUTT_APPEND_HOOK },
  { "close-hook",  mutt_parse_hook, MUTT_CLOSE_HOOK },
  { "open-hook",   mutt_parse_hook, MUTT_OPEN_HOOK },
  // clang-format on
};

/**
 * CompressFormatDef - Expando definitions
 *
 * Config:
 * - append-hook
 * - close-hook
 * - open-hook
 */
const struct ExpandoDefinition CompressFormatDef[] = {
  // clang-format off
  { "f", "from", ED_COMPRESS, ED_CMP_FROM, NULL },
  { "t", "to",   ED_COMPRESS, ED_CMP_TO,   NULL },
  { NULL, NULL, 0, -1, NULL }
  // clang-format on
};

/**
 * mutt_comp_init - Setup feature commands
 */
void mutt_comp_init(void)
{
  commands_register(CompCommands, mutt_array_size(CompCommands));
}

/**
 * lock_realpath - Try to lock the Mailbox.realpath
 * @param m    Mailbox to lock
 * @param excl Lock exclusively?
 * @retval true  Success (locked or readonly)
 * @retval false Error (can't lock the file)
 *
 * Try to (exclusively) lock the mailbox.  If we succeed, then we mark the
 * mailbox as locked.  If we fail, but we didn't want exclusive rights, then
 * the mailbox will be marked readonly.
 */
static bool lock_realpath(struct Mailbox *m, bool excl)
{
  if (!m || !m->compress_info)
    return false;

  struct CompressInfo *ci = m->compress_info;

  if (ci->locked)
    return true;

  if (excl)
    ci->fp_lock = mutt_file_fopen(m->realpath, "a");
  else
    ci->fp_lock = mutt_file_fopen(m->realpath, "r");
  if (!ci->fp_lock)
  {
    mutt_perror("%s", m->realpath);
    return false;
  }

  int r = mutt_file_lock(fileno(ci->fp_lock), excl, true);
  if (r == 0)
  {
    ci->locked = true;
  }
  else if (excl)
  {
    mutt_file_fclose(&ci->fp_lock);
    m->readonly = true;
    return true;
  }

  return r == 0;
}

/**
 * unlock_realpath - Unlock the mailbox->realpath
 * @param m Mailbox to unlock
 *
 * Unlock a mailbox previously locked by lock_mailbox().
 */
static void unlock_realpath(struct Mailbox *m)
{
  if (!m || !m->compress_info)
    return;

  struct CompressInfo *ci = m->compress_info;

  if (!ci->locked)
    return;

  mutt_file_unlock(fileno(ci->fp_lock));

  ci->locked = false;
  mutt_file_fclose(&ci->fp_lock);
}

/**
 * setup_paths - Set the mailbox paths
 * @param m Mailbox to modify
 * @retval  0 Success
 * @retval -1 Error
 *
 * Save the compressed filename in mailbox->realpath.
 * Create a temporary filename and put its name in mailbox->path.
 * The temporary file is created to prevent symlink attacks.
 */
static int setup_paths(struct Mailbox *m)
{
  if (!m)
    return -1;

  /* Setup the right paths */
  mutt_str_replace(&m->realpath, mailbox_path(m));

  /* We will uncompress to TMPDIR */
  struct Buffer *buf = buf_pool_get();
  buf_mktemp(buf);
  buf_copy(&m->pathbuf, buf);
  buf_pool_release(&buf);

  return mutt_file_touch(mailbox_path(m)) ? 0 : -1;
}

/**
 * store_size - Save the size of the compressed file
 * @param m Mailbox
 *
 * Save the compressed file size in the compress_info struct.
 */
static void store_size(const struct Mailbox *m)
{
  if (!m || !m->compress_info)
    return;

  struct CompressInfo *ci = m->compress_info;

  ci->size = mutt_file_get_size(m->realpath);
}

/**
 * validate_compress_expando - Validate the Compress hooks
 * @param s Command string
 * @retval ptr Expando
 */
static struct Expando *validate_compress_expando(const char *s)
{
  struct Buffer *err = buf_pool_get();

  struct Expando *exp = expando_parse(s, CompressFormatDef, err);
  if (!exp)
  {
    mutt_error(_("Expando parse error: %s"), buf_string(err));
  }

  buf_pool_release(&err);
  return exp;
}

/**
 * set_compress_info - Find the compress hooks for a mailbox
 * @param m Mailbox to examine
 * @retval ptr  CompressInfo Hook info for the mailbox's path
 * @retval NULL Error
 *
 * When a mailbox is opened, we check if there are any matching hooks.
 */
static struct CompressInfo *set_compress_info(struct Mailbox *m)
{
  if (!m)
    return NULL;

  if (m->compress_info)
    return m->compress_info;

  /* Open is compulsory */
  const char *o = mutt_find_hook(MUTT_OPEN_HOOK, mailbox_path(m));
  if (!o)
    return NULL;

  const char *c = mutt_find_hook(MUTT_CLOSE_HOOK, mailbox_path(m));
  const char *a = mutt_find_hook(MUTT_APPEND_HOOK, mailbox_path(m));

  struct CompressInfo *ci = MUTT_MEM_CALLOC(1, struct CompressInfo);
  m->compress_info = ci;

  ci->cmd_open = validate_compress_expando(o);
  ci->cmd_close = validate_compress_expando(c);
  ci->cmd_append = validate_compress_expando(a);

  return ci;
}

/**
 * compress_info_free - Frees the compress info members and structure
 * @param m Mailbox to free compress_info for
 */
static void compress_info_free(struct Mailbox *m)
{
  if (!m || !m->compress_info)
    return;

  struct CompressInfo *ci = m->compress_info;
  expando_free(&ci->cmd_open);
  expando_free(&ci->cmd_close);
  expando_free(&ci->cmd_append);

  unlock_realpath(m);

  FREE(&m->compress_info);
}

/**
 * execute_command - Run a system command
 * @param m        Mailbox to work with
 * @param exp      Command expando to execute
 * @param progress Message to show the user
 * @retval true  Success
 * @retval false Failure
 *
 * Run the supplied command, taking care of all the NeoMutt requirements,
 * such as locking files and blocking signals.
 */
static bool execute_command(struct Mailbox *m, const struct Expando *exp, const char *progress)
{
  if (!m || !exp || !progress)
    return false;

  if (m->verbose)
    mutt_message(progress, m->realpath);

  bool rc = true;
  struct Buffer *sys_cmd = buf_pool_get();
  buf_alloc(sys_cmd, STR_COMMAND);

  mutt_sig_block();
  mutt_endwin();
  fflush(stdout);

  struct ExpandoRenderData CompressRenderData[] = {
    // clang-format off
    { ED_COMPRESS, CompressRenderCallbacks, m, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  expando_render(exp, CompressRenderCallbacks, m, MUTT_FORMAT_NO_FLAGS,
                 sys_cmd->dsize, sys_cmd);

  if (mutt_system(buf_string(sys_cmd)) != 0)
  {
    rc = false;
    mutt_any_key_to_continue(NULL);
    mutt_error(_("Error running \"%s\""), buf_string(sys_cmd));
  }

  mutt_sig_unblock();

  buf_pool_release(&sys_cmd);
  return rc;
}

/**
 * mutt_comp_can_append - Can we append to this path?
 * @param m Mailbox
 * @retval true  Yes, we can append to the file
 * @retval false No, appending isn't possible
 *
 * To append to a file we can either use an 'append-hook' or a combination of
 * 'open-hook' and 'close-hook'.
 *
 * A match means it's our responsibility to append to the file.
 */
bool mutt_comp_can_append(struct Mailbox *m)
{
  if (!m)
    return false;

  /* If this succeeds, we know there's an open-hook */
  struct CompressInfo *ci = set_compress_info(m);
  if (!ci)
    return false;

  /* We have an open-hook, so to append we need an append-hook,
   * or a close-hook. */
  if (ci->cmd_append || ci->cmd_close)
    return true;

  mutt_error(_("Can't append without an append-hook or close-hook : %s"), mailbox_path(m));
  return false;
}

/**
 * mutt_comp_can_read - Can we read from this file?
 * @param path Pathname of file to be tested
 * @retval true  Yes, we can read the file
 * @retval false No, we can't read the file
 *
 * Search for an 'open-hook' with a regex that matches the path.
 *
 * A match means it's our responsibility to open the file.
 */
bool mutt_comp_can_read(const char *path)
{
  if (!path)
    return false;

  if (mutt_find_hook(MUTT_OPEN_HOOK, path))
    return true;

  return false;
}

/**
 * mutt_comp_valid_command - Is this command string allowed?
 * @param cmd  Command string
 * @retval 1 Valid command
 * @retval 0 "%f" and/or "%t" is missing
 *
 * A valid command string must have both "%f" (from file) and "%t" (to file).
 * We don't check if we can actually run the command.
 */
int mutt_comp_valid_command(const char *cmd)
{
  if (!cmd)
    return 0;

  return strstr(cmd, "%f") && strstr(cmd, "%t");
}

/**
 * comp_ac_owns_path - Check whether an Account owns a Mailbox path - Implements MxOps::ac_owns_path() - @ingroup mx_ac_owns_path
 */
static bool comp_ac_owns_path(struct Account *a, const char *path)
{
  return false;
}

/**
 * comp_ac_add - Add a Mailbox to an Account - Implements MxOps::ac_add() - @ingroup mx_ac_add
 */
static bool comp_ac_add(struct Account *a, struct Mailbox *m)
{
  return true;
}

/**
 * comp_mbox_open - Open a Mailbox - Implements MxOps::mbox_open() - @ingroup mx_mbox_open
 *
 * Set up a compressed mailbox to be read.
 * Decompress the mailbox and set up the paths and hooks needed.
 * Then determine the type of the mailbox so we can delegate the handling of
 * messages.
 */
static enum MxOpenReturns comp_mbox_open(struct Mailbox *m)
{
  struct CompressInfo *ci = set_compress_info(m);
  if (!ci)
    return MX_OPEN_ERROR;

  /* If there's no close-hook, or the file isn't writable */
  if (!ci->cmd_close || (access(mailbox_path(m), W_OK) != 0))
    m->readonly = true;

  if (setup_paths(m) != 0)
    goto cmo_fail;
  store_size(m);

  if (!lock_realpath(m, false))
  {
    mutt_error(_("Unable to lock mailbox"));
    goto cmo_fail;
  }

  if (!execute_command(m, ci->cmd_open, _("Decompressing %s")))
    goto cmo_fail;

  unlock_realpath(m);

  m->type = mx_path_probe(mailbox_path(m));
  if (m->type == MUTT_UNKNOWN)
  {
    mutt_error(_("Can't identify the contents of the compressed file"));
    goto cmo_fail;
  }

  ci->child_ops = mx_get_ops(m->type);
  if (!ci->child_ops)
  {
    mutt_error(_("Can't find mailbox ops for mailbox type %d"), m->type);
    goto cmo_fail;
  }

  m->account->type = m->type;
  return ci->child_ops->mbox_open(m);

cmo_fail:
  /* remove the partial uncompressed file */
  (void) remove(mailbox_path(m));
  compress_info_free(m);
  return MX_OPEN_ERROR;
}

/**
 * comp_mbox_open_append - Open a Mailbox for appending - Implements MxOps::mbox_open_append() - @ingroup mx_mbox_open_append
 *
 * To append to a compressed mailbox we need an append-hook (or both open- and
 * close-hooks).
 */
static bool comp_mbox_open_append(struct Mailbox *m, OpenMailboxFlags flags)
{
  /* If this succeeds, we know there's an open-hook */
  struct CompressInfo *ci = set_compress_info(m);
  if (!ci)
    return false;

  /* To append we need an append-hook or a close-hook */
  if (!ci->cmd_append && !ci->cmd_close)
  {
    mutt_error(_("Can't append without an append-hook or close-hook : %s"),
               mailbox_path(m));
    goto cmoa_fail1;
  }

  if (setup_paths(m) != 0)
    goto cmoa_fail2;

  /* Lock the realpath for the duration of the append.
   * It will be unlocked in the close */
  if (!lock_realpath(m, true))
  {
    mutt_error(_("Unable to lock mailbox"));
    goto cmoa_fail2;
  }

  /* Open the existing mailbox, unless we are appending */
  if (!ci->cmd_append && (mutt_file_get_size(m->realpath) > 0))
  {
    if (!execute_command(m, ci->cmd_open, _("Decompressing %s")))
    {
      mutt_error(_("Compress command failed: %s"), ci->cmd_open->string);
      goto cmoa_fail2;
    }
    m->type = mx_path_probe(mailbox_path(m));
  }
  else
  {
    m->type = cs_subset_enum(NeoMutt->sub, "mbox_type");
  }

  /* We can only deal with mbox and mmdf mailboxes */
  if ((m->type != MUTT_MBOX) && (m->type != MUTT_MMDF))
  {
    mutt_error(_("Unsupported mailbox type for appending"));
    goto cmoa_fail2;
  }

  ci->child_ops = mx_get_ops(m->type);
  if (!ci->child_ops)
  {
    mutt_error(_("Can't find mailbox ops for mailbox type %d"), m->type);
    goto cmoa_fail2;
  }

  if (!ci->child_ops->mbox_open_append(m, flags))
    goto cmoa_fail2;

  return true;

cmoa_fail2:
  /* remove the partial uncompressed file */
  (void) remove(mailbox_path(m));
cmoa_fail1:
  /* Free the compress_info to prevent close from trying to recompress */
  compress_info_free(m);

  return false;
}

/**
 * comp_mbox_check - Check for new mail - Implements MxOps::mbox_check() - @ingroup mx_mbox_check
 * @param m Mailbox
 * @retval enum #MxStatus
 *
 * If the compressed file changes in size but the mailbox hasn't been changed
 * in NeoMutt, then we can close and reopen the mailbox.
 *
 * If the mailbox has been changed in NeoMutt, warn the user.
 */
static enum MxStatus comp_mbox_check(struct Mailbox *m)
{
  if (!m->compress_info)
    return MX_STATUS_ERROR;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return MX_STATUS_ERROR;

  int size = mutt_file_get_size(m->realpath);
  if (size == ci->size)
    return MX_STATUS_OK;

  if (!lock_realpath(m, false))
  {
    mutt_error(_("Unable to lock mailbox"));
    return MX_STATUS_ERROR;
  }

  bool rc = execute_command(m, ci->cmd_open, _("Decompressing %s"));
  store_size(m);
  unlock_realpath(m);
  if (!rc)
    return MX_STATUS_ERROR;

  return ops->mbox_check(m);
}

/**
 * comp_mbox_sync - Save changes to the Mailbox - Implements MxOps::mbox_sync() - @ingroup mx_mbox_sync
 *
 * Changes in NeoMutt only affect the tmp file.
 * Calling comp_mbox_sync() will commit them to the compressed file.
 */
static enum MxStatus comp_mbox_sync(struct Mailbox *m)
{
  if (!m->compress_info)
    return MX_STATUS_ERROR;

  struct CompressInfo *ci = m->compress_info;

  if (!ci->cmd_close)
  {
    mutt_error(_("Can't sync a compressed file without a close-hook"));
    return MX_STATUS_ERROR;
  }

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return MX_STATUS_ERROR;

  if (!lock_realpath(m, true))
  {
    mutt_error(_("Unable to lock mailbox"));
    return MX_STATUS_ERROR;
  }

  enum MxStatus check = comp_mbox_check(m);
  if (check != MX_STATUS_OK)
    goto sync_cleanup;

  check = ops->mbox_sync(m);
  if (check != MX_STATUS_OK)
    goto sync_cleanup;

  if (!execute_command(m, ci->cmd_close, _("Compressing %s")))
  {
    check = MX_STATUS_ERROR;
    goto sync_cleanup;
  }

  check = MX_STATUS_OK;

sync_cleanup:
  store_size(m);
  unlock_realpath(m);
  return check;
}

/**
 * comp_mbox_close - Close a Mailbox - Implements MxOps::mbox_close() - @ingroup mx_mbox_close
 *
 * If the mailbox has been changed then re-compress the tmp file.
 * Then delete the tmp file.
 */
static enum MxStatus comp_mbox_close(struct Mailbox *m)
{
  if (!m->compress_info)
    return MX_STATUS_ERROR;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
  {
    compress_info_free(m);
    return MX_STATUS_ERROR;
  }

  ops->mbox_close(m);

  /* sync has already been called, so we only need to delete some files */
  if (m->append)
  {
    const struct Expando *append = NULL;
    const char *msg = NULL;

    /* The file exists and we can append */
    if ((access(m->realpath, F_OK) == 0) && ci->cmd_append)
    {
      append = ci->cmd_append;
      msg = _("Compressed-appending to %s...");
    }
    else
    {
      append = ci->cmd_close;
      msg = _("Compressing %s");
    }

    if (!execute_command(m, append, msg))
    {
      mutt_any_key_to_continue(NULL);
      mutt_error(_("Error. Preserving temporary file: %s"), mailbox_path(m));
    }
    else
    {
      if (remove(mailbox_path(m)) < 0)
      {
        mutt_debug(LL_DEBUG1, "remove failed: %s: %s (errno %d)\n",
                   mailbox_path(m), strerror(errno), errno);
      }
    }

    unlock_realpath(m);
  }
  else
  {
    /* If the file was removed, remove the compressed folder too */
    if (access(mailbox_path(m), F_OK) != 0)
    {
      const bool c_save_empty = cs_subset_bool(NeoMutt->sub, "save_empty");
      if (!c_save_empty)
      {
        if (remove(m->realpath) < 0)
        {
          mutt_debug(LL_DEBUG1, "remove failed: %s: %s (errno %d)\n",
                     m->realpath, strerror(errno), errno);
        }
      }
    }
    else
    {
      if (remove(mailbox_path(m)) < 0)
      {
        mutt_debug(LL_DEBUG1, "remove failed: %s: %s (errno %d)\n",
                   mailbox_path(m), strerror(errno), errno);
      }
    }
  }

  compress_info_free(m);

  return MX_STATUS_OK;
}

/**
 * comp_msg_open - Open an email message in a Mailbox - Implements MxOps::msg_open() - @ingroup mx_msg_open
 */
static bool comp_msg_open(struct Mailbox *m, struct Message *msg, struct Email *e)
{
  if (!m->compress_info)
    return false;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return false;

  /* Delegate */
  return ops->msg_open(m, msg, e);
}

/**
 * comp_msg_open_new - Open a new message in a Mailbox - Implements MxOps::msg_open_new() - @ingroup mx_msg_open_new
 */
static bool comp_msg_open_new(struct Mailbox *m, struct Message *msg, const struct Email *e)
{
  if (!m->compress_info)
    return false;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return false;

  /* Delegate */
  return ops->msg_open_new(m, msg, e);
}

/**
 * comp_msg_commit - Save changes to an email - Implements MxOps::msg_commit() - @ingroup mx_msg_commit
 */
static int comp_msg_commit(struct Mailbox *m, struct Message *msg)
{
  if (!m->compress_info)
    return -1;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return -1;

  /* Delegate */
  return ops->msg_commit(m, msg);
}

/**
 * comp_msg_close - Close an email - Implements MxOps::msg_close() - @ingroup mx_msg_close
 */
static int comp_msg_close(struct Mailbox *m, struct Message *msg)
{
  if (!m->compress_info)
    return -1;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops)
    return -1;

  /* Delegate */
  return ops->msg_close(m, msg);
}

/**
 * comp_msg_padding_size - Bytes of padding between messages - Implements MxOps::msg_padding_size() - @ingroup mx_msg_padding_size
 */
static int comp_msg_padding_size(struct Mailbox *m)
{
  if (!m->compress_info)
    return 0;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops || !ops->msg_padding_size)
    return 0;

  return ops->msg_padding_size(m);
}

/**
 * comp_msg_save_hcache - Save message to the header cache - Implements MxOps::msg_save_hcache() - @ingroup mx_msg_save_hcache
 */
static int comp_msg_save_hcache(struct Mailbox *m, struct Email *e)
{
  if (!m->compress_info)
    return 0;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops || !ops->msg_save_hcache)
    return 0;

  return ops->msg_save_hcache(m, e);
}

/**
 * comp_tags_edit - Prompt and validate new messages tags - Implements MxOps::tags_edit() - @ingroup mx_tags_edit
 */
static int comp_tags_edit(struct Mailbox *m, const char *tags, struct Buffer *buf)
{
  if (!m->compress_info)
    return 0;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops || !ops->tags_edit)
    return 0;

  return ops->tags_edit(m, tags, buf);
}

/**
 * comp_tags_commit - Save the tags to a message - Implements MxOps::tags_commit() - @ingroup mx_tags_commit
 */
static int comp_tags_commit(struct Mailbox *m, struct Email *e, const char *buf)
{
  if (!m->compress_info)
    return 0;

  struct CompressInfo *ci = m->compress_info;

  const struct MxOps *ops = ci->child_ops;
  if (!ops || !ops->tags_commit)
    return 0;

  return ops->tags_commit(m, e, buf);
}

/**
 * comp_path_probe - Is this a compressed Mailbox? - Implements MxOps::path_probe() - @ingroup mx_path_probe
 */
static enum MailboxType comp_path_probe(const char *path, const struct stat *st)
{
  if (!st || !S_ISREG(st->st_mode))
    return MUTT_UNKNOWN;

  if (mutt_comp_can_read(path))
    return MUTT_COMPRESSED;

  return MUTT_UNKNOWN;
}

/**
 * comp_path_canon - Canonicalise a Mailbox path - Implements MxOps::path_canon() - @ingroup mx_path_canon
 */
static int comp_path_canon(struct Buffer *path)
{
  mutt_path_canon(path, HomeDir, false);
  return 0;
}

/**
 * MxCompOps - Compressed Mailbox - Implements ::MxOps - @ingroup mx_api
 *
 * Compress only uses open, close and check.
 * The message functions are delegated to mbox.
 */
const struct MxOps MxCompOps = {
  // clang-format off
  .type            = MUTT_COMPRESSED,
  .name             = "compressed",
  .is_local         = true,
  .ac_owns_path     = comp_ac_owns_path,
  .ac_add           = comp_ac_add,
  .mbox_open        = comp_mbox_open,
  .mbox_open_append = comp_mbox_open_append,
  .mbox_check       = comp_mbox_check,
  .mbox_check_stats = NULL,
  .mbox_sync        = comp_mbox_sync,
  .mbox_close       = comp_mbox_close,
  .msg_open         = comp_msg_open,
  .msg_open_new     = comp_msg_open_new,
  .msg_commit       = comp_msg_commit,
  .msg_close        = comp_msg_close,
  .msg_padding_size = comp_msg_padding_size,
  .msg_save_hcache  = comp_msg_save_hcache,
  .tags_edit        = comp_tags_edit,
  .tags_commit      = comp_tags_commit,
  .path_probe       = comp_path_probe,
  .path_canon       = comp_path_canon,
  .path_is_empty    = NULL,
  // clang-format on
};
