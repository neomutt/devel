/**
 * @file
 * Browser functions
 *
 * @authors
 * Copyright (C) 2021-2023 Richard Russon <rich@flatcap.org>
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
 * @page browser_functions Browser functions
 *
 * Browser functions
 */

#include "config.h"
#ifdef _MAKEDOC
#include "docs/makedoc_defs.h"
#else
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "lib.h"
#include "attach/lib.h"
#include "editor/lib.h"
#include "history/lib.h"
#include "imap/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "nntp/lib.h"
#include "pattern/lib.h"
#include "question/lib.h"
#include "send/lib.h"
#include "functions.h"
#include "globals.h"
#include "mutt_mailbox.h"
#include "muttlib.h"
#include "mx.h"
#include "nntp/adata.h" // IWYU pragma: keep
#include "nntp/mdata.h" // IWYU pragma: keep
#include "private_data.h"
#include "sort.h"
#endif

static int op_subscribe_pattern(struct BrowserPrivateData *priv, int op);

// clang-format off
/**
 * OpBrowser - Functions for the file Browser Menu
 */
const struct MenuFuncOp OpBrowser[] = { /* map: browser */
  { "catchup",                       OP_CATCHUP },
  { "change-dir",                    OP_CHANGE_DIRECTORY },
  { "check-new",                     OP_CHECK_NEW },
  { "create-mailbox",                OP_CREATE_MAILBOX },
  { "delete-mailbox",                OP_DELETE_MAILBOX },
  { "descend-directory",             OP_DESCEND_DIRECTORY },
  { "display-filename",              OP_BROWSER_TELL },
  { "enter-mask",                    OP_ENTER_MASK },
  { "exit",                          OP_EXIT },
  { "goto-folder",                   OP_BROWSER_GOTO_FOLDER },
  { "goto-parent",                   OP_GOTO_PARENT },
  { "mailbox-list",                  OP_MAILBOX_LIST },
  { "reload-active",                 OP_LOAD_ACTIVE },
  { "rename-mailbox",                OP_RENAME_MAILBOX },
  { "select-new",                    OP_BROWSER_NEW_FILE },
  { "sort",                          OP_SORT },
  { "sort-reverse",                  OP_SORT_REVERSE },
  { "subscribe",                     OP_BROWSER_SUBSCRIBE },
  { "subscribe-pattern",             OP_SUBSCRIBE_PATTERN },
  { "toggle-mailboxes",              OP_TOGGLE_MAILBOXES },
  { "toggle-subscribed",             OP_BROWSER_TOGGLE_LSUB },
  { "uncatchup",                     OP_UNCATCHUP },
  { "unsubscribe",                   OP_BROWSER_UNSUBSCRIBE },
  { "unsubscribe-pattern",           OP_UNSUBSCRIBE_PATTERN },
  { "view-file",                     OP_BROWSER_VIEW_FILE },
  // Deprecated
  { "buffy-list",                    OP_MAILBOX_LIST },
  { NULL, 0 },
};

/**
 * BrowserDefaultBindings - Key bindings for the file Browser Menu
 */
const struct MenuOpSeq BrowserDefaultBindings[] = { /* map: browser */
  { OP_BROWSER_GOTO_FOLDER,                "=" },
  { OP_BROWSER_NEW_FILE,                   "N" },
  { OP_BROWSER_SUBSCRIBE,                  "s" },
  { OP_BROWSER_TELL,                       "@" },
  { OP_BROWSER_TOGGLE_LSUB,                "T" },
  { OP_BROWSER_UNSUBSCRIBE,                "u" },
  { OP_BROWSER_VIEW_FILE,                  " " },              // <Space>
  { OP_CHANGE_DIRECTORY,                   "c" },
  { OP_CREATE_MAILBOX,                     "C" },
  { OP_DELETE_MAILBOX,                     "d" },
  { OP_ENTER_MASK,                         "m" },
  { OP_EXIT,                               "q" },
  { OP_GOTO_PARENT,                        "p" },
  { OP_MAILBOX_LIST,                       "." },
  { OP_RENAME_MAILBOX,                     "r" },
  { OP_SORT,                               "o" },
  { OP_SORT_REVERSE,                       "O" },
  { OP_TOGGLE_MAILBOXES,                   "\t" },             // <Tab>
  { 0, NULL },
};
// clang-format on

/**
 * destroy_state - Free the BrowserState
 * @param state State to free
 *
 * Frees up the memory allocated for the local-global variables.
 */
void destroy_state(struct BrowserState *state)
{
  struct FolderFile *ff = NULL;
  ARRAY_FOREACH(ff, &state->entry)
  {
    FREE(&ff->name);
    FREE(&ff->desc);
  }
  ARRAY_FREE(&state->entry);
  FREE(&state->folder);
}

// -----------------------------------------------------------------------------

/**
 * op_browser_new_file - Select a new file in this directory - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_browser_new_file(struct BrowserPrivateData *priv, int op)
{
  struct Buffer *buf = buf_pool_get();
  buf_printf(buf, "%s/", buf_string(&LastDir));

  struct FileCompletionData cdata = { false, priv->mailbox, NULL, NULL };
  const int rc = mw_get_field(_("New file name: "), buf, MUTT_COMP_NO_FLAGS,
                              HC_FILE, &CompleteMailboxOps, &cdata);
  if (rc != 0)
  {
    buf_pool_release(&buf);
    return FR_NO_ACTION;
  }

  buf_copy(priv->file, buf);
  buf_pool_release(&buf);
  priv->done = true;
  return FR_DONE;
}

/**
 * op_browser_subscribe - Subscribe to current mbox (IMAP/NNTP only) - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_BROWSER_SUBSCRIBE
 * - OP_BROWSER_UNSUBSCRIBE
 */
static int op_browser_subscribe(struct BrowserPrivateData *priv, int op)
{
  if (OptNews)
  {
    struct NntpAccountData *adata = CurrentNewsSrv;
    int index = menu_get_index(priv->menu);

    if (ARRAY_EMPTY(&priv->state.entry))
    {
      mutt_error(_("No newsgroups match the mask"));
      return FR_ERROR;
    }

    int rc = nntp_newsrc_parse(adata);
    if (rc < 0)
      return FR_ERROR;

    struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
    if (op == OP_BROWSER_SUBSCRIBE)
      mutt_newsgroup_subscribe(adata, ff->name);
    else
      mutt_newsgroup_unsubscribe(adata, ff->name);

    menu_set_index(priv->menu, index + 1);

    if (rc > 0)
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    nntp_newsrc_update(adata);
    nntp_clear_cache(adata);
    nntp_newsrc_close(adata);
  }
  else
  {
    if (ARRAY_EMPTY(&priv->state.entry))
    {
      mutt_error(_("There are no mailboxes"));
      return FR_ERROR;
    }

    struct Buffer *buf = buf_pool_get();
    int index = menu_get_index(priv->menu);
    struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
    buf_strcpy(buf, ff->name);
    buf_expand_path(buf);
    imap_subscribe(buf_string(buf), (op == OP_BROWSER_SUBSCRIBE));
    buf_pool_release(&buf);
  }
  return FR_SUCCESS;
}

/**
 * op_browser_tell - Display the currently selected file's name - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_browser_tell(struct BrowserPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  if (ARRAY_EMPTY(&priv->state.entry))
    return FR_ERROR;

  mutt_message("%s", ARRAY_GET(&priv->state.entry, index)->name);
  return FR_SUCCESS;
}

/**
 * op_browser_toggle_lsub - Toggle view all/subscribed mailboxes (IMAP only) - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_browser_toggle_lsub(struct BrowserPrivateData *priv, int op)
{
  bool_str_toggle(NeoMutt->sub, "imap_list_subscribed", NULL);

  mutt_unget_op(OP_CHECK_NEW);
  return FR_SUCCESS;
}

/**
 * op_browser_view_file - View file - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_browser_view_file(struct BrowserPrivateData *priv, int op)
{
  if (ARRAY_EMPTY(&priv->state.entry))
  {
    mutt_error(_("No files match the file mask"));
    return FR_ERROR;
  }

  int index = menu_get_index(priv->menu);
  struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
  if (ff->selectable)
  {
    buf_strcpy(priv->file, ff->name);
    priv->done = true;
    return FR_DONE;
  }
  else if (S_ISDIR(ff->mode) ||
           (S_ISLNK(ff->mode) && link_is_dir(buf_string(&LastDir), ff->name)))
  {
    mutt_error(_("Can't view a directory"));
    return FR_ERROR;
  }
  else
  {
    struct Buffer *path = buf_pool_get();
    buf_concat_path(path, buf_string(&LastDir), ff->name);
    struct Body *b = mutt_make_file_attach(buf_string(path), NeoMutt->sub);
    if (b)
    {
      mutt_view_attachment(NULL, b, MUTT_VA_REGULAR, NULL, NULL, priv->menu->win);
      mutt_body_free(&b);
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    }
    else
    {
      mutt_error(_("Error trying to view file"));
    }
    buf_pool_release(&path);
  }
  return FR_ERROR;
}

/**
 * op_catchup - Mark all articles in newsgroup as read - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_catchup(struct BrowserPrivateData *priv, int op)
{
  if (!OptNews)
    return FR_NOT_IMPL;

  struct NntpMboxData *mdata = NULL;

  int rc = nntp_newsrc_parse(CurrentNewsSrv);
  if (rc < 0)
    return FR_ERROR;

  int index = menu_get_index(priv->menu);
  struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
  if (op == OP_CATCHUP)
    mdata = mutt_newsgroup_catchup(priv->mailbox, CurrentNewsSrv, ff->name);
  else
    mdata = mutt_newsgroup_uncatchup(priv->mailbox, CurrentNewsSrv, ff->name);

  if (mdata)
  {
    nntp_newsrc_update(CurrentNewsSrv);
    index = menu_get_index(priv->menu) + 1;
    if (index < priv->menu->max)
      menu_set_index(priv->menu, index);
  }

  if (rc != 0)
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  nntp_newsrc_close(CurrentNewsSrv);
  return FR_ERROR;
}

/**
 * op_change_directory - Change directories - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_GOTO_PARENT
 * - OP_CHANGE_DIRECTORY
 */
static int op_change_directory(struct BrowserPrivateData *priv, int op)
{
  if (OptNews)
    return FR_NOT_IMPL;

  struct Buffer *buf = buf_pool_get();
  buf_copy(buf, &LastDir);
  if (!priv->state.imap_browse)
  {
    /* add '/' at the end of the directory name if not already there */
    size_t len = buf_len(buf);
    if ((len > 0) && (buf_string(&LastDir)[len - 1] != '/'))
      buf_addch(buf, '/');
  }

  if (op == OP_CHANGE_DIRECTORY)
  {
    struct FileCompletionData cdata = { false, priv->mailbox, NULL, NULL };
    int rc = mw_get_field(_("Chdir to: "), buf, MUTT_COMP_NO_FLAGS, HC_FILE,
                          &CompleteMailboxOps, &cdata);
    if ((rc != 0) && buf_is_empty(buf))
    {
      buf_pool_release(&buf);
      return FR_NO_ACTION;
    }
  }
  else if (op == OP_GOTO_PARENT)
  {
    mutt_get_parent_path(buf_string(buf), buf->data, buf->dsize);
  }

  if (!buf_is_empty(buf))
  {
    priv->state.is_mailbox_list = false;
    buf_expand_path(buf);
    if (imap_path_probe(buf_string(buf), NULL) == MUTT_IMAP)
    {
      buf_copy(&LastDir, buf);
      destroy_state(&priv->state);
      init_state(&priv->state);
      priv->state.imap_browse = true;
      imap_browse(buf_string(&LastDir), &priv->state);
      browser_sort(&priv->state);
      browser_highlight_default(&priv->state, priv->menu);
      init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
    }
    else
    {
      if (buf_string(buf)[0] != '/')
      {
        /* in case dir is relative, make it relative to LastDir,
         * not current working dir */
        struct Buffer *tmp = buf_pool_get();
        buf_concat_path(tmp, buf_string(&LastDir), buf_string(buf));
        buf_copy(buf, tmp);
        buf_pool_release(&tmp);
      }
      /* Resolve path from <chdir>
       * Avoids buildup such as /a/b/../../c
       * Symlinks are always unraveled to keep code simple */
      if (mutt_path_realpath(buf) == 0)
      {
        buf_pool_release(&buf);
        return FR_ERROR;
      }

      struct stat st = { 0 };
      if (stat(buf_string(buf), &st) == 0)
      {
        if (S_ISDIR(st.st_mode))
        {
          destroy_state(&priv->state);
          if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                                buf_string(buf), buf_string(priv->prefix)) == 0)
          {
            buf_copy(&LastDir, buf);
          }
          else
          {
            mutt_error(_("Error scanning directory"));
            if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                                  buf_string(&LastDir), buf_string(priv->prefix)) == -1)
            {
              priv->done = true;
              return FR_ERROR;
            }
          }
          browser_highlight_default(&priv->state, priv->menu);
          init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
        }
        else
        {
          mutt_error(_("%s is not a directory"), buf_string(buf));
        }
      }
      else
      {
        mutt_perror("%s", buf_string(buf));
      }
    }
  }
  buf_pool_release(&buf);
  return FR_ERROR;
}

/**
 * op_create_mailbox - Create a new mailbox (IMAP only) - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_create_mailbox(struct BrowserPrivateData *priv, int op)
{
  if (!priv->state.imap_browse)
  {
    mutt_error(_("Create is only supported for IMAP mailboxes"));
    return FR_ERROR;
  }

  if (imap_mailbox_create(buf_string(&LastDir)) != 0)
    return FR_ERROR;

  /* TODO: find a way to detect if the new folder would appear in
   *   this window, and insert it without starting over. */
  destroy_state(&priv->state);
  init_state(&priv->state);
  priv->state.imap_browse = true;
  imap_browse(buf_string(&LastDir), &priv->state);
  browser_sort(&priv->state);
  browser_highlight_default(&priv->state, priv->menu);
  init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);

  return FR_SUCCESS;
}

/**
 * op_delete_mailbox - Delete the current mailbox (IMAP only) - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_delete_mailbox(struct BrowserPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
  if (!ff->imap)
  {
    mutt_error(_("Delete is only supported for IMAP mailboxes"));
    return FR_ERROR;
  }

  char msg[128] = { 0 };

  // TODO(sileht): It could be better to select INBOX instead. But I
  // don't want to manipulate Mailboxes/mailbox->account here for now.
  // Let's just protect neomutt against crash for now. #1417
  if (mutt_str_equal(mailbox_path(priv->mailbox), ff->name))
  {
    mutt_error(_("Can't delete currently selected mailbox"));
    return FR_ERROR;
  }

  snprintf(msg, sizeof(msg), _("Really delete mailbox \"%s\"?"), ff->name);
  if (query_yesorno(msg, MUTT_NO) != MUTT_YES)
  {
    mutt_message(_("Mailbox not deleted"));
    return FR_NO_ACTION;
  }

  if (imap_delete_mailbox(priv->mailbox, ff->name) != 0)
  {
    mutt_error(_("Mailbox deletion failed"));
    return FR_ERROR;
  }

  /* free the mailbox from the browser */
  FREE(&ff->name);
  FREE(&ff->desc);
  /* and move all other entries up */
  ARRAY_REMOVE(&priv->state.entry, ff);
  mutt_message(_("Mailbox deleted"));
  init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);

  return FR_SUCCESS;
}

/**
 * op_enter_mask - Enter a file mask - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_enter_mask(struct BrowserPrivateData *priv, int op)
{
  const struct Regex *c_mask = cs_subset_regex(NeoMutt->sub, "mask");
  struct Buffer *buf = buf_pool_get();
  buf_strcpy(buf, c_mask ? c_mask->pattern : NULL);
  if (mw_get_field(_("File Mask: "), buf, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0)
  {
    buf_pool_release(&buf);
    return FR_NO_ACTION;
  }

  buf_fix_dptr(buf);

  priv->state.is_mailbox_list = false;
  /* assume that the user wants to see everything */
  if (buf_is_empty(buf))
    buf_strcpy(buf, ".");

  struct Buffer *errmsg = buf_pool_get();
  int rc = cs_subset_str_string_set(NeoMutt->sub, "mask", buf_string(buf), errmsg);
  buf_pool_release(&buf);
  if (CSR_RESULT(rc) != CSR_SUCCESS)
  {
    if (!buf_is_empty(errmsg))
    {
      mutt_error("%s", buf_string(errmsg));
      buf_pool_release(&errmsg);
    }
    return FR_ERROR;
  }
  buf_pool_release(&errmsg);

  destroy_state(&priv->state);
  if (priv->state.imap_browse)
  {
    init_state(&priv->state);
    priv->state.imap_browse = true;
    imap_browse(buf_string(&LastDir), &priv->state);
    browser_sort(&priv->state);
    init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
  }
  else if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                             buf_string(&LastDir), NULL) == 0)
  {
    init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
  }
  else
  {
    mutt_error(_("Error scanning directory"));
    priv->done = true;
    return FR_ERROR;
  }
  priv->kill_prefix = false;
  if (ARRAY_EMPTY(&priv->state.entry))
  {
    mutt_error(_("No files match the file mask"));
    return FR_ERROR;
  }
  return FR_SUCCESS;
}

/**
 * op_exit - Exit this menu - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_exit(struct BrowserPrivateData *priv, int op)
{
  if (priv->multiple)
  {
    char **tfiles = NULL;

    if (priv->menu->tag_prefix && (priv->menu->num_tagged != 0))
    {
      *priv->numfiles = priv->menu->num_tagged;
      tfiles = MUTT_MEM_CALLOC(*priv->numfiles, char *);
      size_t j = 0;
      struct FolderFile *ff = NULL;
      ARRAY_FOREACH(ff, &priv->state.entry)
      {
        if (ff->tagged)
        {
          struct Buffer *buf = buf_pool_get();
          buf_concat_path(buf, buf_string(&LastDir), ff->name);
          buf_expand_path(buf);
          tfiles[j++] = buf_strdup(buf);
          buf_pool_release(&buf);
        }
      }
      *priv->files = tfiles;
    }
    else if (!buf_is_empty(priv->file)) /* no tagged entries. return selected entry */
    {
      *priv->numfiles = 1;
      tfiles = MUTT_MEM_CALLOC(*priv->numfiles, char *);
      buf_expand_path(priv->file);
      tfiles[0] = buf_strdup(priv->file);
      *priv->files = tfiles;
    }
  }

  priv->done = true;
  return FR_DONE;
}

/**
 * op_generic_select_entry - Select the current entry - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_DESCEND_DIRECTORY
 * - OP_GENERIC_SELECT_ENTRY
 */
static int op_generic_select_entry(struct BrowserPrivateData *priv, int op)
{
  if (ARRAY_EMPTY(&priv->state.entry))
  {
    mutt_error(_("No files match the file mask"));
    return FR_ERROR;
  }

  int index = menu_get_index(priv->menu);
  struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
  if (S_ISDIR(ff->mode) ||
      (S_ISLNK(ff->mode) && link_is_dir(buf_string(&LastDir), ff->name)) || ff->inferiors)
  {
    /* make sure this isn't a MH or maildir mailbox */
    struct Buffer *buf = buf_pool_get();
    if (priv->state.is_mailbox_list)
    {
      buf_strcpy(buf, ff->name);
      buf_expand_path(buf);
    }
    else if (priv->state.imap_browse)
    {
      buf_strcpy(buf, ff->name);
    }
    else
    {
      buf_concat_path(buf, buf_string(&LastDir), ff->name);
    }

    enum MailboxType type = mx_path_probe(buf_string(buf));
    buf_pool_release(&buf);

    if ((op == OP_DESCEND_DIRECTORY) || (type == MUTT_MAILBOX_ERROR) ||
        (type == MUTT_UNKNOWN) || ff->inferiors)
    {
      /* save the old directory */
      buf_copy(priv->old_last_dir, &LastDir);

      if (mutt_str_equal(ff->name, ".."))
      {
        size_t lastdirlen = buf_len(&LastDir);
        if ((lastdirlen > 1) && mutt_str_equal("..", buf_string(&LastDir) + lastdirlen - 2))
        {
          buf_addstr(&LastDir, "/..");
        }
        else
        {
          char *p = NULL;
          if (lastdirlen > 1)
            p = strrchr(LastDir.data + 1, '/');

          if (p)
          {
            *p = '\0';
            buf_fix_dptr(&LastDir);
          }
          else
          {
            if (buf_string(&LastDir)[0] == '/')
              buf_strcpy(&LastDir, "/");
            else
              buf_addstr(&LastDir, "/..");
          }
        }
      }
      else if (priv->state.is_mailbox_list)
      {
        buf_strcpy(&LastDir, ff->name);
        buf_expand_path(&LastDir);
      }
      else if (priv->state.imap_browse)
      {
        buf_strcpy(&LastDir, ff->name);
        /* tack on delimiter here */

        /* special case "" needs no delimiter */
        struct Url *url = url_parse(ff->name);
        if (url && url->path && (ff->delim != '\0'))
        {
          buf_addch(&LastDir, ff->delim);
        }
        url_free(&url);
      }
      else
      {
        struct Buffer *tmp = buf_pool_get();
        buf_concat_path(tmp, buf_string(&LastDir), ff->name);
        buf_copy(&LastDir, tmp);
        buf_pool_release(&tmp);
      }

      destroy_state(&priv->state);
      if (priv->kill_prefix)
      {
        buf_reset(priv->prefix);
        priv->kill_prefix = false;
      }
      priv->state.is_mailbox_list = false;
      if (priv->state.imap_browse)
      {
        init_state(&priv->state);
        priv->state.imap_browse = true;
        imap_browse(buf_string(&LastDir), &priv->state);
        browser_sort(&priv->state);
      }
      else
      {
        if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                              buf_string(&LastDir), buf_string(priv->prefix)) == -1)
        {
          /* try to restore the old values */
          buf_copy(&LastDir, priv->old_last_dir);
          if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                                buf_string(&LastDir), buf_string(priv->prefix)) == -1)
          {
            buf_strcpy(&LastDir, HomeDir);
            priv->done = true;
            return FR_DONE;
          }
        }
        /* resolve paths navigated from GUI */
        if (mutt_path_realpath(&LastDir) == 0)
          return FR_ERROR;
      }

      browser_highlight_default(&priv->state, priv->menu);
      init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
      priv->goto_swapper[0] = '\0';
      return FR_SUCCESS;
    }
  }
  else if (op == OP_DESCEND_DIRECTORY)
  {
    mutt_error(_("%s is not a directory"), ARRAY_GET(&priv->state.entry, index)->name);
    return FR_ERROR;
  }

  if (priv->state.is_mailbox_list || OptNews)
  {
    buf_strcpy(priv->file, ff->name);
    buf_expand_path(priv->file);
  }
  else if (priv->state.imap_browse)
  {
    buf_strcpy(priv->file, ff->name);
  }
  else
  {
    buf_concat_path(priv->file, buf_string(&LastDir), ff->name);
  }

  return op_exit(priv, op);
}

/**
 * op_load_active - Load list of all newsgroups from NNTP server - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_load_active(struct BrowserPrivateData *priv, int op)
{
  if (!OptNews)
    return FR_NOT_IMPL;

  struct NntpAccountData *adata = CurrentNewsSrv;

  if (nntp_newsrc_parse(adata) < 0)
    return FR_ERROR;

  for (size_t i = 0; i < adata->groups_num; i++)
  {
    struct NntpMboxData *mdata = adata->groups_list[i];
    if (mdata)
      mdata->deleted = true;
  }
  nntp_active_fetch(adata, true);
  nntp_newsrc_update(adata);
  nntp_newsrc_close(adata);

  destroy_state(&priv->state);
  if (priv->state.is_mailbox_list)
  {
    examine_mailboxes(priv->mailbox, priv->menu, &priv->state);
  }
  else
  {
    if (examine_directory(priv->mailbox, priv->menu, &priv->state, NULL, NULL) == -1)
      return FR_ERROR;
  }
  init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
  return FR_SUCCESS;
}

/**
 * op_mailbox_list - List mailboxes with new mail - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_mailbox_list(struct BrowserPrivateData *priv, int op)
{
  mutt_mailbox_list();
  return FR_SUCCESS;
}

/**
 * op_rename_mailbox - Rename the current mailbox (IMAP only) - Implements ::browser_function_t - @ingroup browser_function_api
 */
static int op_rename_mailbox(struct BrowserPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  struct FolderFile *ff = ARRAY_GET(&priv->state.entry, index);
  if (!ff->imap)
  {
    mutt_error(_("Rename is only supported for IMAP mailboxes"));
    return FR_ERROR;
  }

  if (imap_mailbox_rename(ff->name) < 0)
    return FR_ERROR;

  destroy_state(&priv->state);
  init_state(&priv->state);
  priv->state.imap_browse = true;
  imap_browse(buf_string(&LastDir), &priv->state);
  browser_sort(&priv->state);
  browser_highlight_default(&priv->state, priv->menu);
  init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);

  return FR_SUCCESS;
}

/**
 * op_sort - Sort messages - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_SORT
 * - OP_SORT_REVERSE
 */
static int op_sort(struct BrowserPrivateData *priv, int op)
{
  bool resort = true;
  int sort = -1;
  int reverse = (op == OP_SORT_REVERSE);

  switch (mw_multi_choice((reverse) ?
                              /* L10N: The highlighted letters must match the "Sort" options */
                              _("Reverse sort by (d)ate, (a)lpha, si(z)e, d(e)scription, (c)ount, ne(w) count, or do(n)'t sort?") :
                              /* L10N: The highlighted letters must match the "Reverse Sort" options */
                              _("Sort by (d)ate, (a)lpha, si(z)e, d(e)scription, (c)ount, ne(w) count, or do(n)'t sort?"),
                          /* L10N: These must match the highlighted letters from "Sort" and "Reverse Sort" */
                          _("dazecwn")))
  {
    case -1: /* abort */
      resort = false;
      break;

    case 1: /* (d)ate */
      sort = BROWSER_SORT_DATE;
      break;

    case 2: /* (a)lpha */
      sort = BROWSER_SORT_ALPHA;
      break;

    case 3: /* si(z)e */
      sort = BROWSER_SORT_SIZE;
      break;

    case 4: /* d(e)scription */
      sort = BROWSER_SORT_DESC;
      break;

    case 5: /* (c)ount */
      sort = BROWSER_SORT_COUNT;
      break;

    case 6: /* ne(w) count */
      sort = BROWSER_SORT_NEW;
      break;

    case 7: /* do(n)'t sort */
      sort = BROWSER_SORT_UNSORTED;
      break;
  }

  if (!resort)
    return FR_NO_ACTION;

  sort |= reverse ? SORT_REVERSE : 0;
  cs_subset_str_native_set(NeoMutt->sub, "browser_sort", sort, NULL);
  browser_sort(&priv->state);
  browser_highlight_default(&priv->state, priv->menu);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return FR_SUCCESS;
}

/**
 * op_subscribe_pattern - Subscribe to newsgroups matching a pattern - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_SUBSCRIBE_PATTERN
 * - OP_UNSUBSCRIBE_PATTERN
 */
static int op_subscribe_pattern(struct BrowserPrivateData *priv, int op)
{
  if (!OptNews)
    return FR_NOT_IMPL;

  struct NntpAccountData *adata = CurrentNewsSrv;
  regex_t rx = { 0 };
  int index = menu_get_index(priv->menu);

  char tmp2[256] = { 0 };

  struct Buffer *buf = buf_pool_get();
  if (op == OP_SUBSCRIBE_PATTERN)
    snprintf(tmp2, sizeof(tmp2), _("Subscribe pattern: "));
  else
    snprintf(tmp2, sizeof(tmp2), _("Unsubscribe pattern: "));
  /* buf comes from the buffer pool, so defaults to size 1024 */
  if ((mw_get_field(tmp2, buf, MUTT_COMP_NO_FLAGS, HC_PATTERN, &CompletePatternOps, NULL) != 0) ||
      buf_is_empty(buf))
  {
    buf_pool_release(&buf);
    return FR_NO_ACTION;
  }

  int err = REG_COMP(&rx, buf->data, REG_NOSUB);
  if (err != 0)
  {
    regerror(err, &rx, buf->data, buf->dsize);
    regfree(&rx);
    mutt_error("%s", buf_string(buf));
    buf_pool_release(&buf);
    return FR_ERROR;
  }
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  index = 0;
  buf_pool_release(&buf);

  int rc = nntp_newsrc_parse(adata);
  if (rc < 0)
    return FR_ERROR;

  struct FolderFile *ff = NULL;
  ARRAY_FOREACH_FROM(ff, &priv->state.entry, index)
  {
    if (regexec(&rx, ff->name, 0, NULL, 0) == 0)
    {
      if (op == OP_SUBSCRIBE_PATTERN)
        mutt_newsgroup_subscribe(adata, ff->name);
      else
        mutt_newsgroup_unsubscribe(adata, ff->name);
    }
  }

  if (op == OP_SUBSCRIBE_PATTERN)
  {
    for (size_t j = 0; j < adata->groups_num; j++)
    {
      struct NntpMboxData *mdata = adata->groups_list[j];
      if (mdata && mdata->group && !mdata->subscribed)
      {
        if (regexec(&rx, mdata->group, 0, NULL, 0) == 0)
        {
          mutt_newsgroup_subscribe(adata, mdata->group);
          browser_add_folder(priv->menu, &priv->state, mdata->group, NULL, NULL, NULL, mdata);
        }
      }
    }
    init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
  }
  if (rc > 0)
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  nntp_newsrc_update(adata);
  nntp_clear_cache(adata);
  nntp_newsrc_close(adata);
  regfree(&rx);
  return FR_SUCCESS;
}

/**
 * op_toggle_mailboxes - Toggle whether to browse mailboxes or all files - Implements ::browser_function_t - @ingroup browser_function_api
 *
 * This function handles:
 * - OP_CHECK_NEW
 * - OP_TOGGLE_MAILBOXES
 */
static int op_toggle_mailboxes(struct BrowserPrivateData *priv, int op)
{
  if (priv->state.is_mailbox_list)
  {
    priv->last_selected_mailbox = menu_get_index(priv->menu);
  }

  if (op == OP_TOGGLE_MAILBOXES)
  {
    priv->state.is_mailbox_list = !priv->state.is_mailbox_list;
  }

  if (op == OP_BROWSER_GOTO_FOLDER)
  {
    /* When in mailboxes mode, disables this feature */
    const char *const c_folder = cs_subset_string(NeoMutt->sub, "folder");
    if (c_folder)
    {
      mutt_debug(LL_DEBUG3, "= hit! Folder: %s, LastDir: %s\n", c_folder,
                 buf_string(&LastDir));
      if (priv->goto_swapper[0] == '\0')
      {
        if (!mutt_str_equal(buf_string(&LastDir), c_folder))
        {
          /* Stores into goto_swapper LastDir, and swaps to `$folder` */
          mutt_str_copy(priv->goto_swapper, buf_string(&LastDir), sizeof(priv->goto_swapper));
          buf_copy(&LastDirBackup, &LastDir);
          buf_strcpy(&LastDir, c_folder);
        }
      }
      else
      {
        buf_copy(&LastDirBackup, &LastDir);
        buf_strcpy(&LastDir, priv->goto_swapper);
        priv->goto_swapper[0] = '\0';
      }
    }
  }
  destroy_state(&priv->state);
  buf_reset(priv->prefix);
  priv->kill_prefix = false;

  if (priv->state.is_mailbox_list)
  {
    examine_mailboxes(priv->mailbox, priv->menu, &priv->state);
  }
  else if (imap_path_probe(buf_string(&LastDir), NULL) == MUTT_IMAP)
  {
    init_state(&priv->state);
    priv->state.imap_browse = true;
    imap_browse(buf_string(&LastDir), &priv->state);
    browser_sort(&priv->state);
  }
  else if (examine_directory(priv->mailbox, priv->menu, &priv->state,
                             buf_string(&LastDir), buf_string(priv->prefix)) == -1)
  {
    priv->done = true;
    return FR_ERROR;
  }
  init_menu(&priv->state, priv->menu, priv->mailbox, priv->sbar);
  if (priv->state.is_mailbox_list)
    menu_set_index(priv->menu, priv->last_selected_mailbox);
  return FR_ERROR;
}

// -----------------------------------------------------------------------------

/**
 * BrowserFunctions - All the NeoMutt functions that the Browser supports
 */
static const struct BrowserFunction BrowserFunctions[] = {
  // clang-format off
  { OP_BROWSER_GOTO_FOLDER,  op_toggle_mailboxes },
  { OP_BROWSER_NEW_FILE,     op_browser_new_file },
  { OP_BROWSER_SUBSCRIBE,    op_browser_subscribe },
  { OP_BROWSER_TELL,         op_browser_tell },
  { OP_BROWSER_TOGGLE_LSUB,  op_browser_toggle_lsub },
  { OP_BROWSER_UNSUBSCRIBE,  op_browser_subscribe },
  { OP_BROWSER_VIEW_FILE,    op_browser_view_file },
  { OP_CATCHUP,              op_catchup },
  { OP_CHANGE_DIRECTORY,     op_change_directory },
  { OP_CHECK_NEW,            op_toggle_mailboxes },
  { OP_CREATE_MAILBOX,       op_create_mailbox },
  { OP_DELETE_MAILBOX,       op_delete_mailbox },
  { OP_DESCEND_DIRECTORY,    op_generic_select_entry },
  { OP_ENTER_MASK,           op_enter_mask },
  { OP_EXIT,                 op_exit },
  { OP_GENERIC_SELECT_ENTRY, op_generic_select_entry },
  { OP_GOTO_PARENT,          op_change_directory },
  { OP_LOAD_ACTIVE,          op_load_active },
  { OP_MAILBOX_LIST,         op_mailbox_list },
  { OP_RENAME_MAILBOX,       op_rename_mailbox },
  { OP_SORT,                 op_sort },
  { OP_SORT_REVERSE,         op_sort },
  { OP_SUBSCRIBE_PATTERN,    op_subscribe_pattern },
  { OP_TOGGLE_MAILBOXES,     op_toggle_mailboxes },
  { OP_UNCATCHUP,            op_catchup },
  { OP_UNSUBSCRIBE_PATTERN,  op_subscribe_pattern },
  { 0, NULL },
  // clang-format on
};

/**
 * browser_function_dispatcher - Perform a Browser function
 * @param win Window for the Browser
 * @param op  Operation to perform, e.g. OP_GOTO_PARENT
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
int browser_function_dispatcher(struct MuttWindow *win, int op)
{
  // The Dispatcher may be called on any Window in the Dialog
  struct MuttWindow *dlg = dialog_find(win);
  if (!dlg || !dlg->wdata)
    return FR_ERROR;

  struct Menu *menu = dlg->wdata;
  struct BrowserPrivateData *priv = menu->mdata;
  if (!priv)
    return FR_ERROR;

  int rc = FR_UNKNOWN;
  for (size_t i = 0; BrowserFunctions[i].op != OP_NULL; i++)
  {
    const struct BrowserFunction *fn = &BrowserFunctions[i];
    if (fn->op == op)
    {
      rc = fn->function(priv, op);
      break;
    }
  }

  return rc;
}
