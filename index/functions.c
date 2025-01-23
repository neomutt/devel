/**
 * @file
 * Index functions
 *
 * @authors
 * Copyright (C) 2021-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2021-2024 Richard Russon <rich@flatcap.org>
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
 * @page index_functions Index functions
 *
 * Index functions
 */

#include "config.h"
#ifdef _MAKEDOC
#include "docs/makedoc_defs.h"
#else
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "lib.h"
#include "attach/lib.h"
#include "browser/lib.h"
#include "editor/lib.h"
#include "history/lib.h"
#include "imap/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "ncrypt/lib.h"
#include "nntp/lib.h"
#include "pager/lib.h"
#include "pattern/lib.h"
#include "pop/lib.h"
#include "progress/lib.h"
#include "question/lib.h"
#include "send/lib.h"
#include "external.h"
#include "functions.h"
#include "globals.h"
#include "hook.h"
#include "mutt_header.h"
#include "mutt_mailbox.h"
#include "mutt_thread.h"
#include "muttlib.h"
#include "mview.h"
#include "mx.h"
#include "nntp/mdata.h"
#include "private_data.h"
#include "protos.h"
#include "shared_data.h"
#ifdef USE_AUTOCRYPT
#include "autocrypt/lib.h"
#endif
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#endif
#endif

// clang-format off
/**
 * OpIndex - Functions for the Index Menu
 */
const struct MenuFuncOp OpIndex[] = { /* map: index */
  { "alias-dialog",                  OP_ALIAS_DIALOG },
#ifdef USE_AUTOCRYPT
  { "autocrypt-acct-menu",           OP_AUTOCRYPT_ACCT_MENU },
#endif
  { "bounce-message",                OP_BOUNCE_MESSAGE },
  { "break-thread",                  OP_MAIN_BREAK_THREAD },
  { "catchup",                       OP_CATCHUP },
  { "change-folder",                 OP_MAIN_CHANGE_FOLDER },
  { "change-folder-readonly",        OP_MAIN_CHANGE_FOLDER_READONLY },
  { "change-newsgroup",              OP_MAIN_CHANGE_GROUP },
  { "change-newsgroup-readonly",     OP_MAIN_CHANGE_GROUP_READONLY },
#ifdef USE_NOTMUCH
  { "change-vfolder",                OP_MAIN_CHANGE_VFOLDER },
#endif
  { "check-traditional-pgp",         OP_CHECK_TRADITIONAL },
  { "clear-flag",                    OP_MAIN_CLEAR_FLAG },
  { "collapse-all",                  OP_MAIN_COLLAPSE_ALL },
  { "collapse-thread",               OP_MAIN_COLLAPSE_THREAD },
  { "compose-to-sender",             OP_COMPOSE_TO_SENDER },
  { "copy-message",                  OP_COPY_MESSAGE },
  { "create-alias",                  OP_CREATE_ALIAS },
  { "decode-copy",                   OP_DECODE_COPY },
  { "decode-save",                   OP_DECODE_SAVE },
  { "decrypt-copy",                  OP_DECRYPT_COPY },
  { "decrypt-save",                  OP_DECRYPT_SAVE },
  { "delete-message",                OP_DELETE },
  { "delete-pattern",                OP_MAIN_DELETE_PATTERN },
  { "delete-subthread",              OP_DELETE_SUBTHREAD },
  { "delete-thread",                 OP_DELETE_THREAD },
  { "display-address",               OP_DISPLAY_ADDRESS },
  { "display-message",               OP_DISPLAY_MESSAGE },
  { "display-toggle-weed",           OP_DISPLAY_HEADERS },
  { "edit",                          OP_EDIT_RAW_MESSAGE },
  { "edit-label",                    OP_EDIT_LABEL },
  { "edit-or-view-raw-message",      OP_EDIT_OR_VIEW_RAW_MESSAGE },
  { "edit-raw-message",              OP_EDIT_RAW_MESSAGE },
  { "edit-type",                     OP_ATTACHMENT_EDIT_TYPE },
#ifdef USE_NOTMUCH
  { "entire-thread",                 OP_MAIN_ENTIRE_THREAD },
#endif
  { "exit",                          OP_EXIT },
  { "extract-keys",                  OP_EXTRACT_KEYS },
  { "fetch-mail",                    OP_MAIN_FETCH_MAIL },
  { "flag-message",                  OP_FLAG_MESSAGE },
  { "followup-message",              OP_FOLLOWUP },
  { "forget-passphrase",             OP_FORGET_PASSPHRASE },
  { "forward-message",               OP_FORWARD_MESSAGE },
  { "forward-to-group",              OP_FORWARD_TO_GROUP },
  { "get-children",                  OP_GET_CHILDREN },
  { "get-message",                   OP_GET_MESSAGE },
  { "get-parent",                    OP_GET_PARENT },
  { "group-chat-reply",              OP_GROUP_CHAT_REPLY },
  { "group-reply",                   OP_GROUP_REPLY },
  { "imap-fetch-mail",               OP_MAIN_IMAP_FETCH },
  { "imap-logout-all",               OP_MAIN_IMAP_LOGOUT_ALL },
  { "limit",                         OP_MAIN_LIMIT },
  { "limit-current-thread",          OP_LIMIT_CURRENT_THREAD },
  { "link-threads",                  OP_MAIN_LINK_THREADS },
  { "list-reply",                    OP_LIST_REPLY },
  { "list-subscribe",                OP_LIST_SUBSCRIBE },
  { "list-unsubscribe",              OP_LIST_UNSUBSCRIBE },
  { "mail",                          OP_MAIL },
  { "mail-key",                      OP_MAIL_KEY },
  { "mailbox-list",                  OP_MAILBOX_LIST },
  { "mark-message",                  OP_MARK_MSG },
  { "modify-labels",                 OP_MAIN_MODIFY_TAGS },
  { "modify-labels-then-hide",       OP_MAIN_MODIFY_TAGS_THEN_HIDE },
  { "modify-tags",                   OP_MAIN_MODIFY_TAGS },
  { "modify-tags-then-hide",         OP_MAIN_MODIFY_TAGS_THEN_HIDE },
  { "next-new",                      OP_MAIN_NEXT_NEW },
  { "next-new-then-unread",          OP_MAIN_NEXT_NEW_THEN_UNREAD },
  { "next-subthread",                OP_MAIN_NEXT_SUBTHREAD },
  { "next-thread",                   OP_MAIN_NEXT_THREAD },
  { "next-undeleted",                OP_MAIN_NEXT_UNDELETED },
  { "next-unread",                   OP_MAIN_NEXT_UNREAD },
  { "next-unread-mailbox",           OP_MAIN_NEXT_UNREAD_MAILBOX },
  { "parent-message",                OP_MAIN_PARENT_MESSAGE },
  { "pipe-entry",                    OP_PIPE },
  { "pipe-message",                  OP_PIPE },
  { "post-message",                  OP_POST },
  { "previous-new",                  OP_MAIN_PREV_NEW },
  { "previous-new-then-unread",      OP_MAIN_PREV_NEW_THEN_UNREAD },
  { "previous-subthread",            OP_MAIN_PREV_SUBTHREAD },
  { "previous-thread",               OP_MAIN_PREV_THREAD },
  { "previous-undeleted",            OP_MAIN_PREV_UNDELETED },
  { "previous-unread",               OP_MAIN_PREV_UNREAD },
  { "print-message",                 OP_PRINT },
  { "purge-message",                 OP_PURGE_MESSAGE },
  { "purge-thread",                  OP_PURGE_THREAD },
  { "quasi-delete",                  OP_MAIN_QUASI_DELETE },
  { "query",                         OP_QUERY },
  { "quit",                          OP_QUIT },
  { "read-subthread",                OP_MAIN_READ_SUBTHREAD },
  { "read-thread",                   OP_MAIN_READ_THREAD },
  { "recall-message",                OP_RECALL_MESSAGE },
  { "reconstruct-thread",            OP_RECONSTRUCT_THREAD },
  { "reply",                         OP_REPLY },
  { "resend-message",                OP_RESEND },
  { "root-message",                  OP_MAIN_ROOT_MESSAGE },
  { "save-message",                  OP_SAVE },
  { "set-flag",                      OP_MAIN_SET_FLAG },
  { "show-limit",                    OP_MAIN_SHOW_LIMIT },
  { "sidebar-first",                 OP_SIDEBAR_FIRST },
  { "sidebar-last",                  OP_SIDEBAR_LAST },
  { "sidebar-next",                  OP_SIDEBAR_NEXT },
  { "sidebar-next-new",              OP_SIDEBAR_NEXT_NEW },
  { "sidebar-open",                  OP_SIDEBAR_OPEN },
  { "sidebar-page-down",             OP_SIDEBAR_PAGE_DOWN },
  { "sidebar-page-up",               OP_SIDEBAR_PAGE_UP },
  { "sidebar-prev",                  OP_SIDEBAR_PREV },
  { "sidebar-prev-new",              OP_SIDEBAR_PREV_NEW },
  { "sidebar-toggle-virtual",        OP_SIDEBAR_TOGGLE_VIRTUAL },
  { "sidebar-toggle-visible",        OP_SIDEBAR_TOGGLE_VISIBLE },
  { "sidebar-start-search",          OP_SIDEBAR_START_SEARCH },
  { "sort-mailbox",                  OP_SORT },
  { "sort-reverse",                  OP_SORT_REVERSE },
  { "sync-mailbox",                  OP_MAIN_SYNC_FOLDER },
  { "tag-pattern",                   OP_MAIN_TAG_PATTERN },
  { "tag-subthread",                 OP_TAG_SUBTHREAD },
  { "tag-thread",                    OP_TAG_THREAD },
  { "toggle-new",                    OP_TOGGLE_NEW },
  { "toggle-read",                   OP_TOGGLE_READ },
  { "toggle-write",                  OP_TOGGLE_WRITE },
  { "undelete-message",              OP_UNDELETE },
  { "undelete-pattern",              OP_MAIN_UNDELETE_PATTERN },
  { "undelete-subthread",            OP_UNDELETE_SUBTHREAD },
  { "undelete-thread",               OP_UNDELETE_THREAD },
  { "untag-pattern",                 OP_MAIN_UNTAG_PATTERN },
#ifdef USE_NOTMUCH
  { "vfolder-from-query",            OP_MAIN_VFOLDER_FROM_QUERY },
  { "vfolder-from-query-readonly",   OP_MAIN_VFOLDER_FROM_QUERY_READONLY },
  { "vfolder-window-backward",       OP_MAIN_WINDOWED_VFOLDER_BACKWARD },
  { "vfolder-window-forward",        OP_MAIN_WINDOWED_VFOLDER_FORWARD },
  { "vfolder-window-reset",          OP_MAIN_WINDOWED_VFOLDER_RESET },
#endif
  { "view-attachments",              OP_VIEW_ATTACHMENTS },
  { "view-raw-message",              OP_VIEW_RAW_MESSAGE },
  // Deprecated
  { "buffy-list",                    OP_MAILBOX_LIST },
  { NULL, 0 },
};

/**
 * IndexDefaultBindings - Key bindings for the Index Menu
 */
const struct MenuOpSeq IndexDefaultBindings[] = { /* map: index */
  { OP_ATTACHMENT_EDIT_TYPE,               "\005" },           // <Ctrl-E>
#ifdef USE_AUTOCRYPT
  { OP_AUTOCRYPT_ACCT_MENU,                "A" },
#endif
  { OP_BOUNCE_MESSAGE,                     "b" },
  { OP_CHECK_TRADITIONAL,                  "\033P" },          // <Alt-P>
  { OP_COPY_MESSAGE,                       "C" },
  { OP_CREATE_ALIAS,                       "a" },
  { OP_DECODE_COPY,                        "\033C" },          // <Alt-C>
  { OP_DECODE_SAVE,                        "\033s" },          // <Alt-s>
  { OP_DELETE,                             "d" },
  { OP_DELETE_SUBTHREAD,                   "\033d" },          // <Alt-d>
  { OP_DELETE_THREAD,                      "\004" },           // <Ctrl-D>
  { OP_DISPLAY_ADDRESS,                    "@" },
  { OP_DISPLAY_HEADERS,                    "h" },
  { OP_DISPLAY_MESSAGE,                    " " },              // <Space>
  { OP_DISPLAY_MESSAGE,                    "<keypadenter>" },
  { OP_DISPLAY_MESSAGE,                    "\n" },             // <Enter>
  { OP_DISPLAY_MESSAGE,                    "\r" },             // <Return>
  { OP_EDIT_LABEL,                         "Y" },
  { OP_EDIT_OR_VIEW_RAW_MESSAGE,           "e" },
  { OP_EXIT,                               "x" },
  { OP_EXTRACT_KEYS,                       "\013" },           // <Ctrl-K>
  { OP_FLAG_MESSAGE,                       "F" },
  { OP_FORGET_PASSPHRASE,                  "\006" },           // <Ctrl-F>
  { OP_FORWARD_MESSAGE,                    "f" },
  { OP_GROUP_REPLY,                        "g" },
  { OP_LIST_REPLY,                         "L" },
  { OP_MAIL,                               "m" },
  { OP_MAILBOX_LIST,                       "." },
  { OP_MAIL_KEY,                           "\033k" },          // <Alt-k>
  { OP_MAIN_BREAK_THREAD,                  "#" },
  { OP_MAIN_CHANGE_FOLDER,                 "c" },
  { OP_MAIN_CHANGE_FOLDER_READONLY,        "\033c" },          // <Alt-c>
  { OP_MAIN_CHANGE_GROUP,                  "i" },
  { OP_MAIN_CHANGE_GROUP_READONLY,         "\033i" },          // <Alt-i>
  { OP_MAIN_CLEAR_FLAG,                    "W" },
  { OP_MAIN_COLLAPSE_ALL,                  "\033V" },          // <Alt-V>
  { OP_MAIN_COLLAPSE_THREAD,               "\033v" },          // <Alt-v>
  { OP_MAIN_DELETE_PATTERN,                "D" },
  { OP_MAIN_FETCH_MAIL,                    "G" },
  { OP_MAIN_LIMIT,                         "l" },
  { OP_MAIN_LINK_THREADS,                  "&" },
  { OP_MAIN_NEXT_NEW_THEN_UNREAD,          "\t" },             // <Tab>
  { OP_MAIN_NEXT_SUBTHREAD,                "\033n" },          // <Alt-n>
  { OP_MAIN_NEXT_THREAD,                   "\016" },           // <Ctrl-N>
  { OP_MAIN_NEXT_UNDELETED,                "<down>" },
  { OP_MAIN_NEXT_UNDELETED,                "j" },
  { OP_MAIN_PARENT_MESSAGE,                "P" },
  { OP_MAIN_PREV_NEW_THEN_UNREAD,          "\033\t" },         // <Alt-\>
  { OP_MAIN_PREV_SUBTHREAD,                "\033p" },          // <Alt-p>
  { OP_MAIN_PREV_THREAD,                   "\020" },           // <Ctrl-P>
  { OP_MAIN_PREV_UNDELETED,                "<up>" },
  { OP_MAIN_PREV_UNDELETED,                "k" },
  { OP_MAIN_READ_SUBTHREAD,                "\033r" },          // <Alt-r>
  { OP_MAIN_READ_THREAD,                   "\022" },           // <Ctrl-R>
  { OP_MAIN_SET_FLAG,                      "w" },
  { OP_MAIN_SHOW_LIMIT,                    "\033l" },          // <Alt-l>
  { OP_MAIN_SYNC_FOLDER,                   "$" },
  { OP_MAIN_TAG_PATTERN,                   "T" },
  { OP_MAIN_UNDELETE_PATTERN,              "U" },
  { OP_MAIN_UNTAG_PATTERN,                 "\024" },           // <Ctrl-T>
  { OP_MARK_MSG,                           "~" },
  { OP_NEXT_ENTRY,                         "J" },
  { OP_PIPE,                               "|" },
  { OP_PREV_ENTRY,                         "K" },
  { OP_PRINT,                              "p" },
  { OP_QUERY,                              "Q" },
  { OP_QUIT,                               "q" },
  { OP_RECALL_MESSAGE,                     "R" },
  { OP_REPLY,                              "r" },
  { OP_RESEND,                             "\033e" },          // <Alt-e>
  { OP_SAVE,                               "s" },
  { OP_SHOW_LOG_MESSAGES,                  "M" },
  { OP_SORT,                               "o" },
  { OP_SORT_REVERSE,                       "O" },
  { OP_TAG_THREAD,                         "\033t" },          // <Alt-t>
  { OP_TOGGLE_NEW,                         "N" },
  { OP_TOGGLE_WRITE,                       "%" },
  { OP_UNDELETE,                           "u" },
  { OP_UNDELETE_SUBTHREAD,                 "\033u" },          // <Alt-u>
  { OP_UNDELETE_THREAD,                    "\025" },           // <Ctrl-U>
  { OP_VIEW_ATTACHMENTS,                   "v" },
  { 0, NULL },
};
// clang-format on

/**
 * enum ResolveMethod - How to advance the cursor
 */
enum ResolveMethod
{
  RESOLVE_NEXT_EMAIL,     ///< Next email, whatever its state
  RESOLVE_NEXT_UNDELETED, ///< Next undeleted email
  RESOLVE_NEXT_THREAD,    ///< Next top-level thread
  RESOLVE_NEXT_SUBTHREAD, ///< Next sibling sub-thread
};

/**
 * resolve_email - Pick the next Email to advance the cursor to
 * @param priv   Private Index data
 * @param shared Shared Index data
 * @param rm     How to advance the cursor, e.g. #RESOLVE_NEXT_EMAIL
 * @retval true Resolve succeeded
 */
static bool resolve_email(struct IndexPrivateData *priv,
                          struct IndexSharedData *shared, enum ResolveMethod rm)
{
  if (!priv || !priv->menu || !shared || !shared->mailbox || !shared->email)
    return false;

  const bool c_resolve = cs_subset_bool(shared->sub, "resolve");
  if (!c_resolve)
    return false;

  int index = -1;
  switch (rm)
  {
    case RESOLVE_NEXT_EMAIL:
      index = menu_get_index(priv->menu) + 1;
      break;

    case RESOLVE_NEXT_UNDELETED:
    {
      const bool uncollapse = mutt_using_threads() && !window_is_focused(priv->win_index);
      index = find_next_undeleted(shared->mailbox_view, menu_get_index(priv->menu), uncollapse);
      break;
    }

    case RESOLVE_NEXT_THREAD:
      index = mutt_next_thread(shared->email);
      break;

    case RESOLVE_NEXT_SUBTHREAD:
      index = mutt_next_subthread(shared->email);
      break;
  }

  if ((index < 0) || (index >= shared->mailbox->vcount))
  {
    // Resolve failed
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    return false;
  }

  menu_set_index(priv->menu, index);
  return true;
}

/**
 * index_next_undeleted - Select the next undeleted Email (if possible)
 * @param win_index Index Window
 * @retval true Selection succeeded
 */
bool index_next_undeleted(struct MuttWindow *win_index)
{
  struct MuttWindow *dlg = dialog_find(win_index);
  if (!dlg)
    return false;

  struct Menu *menu = win_index->wdata;
  struct IndexSharedData *shared = dlg->wdata;
  if (!shared)
    return false;

  struct IndexPrivateData *priv = win_index->parent->wdata;
  const bool uncollapse = mutt_using_threads() && !window_is_focused(priv->win_index);

  int index = find_next_undeleted(shared->mailbox_view, menu_get_index(menu), uncollapse);
  if ((index < 0) || (index >= shared->mailbox->vcount))
  {
    // Selection failed
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    return false;
  }

  menu_set_index(menu, index);
  return true;
}

// -----------------------------------------------------------------------------

/**
 * op_alias_dialog - Open the aliases dialog - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_alias_dialog(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  alias_dialog(shared->mailbox, shared->sub);
  return FR_SUCCESS;
}

/**
 * op_attachment_edit_type - Edit attachment content type - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_attachment_edit_type(struct IndexSharedData *shared,
                                   struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  mutt_edit_content_type(shared->email, shared->email->body, NULL);

  menu_queue_redraw(priv->menu, MENU_REDRAW_CURRENT);
  return FR_SUCCESS;
}

/**
 * op_bounce_message - Remail a message to another user - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_bounce_message(struct IndexSharedData *shared,
                             struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  index_bounce_message(shared->mailbox, &ea);
  ARRAY_FREE(&ea);

  return FR_SUCCESS;
}

/**
 * op_check_traditional - Check for classic PGP - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_check_traditional(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  if (!(WithCrypto & APPLICATION_PGP))
    return FR_NOT_IMPL;
  if (!shared->email)
    return FR_NO_ACTION;

  if (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED))
  {
    struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
    ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    ARRAY_FREE(&ea);
  }

  return FR_SUCCESS;
}

/**
 * op_compose_to_sender - Compose new message to the current message sender - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_compose_to_sender(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  int rc = mutt_send_message(SEND_TO_SENDER, NULL, NULL, shared->mailbox, &ea,
                             shared->sub);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_create_alias - Create an alias from a message sender - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_create_alias(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  struct AddressList *al = NULL;
  if (shared->email && shared->email->env)
    al = mutt_get_address(shared->email->env, NULL);
  alias_create(al, shared->sub);
  menu_queue_redraw(priv->menu, MENU_REDRAW_CURRENT);

  return FR_SUCCESS;
}

/**
 * op_delete - Delete the current entry - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_DELETE
 * - OP_PURGE_MESSAGE
 */
static int op_delete(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't delete message")))
    return FR_ERROR;

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);

  mutt_emails_set_flag(shared->mailbox, &ea, MUTT_DELETE, true);
  mutt_emails_set_flag(shared->mailbox, &ea, MUTT_PURGE, (op == OP_PURGE_MESSAGE));
  const bool c_delete_untag = cs_subset_bool(shared->sub, "delete_untag");
  if (c_delete_untag)
    mutt_emails_set_flag(shared->mailbox, &ea, MUTT_TAG, false);
  ARRAY_FREE(&ea);

  if (priv->tag_prefix)
  {
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  }

  return FR_SUCCESS;
}

/**
 * op_delete_thread - Delete all messages in thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_DELETE_SUBTHREAD
 * - OP_DELETE_THREAD
 * - OP_PURGE_THREAD
 */
static int op_delete_thread(struct IndexSharedData *shared,
                            struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     delete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
    return FR_ERROR;
  if (!shared->email)
    return FR_NO_ACTION;

  int subthread = (op == OP_DELETE_SUBTHREAD);
  int rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_DELETE, true, subthread);
  if (rc == -1)
    return FR_ERROR;
  if (op == OP_PURGE_THREAD)
  {
    rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_PURGE, true, subthread);
    if (rc == -1)
      return FR_ERROR;
  }

  const bool c_delete_untag = cs_subset_bool(shared->sub, "delete_untag");
  if (c_delete_untag)
    mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_TAG, false, subthread);

  resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  return FR_SUCCESS;
}

/**
 * op_display_address - Display full address of sender - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_display_address(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  mutt_display_address(shared->email->env);

  return FR_SUCCESS;
}

/**
 * op_display_message - Display a message - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_DISPLAY_HEADERS
 * - OP_DISPLAY_MESSAGE
 */
static int op_display_message(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  /* toggle the weeding of headers so that a user can press the key
   * again while reading the message.  */
  if (op == OP_DISPLAY_HEADERS)
  {
    bool_str_toggle(shared->sub, "weed", NULL);
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, shared);
    if (!window_is_focused(priv->win_index))
      return FR_SUCCESS;
  }

  OptNeedResort = false;

  if (mutt_using_threads() && shared->email->collapsed)
  {
    mutt_uncollapse_thread(shared->email);
    mutt_set_vnum(shared->mailbox);
    const bool c_uncollapse_jump = cs_subset_bool(shared->sub, "uncollapse_jump");
    if (c_uncollapse_jump)
      menu_set_index(priv->menu, mutt_thread_next_unread(shared->email));
  }

  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
    ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    ARRAY_FREE(&ea);
  }
  const int index = menu_get_index(priv->menu);
  index_shared_data_set_email(shared, mutt_get_virt_email(shared->mailbox, index));

  const char *const c_pager = pager_get_pager(NeoMutt->sub);
  if (c_pager)
  {
    op = external_pager(shared->mailbox_view, shared->email, c_pager);
  }
  else
  {
    op = mutt_display_message(priv->win_index, shared);
  }

  window_set_focus(priv->win_index);
  if (op < OP_NULL)
  {
    OptNeedResort = false;
    return FR_ERROR;
  }

  if (shared->mailbox)
  {
    update_index(priv->menu, shared->mailbox_view, MX_STATUS_NEW_MAIL,
                 shared->mailbox->msg_count, shared);
  }

  return op;
}

/**
 * op_edit_label - Add, change, or delete a message's label - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_edit_label(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  int num_changed = mutt_label_message(shared->mailbox_view, &ea);
  ARRAY_FREE(&ea);

  if (num_changed > 0)
  {
    shared->mailbox->changed = true;
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    /* L10N: This is displayed when the x-label on one or more
       messages is edited. */
    mutt_message(ngettext("%d label changed", "%d labels changed", num_changed), num_changed);

    if (!priv->tag_prefix)
      resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
    return FR_SUCCESS;
  }

  /* L10N: This is displayed when editing an x-label, but no messages
     were updated.  Possibly due to canceling at the prompt or if the new
     label is the same as the old label. */
  mutt_message(_("No labels changed"));
  return FR_NO_ACTION;
}

/**
 * op_edit_raw_message - Edit the raw message (edit and edit-raw-message are synonyms) - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_EDIT_OR_VIEW_RAW_MESSAGE
 * - OP_EDIT_RAW_MESSAGE
 * - OP_VIEW_RAW_MESSAGE
 */
static int op_edit_raw_message(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  /* TODO split this into 3 cases? */
  bool edit;
  if (op == OP_EDIT_RAW_MESSAGE)
  {
    /* L10N: CHECK_ACL */
    if (!check_acl(shared->mailbox, MUTT_ACL_INSERT, _("Can't edit message")))
      return FR_ERROR;
    edit = true;
  }
  else if (op == OP_EDIT_OR_VIEW_RAW_MESSAGE)
  {
    edit = !shared->mailbox->readonly && (shared->mailbox->rights & MUTT_ACL_INSERT);
  }
  else
  {
    edit = false;
  }

  if (!shared->email)
    return FR_NO_ACTION;
  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
    ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    ARRAY_FREE(&ea);
  }
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  mutt_ev_message(shared->mailbox, &ea, edit ? EVM_EDIT : EVM_VIEW);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return FR_SUCCESS;
}

/**
 * op_end_cond - End of conditional execution (noop) - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_end_cond(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  return FR_SUCCESS;
}

/**
 * op_exit - Exit this menu - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_exit(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (shared->attach_msg)
    return FR_DONE;

  if (query_quadoption(_("Exit NeoMutt without saving?"), shared->sub, "quit") == MUTT_YES)
  {
    if (shared->mailbox_view)
    {
      mx_fastclose_mailbox(shared->mailbox, false);
      mview_free(&shared->mailbox_view);
    }
    return FR_DONE;
  }

  return FR_NO_ACTION;
}

/**
 * op_extract_keys - Extract supported public keys - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_extract_keys(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  if (!WithCrypto)
    return FR_NOT_IMPL;
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  crypt_extract_keys_from_messages(shared->mailbox, &ea);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return FR_SUCCESS;
}

/**
 * op_flag_message - Toggle a message's 'important' flag - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_flag_message(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(shared->mailbox, MUTT_ACL_WRITE, _("Can't flag message")))
    return FR_ERROR;

  struct Mailbox *m = shared->mailbox;
  if (priv->tag_prefix)
  {
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(e))
        mutt_set_flag(m, e, MUTT_FLAG, !e->flagged, true);
    }

    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    if (!shared->email)
      return FR_NO_ACTION;
    mutt_set_flag(m, shared->email, MUTT_FLAG, !shared->email->flagged, true);

    resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  }

  return FR_SUCCESS;
}

/**
 * op_forget_passphrase - Wipe passphrases from memory - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_forget_passphrase(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  crypt_forget_passphrase();
  return FR_SUCCESS;
}

/**
 * op_forward_message - Forward a message with comments - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_forward_message(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  int rc = mutt_send_message(SEND_FORWARD, NULL, NULL, shared->mailbox, &ea,
                             shared->sub);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_group_reply - Reply to all recipients - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_GROUP_CHAT_REPLY
 * - OP_GROUP_REPLY
 */
static int op_group_reply(struct IndexSharedData *shared,
                          struct IndexPrivateData *priv, int op)
{
  SendFlags replyflags = SEND_REPLY;
  if (op == OP_GROUP_REPLY)
    replyflags |= SEND_GROUP_REPLY;
  else
    replyflags |= SEND_GROUP_CHAT_REPLY;
  if (!shared->email)
    return FR_NO_ACTION;
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  int rc = mutt_send_message(replyflags, NULL, NULL, shared->mailbox, &ea,
                             shared->sub);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_jump - Jump to an index number - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_jump(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  int rc = FR_ERROR;
  struct Buffer *buf = buf_pool_get();

  const int digit = op - OP_JUMP;
  if ((digit > 0) && (digit < 10))
  {
    mutt_unget_ch('0' + digit);
  }

  int msg_num = 0;
  if ((mw_get_field(_("Jump to message: "), buf, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0) ||
      buf_is_empty(buf))
  {
    mutt_message(_("Nothing to do"));
    rc = FR_NO_ACTION;
  }
  else if (!mutt_str_atoi_full(buf_string(buf), &msg_num))
  {
    mutt_warning(_("Argument must be a message number"));
  }
  else if ((msg_num < 1) || (msg_num > shared->mailbox->msg_count))
  {
    mutt_warning(_("Invalid message number"));
  }
  else if (!shared->mailbox->emails[msg_num - 1]->visible)
  {
    mutt_warning(_("That message is not visible"));
  }
  else
  {
    struct Email *e = shared->mailbox->emails[msg_num - 1];

    if (mutt_messages_in_thread(shared->mailbox, e, MIT_POSITION) > 1)
    {
      mutt_uncollapse_thread(e);
      mutt_set_vnum(shared->mailbox);
    }
    menu_set_index(priv->menu, e->vnum);
    rc = FR_SUCCESS;
  }

  buf_pool_release(&buf);
  return rc;
}

/**
 * op_list_reply - Reply to specified mailing list - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_list_reply(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  int rc = mutt_send_message(SEND_REPLY | SEND_LIST_REPLY, NULL, NULL,
                             shared->mailbox, &ea, shared->sub);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_list_subscribe - Subscribe to a mailing list - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_list_subscribe(struct IndexSharedData *shared,
                             struct IndexPrivateData *priv, int op)
{
  return mutt_send_list_subscribe(shared->mailbox, shared->email) ? FR_SUCCESS : FR_NO_ACTION;
}

/**
 * op_list_unsubscribe - Unsubscribe from mailing list - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_list_unsubscribe(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  return mutt_send_list_unsubscribe(shared->mailbox, shared->email) ? FR_SUCCESS : FR_NO_ACTION;
}

/**
 * op_mail - Compose a new mail message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_mail(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  int rc = mutt_send_message(SEND_NO_FLAGS, NULL, NULL, shared->mailbox, NULL,
                             shared->sub);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_mailbox_list - List mailboxes with new mail - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_mailbox_list(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  mutt_mailbox_list();
  return FR_SUCCESS;
}

/**
 * op_mail_key - Mail a PGP public key - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_mail_key(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!(WithCrypto & APPLICATION_PGP))
    return FR_NOT_IMPL;
  int rc = mutt_send_message(SEND_KEY, NULL, NULL, NULL, NULL, shared->sub);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_main_break_thread - Break the thread in two - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_break_thread(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;
  /* L10N: CHECK_ACL */
  if (!check_acl(m, MUTT_ACL_WRITE, _("Can't break thread")))
    return FR_ERROR;

  struct Email *e = shared->email;
  if (!e)
    return FR_NO_ACTION;

  if (!mutt_using_threads())
  {
    mutt_warning(_("Threading is not enabled"));
    return FR_NO_ACTION;
  }

  struct MailboxView *mv = shared->mailbox_view;
  if (!STAILQ_EMPTY(&e->env->in_reply_to) || !STAILQ_EMPTY(&e->env->references))
  {
    {
      mutt_break_thread(e);
      mutt_sort_headers(mv, true);
      menu_set_index(priv->menu, e->vnum);
    }

    m->changed = true;
    mutt_message(_("Thread broken"));

    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    mutt_error(_("Thread can't be broken, message is not part of a thread"));
  }

  return FR_SUCCESS;
}

/**
 * op_main_change_folder - Open a different folder - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_CHANGE_FOLDER
 * - OP_MAIN_CHANGE_FOLDER_READONLY
 * - OP_MAIN_CHANGE_VFOLDER
 */
static int op_main_change_folder(struct IndexSharedData *shared,
                                 struct IndexPrivateData *priv, int op)
{
  struct Buffer *folderbuf = buf_pool_get();
  buf_alloc(folderbuf, PATH_MAX);

  char *cp = NULL;
  bool read_only;
  const bool c_read_only = cs_subset_bool(shared->sub, "read_only");
  if (shared->attach_msg || c_read_only || (op == OP_MAIN_CHANGE_FOLDER_READONLY))
  {
    cp = _("Open mailbox in read-only mode");
    read_only = true;
  }
  else
  {
    cp = _("Open mailbox");
    read_only = false;
  }

  const bool c_change_folder_next = cs_subset_bool(shared->sub, "change_folder_next");
  if (c_change_folder_next && shared->mailbox && !buf_is_empty(&shared->mailbox->pathbuf))
  {
    buf_strcpy(folderbuf, mailbox_path(shared->mailbox));
    buf_pretty_mailbox(folderbuf);
  }
  /* By default, fill buf with the next mailbox that contains unread mail */
  mutt_mailbox_next(shared->mailbox_view ? shared->mailbox : NULL, folderbuf);

  if (mw_enter_fname(cp, folderbuf, true, shared->mailbox, false, NULL, NULL,
                     MUTT_SEL_NO_FLAGS) == -1)
  {
    goto changefoldercleanup;
  }

  /* Selected directory is okay, let's save it. */
  mutt_browser_select_dir(buf_string(folderbuf));

  if (buf_is_empty(folderbuf))
  {
    msgwin_clear_text(NULL);
    goto changefoldercleanup;
  }

  struct Mailbox *m = mx_mbox_find2(buf_string(folderbuf));
  if (m)
  {
    change_folder_mailbox(priv->menu, m, &priv->oldcount, shared, read_only);
  }
  else
  {
    change_folder_string(priv->menu, folderbuf, &priv->oldcount, shared, read_only);
  }

changefoldercleanup:
  buf_pool_release(&folderbuf);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return FR_SUCCESS;
}

/**
 * op_main_collapse_all - Collapse/uncollapse all threads - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_collapse_all(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  if (!mutt_using_threads())
  {
    mutt_error(_("Threading is not enabled"));
    return FR_ERROR;
  }
  collapse_all(shared->mailbox_view, priv->menu, 1);

  return FR_SUCCESS;
}

/**
 * op_main_collapse_thread - Collapse/uncollapse current thread - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_collapse_thread(struct IndexSharedData *shared,
                                   struct IndexPrivateData *priv, int op)
{
  if (!mutt_using_threads())
  {
    mutt_error(_("Threading is not enabled"));
    return FR_ERROR;
  }

  if (!shared->email)
    return FR_NO_ACTION;

  if (shared->email->collapsed)
  {
    int index = mutt_uncollapse_thread(shared->email);
    mutt_set_vnum(shared->mailbox);
    const bool c_uncollapse_jump = cs_subset_bool(shared->sub, "uncollapse_jump");
    if (c_uncollapse_jump)
      index = mutt_thread_next_unread(shared->email);
    menu_set_index(priv->menu, index);
  }
  else if (mutt_thread_can_collapse(shared->email))
  {
    menu_set_index(priv->menu, mutt_collapse_thread(shared->email));
    mutt_set_vnum(shared->mailbox);
  }
  else
  {
    mutt_error(_("Thread contains unread or flagged messages"));
    return FR_ERROR;
  }

  menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return FR_SUCCESS;
}

/**
 * op_main_delete_pattern - Delete messages matching a pattern - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_delete_pattern(struct IndexSharedData *shared,
                                  struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     delete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this.  */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
    return FR_ERROR;

  mutt_pattern_func(shared->mailbox_view, MUTT_DELETE, _("Delete messages matching: "));
  menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return FR_SUCCESS;
}

/**
 * op_main_limit - Limit view to a pattern/thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_LIMIT_CURRENT_THREAD
 * - OP_MAIN_LIMIT
 * - OP_TOGGLE_READ
 */
static int op_main_limit(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  const bool lmt = mview_has_limit(shared->mailbox_view);
  int old_index = shared->email ? shared->email->index : -1;
  if (op == OP_TOGGLE_READ)
  {
    char buf2[1024] = { 0 };

    if (!lmt || !mutt_strn_equal(shared->mailbox_view->pattern, "!~R!~D~s", 8))
    {
      snprintf(buf2, sizeof(buf2), "!~R!~D~s%s", lmt ? shared->mailbox_view->pattern : ".*");
    }
    else
    {
      mutt_str_copy(buf2, shared->mailbox_view->pattern + 8, sizeof(buf2));
      if ((*buf2 == '\0') || mutt_strn_equal(buf2, ".*", 2))
        snprintf(buf2, sizeof(buf2), "~A");
    }
    mutt_str_replace(&shared->mailbox_view->pattern, buf2);
    mutt_pattern_func(shared->mailbox_view, MUTT_LIMIT, NULL);
  }

  if (((op == OP_LIMIT_CURRENT_THREAD) &&
       mutt_limit_current_thread(shared->mailbox_view, shared->email)) ||
      (op == OP_TOGGLE_READ) ||
      ((op == OP_MAIN_LIMIT) && (mutt_pattern_func(shared->mailbox_view, MUTT_LIMIT,
                                                   _("Limit to messages matching: ")) == 0)))
  {
    priv->menu->max = shared->mailbox->vcount;
    menu_set_index(priv->menu, 0);
    if (old_index >= 0)
    {
      /* try to find what used to be the current message */
      for (size_t i = 0; i < shared->mailbox->vcount; i++)
      {
        struct Email *e = mutt_get_virt_email(shared->mailbox, i);
        if (!e)
          continue;
        if (e->index == old_index)
        {
          menu_set_index(priv->menu, i);
          break;
        }
      }
    }

    if ((shared->mailbox->msg_count != 0) && mutt_using_threads())
    {
      const bool c_collapse_all = cs_subset_bool(shared->sub, "collapse_all");
      if (c_collapse_all)
        collapse_all(shared->mailbox_view, priv->menu, 0);
      mutt_draw_tree(shared->mailbox_view->threads);
    }
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  if (lmt)
    mutt_message(_("To view all messages, limit to \"all\""));

  return FR_SUCCESS;
}

/**
 * op_main_link_threads - Link tagged message to the current one - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_link_threads(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;
  /* L10N: CHECK_ACL */
  if (!check_acl(m, MUTT_ACL_WRITE, _("Can't link threads")))
    return FR_ERROR;

  struct Email *e = shared->email;
  if (!e)
    return FR_NO_ACTION;

  enum FunctionRetval rc = FR_ERROR;

  if (!mutt_using_threads())
  {
    mutt_error(_("Threading is not enabled"));
  }
  else if (!e->env->message_id)
  {
    mutt_error(_("No Message-ID: header available to link thread"));
  }
  else
  {
    struct MailboxView *mv = shared->mailbox_view;
    struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
    ea_add_tagged(&ea, mv, NULL, true);

    if (mutt_link_threads(e, &ea, m))
    {
      mutt_sort_headers(mv, true);
      menu_set_index(priv->menu, e->vnum);

      m->changed = true;
      mutt_message(_("Threads linked"));
      rc = FR_SUCCESS;
    }
    else
    {
      mutt_error(_("No thread linked"));
      rc = FR_NO_ACTION;
    }

    ARRAY_FREE(&ea);
  }

  menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  return rc;
}

/**
 * op_main_modify_tags - Modify (notmuch/imap) tags - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_MODIFY_TAGS
 * - OP_MAIN_MODIFY_TAGS_THEN_HIDE
 */
static int op_main_modify_tags(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  int rc = FR_ERROR;
  struct Buffer *buf = NULL;

  if (!shared->mailbox)
    goto done;
  struct Mailbox *m = shared->mailbox;
  if (!mx_tags_is_supported(m))
  {
    mutt_message(_("Folder doesn't support tagging, aborting"));
    goto done;
  }
  if (!shared->email)
  {
    rc = FR_NO_ACTION;
    goto done;
  }

  struct Buffer *tags = buf_pool_get();
  if (!priv->tag_prefix)
    driver_tags_get_with_hidden(&shared->email->tags, tags);
  buf = buf_pool_get();
  int rc2 = mx_tags_edit(m, buf_string(tags), buf);
  buf_pool_release(&tags);
  if (rc2 < 0)
  {
    goto done;
  }
  else if (rc2 == 0)
  {
    mutt_message(_("No tag specified, aborting"));
    goto done;
  }

  if (priv->tag_prefix)
  {
    struct Progress *progress = NULL;

    if (m->verbose)
    {
      progress = progress_new(MUTT_PROGRESS_WRITE, m->msg_tagged);
      progress_set_message(progress, _("Update tags..."));
    }

#ifdef USE_NOTMUCH
    if (m->type == MUTT_NOTMUCH)
      nm_db_longrun_init(m, true);
#endif
    for (int px = 0, i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (!message_is_tagged(e))
        continue;

      progress_update(progress, ++px, -1);
      mx_tags_commit(m, e, buf_string(buf));
      e->attr_color = NULL;
      if (op == OP_MAIN_MODIFY_TAGS_THEN_HIDE)
      {
        bool still_queried = false;
#ifdef USE_NOTMUCH
        if (m->type == MUTT_NOTMUCH)
          still_queried = nm_message_is_still_queried(m, e);
#endif
        e->quasi_deleted = !still_queried;
        m->changed = true;
      }
    }
    progress_free(&progress);
#ifdef USE_NOTMUCH
    if (m->type == MUTT_NOTMUCH)
      nm_db_longrun_done(m);
#endif
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    if (mx_tags_commit(m, shared->email, buf_string(buf)))
    {
      mutt_message(_("Failed to modify tags, aborting"));
      goto done;
    }
    shared->email->attr_color = NULL;
    if (op == OP_MAIN_MODIFY_TAGS_THEN_HIDE)
    {
      bool still_queried = false;
#ifdef USE_NOTMUCH
      if (m->type == MUTT_NOTMUCH)
        still_queried = nm_message_is_still_queried(m, shared->email);
#endif
      shared->email->quasi_deleted = !still_queried;
      m->changed = true;
    }

    resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  }
  rc = FR_SUCCESS;

done:
  buf_pool_release(&buf);
  return rc;
}

/**
 * op_main_next_new - Jump to the next new message - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_NEXT_NEW
 * - OP_MAIN_NEXT_NEW_THEN_UNREAD
 * - OP_MAIN_NEXT_UNREAD
 * - OP_MAIN_PREV_NEW
 * - OP_MAIN_PREV_NEW_THEN_UNREAD
 * - OP_MAIN_PREV_UNREAD
 */
static int op_main_next_new(struct IndexSharedData *shared,
                            struct IndexPrivateData *priv, int op)
{
  int first_unread = -1;
  int first_new = -1;

  const int saved_current = menu_get_index(priv->menu);
  int mcur = saved_current;
  int index = -1;
  const bool threaded = mutt_using_threads();
  for (size_t i = 0; i != shared->mailbox->vcount; i++)
  {
    if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_NEXT_UNREAD) ||
        (op == OP_MAIN_NEXT_NEW_THEN_UNREAD))
    {
      mcur++;
      if (mcur > (shared->mailbox->vcount - 1))
      {
        mcur = 0;
      }
    }
    else
    {
      mcur--;
      if (mcur < 0)
      {
        mcur = shared->mailbox->vcount - 1;
      }
    }

    struct Email *e = mutt_get_virt_email(shared->mailbox, mcur);
    if (!e)
      break;
    if (e->collapsed && threaded)
    {
      int unread = mutt_thread_contains_unread(e);
      if ((unread != 0) && (first_unread == -1))
        first_unread = mcur;
      if ((unread == 1) && (first_new == -1))
        first_new = mcur;
    }
    else if (!e->deleted && !e->read)
    {
      if (first_unread == -1)
        first_unread = mcur;
      if (!e->old && (first_new == -1))
        first_new = mcur;
    }

    if (((op == OP_MAIN_NEXT_UNREAD) || (op == OP_MAIN_PREV_UNREAD)) && (first_unread != -1))
    {
      break;
    }
    if (((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW) ||
         (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
        (first_new != -1))
    {
      break;
    }
  }
  if (((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW) ||
       (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
      (first_new != -1))
  {
    index = first_new;
  }
  else if (((op == OP_MAIN_NEXT_UNREAD) || (op == OP_MAIN_PREV_UNREAD) ||
            (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
           (first_unread != -1))
  {
    index = first_unread;
  }

  if (index == -1)
  {
    menu_set_index(priv->menu, saved_current);
    if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW))
    {
      if (mview_has_limit(shared->mailbox_view))
        mutt_error(_("No new messages in this limited view"));
      else
        mutt_error(_("No new messages"));
    }
    else
    {
      if (mview_has_limit(shared->mailbox_view))
        mutt_error(_("No unread messages in this limited view"));
      else
        mutt_error(_("No unread messages"));
    }
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    return FR_ERROR;
  }
  else
  {
    menu_set_index(priv->menu, index);
  }

  index = menu_get_index(priv->menu);
  if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_NEXT_UNREAD) ||
      (op == OP_MAIN_NEXT_NEW_THEN_UNREAD))
  {
    if (saved_current > index)
    {
      mutt_message(_("Search wrapped to top"));
    }
  }
  else if (saved_current < index)
  {
    mutt_message(_("Search wrapped to bottom"));
  }

  return FR_SUCCESS;
}

/**
 * op_main_next_thread - Jump to the next thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_NEXT_SUBTHREAD
 * - OP_MAIN_NEXT_THREAD
 * - OP_MAIN_PREV_SUBTHREAD
 * - OP_MAIN_PREV_THREAD
 */
static int op_main_next_thread(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  int index = -1;
  switch (op)
  {
    case OP_MAIN_NEXT_THREAD:
      index = mutt_next_thread(shared->email);
      break;

    case OP_MAIN_NEXT_SUBTHREAD:
      index = mutt_next_subthread(shared->email);
      break;

    case OP_MAIN_PREV_THREAD:
      index = mutt_previous_thread(shared->email);
      break;

    case OP_MAIN_PREV_SUBTHREAD:
      index = mutt_previous_subthread(shared->email);
      break;
  }

  if (index != -1)
    menu_set_index(priv->menu, index);

  if (index < 0)
  {
    if ((op == OP_MAIN_NEXT_THREAD) || (op == OP_MAIN_NEXT_SUBTHREAD))
      mutt_error(_("No more threads"));
    else
      mutt_error(_("You are on the first thread"));

    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
  }

  return FR_SUCCESS;
}

/**
 * op_main_next_undeleted - Move to the next undeleted message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_next_undeleted(struct IndexSharedData *shared,
                                  struct IndexPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  if (index >= (shared->mailbox->vcount - 1))
  {
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    mutt_message(_("You are on the last message"));
    return FR_ERROR;
  }

  const bool uncollapse = mutt_using_threads() && !window_is_focused(priv->win_index);

  index = find_next_undeleted(shared->mailbox_view, index, uncollapse);
  if (index != -1)
  {
    menu_set_index(priv->menu, index);
    if (uncollapse)
      menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  if (index == -1)
  {
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    mutt_error(_("No undeleted messages"));
  }

  return FR_SUCCESS;
}

/**
 * op_main_next_unread_mailbox - Open next mailbox with unread mail - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_next_unread_mailbox(struct IndexSharedData *shared,
                                       struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;

  struct Buffer *folderbuf = buf_pool_get();
  buf_strcpy(folderbuf, mailbox_path(m));
  m = mutt_mailbox_next_unread(m, folderbuf);
  buf_pool_release(&folderbuf);

  if (!m)
  {
    mutt_error(_("No mailboxes have new mail"));
    return FR_ERROR;
  }

  change_folder_mailbox(priv->menu, m, &priv->oldcount, shared, false);
  return FR_SUCCESS;
}

/**
 * op_main_prev_undeleted - Move to the previous undeleted message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_prev_undeleted(struct IndexSharedData *shared,
                                  struct IndexPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  if (index < 1)
  {
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    mutt_message(_("You are on the first message"));
    return FR_ERROR;
  }

  const bool uncollapse = mutt_using_threads() && !window_is_focused(priv->win_index);

  index = find_previous_undeleted(shared->mailbox_view, index, uncollapse);
  if (index != -1)
  {
    menu_set_index(priv->menu, index);
    if (uncollapse)
      menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  if (index == -1)
  {
    mutt_error(_("No undeleted messages"));
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
  }

  return FR_SUCCESS;
}

/**
 * op_main_quasi_delete - Delete from NeoMutt, don't touch on disk - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_quasi_delete(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  if (priv->tag_prefix)
  {
    struct Mailbox *m = shared->mailbox;
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(e))
      {
        e->quasi_deleted = true;
        m->changed = true;
      }
    }
  }
  else
  {
    if (!shared->email)
      return FR_NO_ACTION;
    shared->email->quasi_deleted = true;
    shared->mailbox->changed = true;
  }

  return FR_SUCCESS;
}

/**
 * op_main_read_thread - Mark the current thread as read - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_READ_SUBTHREAD
 * - OP_MAIN_READ_THREAD
 */
static int op_main_read_thread(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     mark zero, 1, 12, ... messages as read. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(shared->mailbox, MUTT_ACL_SEEN, _("Can't mark messages as read")))
    return FR_ERROR;

  int rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_READ, true,
                                (op != OP_MAIN_READ_THREAD));
  if (rc != -1)
  {
    const enum ResolveMethod rm = (op == OP_MAIN_READ_THREAD) ? RESOLVE_NEXT_THREAD :
                                                                RESOLVE_NEXT_SUBTHREAD;
    resolve_email(priv, shared, rm);
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  return FR_SUCCESS;
}

/**
 * op_main_root_message - Jump to root message in thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_PARENT_MESSAGE
 * - OP_MAIN_ROOT_MESSAGE
 */
static int op_main_root_message(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  int index = mutt_parent_message(shared->email, op == OP_MAIN_ROOT_MESSAGE);
  if (index != -1)
    menu_set_index(priv->menu, index);

  return FR_SUCCESS;
}

/**
 * op_main_set_flag - Set a status flag on a message - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_CLEAR_FLAG
 * - OP_MAIN_SET_FLAG
 */
static int op_main_set_flag(struct IndexSharedData *shared,
                            struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);

  if (mw_change_flag(shared->mailbox, &ea, (op == OP_MAIN_SET_FLAG)) == 0)
  {
    if (priv->tag_prefix)
    {
      menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
    }
    else
    {
      resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
    }
  }
  ARRAY_FREE(&ea);

  return FR_SUCCESS;
}

/**
 * op_main_show_limit - Show currently active limit pattern - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_show_limit(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  if (mview_has_limit(shared->mailbox_view))
  {
    char buf2[256] = { 0 };
    /* L10N: ask for a limit to apply */
    snprintf(buf2, sizeof(buf2), _("Limit: %s"), shared->mailbox_view->pattern);
    mutt_message("%s", buf2);
  }
  else
  {
    mutt_message(_("No limit pattern is in effect"));
  }

  return FR_SUCCESS;
}

/**
 * op_main_sync_folder - Save changes to mailbox - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_sync_folder(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  if (!shared->mailbox || (shared->mailbox->msg_count == 0) || shared->mailbox->readonly)
    return FR_NO_ACTION;

  int ovc = shared->mailbox->vcount;
  int oc = shared->mailbox->msg_count;
  struct Email *e = NULL;

  /* don't attempt to move the cursor if there are no visible messages in the current limit */
  int index = menu_get_index(priv->menu);
  if (index < shared->mailbox->vcount)
  {
    /* threads may be reordered, so figure out what header the cursor
     * should be on. */
    int newidx = index;
    if (!shared->email)
      return FR_NO_ACTION;
    if (shared->email->deleted)
      newidx = find_next_undeleted(shared->mailbox_view, index, false);
    if (newidx < 0)
      newidx = find_previous_undeleted(shared->mailbox_view, index, false);
    if (newidx >= 0)
      e = mutt_get_virt_email(shared->mailbox, newidx);
  }

  enum MxStatus check = mx_mbox_sync(shared->mailbox);
  if (check == MX_STATUS_OK)
  {
    if (e && (shared->mailbox->vcount != ovc))
    {
      for (size_t i = 0; i < shared->mailbox->vcount; i++)
      {
        struct Email *e2 = mutt_get_virt_email(shared->mailbox, i);
        if (e2 == e)
        {
          menu_set_index(priv->menu, i);
          break;
        }
      }
    }
    mutt_pattern_free(&shared->search_state->pattern);
  }
  else if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
  {
    update_index(priv->menu, shared->mailbox_view, check, oc, shared);
  }

  /* do a sanity check even if mx_mbox_sync failed.  */

  index = menu_get_index(priv->menu);
  if ((index < 0) || (shared->mailbox && (index >= shared->mailbox->vcount)))
  {
    menu_set_index(priv->menu, find_first_message(shared->mailbox_view));
  }

  /* check for a fatal error, or all messages deleted */
  if (shared->mailbox && buf_is_empty(&shared->mailbox->pathbuf))
  {
    mview_free(&shared->mailbox_view);
  }

  priv->menu->max = shared->mailbox->vcount;
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  struct EventMailbox ev_m = { shared->mailbox };
  notify_send(shared->mailbox->notify, NT_MAILBOX, NT_MAILBOX_CHANGE, &ev_m);

  return FR_SUCCESS;
}

/**
 * op_main_tag_pattern - Tag messages matching a pattern - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_tag_pattern(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  mutt_pattern_func(shared->mailbox_view, MUTT_TAG, _("Tag messages matching: "));
  menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return FR_SUCCESS;
}

/**
 * op_main_undelete_pattern - Undelete messages matching a pattern - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_undelete_pattern(struct IndexSharedData *shared,
                                    struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     undelete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
    return FR_ERROR;

  if (mutt_pattern_func(shared->mailbox_view, MUTT_UNDELETE,
                        _("Undelete messages matching: ")) == 0)
  {
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  return FR_SUCCESS;
}

/**
 * op_main_untag_pattern - Untag messages matching a pattern - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_untag_pattern(struct IndexSharedData *shared,
                                 struct IndexPrivateData *priv, int op)
{
  if (mutt_pattern_func(shared->mailbox_view, MUTT_UNTAG, _("Untag messages matching: ")) == 0)
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return FR_SUCCESS;
}

/**
 * op_mark_msg - Create a hotkey macro for the current message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_mark_msg(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;

  int rc = FR_SUCCESS;

  if (shared->email->env->message_id)
  {
    struct Buffer *buf = buf_pool_get();

    /* L10N: This is the prompt for <mark-message>.  Whatever they
       enter will be prefixed by $mark_macro_prefix and will become
       a macro hotkey to jump to the currently selected message. */
    if ((mw_get_field(_("Enter macro stroke: "), buf, MUTT_COMP_NO_FLAGS,
                      HC_OTHER, NULL, NULL) == 0) &&
        !buf_is_empty(buf))
    {
      const char *const c_mark_macro_prefix = cs_subset_string(shared->sub, "mark_macro_prefix");
      char str[256] = { 0 };
      snprintf(str, sizeof(str), "%s%s", c_mark_macro_prefix, buf_string(buf));

      struct Buffer *msg_id = buf_pool_get();
      mutt_file_sanitize_regex(msg_id, shared->email->env->message_id);
      char macro[256] = { 0 };
      snprintf(macro, sizeof(macro), "<search>~i '%s'\n", buf_string(msg_id));
      buf_pool_release(&msg_id);

      /* L10N: "message hotkey" is the key bindings menu description of a
         macro created by <mark-message>. */
      km_bind(str, MENU_INDEX, OP_MACRO, macro, _("message hotkey"));

      /* L10N: This is echoed after <mark-message> creates a new hotkey
         macro.  %s is the hotkey string ($mark_macro_prefix followed
         by whatever they typed at the prompt.) */
      buf_printf(buf, _("Message bound to %s"), str);
      mutt_message("%s", buf_string(buf));
      mutt_debug(LL_DEBUG1, "Mark: %s => %s\n", str, macro);
      buf_pool_release(&buf);
    }
  }
  else
  {
    /* L10N: This error is printed if <mark-message> can't find a
       Message-ID for the currently selected message in the index. */
    mutt_error(_("No message ID to macro"));
    rc = FR_ERROR;
  }

  return rc;
}

/**
 * op_next_entry - Move to the next entry - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_next_entry(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  const int index = menu_get_index(priv->menu) + 1;
  if (index >= shared->mailbox->vcount)
  {
    mutt_message(_("You are on the last message"));
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    return FR_ERROR;
  }
  menu_set_index(priv->menu, index);
  return FR_SUCCESS;
}

/**
 * op_pipe - Pipe message/attachment to a shell command - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_pipe(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  mutt_pipe_message(shared->mailbox, &ea);
  ARRAY_FREE(&ea);

  /* in an IMAP folder index with imap_peek=no, piping could change
   * new or old messages status to read. Redraw what's needed.  */
  const bool c_imap_peek = cs_subset_bool(shared->sub, "imap_peek");
  if ((shared->mailbox->type == MUTT_IMAP) && !c_imap_peek)
  {
    menu_queue_redraw(priv->menu, (priv->tag_prefix ? MENU_REDRAW_INDEX : MENU_REDRAW_CURRENT));
  }

  return FR_SUCCESS;
}

/**
 * op_prev_entry - Move to the previous entry - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_prev_entry(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  int index = menu_get_index(priv->menu);
  if (index < 1)
  {
    notify_send(shared->notify, NT_INDEX, NT_INDEX_EMAIL, NULL);
    mutt_message(_("You are on the first message"));
    return FR_ERROR;
  }
  menu_set_index(priv->menu, index - 1);
  return FR_SUCCESS;
}

/**
 * op_print - Print the current entry - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_print(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  mutt_print_message(shared->mailbox, &ea);
  ARRAY_FREE(&ea);

  /* in an IMAP folder index with imap_peek=no, printing could change
   * new or old messages status to read. Redraw what's needed.  */
  const bool c_imap_peek = cs_subset_bool(shared->sub, "imap_peek");
  if ((shared->mailbox->type == MUTT_IMAP) && !c_imap_peek)
  {
    menu_queue_redraw(priv->menu, (priv->tag_prefix ? MENU_REDRAW_INDEX : MENU_REDRAW_CURRENT));
  }

  return FR_SUCCESS;
}

/**
 * op_query - Query external program for addresses - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_query(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  query_index(shared->mailbox, shared->sub);
  return FR_SUCCESS;
}

/**
 * op_quit - Save changes to mailbox and quit - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_quit(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (shared->attach_msg)
    return FR_DONE;

  if (query_quadoption(_("Quit NeoMutt?"), shared->sub, "quit") == MUTT_YES)
  {
    priv->oldcount = shared->mailbox ? shared->mailbox->msg_count : 0;

    mutt_startup_shutdown_hook(MUTT_SHUTDOWN_HOOK);
    mutt_debug(LL_NOTIFY, "NT_GLOBAL_SHUTDOWN\n");
    notify_send(NeoMutt->notify, NT_GLOBAL, NT_GLOBAL_SHUTDOWN, NULL);

    enum MxStatus check = MX_STATUS_OK;
    if (!shared->mailbox_view || ((check = mx_mbox_close(shared->mailbox)) == MX_STATUS_OK))
    {
      mview_free(&shared->mailbox_view);
      mailbox_free(&shared->mailbox);
      return FR_DONE;
    }

    if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
    {
      update_index(priv->menu, shared->mailbox_view, check, priv->oldcount, shared);
    }

    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL); /* new mail arrived? */
    mutt_pattern_free(&shared->search_state->pattern);
  }

  return FR_NO_ACTION;
}

/**
 * op_recall_message - Recall a postponed message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_recall_message(struct IndexSharedData *shared,
                             struct IndexPrivateData *priv, int op)
{
  int rc = mutt_send_message(SEND_POSTPONED, NULL, NULL, shared->mailbox, NULL,
                             shared->sub);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_reply - Reply to a message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_reply(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;
  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
  const bool c_pgp_auto_decode = cs_subset_bool(shared->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode &&
      (priv->tag_prefix || !(shared->email->security & PGP_TRADITIONAL_CHECKED)))
  {
    if (mutt_check_traditional_pgp(shared->mailbox, &ea))
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  int rc = mutt_send_message(SEND_REPLY, NULL, NULL, shared->mailbox, &ea,
                             shared->sub);
  ARRAY_FREE(&ea);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_resend - Use the current message as a template for a new one - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_resend(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  int rc = -1;
  if (priv->tag_prefix)
  {
    struct Mailbox *m = shared->mailbox;
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(e))
        rc = mutt_resend_message(NULL, shared->mailbox, e, shared->sub);
    }
  }
  else
  {
    rc = mutt_resend_message(NULL, shared->mailbox, shared->email, shared->sub);
  }

  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_save - Make decrypted copy - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_COPY_MESSAGE
 * - OP_DECODE_COPY
 * - OP_DECODE_SAVE
 * - OP_DECRYPT_COPY
 * - OP_DECRYPT_SAVE
 * - OP_SAVE
 */
static int op_save(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (((op == OP_DECRYPT_COPY) || (op == OP_DECRYPT_SAVE)) && !WithCrypto)
    return FR_NOT_IMPL;

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);

  const enum MessageSaveOpt save_opt = ((op == OP_SAVE) || (op == OP_DECODE_SAVE) ||
                                        (op == OP_DECRYPT_SAVE)) ?
                                           SAVE_MOVE :
                                           SAVE_COPY;

  enum MessageTransformOpt transform_opt =
      ((op == OP_DECODE_SAVE) || (op == OP_DECODE_COPY))   ? TRANSFORM_DECODE :
      ((op == OP_DECRYPT_SAVE) || (op == OP_DECRYPT_COPY)) ? TRANSFORM_DECRYPT :
                                                             TRANSFORM_NONE;

  const int rc = mutt_save_message(shared->mailbox, &ea, save_opt, transform_opt);
  if ((rc == 0) && (save_opt == SAVE_MOVE))
  {
    resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  }
  ARRAY_FREE(&ea);

  if (priv->tag_prefix)
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return (rc == -1) ? FR_ERROR : FR_SUCCESS;
}

/**
 * op_search - Search for a regular expression - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_SEARCH
 * - OP_SEARCH_NEXT
 * - OP_SEARCH_OPPOSITE
 * - OP_SEARCH_REVERSE
 */
static int op_search(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  SearchFlags flags = SEARCH_NO_FLAGS;
  switch (op)
  {
    case OP_SEARCH:
      flags |= SEARCH_PROMPT;
      shared->search_state->reverse = false;
      break;
    case OP_SEARCH_REVERSE:
      flags |= SEARCH_PROMPT;
      shared->search_state->reverse = true;
      break;
    case OP_SEARCH_NEXT:
      break;
    case OP_SEARCH_OPPOSITE:
      flags |= SEARCH_OPPOSITE;
      break;
  }

  // Initiating a search can happen on an empty mailbox, but
  // searching for next/previous/... needs to be on a message and
  // thus a non-empty mailbox
  int index = menu_get_index(priv->menu);
  index = mutt_search_command(shared->mailbox_view, priv->menu, index,
                              shared->search_state, flags);
  if (index != -1)
    menu_set_index(priv->menu, index);

  return FR_SUCCESS;
}

/**
 * op_sort - Sort messages - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_SORT
 * - OP_SORT_REVERSE
 */
static int op_sort(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!mutt_select_sort(op == OP_SORT_REVERSE))
    return FR_ERROR;

  if (shared->mailbox && (shared->mailbox->msg_count != 0))
  {
    resort_index(shared->mailbox_view, priv->menu);
    mutt_pattern_free(&shared->search_state->pattern);
  }

  return FR_SUCCESS;
}

/**
 * op_tag - Tag the current entry - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_tag(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  const bool c_auto_tag = cs_subset_bool(shared->sub, "auto_tag");
  if (priv->tag_prefix && !c_auto_tag)
  {
    struct Mailbox *m = shared->mailbox;
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (e->visible)
        mutt_set_flag(m, e, MUTT_TAG, false, true);
    }
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
    return FR_SUCCESS;
  }

  if (!shared->email)
    return FR_NO_ACTION;

  mutt_set_flag(shared->mailbox, shared->email, MUTT_TAG, !shared->email->tagged, true);

  resolve_email(priv, shared, RESOLVE_NEXT_EMAIL);
  return FR_SUCCESS;
}

/**
 * op_tag_thread - Tag the current thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_TAG_SUBTHREAD
 * - OP_TAG_THREAD
 */
static int op_tag_thread(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;

  int rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_TAG,
                                !shared->email->tagged, (op != OP_TAG_THREAD));
  if (rc != -1)
  {
    const enum ResolveMethod rm = (op == OP_TAG_THREAD) ? RESOLVE_NEXT_THREAD :
                                                          RESOLVE_NEXT_SUBTHREAD;
    resolve_email(priv, shared, rm);
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  return FR_SUCCESS;
}

/**
 * op_toggle_new - Toggle a message's 'new' flag - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_toggle_new(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(shared->mailbox, MUTT_ACL_SEEN, _("Can't toggle new")))
    return FR_ERROR;

  struct Mailbox *m = shared->mailbox;
  if (priv->tag_prefix)
  {
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (!message_is_tagged(e))
        continue;

      if (e->read || e->old)
        mutt_set_flag(m, e, MUTT_NEW, true, true);
      else
        mutt_set_flag(m, e, MUTT_READ, true, true);
    }
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    if (!shared->email)
      return FR_NO_ACTION;
    if (shared->email->read || shared->email->old)
      mutt_set_flag(m, shared->email, MUTT_NEW, true, true);
    else
      mutt_set_flag(m, shared->email, MUTT_READ, true, true);

    resolve_email(priv, shared, RESOLVE_NEXT_UNDELETED);
  }

  return FR_SUCCESS;
}

/**
 * op_toggle_write - Toggle whether the mailbox will be rewritten - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_toggle_write(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  mx_toggle_write(shared->mailbox);
  return FR_SUCCESS;
}

/**
 * op_undelete - Undelete the current entry - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_undelete(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't undelete message")))
    return FR_ERROR;

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);

  mutt_emails_set_flag(shared->mailbox, &ea, MUTT_DELETE, false);
  mutt_emails_set_flag(shared->mailbox, &ea, MUTT_PURGE, false);
  ARRAY_FREE(&ea);

  if (priv->tag_prefix)
  {
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }
  else
  {
    resolve_email(priv, shared, RESOLVE_NEXT_EMAIL);
  }

  return FR_SUCCESS;
}

/**
 * op_undelete_thread - Undelete all messages in thread - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_UNDELETE_SUBTHREAD
 * - OP_UNDELETE_THREAD
 */
static int op_undelete_thread(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     undelete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(shared->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
    return FR_ERROR;

  int rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_DELETE,
                                false, (op != OP_UNDELETE_THREAD));
  if (rc != -1)
  {
    rc = mutt_thread_set_flag(shared->mailbox, shared->email, MUTT_PURGE, false,
                              (op != OP_UNDELETE_THREAD));
  }
  if (rc != -1)
  {
    const enum ResolveMethod rm = (op == OP_UNDELETE_THREAD) ? RESOLVE_NEXT_THREAD :
                                                               RESOLVE_NEXT_SUBTHREAD;
    resolve_email(priv, shared, rm);
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  return FR_SUCCESS;
}

/**
 * op_view_attachments - Show MIME attachments - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_view_attachments(struct IndexSharedData *shared,
                               struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;

  enum FunctionRetval rc = FR_ERROR;
  struct Message *msg = mx_msg_open(shared->mailbox, shared->email);
  if (msg)
  {
    dlg_attachment(NeoMutt->sub, shared->mailbox_view, shared->email, msg->fp,
                   shared->attach_msg);
    if (shared->email->attach_del)
    {
      shared->mailbox->changed = true;
    }
    mx_msg_close(shared->mailbox, &msg);
    rc = FR_SUCCESS;
  }
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return rc;
}

// -----------------------------------------------------------------------------

#ifdef USE_AUTOCRYPT
/**
 * op_autocrypt_acct_menu - Manage autocrypt accounts - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_autocrypt_acct_menu(struct IndexSharedData *shared,
                                  struct IndexPrivateData *priv, int op)
{
  dlg_autocrypt();
  return FR_SUCCESS;
}
#endif

/**
 * op_main_imap_fetch - Force retrieval of mail from IMAP server - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_imap_fetch(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  if (!shared->mailbox || (shared->mailbox->type != MUTT_IMAP))
    return FR_NO_ACTION;

  imap_check_mailbox(shared->mailbox, true);
  return FR_SUCCESS;
}

/**
 * op_main_imap_logout_all - Logout from all IMAP servers - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_imap_logout_all(struct IndexSharedData *shared,
                                   struct IndexPrivateData *priv, int op)
{
  if (shared->mailbox && (shared->mailbox->type == MUTT_IMAP))
  {
    const enum MxStatus check = mx_mbox_close(shared->mailbox);
    if (check == MX_STATUS_OK)
    {
      mview_free(&shared->mailbox_view);
    }
    else
    {
      if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
      {
        update_index(priv->menu, shared->mailbox_view, check, priv->oldcount, shared);
      }
      mutt_pattern_free(&shared->search_state->pattern);
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
      return FR_ERROR;
    }
  }
  imap_logout_all();
  mutt_message(_("Logged out of IMAP servers"));
  mutt_pattern_free(&shared->search_state->pattern);
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);

  return FR_SUCCESS;
}

/**
 * op_catchup - Mark all articles in newsgroup as read - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_catchup(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;
  if (!m || (m->type != MUTT_NNTP))
    return FR_NO_ACTION;

  struct NntpMboxData *mdata = m->mdata;
  if (mutt_newsgroup_catchup(m, mdata->adata, mdata->group))
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);

  return FR_SUCCESS;
}

/**
 * op_get_children - Get all children of the current message - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_GET_CHILDREN
 * - OP_RECONSTRUCT_THREAD
 */
static int op_get_children(struct IndexSharedData *shared,
                           struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;
  if (m->type != MUTT_NNTP)
    return FR_ERROR;

  struct Email *e = shared->email;
  if (!e)
    return FR_NO_ACTION;

  char buf[PATH_MAX] = { 0 };
  int oldmsgcount = m->msg_count;
  int oldindex = e->index;
  int rc = 0;

  if (!e->env->message_id)
  {
    mutt_error(_("No Message-Id. Unable to perform operation."));
    return FR_ERROR;
  }

  mutt_message(_("Fetching message headers..."));
  if (!m->id_hash)
    m->id_hash = mutt_make_id_hash(m);
  mutt_str_copy(buf, e->env->message_id, sizeof(buf));

  /* trying to find msgid of the root message */
  if (op == OP_RECONSTRUCT_THREAD)
  {
    struct ListNode *ref = NULL;
    STAILQ_FOREACH(ref, &e->env->references, entries)
    {
      if (!mutt_hash_find(m->id_hash, ref->data))
      {
        rc = nntp_check_msgid(m, ref->data);
        if (rc < 0)
          return FR_ERROR;
      }

      /* the last msgid in References is the root message */
      if (!STAILQ_NEXT(ref, entries))
        mutt_str_copy(buf, ref->data, sizeof(buf));
    }
  }

  /* fetching all child messages */
  rc = nntp_check_children(m, buf);

  /* at least one message has been loaded */
  if (m->msg_count > oldmsgcount)
  {
    bool verbose = m->verbose;

    if (rc < 0)
      m->verbose = false;

    struct MailboxView *mv = shared->mailbox_view;
    mutt_sort_headers(mv, (op == OP_RECONSTRUCT_THREAD));
    m->verbose = verbose;

    /* if the root message was retrieved, move to it */
    struct Email *e2 = mutt_hash_find(m->id_hash, buf);
    if (e2)
    {
      menu_set_index(priv->menu, e2->vnum);
    }
    else
    {
      /* try to restore old position */
      for (int i = 0; i < m->msg_count; i++)
      {
        e2 = m->emails[i];
        if (!e2)
          break;
        if (e2->index == oldindex)
        {
          menu_set_index(priv->menu, e2->vnum);
          /* as an added courtesy, recenter the menu
           * with the current entry at the middle of the screen */
          menu_current_middle(priv->menu);
        }
      }
    }
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  }
  else if (rc >= 0)
  {
    mutt_error(_("No deleted messages found in the thread"));
  }

  return FR_SUCCESS;
}

/**
 * op_get_message - Get parent of the current message - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_GET_MESSAGE
 * - OP_GET_PARENT
 */
static int op_get_message(struct IndexSharedData *shared,
                          struct IndexPrivateData *priv, int op)
{
  struct Mailbox *m = shared->mailbox;
  if (m->type != MUTT_NNTP)
    return FR_SUCCESS;

  int rc = FR_ERROR;
  struct Buffer *buf = buf_pool_get();

  if (op == OP_GET_MESSAGE)
  {
    if ((mw_get_field(_("Enter Message-Id: "), buf, MUTT_COMP_NO_FLAGS,
                      HC_OTHER, NULL, NULL) != 0) ||
        buf_is_empty(buf))
    {
      goto done;
    }
  }
  else
  {
    struct Email *e = shared->email;
    if (!e || STAILQ_EMPTY(&e->env->references))
    {
      mutt_error(_("Article has no parent reference"));
      goto done;
    }
    buf_strcpy(buf, STAILQ_FIRST(&e->env->references)->data);
  }

  if (!m->id_hash)
    m->id_hash = mutt_make_id_hash(m);
  struct Email *e = mutt_hash_find(m->id_hash, buf_string(buf));
  if (e)
  {
    if (e->vnum != -1)
    {
      menu_set_index(priv->menu, e->vnum);
    }
    else if (e->collapsed)
    {
      mutt_uncollapse_thread(e);
      mutt_set_vnum(m);
      menu_set_index(priv->menu, e->vnum);
    }
    else
    {
      mutt_error(_("Message is not visible in limited view"));
    }
  }
  else
  {
    mutt_message(_("Fetching %s from server..."), buf_string(buf));
    int rc2 = nntp_check_msgid(m, buf_string(buf));
    if (rc2 == 0)
    {
      e = m->emails[m->msg_count - 1];
      struct MailboxView *mv = shared->mailbox_view;
      mutt_sort_headers(mv, false);
      menu_set_index(priv->menu, e->vnum);
      menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
      rc = FR_SUCCESS;
    }
    else if (rc2 > 0)
    {
      mutt_error(_("Article %s not found on the server"), buf_string(buf));
    }
  }

done:
  buf_pool_release(&buf);
  return rc;
}

/**
 * op_main_change_group - Open a different newsgroup - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_CHANGE_GROUP
 * - OP_MAIN_CHANGE_GROUP_READONLY
 */
static int op_main_change_group(struct IndexSharedData *shared,
                                struct IndexPrivateData *priv, int op)
{
  struct Buffer *folderbuf = buf_pool_get();
  buf_alloc(folderbuf, PATH_MAX);

  OptNews = false;
  bool read_only;
  char *cp = NULL;
  const bool c_read_only = cs_subset_bool(shared->sub, "read_only");
  if (shared->attach_msg || c_read_only || (op == OP_MAIN_CHANGE_GROUP_READONLY))
  {
    cp = _("Open newsgroup in read-only mode");
    read_only = true;
  }
  else
  {
    cp = _("Open newsgroup");
    read_only = false;
  }

  const bool c_change_folder_next = cs_subset_bool(shared->sub, "change_folder_next");
  if (c_change_folder_next && shared->mailbox && !buf_is_empty(&shared->mailbox->pathbuf))
  {
    buf_strcpy(folderbuf, mailbox_path(shared->mailbox));
    buf_pretty_mailbox(folderbuf);
  }

  OptNews = true;
  const char *const c_news_server = cs_subset_string(shared->sub, "news_server");
  if (!CurrentNewsSrv)
    CurrentNewsSrv = nntp_select_server(shared->mailbox, c_news_server, false);
  if (!CurrentNewsSrv)
    goto changefoldercleanup2;

  nntp_mailbox(shared->mailbox, folderbuf->data, folderbuf->dsize);

  if (mw_enter_fname(cp, folderbuf, true, shared->mailbox, false, NULL, NULL,
                     MUTT_SEL_NO_FLAGS) == -1)
  {
    goto changefoldercleanup2;
  }

  /* Selected directory is okay, let's save it. */
  mutt_browser_select_dir(buf_string(folderbuf));

  if (buf_is_empty(folderbuf))
  {
    msgwin_clear_text(NULL);
    goto changefoldercleanup2;
  }

  struct Mailbox *m = mx_mbox_find2(buf_string(folderbuf));
  if (m)
  {
    change_folder_mailbox(priv->menu, m, &priv->oldcount, shared, read_only);
  }
  else
  {
    change_folder_string(priv->menu, folderbuf, &priv->oldcount, shared, read_only);
  }
  struct MuttWindow *dlg = dialog_find(priv->win_index);
  dlg->help_data = IndexNewsHelp;

changefoldercleanup2:
  buf_pool_release(&folderbuf);
  return FR_SUCCESS;
}

/**
 * op_post - Followup to newsgroup - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_FOLLOWUP
 * - OP_POST
 */
static int op_post(struct IndexSharedData *shared, struct IndexPrivateData *priv, int op)
{
  if (!shared->email)
    return FR_NO_ACTION;

  if ((op != OP_FOLLOWUP) || !shared->email->env->followup_to ||
      !mutt_istr_equal(shared->email->env->followup_to, "poster") ||
      (query_quadoption(_("Reply by mail as poster prefers?"), shared->sub,
                        "followup_to_poster") != MUTT_YES))
  {
    if (shared->mailbox && (shared->mailbox->type == MUTT_NNTP) &&
        !((struct NntpMboxData *) shared->mailbox->mdata)->allowed &&
        (query_quadoption(_("Posting to this group not allowed, may be moderated. Continue?"),
                          shared->sub, "post_moderated") != MUTT_YES))
    {
      return FR_ERROR;
    }
    if (op == OP_POST)
    {
      mutt_send_message(SEND_NEWS, NULL, NULL, shared->mailbox, NULL, shared->sub);
    }
    else
    {
      struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
      ea_add_tagged(&ea, shared->mailbox_view, shared->email, priv->tag_prefix);
      mutt_send_message(((op == OP_FOLLOWUP) ? SEND_REPLY : SEND_FORWARD) | SEND_NEWS,
                        NULL, NULL, shared->mailbox, &ea, shared->sub);
      ARRAY_FREE(&ea);
    }
    menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
    return FR_SUCCESS;
  }

  return op_reply(shared, priv, OP_REPLY);
}

#ifdef USE_NOTMUCH
/**
 * op_main_entire_thread - Read entire thread of the current message - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_entire_thread(struct IndexSharedData *shared,
                                 struct IndexPrivateData *priv, int op)
{
  if (shared->mailbox->type != MUTT_NOTMUCH)
  {
    if (((shared->mailbox->type != MUTT_MH) && (shared->mailbox->type != MUTT_MAILDIR)) ||
        (!shared->email || !shared->email->env || !shared->email->env->message_id))
    {
      mutt_message(_("No virtual folder and no Message-Id, aborting"));
      return FR_ERROR;
    } // no virtual folder, but we have message-id, reconstruct thread on-the-fly

    struct Buffer *buf = buf_pool_get();
    buf_alloc(buf, PATH_MAX);
    buf_addstr(buf, "id:");

    int msg_id_offset = 0;
    if ((shared->email->env->message_id)[0] == '<')
      msg_id_offset = 1;

    buf_addstr(buf, shared->email->env->message_id + msg_id_offset);

    size_t len = buf_len(buf);
    ASSERT(len > 0);
    if (buf->data[len - 1] == '>')
      buf->data[len - 1] = '\0';

    change_folder_notmuch(priv->menu, buf->data, buf->dsize, &priv->oldcount, shared, false);
    buf_pool_release(&buf);

    // If notmuch doesn't contain the message, we're left in an empty
    // vfolder. No messages are found, but nm_read_entire_thread assumes
    // a valid message-id and will throw a segfault.
    //
    // To prevent that, stay in the empty vfolder and print an error.
    if (shared->mailbox->msg_count == 0)
    {
      mutt_error(_("failed to find message in notmuch database. try running 'notmuch new'."));
      return FR_ERROR;
    }
  }
  priv->oldcount = shared->mailbox->msg_count;
  int index = menu_get_index(priv->menu);
  struct Email *e_oldcur = mutt_get_virt_email(shared->mailbox, index);
  if (!e_oldcur)
    return FR_ERROR;

  if (nm_read_entire_thread(shared->mailbox, e_oldcur) < 0)
  {
    mutt_message(_("Failed to read thread, aborting"));
    return FR_ERROR;
  }

  // nm_read_entire_thread() may modify msg_count and menu won't be updated.
  priv->menu->max = shared->mailbox->msg_count;

  if (priv->oldcount < shared->mailbox->msg_count)
  {
    /* nm_read_entire_thread() triggers mutt_sort_headers() if necessary */
    index = e_oldcur->vnum;
    if (e_oldcur->collapsed || shared->mailbox_view->collapsed)
    {
      index = mutt_uncollapse_thread(e_oldcur);
      mutt_set_vnum(shared->mailbox);
    }
    menu_set_index(priv->menu, index);
    menu_queue_redraw(priv->menu, MENU_REDRAW_INDEX);
  }

  return FR_SUCCESS;
}

/**
 * op_main_vfolder_from_query - Generate virtual folder from query - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_VFOLDER_FROM_QUERY
 * - OP_MAIN_VFOLDER_FROM_QUERY_READONLY op_main_vfolder_from_query
 */
static int op_main_vfolder_from_query(struct IndexSharedData *shared,
                                      struct IndexPrivateData *priv, int op)
{
  int rc = FR_SUCCESS;
  struct Buffer *buf = buf_pool_get();

  if ((mw_get_field("Query: ", buf, MUTT_COMP_NO_FLAGS, HC_OTHER,
                    &CompleteNmQueryOps, NULL) != 0) ||
      buf_is_empty(buf))
  {
    mutt_message(_("No query, aborting"));
    rc = FR_NO_ACTION;
    goto done;
  }

  // Keep copy of user's query to name the mailbox
  char *query_unencoded = buf_strdup(buf);

  buf_alloc(buf, PATH_MAX);
  struct Mailbox *m_query = change_folder_notmuch(priv->menu, buf->data, buf->dsize,
                                                  &priv->oldcount, shared,
                                                  (op == OP_MAIN_VFOLDER_FROM_QUERY_READONLY));
  if (m_query)
  {
    FREE(&m_query->name);
    m_query->name = query_unencoded;
    query_unencoded = NULL;
    rc = FR_SUCCESS;
  }
  else
  {
    FREE(&query_unencoded);
  }

done:
  buf_pool_release(&buf);
  return rc;
}

/**
 * op_main_windowed_vfolder - Shifts virtual folder time window - Implements ::index_function_t - @ingroup index_function_api
 *
 * This function handles:
 * - OP_MAIN_WINDOWED_VFOLDER_BACKWARD
 * - OP_MAIN_WINDOWED_VFOLDER_FORWARD
 * - OP_MAIN_WINDOWED_VFOLDER_RESET
 */
static int op_main_windowed_vfolder(struct IndexSharedData *shared,
                                    struct IndexPrivateData *priv, int op)
{
  // Common guard clauses.
  if (!nm_query_window_available())
  {
    mutt_message(_("Windowed queries disabled"));
    return FR_ERROR;
  }
  const char *const c_nm_query_window_current_search = cs_subset_string(shared->sub, "nm_query_window_current_search");
  if (!c_nm_query_window_current_search)
  {
    mutt_message(_("No notmuch vfolder currently loaded"));
    return FR_ERROR;
  }

  // Call the specific operation.
  switch (op)
  {
    case OP_MAIN_WINDOWED_VFOLDER_BACKWARD:
      nm_query_window_backward();
      break;
    case OP_MAIN_WINDOWED_VFOLDER_FORWARD:
      nm_query_window_forward();
      break;
    case OP_MAIN_WINDOWED_VFOLDER_RESET:
      nm_query_window_reset();
      break;
  }

  // Common query window folder change.
  char buf[PATH_MAX] = { 0 };
  mutt_str_copy(buf, c_nm_query_window_current_search, sizeof(buf));
  change_folder_notmuch(priv->menu, buf, sizeof(buf), &priv->oldcount, shared, false);

  return FR_SUCCESS;
}
#endif

/**
 * op_main_fetch_mail - Retrieve mail from POP server - Implements ::index_function_t - @ingroup index_function_api
 */
static int op_main_fetch_mail(struct IndexSharedData *shared,
                              struct IndexPrivateData *priv, int op)
{
  pop_fetch_mail();
  menu_queue_redraw(priv->menu, MENU_REDRAW_FULL);
  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * prereq - Check the pre-requisites for a function
 * @param shared Index shared data
 * @param menu   Current Menu
 * @param checks Checks to perform, see #CheckFlags
 * @retval true The checks pass successfully
 */
static bool prereq(struct IndexSharedData *shared, struct Menu *menu, CheckFlags checks)
{
  bool result = true;
  struct MailboxView *mv = shared->mailbox_view;

  if (checks & (CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
    checks |= CHECK_IN_MAILBOX;

  if ((checks & CHECK_IN_MAILBOX) && (!mv || !mv->mailbox))
  {
    mutt_error(_("No mailbox is open"));
    result = false;
  }

  if (result && (checks & CHECK_MSGCOUNT) && (mv->mailbox->msg_count == 0))
  {
    mutt_error(_("There are no messages"));
    result = false;
  }

  int index = menu_get_index(menu);
  if (result && (checks & CHECK_VISIBLE) &&
      ((index < 0) || (index >= mv->mailbox->vcount)))
  {
    mutt_error(_("No visible messages"));
    result = false;
  }

  if (result && (checks & CHECK_READONLY) && mv->mailbox->readonly)
  {
    mutt_error(_("Mailbox is read-only"));
    result = false;
  }

  if (result && (checks & CHECK_ATTACH) && shared->attach_msg)
  {
    mutt_error(_("Function not permitted in attach-message mode"));
    result = false;
  }

  if (!result)
    mutt_flushinp();

  return result;
}

/**
 * IndexFunctions - All the NeoMutt functions that the Index supports
 */
static const struct IndexFunction IndexFunctions[] = {
  // clang-format off
  { OP_ALIAS_DIALOG,                        op_alias_dialog,                      CHECK_NO_FLAGS },
  { OP_ATTACHMENT_EDIT_TYPE,                op_attachment_edit_type,              CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_BOUNCE_MESSAGE,                      op_bounce_message,                    CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_CATCHUP,                             op_catchup,                           CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY },
  { OP_CHECK_TRADITIONAL,                   op_check_traditional,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_COMPOSE_TO_SENDER,                   op_compose_to_sender,                 CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_COPY_MESSAGE,                        op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_CREATE_ALIAS,                        op_create_alias,                      CHECK_NO_FLAGS },
  { OP_DECODE_COPY,                         op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DECODE_SAVE,                         op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DECRYPT_COPY,                        op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DECRYPT_SAVE,                        op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DELETE,                              op_delete,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_DELETE_SUBTHREAD,                    op_delete_thread,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_DELETE_THREAD,                       op_delete_thread,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_DISPLAY_ADDRESS,                     op_display_address,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DISPLAY_HEADERS,                     op_display_message,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DISPLAY_MESSAGE,                     op_display_message,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_EDIT_LABEL,                          op_edit_label,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_EDIT_OR_VIEW_RAW_MESSAGE,            op_edit_raw_message,                  CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_EDIT_RAW_MESSAGE,                    op_edit_raw_message,                  CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_END_COND,                            op_end_cond,                          CHECK_NO_FLAGS },
  { OP_EXIT,                                op_exit,                              CHECK_NO_FLAGS },
  { OP_EXTRACT_KEYS,                        op_extract_keys,                      CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_FLAG_MESSAGE,                        op_flag_message,                      CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_FOLLOWUP,                            op_post,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_FORGET_PASSPHRASE,                   op_forget_passphrase,                 CHECK_NO_FLAGS },
  { OP_FORWARD_MESSAGE,                     op_forward_message,                   CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_FORWARD_TO_GROUP,                    op_post,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_GET_CHILDREN,                        op_get_children,                      CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_GET_MESSAGE,                         op_get_message,                       CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_READONLY },
  { OP_GET_PARENT,                          op_get_message,                       CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_GENERIC_SELECT_ENTRY,                op_display_message,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_GROUP_CHAT_REPLY,                    op_group_reply,                       CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_GROUP_REPLY,                         op_group_reply,                       CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_JUMP,                                op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_1,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_2,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_3,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_4,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_5,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_6,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_7,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_8,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_JUMP_9,                              op_jump,                              CHECK_IN_MAILBOX },
  { OP_LIMIT_CURRENT_THREAD,                op_main_limit,                        CHECK_IN_MAILBOX },
  { OP_LIST_REPLY,                          op_list_reply,                        CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_LIST_SUBSCRIBE,                      op_list_subscribe,                    CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_LIST_UNSUBSCRIBE,                    op_list_unsubscribe,                  CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIL,                                op_mail,                              CHECK_ATTACH },
  { OP_MAILBOX_LIST,                        op_mailbox_list,                      CHECK_NO_FLAGS },
  { OP_MAIL_KEY,                            op_mail_key,                          CHECK_ATTACH },
  { OP_MAIN_BREAK_THREAD,                   op_main_break_thread,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_CHANGE_FOLDER,                  op_main_change_folder,                CHECK_NO_FLAGS },
  { OP_MAIN_CHANGE_FOLDER_READONLY,         op_main_change_folder,                CHECK_NO_FLAGS },
  { OP_MAIN_CHANGE_GROUP,                   op_main_change_group,                 CHECK_NO_FLAGS },
  { OP_MAIN_CHANGE_GROUP_READONLY,          op_main_change_group,                 CHECK_NO_FLAGS },
  { OP_MAIN_CLEAR_FLAG,                     op_main_set_flag,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_COLLAPSE_ALL,                   op_main_collapse_all,                 CHECK_IN_MAILBOX },
  { OP_MAIN_COLLAPSE_THREAD,                op_main_collapse_thread,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_DELETE_PATTERN,                 op_main_delete_pattern,               CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_READONLY },
  { OP_MAIN_FETCH_MAIL,                     op_main_fetch_mail,                   CHECK_ATTACH },
  { OP_MAIN_IMAP_FETCH,                     op_main_imap_fetch,                   CHECK_NO_FLAGS },
  { OP_MAIN_IMAP_LOGOUT_ALL,                op_main_imap_logout_all,              CHECK_NO_FLAGS },
  { OP_MAIN_LIMIT,                          op_main_limit,                        CHECK_IN_MAILBOX },
  { OP_MAIN_LINK_THREADS,                   op_main_link_threads,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_MODIFY_TAGS,                    op_main_modify_tags,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_MODIFY_TAGS_THEN_HIDE,          op_main_modify_tags,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_NEXT_NEW,                       op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_NEW_THEN_UNREAD,           op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_SUBTHREAD,                 op_main_next_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_THREAD,                    op_main_next_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_UNDELETED,                 op_main_next_undeleted,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_UNREAD,                    op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_UNREAD_MAILBOX,            op_main_next_unread_mailbox,          CHECK_IN_MAILBOX },
  { OP_MAIN_PARENT_MESSAGE,                 op_main_root_message,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_NEW,                       op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_NEW_THEN_UNREAD,           op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_SUBTHREAD,                 op_main_next_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_THREAD,                    op_main_next_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_UNDELETED,                 op_main_prev_undeleted,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_UNREAD,                    op_main_next_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_QUASI_DELETE,                   op_main_quasi_delete,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_READ_SUBTHREAD,                 op_main_read_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_READ_THREAD,                    op_main_read_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_ROOT_MESSAGE,                   op_main_root_message,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_SET_FLAG,                       op_main_set_flag,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_MAIN_SHOW_LIMIT,                     op_main_show_limit,                   CHECK_IN_MAILBOX },
  { OP_MAIN_SYNC_FOLDER,                    op_main_sync_folder,                  CHECK_NO_FLAGS },
  { OP_MAIN_TAG_PATTERN,                    op_main_tag_pattern,                  CHECK_IN_MAILBOX },
  { OP_MAIN_UNDELETE_PATTERN,               op_main_undelete_pattern,             CHECK_IN_MAILBOX | CHECK_READONLY },
  { OP_MAIN_UNTAG_PATTERN,                  op_main_untag_pattern,                CHECK_IN_MAILBOX },
  { OP_MARK_MSG,                            op_mark_msg,                          CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_NEXT_ENTRY,                          op_next_entry,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PIPE,                                op_pipe,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_POST,                                op_post,                              CHECK_ATTACH | CHECK_IN_MAILBOX },
  { OP_PREV_ENTRY,                          op_prev_entry,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PRINT,                               op_print,                             CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PURGE_MESSAGE,                       op_delete,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_PURGE_THREAD,                        op_delete_thread,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_QUERY,                               op_query,                             CHECK_ATTACH },
  { OP_QUIT,                                op_quit,                              CHECK_NO_FLAGS },
  { OP_RECALL_MESSAGE,                      op_recall_message,                    CHECK_ATTACH },
  { OP_RECONSTRUCT_THREAD,                  op_get_children,                      CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_REPLY,                               op_reply,                             CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_RESEND,                              op_resend,                            CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SAVE,                                op_save,                              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SEARCH,                              op_search,                            CHECK_IN_MAILBOX },
  { OP_SEARCH_NEXT,                         op_search,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SEARCH_OPPOSITE,                     op_search,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SEARCH_REVERSE,                      op_search,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SORT,                                op_sort,                              CHECK_NO_FLAGS },
  { OP_SORT_REVERSE,                        op_sort,                              CHECK_NO_FLAGS },
  { OP_TAG,                                 op_tag,                               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_TAG_SUBTHREAD,                       op_tag_thread,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_TAG_THREAD,                          op_tag_thread,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_TOGGLE_NEW,                          op_toggle_new,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_TOGGLE_READ,                         op_main_limit,                        CHECK_IN_MAILBOX },
  { OP_TOGGLE_WRITE,                        op_toggle_write,                      CHECK_IN_MAILBOX },
  { OP_UNDELETE,                            op_undelete,                          CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_UNDELETE_SUBTHREAD,                  op_undelete_thread,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_UNDELETE_THREAD,                     op_undelete_thread,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_VISIBLE },
  { OP_VIEW_ATTACHMENTS,                    op_view_attachments,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_VIEW_RAW_MESSAGE,                    op_edit_raw_message,                  CHECK_ATTACH | CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
#ifdef USE_AUTOCRYPT
  { OP_AUTOCRYPT_ACCT_MENU,                 op_autocrypt_acct_menu,               CHECK_NO_FLAGS },
#endif
#ifdef USE_NOTMUCH
  { OP_MAIN_CHANGE_VFOLDER,                 op_main_change_folder,                CHECK_NO_FLAGS },
  { OP_MAIN_ENTIRE_THREAD,                  op_main_entire_thread,                CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_VFOLDER_FROM_QUERY,             op_main_vfolder_from_query,           CHECK_NO_FLAGS },
  { OP_MAIN_VFOLDER_FROM_QUERY_READONLY,    op_main_vfolder_from_query,           CHECK_NO_FLAGS },
  { OP_MAIN_WINDOWED_VFOLDER_BACKWARD,      op_main_windowed_vfolder,             CHECK_IN_MAILBOX },
  { OP_MAIN_WINDOWED_VFOLDER_FORWARD,       op_main_windowed_vfolder,             CHECK_IN_MAILBOX },
  { OP_MAIN_WINDOWED_VFOLDER_RESET,         op_main_windowed_vfolder,             CHECK_IN_MAILBOX },
#endif
  { 0, NULL, CHECK_NO_FLAGS },
  // clang-format on
};

/**
 * index_function_dispatcher - Perform an Index function - Implements ::function_dispatcher_t - @ingroup dispatcher_api
 */
int index_function_dispatcher(struct MuttWindow *win, int op)
{
  // The Dispatcher may be called on any Window in the Dialog
  struct MuttWindow *dlg = dialog_find(win);
  if (!dlg || !dlg->wdata || !win->parent || !win->parent->wdata)
    return FR_ERROR;

  struct IndexPrivateData *priv = win->parent->wdata;
  struct IndexSharedData *shared = dlg->wdata;

  int rc = FR_UNKNOWN;
  for (size_t i = 0; IndexFunctions[i].op != OP_NULL; i++)
  {
    const struct IndexFunction *fn = &IndexFunctions[i];
    if (fn->op == op)
    {
      if (!prereq(shared, priv->menu, fn->flags))
      {
        rc = FR_ERROR;
        break;
      }
      rc = fn->function(shared, priv, op);
      break;
    }
  }

  if (rc == FR_UNKNOWN) // Not our function
    return rc;

  const char *result = dispatcher_get_retval_name(rc);
  mutt_debug(LL_DEBUG1, "Handled %s (%d) -> %s\n", opcodes_get_name(op), op, NONULL(result));

  return rc;
}
