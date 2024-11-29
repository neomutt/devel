/**
 * @file
 * Attachment Selection Dialog
 *
 * @authors
 * Copyright (C) 2021 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2021-2024 Richard Russon <rich@flatcap.org>
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
 * @page attach_dlg_attach Attachment Selection Dialog
 *
 * The Attachment Selection Dialog lets the user select an email attachment.
 *
 * This is a @ref gui_simple
 *
 * ## Windows
 *
 * | Name                        | Type              | See Also         |
 * | :-------------------------- | :---------------- | :--------------- |
 * | Attachment Selection Dialog | WT_DLG_ATTACHMENT | dlg_attachment() |
 *
 * **Parent**
 * - @ref gui_dialog
 *
 * **Children**
 * - See: @ref gui_simple
 *
 * ## Data
 * - #Menu
 * - #Menu::mdata
 * - #AttachCtx
 *
 * The @ref gui_simple holds a Menu.  The Attachment Selection Dialog stores
 * its data (#AttachCtx) in Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type  | Handler                  |
 * | :---------- | :----------------------- |
 * | #NT_CONFIG  | attach_config_observer() |
 * | #NT_WINDOW  | attach_window_observer() |
 *
 * The Attachment Selection Dialog doesn't have any specific colours, so it
 * doesn't need to support #NT_COLOR.
 *
 * The Attachment Selection Dialog does not implement MuttWindow::recalc() or
 * MuttWindow::repaint().
 *
 * Some other events are handled by the @ref gui_simple.
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "expando/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "attach.h"
#include "attachments.h"
#include "functions.h"
#include "globals.h"
#include "hook.h"
#include "mutt_logging.h"
#include "mview.h"
#include "private_data.h"
#include "recvattach.h"

/// Help Bar for the Attachment selection dialog
static const struct Mapping AttachmentHelp[] = {
  // clang-format off
  { N_("Exit"),  OP_EXIT },
  { N_("Save"),  OP_ATTACHMENT_SAVE },
  { N_("Pipe"),  OP_PIPE },
  { N_("Print"), OP_ATTACHMENT_PRINT },
  { N_("Help"),  OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * attach_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 *
 * The Address Book Window is affected by changes to `$sort_attach`.
 */
static int attach_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (!mutt_str_equal(ev_c->name, "attach_format") && !mutt_str_equal(ev_c->name, "message_format"))
    return 0;

  struct Menu *menu = nc->global_data;
  menu_queue_redraw(menu, MENU_REDRAW_FULL);
  mutt_debug(LL_DEBUG5, "config done, request WA_RECALC, MENU_REDRAW_FULL\n");

  return 0;
}

/**
 * attach_make_entry - Format an Attachment for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $attach_format
 */
static int attach_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  struct AttachPrivateData *priv = menu->mdata;
  struct AttachCtx *actx = priv->actx;

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  struct AttachPtr *aptr = actx->idx[actx->v2r[line]];

  struct ExpandoRenderData AttachRenderData[] = {
    // clang-format off
    { ED_ATTACH, AttachRenderCallbacks1, aptr, MUTT_FORMAT_ARROWCURSOR },
    { ED_BODY,   AttachRenderCallbacks2, aptr, MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_attach_format = cs_subset_expando(NeoMutt->sub, "attach_format");
  return expando_filter(c_attach_format, AttachRenderData, max_cols, EnvList, buf);
}

/**
 * attach_tag - Tag an attachment - Implements Menu::tag() - @ingroup menu_tag
 */
static int attach_tag(struct Menu *menu, int sel, int act)
{
  struct AttachPrivateData *priv = menu->mdata;
  struct AttachCtx *actx = priv->actx;

  struct Body *cur = actx->idx[actx->v2r[sel]]->body;
  bool ot = cur->tagged;

  cur->tagged = ((act >= 0) ? act : !cur->tagged);
  return cur->tagged - ot;
}

/**
 * attach_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 *
 * This function is triggered by changes to the windows.
 *
 * - Delete (this window): clean up the resources held by the Help Bar
 */
static int attach_window_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_WINDOW)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;
  if (nc->event_subtype != NT_WINDOW_DELETE)
    return 0;

  struct MuttWindow *win_menu = nc->global_data;
  struct EventWindow *ev_w = nc->event_data;
  if (ev_w->win != win_menu)
    return 0;

  struct Menu *menu = win_menu->wdata;

  notify_observer_remove(NeoMutt->sub->notify, attach_config_observer, menu);
  notify_observer_remove(win_menu->notify, attach_window_observer, win_menu);

  mutt_debug(LL_DEBUG5, "window delete done\n");
  return 0;
}

/**
 * dlg_attachment - Show the attachments in a Menu - @ingroup gui_dlg
 * @param sub        Config Subset
 * @param mv         Mailbox view
 * @param e          Email
 * @param fp         File with the content of the email, or NULL
 * @param attach_msg Are we in "attach message" mode?
 *
 * The Select Attachment dialog shows an Email's attachments.
 * They can be viewed using the Pager or Mailcap programs.
 * They can also be saved, printed, deleted, etc.
 */
void dlg_attachment(struct ConfigSubset *sub, struct MailboxView *mv,
                    struct Email *e, FILE *fp, bool attach_msg)
{
  if (!mv || !mv->mailbox || !e || !fp)
    return;

  struct Mailbox *m = mv->mailbox;

  /* make sure we have parsed this message */
  mutt_parse_mime_message(e, fp);
  mutt_message_hook(m, e, MUTT_MESSAGE_HOOK);

  struct SimpleDialogWindows sdw = simple_dialog_new(MENU_ATTACHMENT, WT_DLG_ATTACHMENT,
                                                     AttachmentHelp);
  struct Menu *menu = sdw.menu;
  menu->make_entry = attach_make_entry;
  menu->tag = attach_tag;

  struct AttachCtx *actx = mutt_actx_new();
  actx->email = e;
  actx->fp_root = fp;
  mutt_update_recvattach_menu(actx, menu, true);

  struct AttachPrivateData *priv = attach_private_data_new();
  priv->menu = menu;
  priv->actx = actx;
  priv->sub = sub;
  priv->mailbox = m;
  priv->attach_msg = attach_msg;
  menu->mdata = priv;
  menu->mdata_free = attach_private_data_free;

  // NT_COLOR is handled by the SimpleDialog
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, attach_config_observer, menu);
  notify_observer_add(menu->win->notify, NT_WINDOW, attach_window_observer, menu->win);

  sbar_set_title(sdw.sbar, _("Attachments"));

  struct MuttWindow *old_focus = window_set_focus(menu->win);
  // ---------------------------------------------------------------------------
  // Event Loop
  int rc = 0;
  int op = OP_NULL;
  do
  {
    menu_tagging_dispatcher(menu->win, op);
    window_redraw(NULL);

    op = km_dokey(MENU_ATTACHMENT, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);
    if (op < 0)
      continue;
    if (op == OP_NULL)
    {
      km_error_key(MENU_ATTACHMENT);
      continue;
    }
    mutt_clear_error();

    rc = attach_function_dispatcher(sdw.dlg, op);
    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(menu->win, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);

    if (rc == FR_CONTINUE)
    {
      op = priv->op;
    }

  } while (rc != FR_DONE);
  // ---------------------------------------------------------------------------

  window_set_focus(old_focus);
  simple_dialog_free(&sdw.dlg);
}
