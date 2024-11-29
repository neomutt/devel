/**
 * @file
 * Compose Attachments
 *
 * @authors
 * Copyright (C) 2021-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
 * Copyright (C) 2024 Dennis Schön <mail@dennis-schoen.de>
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
 * @page compose_attach Attachments window
 *
 * The Compose Attachments Window displays the attachments of an email.
 *
 * ## Windows
 *
 * | Name                       | Type      | See Also     |
 * | :------------------------- | :-------- | :----------- |
 * | Compose Attachments Window | WT_MENU   | attach_new() |
 *
 * **Parent**
 * - @ref compose_dlg_compose
 *
 * **Children**
 *
 * None.
 *
 * ## Data
 * - #ComposeAttachData
 *
 * The Compose Attachments Window stores its data (#ComposeAttachData) in
 * Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type            | Handler                   |
 * | :-------------------- | :------------------------ |
 * | #NT_CONFIG            | attach_config_observer()  |
 * | #NT_EMAIL             | attach_email_observer()   |
 * | #NT_WINDOW            | attach_window_observer()  |
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "attach/lib.h"
#include "convert/lib.h"
#include "expando/lib.h"
#include "menu/lib.h"
#include "attach_data.h"
#include "globals.h"
#include "shared_data.h"

/**
 * cum_attachs_size - Cumulative Attachments Size
 * @param sub   Config Subset
 * @param adata Attachment data
 * @retval num Bytes in attachments
 *
 * Returns the total number of bytes used by the attachments in the attachment
 * list _after_ content-transfer-encodings have been applied.
 */
unsigned long cum_attachs_size(struct ConfigSubset *sub, struct ComposeAttachData *adata)
{
  if (!adata || !adata->actx)
    return 0;

  size_t s = 0;
  struct Content *info = NULL;
  struct Body *b = NULL;
  struct AttachCtx *actx = adata->actx;
  struct AttachPtr **idx = actx->idx;

  for (unsigned short i = 0; i < actx->idxlen; i++)
  {
    b = idx[i]->body;

    if (!b->content)
      b->content = mutt_get_content_info(b->filename, b, sub);

    info = b->content;
    if (info)
    {
      switch (b->encoding)
      {
        case ENC_QUOTED_PRINTABLE:
          s += 3 * (info->lobin + info->hibin) + info->ascii + info->crlf;
          break;
        case ENC_BASE64:
          s += (4 * (info->lobin + info->hibin + info->ascii + info->crlf)) / 3;
          break;
        default:
          s += info->lobin + info->hibin + info->ascii + info->crlf;
          break;
      }
    }
  }

  return s;
}

/**
 * attach_email_observer - Notification that the Email has changed - Implements ::observer_t - @ingroup observer_api
 */
static int attach_email_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_EMAIL)
    return 0;
  if (!nc->global_data)
    return -1;
  if (nc->event_subtype != NT_EMAIL_CHANGE_ATTACH)
    return 0;

  struct MuttWindow *win_attach = nc->global_data;

  win_attach->actions |= WA_RECALC;
  mutt_debug(LL_DEBUG5, "compose done, request WA_RECALC\n");

  return 0;
}

/**
 * attach_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
int attach_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;
  if (!mutt_str_equal(ev_c->name, "attach_format"))
    return 0;

  struct MuttWindow *win_attach = nc->global_data;
  win_attach->actions |= WA_RECALC;
  mutt_debug(LL_DEBUG5, "config, request WA_RECALC\n");

  return 0;
}

/**
 * attach_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 */
static int attach_window_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_WINDOW)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct MuttWindow *win_attach = nc->global_data;
  struct EventWindow *ev_w = nc->event_data;
  if (ev_w->win != win_attach)
    return 0;

  if (nc->event_subtype == NT_WINDOW_STATE)
  {
    win_attach->actions |= WA_RECALC;
    mutt_debug(LL_DEBUG5, "window state done, request WA_RECALC\n");
  }
  else if (nc->event_subtype == NT_WINDOW_DELETE)
  {
    struct Menu *menu = win_attach->wdata;
    struct ComposeAttachData *adata = menu->mdata;
    struct AttachCtx *actx = adata->actx;
    notify_observer_remove(actx->email->notify, attach_email_observer, win_attach);
    notify_observer_remove(NeoMutt->sub->notify, attach_config_observer, win_attach);
    notify_observer_remove(win_attach->notify, attach_window_observer, win_attach);
    mutt_debug(LL_DEBUG5, "window delete done\n");
  }

  return 0;
}

/**
 * compose_attach_tag - Tag an attachment - Implements Menu::tag() - @ingroup menu_tag
 */
static int compose_attach_tag(struct Menu *menu, int sel, int act)
{
  struct ComposeAttachData *adata = menu->mdata;
  struct AttachCtx *actx = adata->actx;
  struct Body *cur = actx->idx[actx->v2r[sel]]->body;
  bool ot = cur->tagged;

  cur->tagged = ((act >= 0) ? act : !cur->tagged);
  return cur->tagged - ot;
}

/**
 * compose_make_entry - Format an Attachment for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $attach_format
 */
static int compose_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  struct ComposeAttachData *adata = menu->mdata;
  struct AttachCtx *actx = adata->actx;
  struct ComposeSharedData *shared = menu->win->parent->wdata;
  struct ConfigSubset *sub = shared->sub;

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
    { ED_ATTACH, AttachRenderCallbacks, aptr, MUTT_FORMAT_STAT_FILE | MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_attach_format = cs_subset_expando(sub, "attach_format");
  return expando_filter(c_attach_format, AttachRenderData, max_cols, EnvList, buf);
}

/**
 * attach_recalc - Recalculate the Window data - Implements MuttWindow::recalc() - @ingroup window_recalc
 */
static int attach_recalc(struct MuttWindow *win)
{
  struct Menu *menu = win->wdata;
  struct ComposeAttachData *adata = menu->mdata;

  const int cur_rows = win->state.rows;
  const int new_rows = adata->actx->idxlen;

  if (new_rows != cur_rows)
  {
    win->req_rows = new_rows;
    mutt_window_reflow(win->parent);
    menu_adjust(menu);
  }

  win->actions |= WA_REPAINT;
  mutt_debug(LL_DEBUG5, "recalc done, request WA_REPAINT\n");
  return 0;
}

/**
 * attach_new - Create the Attachments Menu
 * @param parent     Parent Window
 * @param shared     Shared compose data
 */
struct MuttWindow *attach_new(struct MuttWindow *parent, struct ComposeSharedData *shared)
{
  struct MuttWindow *win_attach = menu_window_new(MENU_COMPOSE, NeoMutt->sub);

  struct ComposeAttachData *adata = attach_data_new(shared->email);

  shared->adata = adata;

  // NT_COLOR is handled by the Menu Window
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, attach_config_observer, win_attach);
  notify_observer_add(shared->email->notify, NT_EMAIL, attach_email_observer, win_attach);
  notify_observer_add(win_attach->notify, NT_WINDOW, attach_window_observer, win_attach);

  struct Menu *menu = win_attach->wdata;
  menu->page_len = win_attach->state.rows;
  menu->win = win_attach;

  menu->make_entry = compose_make_entry;
  menu->tag = compose_attach_tag;
  menu->mdata = adata;
  menu->mdata_free = attach_data_free;
  adata->menu = menu;

  return win_attach;
}

/**
 * attachment_size_fixed - Make the Attachment Window fixed-size
 * @param win Attachment Window
 */
void attachment_size_fixed(struct MuttWindow *win)
{
  if (!win || (win->size == MUTT_WIN_SIZE_FIXED))
    return;

  win->size = MUTT_WIN_SIZE_FIXED;
  win->recalc = attach_recalc;
}

/**
 * attachment_size_max - Make the Attachment Window maximised
 * @param win Attachment Window
 */
void attachment_size_max(struct MuttWindow *win)
{
  if (!win || (win->size == MUTT_WIN_SIZE_MAXIMISE))
    return;

  win->size = MUTT_WIN_SIZE_MAXIMISE;
  win->recalc = NULL;
}
