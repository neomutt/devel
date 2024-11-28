/**
 * @file
 * Compose Bar (status)
 *
 * @authors
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
 * @page compose_cbar Compose Bar (status)
 *
 * The Compose Bar Window displays status info about the email.
 *
 * ## Windows
 *
 * | Name               | Type          | See Also   |
 * | :----------------- | :------------ | :--------- |
 * | Compose Bar Window | WT_STATUS_BAR | cbar_new() |
 *
 * **Parent**
 * - @ref compose_dlg_compose
 *
 * **Children**
 *
 * None.
 *
 * ## Data
 * - #ComposeBarData
 *
 * The Compose Bar Window stores its data (#ComposeBarData) in
 * MuttWindow::wdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type            | Handler                 |
 * | :-------------------- | :---------------------- |
 * | #NT_COLOR             | cbar_color_observer()   |
 * | #NT_CONFIG            | cbar_config_observer()  |
 * | #NT_EMAIL             | cbar_email_observer()   |
 * | #NT_WINDOW            | cbar_window_observer()  |
 * | MuttWindow::recalc()  | cbar_recalc()           |
 * | MuttWindow::repaint() | cbar_repaint()          |
 */

#include "config.h"
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "cbar.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "index/lib.h"
#include "cbar_data.h"
#include "expando.h"
#include "globals.h"
#include "shared_data.h"

/**
 * cbar_recalc - Recalculate the Window data - Implements MuttWindow::recalc() - @ingroup window_recalc
 *
 * @sa $compose_format
 */
static int cbar_recalc(struct MuttWindow *win)
{
  struct Buffer *buf = buf_pool_get();
  struct ComposeSharedData *shared = win->parent->wdata;

  struct ExpandoRenderData ComposeRenderData[] = {
    // clang-format off
    { ED_COMPOSE, ComposeRenderCallbacks, shared, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_compose_format = cs_subset_expando(shared->sub, "compose_format");
  expando_filter(c_compose_format, ComposeRenderCallbacks, shared,
                 MUTT_FORMAT_NO_FLAGS, win->state.cols, EnvList, buf);

  struct ComposeBarData *cbar_data = win->wdata;
  if (!mutt_str_equal(buf_string(buf), cbar_data->compose_format))
  {
    mutt_str_replace(&cbar_data->compose_format, buf_string(buf));
    win->actions |= WA_REPAINT;
    mutt_debug(LL_DEBUG5, "recalc done, request WA_REPAINT\n");
  }
  buf_pool_release(&buf);

  return 0;
}

/**
 * cbar_repaint - Repaint the Window - Implements MuttWindow::repaint() - @ingroup window_repaint
 */
static int cbar_repaint(struct MuttWindow *win)
{
  struct ComposeBarData *cbar_data = win->wdata;

  mutt_window_move(win, 0, 0);
  mutt_curses_set_normal_backed_color_by_id(MT_COLOR_STATUS);
  mutt_window_clrtoeol(win);

  mutt_window_move(win, 0, 0);
  mutt_draw_statusline(win, win->state.cols, cbar_data->compose_format,
                       mutt_str_len(cbar_data->compose_format));
  mutt_curses_set_color_by_id(MT_COLOR_NORMAL);
  mutt_debug(LL_DEBUG5, "repaint done\n");

  return 0;
}

/**
 * cbar_color_observer - Notification that a Color has changed - Implements ::observer_t - @ingroup observer_api
 */
int cbar_color_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_COLOR)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventColor *ev_c = nc->event_data;

  // MT_COLOR_MAX is sent on `uncolor *`
  if ((ev_c->cid != MT_COLOR_STATUS) && (ev_c->cid != MT_COLOR_NORMAL) &&
      (ev_c->cid != MT_COLOR_MAX))
  {
    return 0;
  }

  struct MuttWindow *win_cbar = nc->global_data;
  win_cbar->actions |= WA_REPAINT;
  mutt_debug(LL_DEBUG5, "color done, request WA_REPAINT\n");

  return 0;
}

/**
 * cbar_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
int cbar_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;
  if (!mutt_str_equal(ev_c->name, "compose_format"))
    return 0;

  struct MuttWindow *win_cbar = nc->global_data;
  win_cbar->actions |= WA_RECALC;
  mutt_debug(LL_DEBUG5, "config done, request WA_RECALC\n");

  return 0;
}

/**
 * cbar_email_observer - Notification that the Email has changed - Implements ::observer_t - @ingroup observer_api
 */
static int cbar_email_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_EMAIL)
    return 0;
  if (!nc->global_data)
    return -1;

  struct MuttWindow *win_cbar = nc->global_data;
  win_cbar->actions |= WA_RECALC;
  mutt_debug(LL_DEBUG5, "compose done, request WA_RECALC\n");

  return 0;
}

/**
 * cbar_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 */
static int cbar_window_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_WINDOW)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct MuttWindow *win_cbar = nc->global_data;
  struct EventWindow *ev_w = nc->event_data;
  if (ev_w->win != win_cbar)
    return 0;

  if (nc->event_subtype == NT_WINDOW_STATE)
  {
    win_cbar->actions |= WA_RECALC | WA_REPAINT;
    mutt_debug(LL_DEBUG5, "window state done, request WA_RECALC\n");
  }
  else if (nc->event_subtype == NT_WINDOW_DELETE)
  {
    struct MuttWindow *dlg = win_cbar->parent;
    struct ComposeSharedData *shared = dlg->wdata;

    mutt_color_observer_remove(cbar_color_observer, win_cbar);
    notify_observer_remove(NeoMutt->sub->notify, cbar_config_observer, win_cbar);
    notify_observer_remove(shared->email->notify, cbar_email_observer, win_cbar);
    notify_observer_remove(win_cbar->notify, cbar_window_observer, win_cbar);

    mutt_debug(LL_DEBUG5, "window delete done\n");
  }

  return 0;
}

/**
 * cbar_new - Create the Compose Bar (status)
 * @param shared Shared compose data
 */
struct MuttWindow *cbar_new(struct ComposeSharedData *shared)
{
  struct MuttWindow *win_cbar = mutt_window_new(WT_STATUS_BAR, MUTT_WIN_ORIENT_VERTICAL,
                                                MUTT_WIN_SIZE_FIXED,
                                                MUTT_WIN_SIZE_UNLIMITED, 1);

  win_cbar->wdata = cbar_data_new();
  win_cbar->wdata_free = cbar_data_free;
  win_cbar->recalc = cbar_recalc;
  win_cbar->repaint = cbar_repaint;

  mutt_color_observer_add(cbar_color_observer, win_cbar);
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, cbar_config_observer, win_cbar);
  notify_observer_add(shared->email->notify, NT_EMAIL, cbar_email_observer, win_cbar);
  notify_observer_add(win_cbar->notify, NT_WINDOW, cbar_window_observer, win_cbar);

  return win_cbar;
}
