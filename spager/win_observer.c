/**
 * @file
 * Simple Pager Window notification observers
 *
 * @authors
 * Copyright (C) 2024-2025 Richard Russon <rich@flatcap.org>
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
 * @page spager_win_observer Simple Pager Window notification observers
 *
 * Simple Pager Window notification observers
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "win_observer.h"
#include "color/lib.h"
#include "wdata.h"

/**
 * win_spager_color_observer - Notification that a Color has changed - Implements ::observer_t - @ingroup observer_api
 */
static int win_spager_color_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_COLOR)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  // struct EventColor *ev_c = nc->event_data;

  // We _could_ recursively check the PagedFile to see if the colour is used,
  // but for now, just force a recalc.
  struct MuttWindow *win = nc->global_data;
  win->actions |= WA_REPAINT;
  mutt_debug(LL_DEBUG5, "color done, request WA_REPAINT, spager_REDRAW_FULL\n");

  return 0;
}

/**
 * update_cached_config - Update the cached copies of config options
 * @param wdata Window Data
 * @param name  Config option
 * @retval true Success, data updated
 *
 * The Simple Pager is affected by the following config:
 * - `$markers`
 * - `$smart_wrap`
 * - `$tilde`
 * - `$wrap`
 */
bool update_cached_config(struct SimplePagerWindowData *wdata, const char *name)
{
  if (!name || mutt_str_equal(name, "markers"))
  {
    wdata->c_markers = cs_subset_bool(wdata->sub, "markers");
    if (name)
      return true;
  }

  if (!name || mutt_str_equal(name, "smart_wrap"))
  {
    wdata->c_smart_wrap = cs_subset_bool(wdata->sub, "smart_wrap");
    if (name)
      return true;
  }

  if (!name || mutt_str_equal(name, "tilde"))
  {
    wdata->c_tilde = cs_subset_bool(wdata->sub, "tilde");
    if (name)
      return true;
  }

  if (!name || mutt_str_equal(name, "wrap"))
  {
    wdata->c_wrap = cs_subset_number(wdata->sub, "wrap");
    if (name)
      return true;
  }

  return !name;
}

/**
 * win_spager_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
static int win_spager_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;
  struct MuttWindow *win = nc->global_data;
  struct SimplePagerWindowData *wdata = win->wdata;

  if (update_cached_config(wdata, ev_c->name))
  {
    win->actions |= WA_RECALC;
    mutt_debug(LL_DEBUG5, "config done, request WA_RECALC\n");
  }

  return 0;
}

/**
 * win_spager_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 */
static int win_spager_window_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_WINDOW)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct MuttWindow *win = nc->global_data;
  struct EventWindow *ev_w = nc->event_data;
  if (ev_w->win != win)
    return 0;

  if (nc->event_subtype == NT_WINDOW_STATE)
  {
    win->actions |= WA_RECALC;
    mutt_debug(LL_DEBUG5, "window state done, request WA_RECALC\n");
  }
  else if (nc->event_subtype == NT_WINDOW_DELETE)
  {
    notify_observer_remove(NeoMutt->sub->notify, win_spager_config_observer, win);
    notify_observer_remove(win->notify, win_spager_window_observer, win);
    mutt_color_observer_remove(win_spager_color_observer, win);
    msgwin_clear_text(NULL);
    mutt_debug(LL_DEBUG5, "window delete done\n");
  }

  return 0;
}

/**
 * win_spager_add_observers - Add the notification observers
 * @param win Simple Pager Window
 * @param sub Config Subset
 */
void win_spager_add_observers(struct MuttWindow *win, struct ConfigSubset *sub)
{
  notify_observer_add(sub->notify, NT_CONFIG, win_spager_config_observer, win);
  notify_observer_add(win->notify, NT_WINDOW, win_spager_window_observer, win);
  mutt_color_observer_add(win_spager_color_observer, win);
}
