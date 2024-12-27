/**
 * @file
 * Simple Pager Dialog notification observers
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
 * @page spager_dlg_observer Simple Pager Dialog notification observers
 *
 * Simple Pager Dialog notification observers
 */

#include "config.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "dlg_observer.h"
#include "ddata.h"
#include "dlg_spager.h"
#include "wdata.h"

/**
 * dlg_spager_spager_observer - Notification that the Simple Pager has changed - Implements ::observer_t - @ingroup observer_api
 */
static int dlg_spager_spager_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_SPAGER)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  // struct EventSimplePager *ev_sp = nc->event_data;
  struct SimplePagerDialogData *ddata = nc->global_data;
  struct SimplePagerWindowData *wdata = ddata->win_pager->wdata;

  update_sbar(ddata, wdata);

  mutt_debug(LL_DEBUG1, "\033[1;7mSimple Pager event\033[0m\n");
  return 0;
}

/**
 * dlg_spager_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
static int dlg_spager_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (mutt_str_equal(ev_c->name, "markers"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "pager_context"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "search_context"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "smart_wrap"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "status_on_top"))
  {
    struct MuttWindow *dlg = nc->global_data;
    window_status_on_top(dlg, ev_c->sub);
  }
  else if (mutt_str_equal(ev_c->name, "tilde"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "wrap"))
  {
  }
  else if (mutt_str_equal(ev_c->name, "wrap_search"))
  {
  }

  return 0;
}

/**
 * dlg_spager_add_observers - Add observers to the Simple Pager Dialog
 * @param dlg Dialog Window
 */
void dlg_spager_add_observers(struct MuttWindow *dlg)
{
  struct SimplePagerDialogData *ddata = dlg->wdata;

  spager_observer_add(ddata->win_pager, dlg_spager_spager_observer, ddata);
  notify_observer_add(NeoMutt->notify, NT_CONFIG, dlg_spager_config_observer, dlg);
}

/**
 * dlg_spager_remove_observers - Remove observers from the Simple Pager Dialog
 * @param dlg Dialog Window
 *
 * prob unnec, use window notification
 */
void dlg_spager_remove_observers(struct MuttWindow *dlg)
{
  struct SimplePagerDialogData *ddata = dlg->wdata;

  spager_observer_remove(ddata->win_pager, dlg_spager_spager_observer, ddata->win_pager);
}
