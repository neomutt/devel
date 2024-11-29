/**
 * @file
 * PGP Key Selection Dialog
 *
 * @authors
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 наб <nabijaczleweli@nabijaczleweli.xyz>
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
 * @page crypt_dlg_pgp PGP Key Selection Dialog
 *
 * The PGP Key Selection Dialog lets the user select a PGP key.
 *
 * This is a @ref gui_simple
 *
 * ## Windows
 *
 * | Name                     | Type       | See Also  |
 * | :----------------------- | :--------- | :-------- |
 * | PGP Key Selection Dialog | WT_DLG_PGP | dlg_pgp() |
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
 * - #PgpUid
 *
 * The @ref gui_simple holds a Menu.  The PGP Key Selection Dialog stores its
 * data (#PgpUid) in Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type  | Handler                   |
 * | :---------- | :------------------------ |
 * | #NT_CONFIG  | pgp_key_config_observer() |
 * | #NT_WINDOW  | pgp_key_window_observer() |
 *
 * The PGP Key Selection Dialog doesn't have any specific colours, so it
 * doesn't need to support #NT_COLOR.
 *
 * The PGP Key Selection Dialog does not implement MuttWindow::recalc() or
 * MuttWindow::repaint().
 *
 * Some other events are handled by the @ref gui_simple.
 */

#include "config.h"
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include "private.h"
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "expando/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "expando_pgp.h"
#include "globals.h"
#include "mutt_logging.h"
#include "pgp_functions.h"
#include "pgplib.h"
#include "sort.h"

/// Help Bar for the PGP key selection dialog
static const struct Mapping PgpHelp[] = {
  // clang-format off
  { N_("Exit"),      OP_EXIT },
  { N_("Select"),    OP_GENERIC_SELECT_ENTRY },
  { N_("Check key"), OP_VERIFY_KEY },
  { N_("Help"),      OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * pgp_make_entry - Format a PGP Key for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $pgp_entry_format
 */
static int pgp_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  struct PgpData *pd = menu->mdata;
  struct PgpUid **puid = ARRAY_GET(pd->key_table, line);
  if (!*puid)
    return 0;

  struct PgpEntry entry = { line + 1, *puid };

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  struct ExpandoRenderData PgpEntryRenderData[] = {
    // clang-format off
    { ED_PGP,     PgpEntryRenderCallbacks1, &entry, MUTT_FORMAT_ARROWCURSOR },
    { ED_PGP_KEY, PgpEntryRenderCallbacks2, &entry, MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_pgp_entry_format = cs_subset_expando(NeoMutt->sub, "pgp_entry_format");
  return expando_filter(c_pgp_entry_format, PgpEntryRenderData, max_cols, EnvList, buf);
}

/**
 * pgp_key_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
static int pgp_key_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (!mutt_str_equal(ev_c->name, "pgp_entry_format") &&
      !mutt_str_equal(ev_c->name, "pgp_key_sort"))
  {
    return 0;
  }

  struct Menu *menu = nc->global_data;
  menu_queue_redraw(menu, MENU_REDRAW_FULL);
  mutt_debug(LL_DEBUG5, "config done, request WA_RECALC, MENU_REDRAW_FULL\n");

  return 0;
}

/**
 * pgp_key_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 *
 * This function is triggered by changes to the windows.
 *
 * - Delete (this window): clean up the resources held by the Help Bar
 */
static int pgp_key_window_observer(struct NotifyCallback *nc)
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

  notify_observer_remove(NeoMutt->sub->notify, pgp_key_config_observer, menu);
  notify_observer_remove(win_menu->notify, pgp_key_window_observer, win_menu);

  mutt_debug(LL_DEBUG5, "window delete done\n");
  return 0;
}

/**
 * dlg_pgp - Let the user select a key to use - @ingroup gui_dlg
 * @param keys List of PGP keys
 * @param p    Address to match
 * @param s    String to match
 * @retval ptr Selected PGP key
 *
 * The Select PGP Key Dialog lets the user select an PGP Key to use.
 */
struct PgpKeyInfo *dlg_pgp(struct PgpKeyInfo *keys, struct Address *p, const char *s)
{
  struct Menu *menu = NULL;
  char buf[1024] = { 0 };
  bool unusable = false;
  struct PgpUidArray pua = ARRAY_HEAD_INITIALIZER;

  const bool c_pgp_show_unusable = cs_subset_bool(NeoMutt->sub, "pgp_show_unusable");
  for (struct PgpKeyInfo *kp = keys; kp; kp = kp->next)
  {
    if (!c_pgp_show_unusable && (kp->flags & KEYFLAG_CANTUSE))
    {
      unusable = true;
      continue;
    }

    for (struct PgpUid *a = kp->address; a; a = a->next)
    {
      if (!c_pgp_show_unusable && (a->flags & KEYFLAG_CANTUSE))
      {
        unusable = true;
        continue;
      }

      ARRAY_ADD(&pua, a);
    }
  }

  if ((ARRAY_SIZE(&pua) == 0) && unusable)
  {
    mutt_error(_("All matching keys are expired, revoked, or disabled"));
    return NULL;
  }

  pgp_sort_keys(&pua);

  struct SimpleDialogWindows sdw = simple_dialog_new(MENU_PGP, WT_DLG_PGP, PgpHelp);
  menu = sdw.menu;
  struct PgpData pd = { false, menu, &pua, NULL };

  menu->max = ARRAY_SIZE(&pua);
  menu->make_entry = pgp_make_entry;
  menu->mdata = &pd;
  menu->mdata_free = NULL; // Menu doesn't own the data

  // NT_COLOR is handled by the SimpleDialog
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, pgp_key_config_observer, menu);
  notify_observer_add(menu->win->notify, NT_WINDOW, pgp_key_window_observer, menu->win);

  if (p)
    snprintf(buf, sizeof(buf), _("PGP keys matching <%s>"), buf_string(p->mailbox));
  else
    snprintf(buf, sizeof(buf), _("PGP keys matching \"%s\""), s);

  sbar_set_title(sdw.sbar, buf);

  mutt_clear_error();

  struct MuttWindow *old_focus = window_set_focus(menu->win);
  // ---------------------------------------------------------------------------
  // Event Loop
  int op = OP_NULL;
  do
  {
    menu_tagging_dispatcher(menu->win, op);
    window_redraw(NULL);

    op = km_dokey(MENU_PGP, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);
    if (op < 0)
      continue;
    if (op == OP_NULL)
    {
      km_error_key(MENU_PGP);
      continue;
    }
    mutt_clear_error();

    int rc = pgp_function_dispatcher(sdw.dlg, op);

    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(menu->win, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);
  } while (!pd.done);
  // ---------------------------------------------------------------------------

  ARRAY_FREE(&pua);
  window_set_focus(old_focus);
  simple_dialog_free(&sdw.dlg);
  return pd.key;
}
