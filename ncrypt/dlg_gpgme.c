/**
 * @file
 * GPGME Key Selection Dialog
 *
 * @authors
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Rayford Shireman
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
 * @page crypt_dlg_gpgme GPGME Key Selection Dialog
 *
 * The GPGME Key Selection Dialog lets the user select a PGP key.
 *
 * This is a @ref gui_simple
 *
 * ## Windows
 *
 * | Name                       | Type         | See Also           |
 * | :------------------------- | :----------- | :----------------- |
 * | GPGME Key Selection Dialog | WT_DLG_GPGME | dlg_gpgme()        |
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
 * - #CryptKeyInfo
 *
 * The @ref gui_simple holds a Menu.  The GPGME Key Selection Dialog stores its
 * data (#CryptKeyInfo) in Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type  | Handler                     |
 * | :---------- | :-------------------------- |
 * | #NT_CONFIG  | gpgme_key_config_observer() |
 * | #NT_WINDOW  | gpgme_key_window_observer() |
 *
 * The GPGME Key Selection Dialog doesn't have any specific colours, so it
 * doesn't need to support #NT_COLOR.
 *
 * The GPGME Key Selection Dialog does not implement MuttWindow::recalc() or
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
#include "crypt_gpgme.h"
#include "expando_gpgme.h"
#include "globals.h"
#include "gpgme_functions.h"
#include "mutt_logging.h"
#include "sort.h"

/// Help Bar for the GPGME key selection dialog
static const struct Mapping GpgmeHelp[] = {
  // clang-format off
  { N_("Exit"),      OP_EXIT },
  { N_("Select"),    OP_GENERIC_SELECT_ENTRY },
  { N_("Check key"), OP_VERIFY_KEY },
  { N_("Help"),      OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * crypt_make_entry - Format a PGP Key for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $pgp_entry_format
 */
static int crypt_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  struct GpgmeData *gd = menu->mdata;
  struct CryptKeyInfo **pinfo = ARRAY_GET(gd->key_table, line);
  if (!pinfo)
    return 0;

  struct CryptEntry entry = { line + 1, *pinfo };

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  struct ExpandoRenderData PgpEntryGpgmeRenderData[] = {
    // clang-format off
    { ED_PGP,     PgpEntryGpgmeRenderCallbacks1, &entry, MUTT_FORMAT_ARROWCURSOR },
    { ED_PGP_KEY, PgpEntryGpgmeRenderCallbacks2, &entry, MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_pgp_entry_format = cs_subset_expando(NeoMutt->sub, "pgp_entry_format");
  return expando_filter(c_pgp_entry_format, PgpEntryGpgmeRenderData, max_cols, EnvList, buf);
}

/**
 * gpgme_key_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
static int gpgme_key_config_observer(struct NotifyCallback *nc)
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
 * gpgme_key_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 *
 * This function is triggered by changes to the windows.
 *
 * - Delete (this window): clean up the resources held by the Help Bar
 */
static int gpgme_key_window_observer(struct NotifyCallback *nc)
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

  notify_observer_remove(NeoMutt->sub->notify, gpgme_key_config_observer, menu);
  notify_observer_remove(win_menu->notify, gpgme_key_window_observer, win_menu);

  mutt_debug(LL_DEBUG5, "window delete done\n");
  return 0;
}

/**
 * dlg_gpgme - Get the user to select a key - @ingroup gui_dlg
 * @param[in]  keys         List of keys to select from
 * @param[in]  p            Address to match
 * @param[in]  s            Real name to display
 * @param[in]  app          Flags, e.g. #APPLICATION_PGP
 * @param[out] forced_valid Set to true if user overrode key's validity
 * @retval ptr Key selected by user
 *
 * The Select GPGME Key Dialog lets the user select a PGP Key to use.
 */
struct CryptKeyInfo *dlg_gpgme(struct CryptKeyInfo *keys, struct Address *p,
                               const char *s, unsigned int app, bool *forced_valid)
{
  /* build the key table */
  struct CryptKeyInfoArray ckia = ARRAY_HEAD_INITIALIZER;
  const bool c_pgp_show_unusable = cs_subset_bool(NeoMutt->sub, "pgp_show_unusable");
  bool unusable = false;
  for (struct CryptKeyInfo *k = keys; k; k = k->next)
  {
    if (!c_pgp_show_unusable && (k->flags & KEYFLAG_CANTUSE))
    {
      unusable = true;
      continue;
    }

    ARRAY_ADD(&ckia, k);
  }

  if ((ARRAY_SIZE(&ckia) == 0) && unusable)
  {
    mutt_error(_("All matching keys are marked expired/revoked"));
    return NULL;
  }

  gpgme_sort_keys(&ckia);

  enum MenuType menu_to_use = MENU_GENERIC;
  if (app & APPLICATION_PGP)
    menu_to_use = MENU_PGP;
  else if (app & APPLICATION_SMIME)
    menu_to_use = MENU_SMIME;

  struct SimpleDialogWindows sdw = simple_dialog_new(menu_to_use, WT_DLG_GPGME, GpgmeHelp);

  struct Menu *menu = sdw.menu;
  struct GpgmeData gd = { false, menu, &ckia, NULL, forced_valid };

  menu->max = ARRAY_SIZE(&ckia);
  menu->make_entry = crypt_make_entry;
  menu->mdata = &gd;
  menu->mdata_free = NULL; // Menu doesn't own the data

  // NT_COLOR is handled by the SimpleDialog
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, gpgme_key_config_observer, menu);
  notify_observer_add(menu->win->notify, NT_WINDOW, gpgme_key_window_observer, menu->win);

  const char *ts = NULL;

  if ((app & APPLICATION_PGP) && (app & APPLICATION_SMIME))
    ts = _("PGP and S/MIME keys matching");
  else if ((app & APPLICATION_PGP))
    ts = _("PGP keys matching");
  else if ((app & APPLICATION_SMIME))
    ts = _("S/MIME keys matching");
  else
    ts = _("keys matching");

  char buf[1024] = { 0 };
  if (p)
  {
    /* L10N: 1$s is one of the previous four entries.
       %2$s is an address.
       e.g. "S/MIME keys matching <john.doe@example.com>" */
    snprintf(buf, sizeof(buf), _("%s <%s>"), ts, buf_string(p->mailbox));
  }
  else
  {
    /* L10N: e.g. 'S/MIME keys matching "John Doe".' */
    snprintf(buf, sizeof(buf), _("%s \"%s\""), ts, s);
  }

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

    op = km_dokey(menu_to_use, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);
    if (op < 0)
      continue;
    if (op == OP_NULL)
    {
      km_error_key(menu_to_use);
      continue;
    }
    mutt_clear_error();

    int rc = gpgme_function_dispatcher(sdw.dlg, op);

    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(menu->win, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);
  } while (!gd.done);
  // ---------------------------------------------------------------------------

  ARRAY_FREE(&ckia);
  window_set_focus(old_focus);
  simple_dialog_free(&sdw.dlg);
  return gd.key;
}
