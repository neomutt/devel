/**
 * @file
 * Pattern Selection Dialog
 *
 * @authors
 * Copyright (C) 2019 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
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
 * @page pattern_dlg_pattern Pattern Selection Dialog
 *
 * The Pattern Selection Dialog lets the user select a pattern.
 *
 * This is a @ref gui_simple
 *
 * ## Windows
 *
 * | Name                     | Type           | See Also      |
 * | :----------------------- | :------------- | :------------ |
 * | Pattern Selection Dialog | WT_DLG_PATTERN | dlg_pattern() |
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
 * - #PatternEntry
 *
 * The @ref gui_simple holds a Menu.  The Pattern Selection Dialog stores its
 * data (#PatternEntry) in Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type  | Handler                   |
 * | :---------- | :------------------------ |
 * | #NT_CONFIG  | pattern_config_observer() |
 * | #NT_WINDOW  | pattern_window_observer() |
 *
 * The Pattern Selection Dialog doesn't have any specific colours, so it
 * doesn't need to support #NT_COLOR.
 *
 * The Pattern Selection Dialog does not implement MuttWindow::recalc() or
 * MuttWindow::repaint().
 *
 * Some other events are handled by the @ref gui_simple.
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "expando/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "expando.h"
#include "functions.h"
#include "globals.h"
#include "mutt_logging.h"
#include "pattern_data.h"

/// Help Bar for the Pattern selection dialog
static const struct Mapping PatternHelp[] = {
  // clang-format off
  { N_("Exit"),   OP_EXIT },
  { N_("Select"), OP_GENERIC_SELECT_ENTRY },
  { N_("Help"),   OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * pattern_make_entry - Create a Pattern for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $pattern_format
 */
static int pattern_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  struct PatternData *pd = menu->mdata;

  struct PatternEntry *entry = ARRAY_GET(&pd->entries, line);

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  struct ExpandoRenderData PatternRenderData[] = {
    // clang-format off
    { ED_PATTERN, PatternRenderCallbacks, entry, MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_pattern_format = cs_subset_expando(NeoMutt->sub, "pattern_format");
  return expando_filter(c_pattern_format, PatternRenderData, max_cols, EnvList, buf);
}

/**
 * create_pattern_entries - Create the Pattern Entries
 * @param pea Pattern Entry Array to fill
 */
static void create_pattern_entries(struct PatternEntryArray *pea)
{
  int num_entries = 0;
  while (Flags[num_entries].tag != 0)
    num_entries++;

  /* Add three more hard-coded entries */
  ARRAY_RESERVE(pea, num_entries + 3);

  struct Buffer *buf = buf_pool_get();

  struct PatternEntry entry = { 0 };
  for (int i = 0; Flags[i].tag != '\0'; i++)
  {
    entry.num = i + 1;

    buf_printf(buf, "~%c", Flags[i].tag);
    entry.tag = buf_strdup(buf);

    switch (Flags[i].eat_arg)
    {
      case EAT_REGEX:
        /* L10N:
           Pattern Completion Menu argument type: a regular expression
        */
        buf_add_printf(buf, " %s", _("EXPR"));
        break;
      case EAT_RANGE:
      case EAT_MESSAGE_RANGE:
        /* L10N:
           Pattern Completion Menu argument type: a numeric range.
           Used by ~m, ~n, ~X, ~z.
        */
        buf_add_printf(buf, " %s", _("RANGE"));
        break;
      case EAT_DATE:
        /* L10N:
           Pattern Completion Menu argument type: a date range
           Used by ~d, ~r.
        */
        buf_add_printf(buf, " %s", _("DATERANGE"));
        break;
      case EAT_QUERY:
        /* L10N:
           Pattern Completion Menu argument type: a query
           Used by ~I.
        */
        buf_add_printf(buf, " %s", _("QUERY"));
        break;
      default:
        break;
    }

    entry.expr = buf_strdup(buf);
    entry.desc = mutt_str_dup(_(Flags[i].desc));

    ARRAY_ADD(pea, entry);
  }

  /* Add struct MuttThread patterns manually.
   * Note we allocated 3 extra slots for these above. */

  /* L10N:
     Pattern Completion Menu argument type: a nested pattern.
     Used by ~(), ~<(), ~>().
  */
  const char *patternstr = _("PATTERN");

  entry.num = ARRAY_SIZE(pea) + 1;
  entry.tag = mutt_str_dup("~()");
  buf_printf(buf, "~(%s)", patternstr);
  entry.expr = buf_strdup(buf);
  // L10N: Pattern Completion Menu description for ~()
  entry.desc = mutt_str_dup(_("messages in threads containing messages matching PATTERN"));
  ARRAY_ADD(pea, entry);

  entry.num = ARRAY_SIZE(pea) + 1;
  entry.tag = mutt_str_dup("~<()");
  buf_printf(buf, "~<(%s)", patternstr);
  entry.expr = buf_strdup(buf);
  // L10N: Pattern Completion Menu description for ~<()
  entry.desc = mutt_str_dup(_("messages whose immediate parent matches PATTERN"));
  ARRAY_ADD(pea, entry);

  entry.num = ARRAY_SIZE(pea) + 1;
  entry.tag = mutt_str_dup("~>()");
  buf_printf(buf, "~>(%s)", patternstr);
  entry.expr = buf_strdup(buf);
  // L10N: Pattern Completion Menu description for ~>()
  entry.desc = mutt_str_dup(_("messages having an immediate child matching PATTERN"));
  ARRAY_ADD(pea, entry);

  buf_pool_release(&buf);
}

/**
 * pattern_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 *
 * The Address Book Window is affected by changes to `$sort_pattern`.
 */
static int pattern_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (!mutt_str_equal(ev_c->name, "pattern_format"))
    return 0;

  struct Menu *menu = nc->global_data;
  menu_queue_redraw(menu, MENU_REDRAW_FULL);
  mutt_debug(LL_DEBUG5, "config done, request WA_RECALC, MENU_REDRAW_FULL\n");

  return 0;
}

/**
 * pattern_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 *
 * This function is triggered by changes to the windows.
 *
 * - Delete (this window): clean up the resources held by the Help Bar
 */
static int pattern_window_observer(struct NotifyCallback *nc)
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

  notify_observer_remove(NeoMutt->sub->notify, pattern_config_observer, menu);
  notify_observer_remove(win_menu->notify, pattern_window_observer, win_menu);

  mutt_debug(LL_DEBUG5, "window delete done\n");
  return 0;
}

/**
 * dlg_pattern - Show menu to select a Pattern - @ingroup gui_dlg
 * @param buf Buffer for the selected Pattern
 * @retval true A selection was made
 *
 * The Select Pattern Dialog shows the user a help page of Patterns.
 * They can select one to auto-complete some functions, e.g. `<limit>`
 */
bool dlg_pattern(struct Buffer *buf)
{
  struct PatternData *pd = pattern_data_new();

  struct SimpleDialogWindows sdw = simple_dialog_new(MENU_GENERIC, WT_DLG_PATTERN, PatternHelp);
  create_pattern_entries(&pd->entries);

  struct Menu *menu = sdw.menu;
  pd->menu = menu;
  pd->buf = buf;

  menu->mdata = pd;
  menu->mdata_free = pattern_data_free;
  menu->make_entry = pattern_make_entry;
  menu->max = ARRAY_SIZE(&pd->entries);

  // L10N: Pattern completion menu title
  sbar_set_title(sdw.sbar, _("Patterns"));

  // NT_COLOR is handled by the SimpleDialog
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, pattern_config_observer, menu);
  notify_observer_add(menu->win->notify, NT_WINDOW, pattern_window_observer, menu->win);

  struct MuttWindow *old_focus = window_set_focus(menu->win);
  // ---------------------------------------------------------------------------
  // Event Loop
  int op = OP_NULL;
  do
  {
    menu_tagging_dispatcher(menu->win, op);
    window_redraw(NULL);

    op = km_dokey(MENU_DIALOG, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);
    if (op < 0)
      continue;
    if (op == OP_NULL)
    {
      km_error_key(MENU_GENERIC);
      continue;
    }
    mutt_clear_error();

    int rc = pattern_function_dispatcher(sdw.dlg, op);
    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(menu->win, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);
  } while (!pd->done);
  // ---------------------------------------------------------------------------

  bool rc = pd->selection;

  window_set_focus(old_focus);
  simple_dialog_free(&sdw.dlg);

  return rc;
}
