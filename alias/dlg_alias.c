/**
 * @file
 * Address book
 *
 * @authors
 * Copyright (C) 2017-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2020 Romeu Vieira <romeu.bizz@gmail.com>
 * Copyright (C) 2020-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2023 Anna Figueiredo Gomes <navi@vlhl.dev>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page alias_dlg_alias Address Book Dialog
 *
 * The Address Book Dialog allows the user to select, add or delete aliases.
 *
 * This is a @ref gui_simple
 *
 * @note New aliases will be saved to `$alias_file`.
 *       Deleted aliases are deleted from memory only.
 *
 * ## Windows
 *
 * | Name                | Type         | See Also    |
 * | :------------------ | :----------- | :---------- |
 * | Address Book Dialog | WT_DLG_ALIAS | dlg_alias() |
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
 * - #AliasMenuData
 *
 * The @ref gui_simple holds a Menu.  The Address Book Dialog stores
 * its data (#AliasMenuData) in Menu::mdata.
 *
 * ## Events
 *
 * Once constructed, it is controlled by the following events:
 *
 * | Event Type            | Handler                    |
 * | :-------------------- | :------------------------- |
 * | #NT_ALIAS             | alias_alias_observer()     |
 * | #NT_CONFIG            | alias_config_observer()    |
 * | #NT_WINDOW            | alias_window_observer()    |
 * | MuttWindow::recalc()  | alias_recalc()             |
 *
 * The Address Book Dialog doesn't have any specific colours, so it doesn't
 * need to support #NT_COLOR.
 *
 * MuttWindow::recalc() is handled to support custom sorting.
 *
 * Some other events are handled by the @ref gui_simple.
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "expando/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "pattern/lib.h"
#include "send/lib.h"
#include "alias.h"
#include "expando.h"
#include "functions.h"
#include "globals.h"
#include "gui.h"
#include "mutt_logging.h"

/// Help Bar for the Alias dialog (address book)
static const struct Mapping AliasHelp[] = {
  // clang-format off
  { N_("Exit"),     OP_EXIT },
  { N_("Del"),      OP_DELETE },
  { N_("Undel"),    OP_UNDELETE },
  { N_("Sort"),     OP_SORT },
  { N_("Rev-Sort"), OP_SORT_REVERSE },
  { N_("Select"),   OP_GENERIC_SELECT_ENTRY },
  { N_("Help"),     OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * alias_make_entry - Format an Alias for the Menu - Implements Menu::make_entry() - @ingroup menu_make_entry
 *
 * @sa $alias_format
 */
static int alias_make_entry(struct Menu *menu, int line, int max_cols, struct Buffer *buf)
{
  const struct AliasMenuData *mdata = menu->mdata;
  const struct AliasViewArray *ava = &mdata->ava;
  struct AliasView *av = ARRAY_GET(ava, line);

  const bool c_arrow_cursor = cs_subset_bool(menu->sub, "arrow_cursor");
  if (c_arrow_cursor)
  {
    const char *const c_arrow_string = cs_subset_string(menu->sub, "arrow_string");
    if (max_cols > 0)
      max_cols -= (mutt_strwidth(c_arrow_string) + 1);
  }

  struct ExpandoRenderData AliasRenderData[] = {
    // clang-format off
    { ED_ALIAS, AliasRenderCallbacks, av, MUTT_FORMAT_ARROWCURSOR },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  const struct Expando *c_alias_format = cs_subset_expando(mdata->sub, "alias_format");
  return expando_filter(c_alias_format, AliasRenderCallbacks, av,
                        MUTT_FORMAT_ARROWCURSOR, max_cols, EnvList, buf);
}

/**
 * alias_tag - Tag some aliases - Implements Menu::tag() - @ingroup menu_tag
 */
static int alias_tag(struct Menu *menu, int sel, int act)
{
  const struct AliasMenuData *mdata = menu->mdata;
  const struct AliasViewArray *ava = &mdata->ava;
  struct AliasView *av = ARRAY_GET(ava, sel);

  bool ot = av->is_tagged;

  av->is_tagged = ((act >= 0) ? act : !av->is_tagged);

  return av->is_tagged - ot;
}

/**
 * alias_alias_observer - Notification that an Alias has changed - Implements ::observer_t - @ingroup observer_api
 */
static int alias_alias_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_ALIAS)
    return 0;
  if (!nc->global_data || !nc->event_data)
    return -1;

  struct EventAlias *ev_a = nc->event_data;
  struct Menu *menu = nc->global_data;
  struct AliasMenuData *mdata = menu->mdata;
  struct Alias *alias = ev_a->alias;

  if (nc->event_subtype == NT_ALIAS_ADD)
  {
    alias_array_alias_add(&mdata->ava, alias);

    if (alias_array_count_visible(&mdata->ava) != ARRAY_SIZE(&mdata->ava))
    {
      mutt_pattern_alias_func(NULL, mdata, PAA_VISIBLE, menu);
    }
  }
  else if (nc->event_subtype == NT_ALIAS_DELETE)
  {
    alias_array_alias_delete(&mdata->ava, alias);

    int vcount = alias_array_count_visible(&mdata->ava);
    int index = menu_get_index(menu);
    if ((index > (vcount - 1)) && (index > 0))
      menu_set_index(menu, index - 1);
  }

  alias_array_sort(&mdata->ava, mdata->sub);

  menu->max = alias_array_count_visible(&mdata->ava);
  menu_queue_redraw(menu, MENU_REDRAW_FULL);
  mutt_debug(LL_DEBUG5, "alias done, request WA_RECALC, MENU_REDRAW_FULL\n");

  return 0;
}

/**
 * alias_window_observer - Notification that a Window has changed - Implements ::observer_t - @ingroup observer_api
 *
 * This function is triggered by changes to the windows.
 *
 * - Delete (this window): clean up the resources held by the Help Bar
 */
static int alias_window_observer(struct NotifyCallback *nc)
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

  notify_observer_remove(NeoMutt->notify, alias_alias_observer, menu);
  notify_observer_remove(NeoMutt->sub->notify, alias_config_observer, menu);
  notify_observer_remove(win_menu->notify, alias_window_observer, win_menu);

  mutt_debug(LL_DEBUG5, "window delete done\n");
  return 0;
}

/**
 * alias_dialog_new - Create an Alias Selection Dialog
 * @param mdata Menu data holding Aliases
 * @retval obj SimpleDialogWindows Tuple containing Dialog, SimpleBar and Menu pointers
 */
static struct SimpleDialogWindows alias_dialog_new(struct AliasMenuData *mdata)
{
  struct SimpleDialogWindows sdw = simple_dialog_new(MENU_ALIAS, WT_DLG_ALIAS, AliasHelp);

  struct Menu *menu = sdw.menu;

  menu->make_entry = alias_make_entry;
  menu->tag = alias_tag;
  menu->max = alias_array_count_visible(&mdata->ava);
  menu->mdata = mdata;
  menu->mdata_free = NULL; // Menu doesn't own the data

  struct MuttWindow *win_menu = menu->win;

  // Override the Simple Dialog's recalc()
  win_menu->recalc = alias_recalc;

  alias_set_title(sdw.sbar, mdata->title, mdata->limit);

  // NT_COLOR is handled by the SimpleDialog
  notify_observer_add(NeoMutt->notify, NT_ALIAS, alias_alias_observer, menu);
  notify_observer_add(NeoMutt->sub->notify, NT_CONFIG, alias_config_observer, menu);
  notify_observer_add(win_menu->notify, NT_WINDOW, alias_window_observer, win_menu);

  return sdw;
}

/**
 * dlg_alias - Display a menu of Aliases - @ingroup gui_dlg
 * @param mdata Menu data holding Aliases
 * @retval true Selection was made
 *
 * The Alias Dialog is an Address Book.
 * The user can select addresses to add to an Email.
 */
static bool dlg_alias(struct AliasMenuData *mdata)
{
  if (ARRAY_EMPTY(&mdata->ava))
  {
    mutt_warning(_("You have no aliases"));
    return false;
  }

  mdata->title = mutt_str_dup(_("Aliases"));

  struct SimpleDialogWindows sdw = alias_dialog_new(mdata);
  struct Menu *menu = sdw.menu;
  mdata->menu = menu;
  mdata->sbar = sdw.sbar;

  alias_array_sort(&mdata->ava, mdata->sub);

  struct AliasView *avp = NULL;
  ARRAY_FOREACH(avp, &mdata->ava)
  {
    avp->num = ARRAY_FOREACH_IDX_avp;
  }

  struct MuttWindow *old_focus = window_set_focus(menu->win);
  // ---------------------------------------------------------------------------
  // Event Loop
  int rc = 0;
  int op = OP_NULL;
  do
  {
    menu_tagging_dispatcher(menu->win, op);
    window_redraw(NULL);

    op = km_dokey(MENU_ALIAS, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);
    if (op < 0)
      continue;
    if (op == OP_NULL)
    {
      km_error_key(MENU_ALIAS);
      continue;
    }
    mutt_clear_error();

    rc = alias_function_dispatcher(sdw.dlg, op);
    if (rc == FR_UNKNOWN)
      rc = menu_function_dispatcher(menu->win, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);
  } while ((rc != FR_DONE) && (rc != FR_CONTINUE));
  // ---------------------------------------------------------------------------

  window_set_focus(old_focus);
  simple_dialog_free(&sdw.dlg);
  window_redraw(NULL);
  return (rc == FR_CONTINUE); // Was a selection made?
}

/**
 * alias_complete - Alias completion routine
 * @param buf Partial Alias to complete
 * @param sub Config items
 * @retval 1 Success
 * @retval 0 Error
 *
 * Given a partial alias, this routine attempts to fill in the alias
 * from the alias list as much as possible. if given empty search string
 * or found nothing, present all aliases
 */
int alias_complete(struct Buffer *buf, struct ConfigSubset *sub)
{
  struct Alias *np = NULL;
  char bestname[8192] = { 0 };

  struct AliasMenuData mdata = { ARRAY_HEAD_INITIALIZER, NULL, sub };
  mdata.limit = buf_strdup(buf);
  mdata.search_state = search_state_new();

  if (buf_at(buf, 0) != '\0')
  {
    TAILQ_FOREACH(np, &Aliases, entries)
    {
      if (np->name && mutt_strn_equal(np->name, buf_string(buf), buf_len(buf)))
      {
        if (bestname[0] == '\0') /* init */
        {
          mutt_str_copy(bestname, np->name,
                        MIN(mutt_str_len(np->name) + 1, sizeof(bestname)));
        }
        else
        {
          int i;
          for (i = 0; np->name[i] && (np->name[i] == bestname[i]); i++)
            ; // do nothing

          bestname[i] = '\0';
        }
      }
    }

    if (bestname[0] == '\0')
    {
      // Create a View Array of all the Aliases
      FREE(&mdata.limit);
      TAILQ_FOREACH(np, &Aliases, entries)
      {
        alias_array_alias_add(&mdata.ava, np);
      }
    }
    else
    {
      /* fake the pattern for menu title */
      char *mtitle = NULL;
      mutt_str_asprintf(&mtitle, "~f ^%s", buf_string(buf));
      FREE(&mdata.limit);
      mdata.limit = mtitle;

      if (!mutt_str_equal(bestname, buf_string(buf)))
      {
        /* we are adding something to the completion */
        buf_strcpy_n(buf, bestname, mutt_str_len(bestname) + 1);
        FREE(&mdata.limit);
        search_state_free(&mdata.search_state);
        return 1;
      }

      /* build alias list and show it */
      TAILQ_FOREACH(np, &Aliases, entries)
      {
        int aasize = alias_array_alias_add(&mdata.ava, np);

        struct AliasView *av = ARRAY_GET(&mdata.ava, aasize - 1);

        if (np->name && !mutt_strn_equal(np->name, buf_string(buf), buf_len(buf)))
        {
          av->is_visible = false;
        }
      }
    }
  }

  if (ARRAY_EMPTY(&mdata.ava))
  {
    TAILQ_FOREACH(np, &Aliases, entries)
    {
      alias_array_alias_add(&mdata.ava, np);
    }

    mutt_pattern_alias_func(NULL, &mdata, PAA_VISIBLE, NULL);
  }

  if (!dlg_alias(&mdata))
    goto done;

  buf_reset(buf);

  // Extract the selected aliases
  struct Buffer *tmpbuf = buf_pool_get();
  struct AliasView *avp = NULL;
  ARRAY_FOREACH(avp, &mdata.ava)
  {
    if (!avp->is_tagged)
      continue;

    mutt_addrlist_write(&avp->alias->addr, tmpbuf, true);
    buf_addstr(tmpbuf, ", ");
  }
  buf_copy(buf, tmpbuf);
  buf_pool_release(&tmpbuf);

done:
  // Process any deleted aliases
  ARRAY_FOREACH(avp, &mdata.ava)
  {
    if (!avp->is_deleted)
      continue;

    TAILQ_REMOVE(&Aliases, avp->alias, entries);
    alias_free(&avp->alias);
  }

  ARRAY_FREE(&mdata.ava);
  FREE(&mdata.limit);
  FREE(&mdata.title);
  search_state_free(&mdata.search_state);

  return 0;
}

/**
 * alias_dialog - Open the aliases dialog
 * @param m   Mailbox
 * @param sub Config item
 */
void alias_dialog(struct Mailbox *m, struct ConfigSubset *sub)
{
  struct Alias *np = NULL;

  struct AliasMenuData mdata = { ARRAY_HEAD_INITIALIZER, NULL, sub };
  mdata.search_state = search_state_new();

  // Create a View Array of all the Aliases
  TAILQ_FOREACH(np, &Aliases, entries)
  {
    alias_array_alias_add(&mdata.ava, np);
  }

  if (!dlg_alias(&mdata))
    goto done;

  // Prepare the "To:" field of a new email
  struct Email *e = email_new();
  e->env = mutt_env_new();

  struct AliasView *avp = NULL;
  ARRAY_FOREACH(avp, &mdata.ava)
  {
    if (!avp->is_tagged)
      continue;

    struct AddressList al_copy = TAILQ_HEAD_INITIALIZER(al_copy);
    if (alias_to_addrlist(&al_copy, avp->alias))
    {
      mutt_addrlist_copy(&e->env->to, &al_copy, false);
      mutt_addrlist_clear(&al_copy);
    }
  }

  mutt_send_message(SEND_REVIEW_TO, e, NULL, m, NULL, sub);

done:
  // Process any deleted aliases
  ARRAY_FOREACH(avp, &mdata.ava)
  {
    if (avp->is_deleted)
    {
      TAILQ_REMOVE(&Aliases, avp->alias, entries);
      alias_free(&avp->alias);
    }
  }

  ARRAY_FREE(&mdata.ava);
  FREE(&mdata.limit);
  FREE(&mdata.title);
  search_state_free(&mdata.search_state);
}
