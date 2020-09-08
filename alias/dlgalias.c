/**
 * @file
 * Address book handling aliases
 *
 * @authors
 * Copyright (C) 1996-2000,2007 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2019 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Richard Russon <rich@flatcap.org>
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
 * @page alias_dlgalias Address book handling aliases
 *
 * Address book handling aliases
 */

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "lib.h"
#include "pattern/lib.h"
#include "alias.h"
#include "format_flags.h"
#include "gui.h"
#include "keymap.h"
#include "mutt_globals.h"
#include "mutt_menu.h"
#include "muttlib.h"
#include "opcodes.h"

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
 * alias_format_str - Format a string for the alias list - Implements ::format_t
 *
 * | Expando | Description
 * |:--------|:--------------------------------------------------------
 * | \%a     | Alias name
 * | \%c     | Comments
 * | \%f     | Flags - currently, a 'd' for an alias marked for deletion
 * | \%n     | Index number
 * | \%r     | Address which alias expands to
 * | \%t     | Character which indicates if the alias is tagged for inclusion
 */
static const char *alias_format_str(char *buf, size_t buflen, size_t col, int cols,
                                    char op, const char *src, const char *prec,
                                    const char *if_str, const char *else_str,
                                    intptr_t data, MuttFormatFlags flags)
{
  char fmt[128], addr[1024];
  struct AliasView *av = (struct AliasView *) data;
  struct Alias *alias = av->alias;

  switch (op)
  {
    case 'a':
      mutt_format_s(buf, buflen, prec, alias->name);
      break;
    case 'c':
      mutt_format_s(buf, buflen, prec, alias->comment);
      break;
    case 'f':
      snprintf(fmt, sizeof(fmt), "%%%ss", prec);
      snprintf(buf, buflen, fmt, av->is_deleted ? "D" : " ");
      break;
    case 'n':
      snprintf(fmt, sizeof(fmt), "%%%sd", prec);
      snprintf(buf, buflen, fmt, av->num + 1);
      break;
    case 'r':
      addr[0] = '\0';
      mutt_addrlist_write(&alias->addr, addr, sizeof(addr), true);
      mutt_format_s(buf, buflen, prec, addr);
      break;
    case 't':
      buf[0] = av->is_tagged ? '*' : ' ';
      buf[1] = '\0';
      break;
  }

  return src;
}

/**
 * alias_make_entry - Format a menu item for the alias list - Implements Menu::make_entry()
 */
static void alias_make_entry(char *buf, size_t buflen, struct Menu *menu, int line)
{
  const struct AliasMenuData *mdata = menu->mdata;
  const struct AliasView *av = ARRAY_GET(mdata, line);

  mutt_expando_format(buf, buflen, 0, menu->win_index->state.cols, NONULL(C_AliasFormat),
                      alias_format_str, IP av, MUTT_FORMAT_ARROWCURSOR);
}

/**
 * alias_tag - Tag some aliases - Implements Menu::tag()
 */
static int alias_tag(struct Menu *menu, int sel, int act)
{
  struct AliasMenuData *mdata = (struct AliasMenuData *) menu->mdata;
  struct AliasView *av = ARRAY_GET(mdata, sel);

  bool ot = av->is_tagged;

  av->is_tagged = ((act >= 0) ? act : !av->is_tagged);

  return av->is_tagged - ot;
}

/**
 * alias_alias_observer - Listen for data changes affecting the Alias menu - Implements ::observer_t
 */
static int alias_alias_observer(struct NotifyCallback *nc)
{
  if (!nc->event_data || !nc->global_data)
    return -1;
  if (nc->event_type != NT_ALIAS)
    return 0;

  struct EventAlias *ea = nc->event_data;
  struct Menu *menu = nc->global_data;
  struct AliasMenuData *mdata = menu->mdata;
  struct Alias *alias = ea->alias;

  if (nc->event_subtype == NT_ALIAS_NEW)
  {
    menu_data_alias_add(mdata, alias);
  }
  else if (nc->event_subtype == NT_ALIAS_DELETED)
  {
    menu_data_alias_delete(mdata, alias);
  }
  menu_data_sort(mdata);

  menu->max = ARRAY_SIZE(mdata);
  menu->redraw = REDRAW_FULL;
  return 0;
}

/**
 * dlg_select_alias - Display a menu of Aliases
 * @param buf    Buffer for expanded aliases
 * @param buflen Length of buffer
 * @param mdata  Menu data holding Aliases
 */
static void dlg_select_alias(char *buf, size_t buflen, struct AliasMenuData *mdata)
{
  if (ARRAY_EMPTY(mdata))
  {
    mutt_warning(_("You have no aliases"));
    return;
  }

  int t = -1;
  bool done = false;

  struct Menu *menu = mutt_menu_new(MENU_ALIAS);
  struct MuttWindow *dlg = dialog_create_simple_index(menu, WT_DLG_ALIAS);
  dlg->help_data = AliasHelp;
  dlg->help_menu = MENU_ALIAS;

  menu->make_entry = alias_make_entry;
  menu->custom_search = true;
  menu->tag = alias_tag;
  menu->title = _("Aliases");
  menu->max = ARRAY_SIZE(mdata);
  menu->mdata = mdata;

  notify_observer_add(NeoMutt->notify, NT_ALIAS, alias_alias_observer, menu);
  notify_observer_add(NeoMutt->notify, NT_CONFIG, alias_config_observer, mdata);
  notify_observer_add(NeoMutt->notify, NT_COLOR, alias_color_observer, menu);

  mutt_menu_push_current(menu);

  ARRAY_SORT(mdata, alias_get_sort_function(C_SortAlias));

  struct AliasView *avp = NULL;
  ARRAY_FOREACH(avp, mdata)
  {
    avp->num = ARRAY_FOREACH_IDX;
  }

  while (!done)
  {
    int op = mutt_menu_loop(menu);
    switch (op)
    {
      case OP_DELETE:
      case OP_UNDELETE:
        if (menu->tagprefix)
        {
          ARRAY_FOREACH(avp, mdata)
          {
            if (avp->is_tagged)
              avp->is_deleted = (op == OP_DELETE);
          }
          menu->redraw |= REDRAW_INDEX;
        }
        else
        {
          ARRAY_GET(mdata, menu->current)->is_deleted = (op == OP_DELETE);
          menu->redraw |= REDRAW_CURRENT;
          if (C_Resolve && (menu->current < menu->max - 1))
          {
            menu->current++;
            menu->redraw |= REDRAW_INDEX;
          }
        }
        break;
      case OP_SORT:
      case OP_SORT_REVERSE:
      {
        int sort = C_SortAlias;
        bool resort = true;
        bool reverse = (op == OP_SORT_REVERSE);

        switch (mutt_multi_choice(
            reverse ?
                /* L10N: The highlighted letters must match the "Sort" options */
                _("Rev-Sort (a)lias, a(d)dress or (u)nsorted?") :
                /* L10N: The highlighted letters must match the "Rev-Sort" options */
                _("Sort (a)lias, a(d)dress or (u)nsorted?"),
            /* L10N: These must match the highlighted letters from "Sort" and "Rev-Sort" */
            _("adu")))
        {
          case -1: /* abort */
            resort = false;
            break;

          case 1: /* (a)lias */
            sort = SORT_ALIAS;
            break;

          case 2: /* a(d)dress */
            sort = SORT_ADDRESS;
            break;

          case 3: /* (u)nsorted */
            sort = SORT_ORDER;
            break;
        }

        if (resort)
        {
          sort |= reverse ? SORT_REVERSE : 0;

          cs_subset_str_native_set(NeoMutt->sub, "sort_alias", sort, NULL);
          menu->redraw = REDRAW_FULL;
        }

        break;
      }
      case OP_SEARCH_REVERSE:
      case OP_SEARCH_NEXT:
      case OP_SEARCH_OPPOSITE:
      case OP_SEARCH:
        menu->current = mutt_search_alias_command(menu, menu->current, op);
        if (menu->current == -1)
          menu->current = menu->oldcurrent;
        else
          menu->redraw |= REDRAW_MOTION;
        break;

      case OP_GENERIC_SELECT_ENTRY:
        t = menu->current;
        if (t >= ARRAY_SIZE(mdata))
          t = -1;
        done = true;
        break;
      case OP_EXIT:
        done = true;
        break;
    }
  }

  ARRAY_FOREACH(avp, mdata)
  {
    if (avp->is_tagged)
    {
      mutt_addrlist_write(&avp->alias->addr, buf, buflen, true);
      t = -1;
    }
  }

  if (t != -1)
  {
    mutt_addrlist_write(&ARRAY_GET(mdata, t)->alias->addr, buf, buflen, true);
  }

  notify_observer_remove(NeoMutt->notify, alias_alias_observer, menu);
  notify_observer_remove(NeoMutt->notify, alias_config_observer, mdata);
  notify_observer_remove(NeoMutt->notify, alias_color_observer, menu);

  mutt_menu_pop_current(menu);
  mutt_menu_free(&menu);
  dialog_destroy_simple_index(&dlg);
}

/**
 * alias_complete - alias completion routine
 * @param buf    Partial Alias to complete
 * @param buflen Length of buffer
 * @retval 1 Success
 * @retval 0 Error
 *
 * Given a partial alias, this routine attempts to fill in the alias
 * from the alias list as much as possible. if given empty search string
 * or found nothing, present all aliases
 */
int alias_complete(char *buf, size_t buflen)
{
  struct Alias *np = NULL;
  char bestname[8192] = { 0 };
  struct AliasMenuData mdata = ARRAY_HEAD_INITIALIZER;

  if (buf[0] != '\0')
  {
    TAILQ_FOREACH(np, &Aliases, entries)
    {
      if (np->name && mutt_strn_equal(np->name, buf, strlen(buf)))
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

    if (bestname[0] != '\0')
    {
      if (!mutt_str_equal(bestname, buf))
      {
        /* we are adding something to the completion */
        mutt_str_copy(buf, bestname, mutt_str_len(bestname) + 1);
        return 1;
      }

      /* build alias list and show it */
      TAILQ_FOREACH(np, &Aliases, entries)
      {
        if (np->name && mutt_strn_equal(np->name, buf, strlen(buf)))
        {
          menu_data_alias_add(&mdata, np);
        }
      }
    }
  }

  if (ARRAY_EMPTY(&mdata))
  {
    TAILQ_FOREACH(np, &Aliases, entries)
    {
      menu_data_alias_add(&mdata, np);
    }
  }
  menu_data_sort(&mdata);

  bestname[0] = '\0';
  dlg_select_alias(bestname, sizeof(bestname), &mdata);
  if (bestname[0] != '\0')
    mutt_str_copy(buf, bestname, buflen);

  struct AliasView *avp = NULL;
  ARRAY_FOREACH(avp, &mdata)
  {
    if (!avp->is_deleted)
      continue;

    TAILQ_REMOVE(&Aliases, avp->alias, entries);
    alias_free(&avp->alias);
  }

  ARRAY_FREE(&mdata);

  return 0;
}
