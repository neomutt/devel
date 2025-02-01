/**
 * @file
 * Dump key bindings
 *
 * @authors
 * Copyright (C) 2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page key_dump Dump key bindings
 *
 * Dump key bindings
 */

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "color/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "parse/lib.h"
#include "pfile/lib.h"
#include "spager/lib.h"
#ifdef ENABLE_NLS
#include <libintl.h>
#endif

/**
 * print_bind - Display the bindings for one menu
 * @param menu Menu type
 * @param pf   PagedFile to write to
 * @retval num Number of bindings
 */
static int print_bind(enum MenuType menu, struct PagedFile *pf)
{
  struct BindingInfoArray bia_bind = ARRAY_HEAD_INITIALIZER;
  struct PagedLine *pl = NULL;

  gather_menu(menu, &bia_bind, NULL);
  if (ARRAY_EMPTY(&bia_bind))
    return 0;

  ARRAY_SORT(&bia_bind, binding_sort, NULL);
  const int wb0 = measure_column(&bia_bind, 0);
  const int wb1 = measure_column(&bia_bind, 1);
  int len0;
  int len1;

  const char *menu_name = mutt_map_get_name(menu, MenuNames);

  struct Buffer *buf = buf_pool_get();
  struct BindingInfo *bi = NULL;
  ARRAY_FOREACH(bi, &bia_bind)
  {
    pl = paged_file_new_line(pf);

    // bind menu
    paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, "bind");
    paged_line_add_text(pl, " ");
    paged_line_add_colored_text(pl, MT_COLOR_ENUM, menu_name);
    paged_line_add_text(pl, " ");

    // keybinding
    len0 = paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, bi->a[0]);
    buf_printf(buf, "%*s", wb0 - len0, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, " ");

    // function
    len1 = paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, bi->a[1]);
    buf_printf(buf, "%*s", wb1 - len1, "");
    paged_line_add_text(pl, buf_string(buf));

    // function description
    paged_line_add_text(pl, " ");
    buf_printf(buf, "# %s\n", bi->a[2]);
    paged_line_add_colored_text(pl, MT_COLOR_COMMENT, buf_string(buf));
  }
  buf_pool_release(&buf);

  // Apply striping
  ARRAY_FOREACH(pl, &pf->lines)
  {
    if ((ARRAY_FOREACH_IDX_pl % 2) == 0)
      pl->cid = MT_COLOR_STRIPE_ODD;
    else
      pl->cid = MT_COLOR_STRIPE_EVEN;
  }

  const int count = ARRAY_SIZE(&bia_bind);
  ARRAY_FOREACH(bi, &bia_bind)
  {
    // we only need to free the keybinding
    FREE(&bi->a[0]);
  }

  return count;
}

/**
 * colon_bind - Dump the key bindings
 * @param menu Menu type
 * @param pf   PagedFile to write to
 */
static void colon_bind(enum MenuType menu, struct PagedFile *pf)
{
  if (menu == MENU_MAX)
  {
    struct PagedLine *pl = NULL;
    for (enum MenuType i = 1; i < MENU_MAX; i++)
    {
      print_bind(i, pf);

      //XXX need to elide last blank line
      pl = paged_file_new_line(pf);
      paged_line_add_newline(pl);
    }
  }
  else
  {
    print_bind(menu, pf);
  }
}

/**
 * print_macro - Display the macros for one menu
 * @param menu Menu type
 * @param pf   PagedFile to write to
 * @retval num Number of macros
 */
static int print_macro(enum MenuType menu, struct PagedFile *pf)
{
  struct BindingInfoArray bia_macro = ARRAY_HEAD_INITIALIZER;
  struct PagedLine *pl = NULL;

  gather_menu(menu, NULL, &bia_macro);
  if (ARRAY_EMPTY(&bia_macro))
    return 0;

  ARRAY_SORT(&bia_macro, binding_sort, NULL);
  const int wm0 = measure_column(&bia_macro, 0);
  int len0;

  const char *menu_name = mutt_map_get_name(menu, MenuNames);

  struct Buffer *buf = buf_pool_get();
  struct BindingInfo *bi = NULL;
  ARRAY_FOREACH(bi, &bia_macro)
  {
    pl = paged_file_new_line(pf);

    // macro menu
    paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, "macro");
    paged_line_add_text(pl, " ");
    paged_line_add_colored_text(pl, MT_COLOR_ENUM, menu_name);
    paged_line_add_text(pl, " ");

    // keybinding
    len0 = paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, bi->a[0]);
    buf_printf(buf, "%*s", wm0 - len0, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, " ");

    // macro text
    buf_printf(buf, "\"%s\"", bi->a[1]);
    paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));

    // description
    if (bi->a[2])
    {
      paged_line_add_text(pl, " ");
      buf_printf(buf, "\"%s\"", bi->a[2]);
      paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));
    }

    paged_line_add_newline(pl);
  }
  buf_pool_release(&buf);

  // Apply striping
  ARRAY_FOREACH(pl, &pf->lines)
  {
    if ((ARRAY_FOREACH_IDX_pl % 2) == 0)
      pl->cid = MT_COLOR_STRIPE_ODD;
    else
      pl->cid = MT_COLOR_STRIPE_EVEN;
  }

  const int count = ARRAY_SIZE(&bia_macro);
  ARRAY_FOREACH(bi, &bia_macro)
  {
    // free the keybinding and the macro text
    FREE(&bi->a[0]);
    FREE(&bi->a[1]);
  }

  ARRAY_FREE(&bia_macro);
  return count;
}

/**
 * colon_macro - Dump the macros
 * @param menu Menu type
 * @param pf   PagedFile to write to
 */
static void colon_macro(enum MenuType menu, struct PagedFile *pf)
{
  if (menu == MENU_MAX)
  {
    struct PagedLine *pl = NULL;
    for (enum MenuType i = 1; i < MENU_MAX; i++)
    {
      if (print_macro(i, pf) > 0)
      {
        //XXX need to elide last blank line
        pl = paged_file_new_line(pf);
        paged_line_add_newline(pl);
      }
    }
  }
  else
  {
    print_macro(menu, pf);
  }
}

/**
 * dump_bind_macro - Parse 'bind' and 'macro' commands - Implements Command::parse() - @ingroup command_parse
 */
enum CommandResult dump_bind_macro(struct Buffer *buf, struct Buffer *s,
                                   intptr_t data, struct Buffer *err)
{
  struct PagedFile *pf = NULL;
  bool dump_all = false;
  bool bind = (data == 0);
  int rc = MUTT_CMD_ERROR;

  if (!MoreArgs(s))
    dump_all = true;
  else
    parse_extract_token(buf, s, TOKEN_NO_FLAGS);

  if (MoreArgs(s))
  {
    /* More arguments potentially means the user is using the
     * ::command_t :bind command thus we delegate the task. */
    goto done;
  }

  pf = paged_file_new(NULL);
  if (!pf)
    goto done;

  if (dump_all || mutt_istr_equal(buf_string(buf), "all"))
  {
    if (bind)
      colon_bind(MENU_MAX, pf);
    else
      colon_macro(MENU_MAX, pf);
  }
  else
  {
    const int menu = mutt_map_get_value(buf_string(buf), MenuNames);
    if (menu == -1)
    {
      // L10N: '%s' is the (misspelled) name of the menu, e.g. 'index' or 'pager'
      buf_printf(err, _("%s: no such menu"), buf_string(buf));
      goto done;
    }

    if (bind)
      colon_bind(menu, pf);
    else
      colon_macro(menu, pf);
  }

  // XXX Check reval from colon_bind/macro
  // if (ftello(fp) == 0)
  // {
  //   // L10N: '%s' is the name of the menu, e.g. 'index' or 'pager',
  //   //       it might also be 'all' when all menus are affected.
  //   buf_printf(err, bind ? _("%s: no binds for this menu") : _("%s: no macros for this menu"),
  //              dump_all ? "all" : buf_string(buf));
  //   goto done;
  // }

  const char *banner = bind ? "bind" : "macro";
  dlg_spager(pf, banner, NeoMutt->sub);

  rc = MUTT_CMD_SUCCESS;

done:
  paged_file_free(&pf);

  return rc;
}
