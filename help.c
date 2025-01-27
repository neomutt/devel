/**
 * @file
 * Generate the help-page and GUI display it
 *
 * @authors
 * Copyright (C) 1996-2000,2009 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2017-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018-2020 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Yousef Akbar <yousef@yhakbar.com>
 * Copyright (C) 2021 Ihor Antonov <ihor@antonovs.family>
 * Copyright (C) 2023 Tóth János <gomba007@gmail.com>
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
 * @page neo_help Generate the help-page and GUI display it
 *
 * Generate and help-page and GUI display it
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "color/lib.h"
#include "index/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "pfile/lib.h"
#include "spager/lib.h"
#include "protos.h"

/**
 * FlagCharsDesc - Descriptions of the $flag_chars flags
 *
 * This must be in the same order as #FlagChars
 */
static const char *FlagCharsDesc[] = {
  N_("message is tagged"),
  N_("message is flagged"),
  N_("message is deleted"),
  N_("attachment is deleted"),
  N_("message has been replied to"),
  N_("message has been read"),
  N_("message is new"),
  N_("thread has been read"),
  N_("thread has at least one new message"),
  N_("message has been read (%S expando)"),
  N_("message has been read (%Z expando)"),
};

/**
 * CryptCharsDesc - Descriptions of the $crypt_chars flags
 *
 * This must be in the same order as #CryptChars
 */
static const char *CryptCharsDesc[] = {
  N_("message signed with a verified key"),
  N_("message is PGP-encrypted"),
  N_("message is signed"),
  N_("message contains a PGP key"),
  N_("message has no cryptography information"),
};

/**
 * ToCharsDesc - Descriptions of the $to_chars flags
 *
 * This must be in the same order as #ToChars
 */
static const char *ToCharsDesc[] = {
  N_("message is not To: you"),
  N_("message is To: you and only you"),
  N_("message is To: you"),
  N_("message is Cc: to you"),
  N_("message is From: you"),
  N_("message is sent to a subscribed mailing list"),
  N_("you are in the Reply-To: list"),
};

/**
 * StatusCharsDesc - Descriptions of the $status_chars flags
 *
 * This must be in the same order as #StatusChars
 */
static const char *StatusCharsDesc[] = {
  N_("mailbox is unchanged"),
  N_("message needs resync"),
  N_("message is read-only"),
  N_("message is in atttach-message mode"),
};

/**
 * add_heading - Add a heading
 * @param pf      Paged File to write to
 * @param heading Header text
 */
static void add_heading(struct PagedFile *pf, const char *heading)
{
  struct PagedLine *pl = NULL;

  pl = paged_file_new_line(pf);
  paged_line_add_colored_text(pl, MT_COLOR_HEADING, heading);
  paged_line_add_text(pl, "\n");

  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);
}

/**
 * add_chars - Add a table of flag characters
 * @param pf        Paged File to write to
 * @param config    Config variable
 * @param num_flags Number of flags
 * @param desc      Flag descriptions
 */
static void add_chars(struct PagedFile *pf, const char *config, int num_flags,
                      const char **desc)
{
  struct Buffer *buf = buf_pool_get();
  struct PagedLine *pl = paged_file_new_line(pf);

  const struct MbTable *mb_table = cs_subset_mbtable(NeoMutt->sub, config);
  paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, "set");
  paged_line_add_text(pl, " ");
  paged_line_add_colored_text(pl, MT_COLOR_IDENTIFIER, config);
  paged_line_add_text(pl, " ");
  paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, "=");
  paged_line_add_text(pl, " ");

  buf_reset(buf);
  cs_subset_str_string_get(NeoMutt->sub, config, buf);
  paged_line_add_colored_text(pl, MT_COLOR_STRING, "\"");
  paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));
  paged_line_add_colored_text(pl, MT_COLOR_STRING, "\"");
  paged_line_add_text(pl, "\n");

  const char *flag = NULL;
  int cols;
  for (int i = 0; i < num_flags; i++)
  {
    flag = mbtable_get_nth_wchar(mb_table, i);
    cols = mutt_strwidth(flag);
    pl = paged_file_new_line(pf);

    paged_line_add_text(pl, "    ");
    buf_printf(buf, "'%s'", flag);
    paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));

    buf_printf(buf, "%*s", 4 - cols, "");
    paged_line_add_text(pl, buf_string(buf));

    paged_line_add_colored_text(pl, MT_COLOR_COMMENT, _(desc[i]));
    paged_line_add_text(pl, "\n");
  }

  buf_pool_release(&buf);
}

/**
 * dump_message_flags - Write out all the message flags
 * @param menu Menu type
 * @param pf   Paged File to write to
 *
 * Display a quick reminder of all the flags in the config options:
 * - $crypt_chars
 * - $flag_chars
 * - $to_chars
 */
static void dump_message_flags(enum MenuType menu, struct PagedFile *pf)
{
  if (menu != MENU_INDEX)
    return;

  struct PagedLine *pl = NULL;

  add_heading(pf, _("Message flags:"));

  add_chars(pf, "flag_chars", FLAG_CHAR_MAX, FlagCharsDesc);
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  add_chars(pf, "crypt_chars", FLAG_CHAR_CRYPT_MAX, CryptCharsDesc);
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  add_chars(pf, "to_chars", FLAG_CHAR_TO_MAX, ToCharsDesc);
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  add_heading(pf, _("Status flags:"));
  add_chars(pf, "status_chars", STATUS_CHAR_MAX, StatusCharsDesc);
}

/**
 * mutt_help - Display the Help Page
 * @param menu Menu type
 */
void mutt_help(enum MenuType menu)
{
  struct BindingInfoArray bia_bind = ARRAY_HEAD_INITIALIZER;
  struct BindingInfoArray bia_macro = ARRAY_HEAD_INITIALIZER;
  struct BindingInfoArray bia_gen = ARRAY_HEAD_INITIALIZER;
  struct BindingInfoArray bia_unbound = ARRAY_HEAD_INITIALIZER;
  struct Buffer *buf = NULL;
  struct PagedFile *pf = NULL;
  struct PagedLine *pl = NULL;

  // ---------------------------------------------------------------------------
  // Gather the data

  gather_menu(menu, &bia_bind, &bia_macro);

  ARRAY_SORT(&bia_bind, binding_sort, NULL);
  ARRAY_SORT(&bia_macro, binding_sort, NULL);

  int wb0 = measure_column(&bia_bind, 0);
  int wb1 = measure_column(&bia_bind, 1);

  const bool need_generic = (menu != MENU_EDITOR) && (menu != MENU_PAGER) &&
                            (menu != MENU_GENERIC);
  if (need_generic)
  {
    gather_menu(MENU_GENERIC, &bia_gen, &bia_macro);

    ARRAY_SORT(&bia_gen, binding_sort, NULL);
    wb0 = MAX(wb0, measure_column(&bia_gen, 0));
    wb1 = MAX(wb1, measure_column(&bia_gen, 1));
  }

  const int wm0 = measure_column(&bia_macro, 0);

  const struct MenuFuncOp *funcs = km_get_table(menu);
  gather_unbound(funcs, &Keymaps[menu], NULL, &bia_unbound);

  if (need_generic)
    gather_unbound(OpGeneric, &Keymaps[MENU_GENERIC], &Keymaps[menu], &bia_unbound);

  ARRAY_SORT(&bia_unbound, binding_sort, NULL);
  const int wu1 = measure_column(&bia_unbound, 1);

  // ---------------------------------------------------------------------------
  // Save the data to a file

  buf = buf_pool_get();
  pf = paged_file_new(NULL);
  if (!pf)
    goto cleanup;

  const char *menu_name = mutt_map_get_name(menu, MenuNames);
  struct BindingInfo *bi = NULL;

  // heading + blank line
  pl = paged_file_new_line(pf);
  buf_printf(buf, "%s bindings\n", menu_name);
  paged_line_add_colored_text(pl, MT_COLOR_HEADING, buf_string(buf));
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  int len0;
  int len1;
  ARRAY_FOREACH(bi, &bia_bind)
  {
    pl = paged_file_new_line(pf);

    // keybinding
    len0 = paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, bi->a[0]);
    buf_printf(buf, "%*s", wb0 - len0, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, "  ");

    // function
    len1 = paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, bi->a[1]);
    buf_printf(buf, "%*s", wb1 - len1, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, "  ");

    // function description
    paged_line_add_colored_text(pl, MT_COLOR_COMMENT, bi->a[2]);
    paged_line_add_newline(pl);
  }
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  if (need_generic)
  {
    // heading + blank line
    pl = paged_file_new_line(pf);
    buf_printf(buf, "%s bindings\n", "generic");
    paged_line_add_colored_text(pl, MT_COLOR_HEADING, buf_string(buf));
    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);

    ARRAY_FOREACH(bi, &bia_gen)
    {
      pl = paged_file_new_line(pf);

      // keybinding
      len0 = paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, bi->a[0]);
      buf_printf(buf, "%*s", wb0 - len0, "");
      paged_line_add_text(pl, buf_string(buf));
      paged_line_add_text(pl, "  ");

      // function
      len1 = paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, bi->a[1]);
      buf_printf(buf, "%*s", wb1 - len1, "");
      paged_line_add_text(pl, buf_string(buf));
      paged_line_add_text(pl, "  ");

      // function description
      paged_line_add_colored_text(pl, MT_COLOR_COMMENT, bi->a[2]);
      paged_line_add_newline(pl);
    }
    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);
  }

  // heading + blank line
  pl = paged_file_new_line(pf);
  buf_printf(buf, "macros\n");
  paged_line_add_colored_text(pl, MT_COLOR_HEADING, buf_string(buf));
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  ARRAY_FOREACH(bi, &bia_macro)
  {
    pl = paged_file_new_line(pf);

    // keybinding
    len0 = paged_line_add_colored_text(pl, MT_COLOR_OPERATOR, bi->a[0]);
    buf_printf(buf, "%*s", wm0 - len0, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, " ");

    // description
    if (bi->a[2])
    {
      buf_printf(buf, "\"%s\"\n", bi->a[2]);
      paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));
      pl = paged_file_new_line(pf);
    }

    // macro text
    buf_printf(buf, "\"%s\"\n", bi->a[1]);
    paged_line_add_colored_text(pl, MT_COLOR_STRING, buf_string(buf));

    // blank line after two-line macro display
    if (bi->a[2])
    {
      pl = paged_file_new_line(pf);
      paged_line_add_newline(pl);
    }
  }
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  // heading + blank line
  pl = paged_file_new_line(pf);
  buf_printf(buf, "unbound functions\n");
  paged_line_add_colored_text(pl, MT_COLOR_HEADING, buf_string(buf));
  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  ARRAY_FOREACH(bi, &bia_unbound)
  {
    pl = paged_file_new_line(pf);

    // function
    len1 = paged_line_add_colored_text(pl, MT_COLOR_FUNCTION, bi->a[1]);
    buf_printf(buf, "%*s", wu1 - len1, "");
    paged_line_add_text(pl, buf_string(buf));
    paged_line_add_text(pl, "  ");

    // function description
    paged_line_add_colored_text(pl, MT_COLOR_COMMENT, bi->a[2]);
    paged_line_add_newline(pl);
  }

  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  dump_message_flags(menu, pf);

  // Apply striping
  ARRAY_FOREACH(pl, &pf->lines)
  {
    if ((ARRAY_FOREACH_IDX_pl % 2) == 0)
      pl->cid = MT_COLOR_STRIPE_ODD;
    else
      pl->cid = MT_COLOR_STRIPE_EVEN;
  }

  // ---------------------------------------------------------------------------
  // Display data

  //QWQ pview.flags = MUTT_PAGER_MARKER | MUTT_PAGER_NOWRAP | MUTT_PAGER_STRIPES;

  buf_printf(buf, _("Help for %s"), menu_name);
  dlg_spager(pf, buf_string(buf), NeoMutt->sub);

cleanup:
  buf_pool_release(&buf);
  paged_file_free(&pf);
  ARRAY_FREE(&bia_bind);
  ARRAY_FREE(&bia_macro);
  ARRAY_FREE(&bia_gen);
  ARRAY_FREE(&bia_unbound);
}
