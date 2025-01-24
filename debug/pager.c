/**
 * @file
 * Pager Debugging
 *
 * @authors
 * Copyright (C) 2022 Richard Russon <rich@flatcap.org>
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
 * @page debug_pager Pager Debugging
 *
 * Pager Debugging
 */

#include "config.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "lib.h"
#include "color/lib.h"
#include "pager/lib.h"
#include "pager/display.h"
#include "pager/private_data.h"

void dump_text_syntax_array(struct TextSyntaxArray *tsa)
{
  if (!tsa || ARRAY_EMPTY(tsa))
    return;

  mutt_debug(LL_DEBUG1, "\tsyntax: %d\n", ARRAY_SIZE(tsa));

  struct TextSyntax *ts = NULL;
  ARRAY_FOREACH(ts, tsa)
  {
    int index = 0;
    const char *swatch = "";

    if (ts->attr_color)
    {
      struct CursesColor *cc = ts->attr_color->curses_color;
      if (cc)
      {
        index = cc->index;
        swatch = color_log_color(cc->fg, cc->bg);
      }
    }
    mutt_debug(LL_DEBUG1, "\t\t(%d-%d) %d %s\n", ts->first, ts->last - 1, index, swatch);
  }
}

void dump_text_syntax(struct TextSyntax *ts, int num)
{
  if (!ts || (num == 0))
    return;

  for (int i = 0; i < num; i++)
  {
    int index = -1;
    const char *swatch = "";
    if (ts[i].attr_color)
    {
      struct CursesColor *cc = ts[i].attr_color->curses_color;
      if (cc)
      {
        index = cc->index;
        swatch = color_log_color(cc->fg, cc->bg);
      }
    }
    mutt_debug(LL_DEBUG1, "\t\t(%d-%d) %d %s\n", ts[i].first, ts[i].last - 1, index, swatch);
  }
}

void dump_line(int i, struct Line *line)
{
  struct Buffer *buf = buf_pool_get();

  buf_add_printf(buf, "%d [+%ld]", i, line->offset);

  if ((line->cid > 0) && (line->cid != MT_COLOR_NORMAL))
  {
    const char *swatch = "";
    struct AttrColor *ac = simple_color_get(line->cid);
    if (ac && ac->curses_color)
    {
      struct CursesColor *cc = ac->curses_color;
      swatch = color_log_color(cc->fg, cc->bg);
    }

    buf_add_printf(buf, " %s (%d) %s", name_color_id(line->cid), line->cid, swatch);
  }
  mutt_debug(LL_DEBUG1, "%s\n", buf_string(buf));

  if (line->cont_line || line->cont_header)
  {
    mutt_debug(LL_DEBUG1, "\tcont: %s%s\n", line->cont_line ? "\033[1;32mL\033[0m" : "-",
               line->cont_header ? "\033[1;32mH\033[0m" : "-");
  }

  if (line->syntax_arr_size > 0)
  {
    mutt_debug(LL_DEBUG1, "\tsyntax: %d %p\n", line->syntax_arr_size,
               (void *) line->syntax);
    dump_text_syntax(line->syntax, line->syntax_arr_size);
  }
  if (line->search_arr_size > 0)
  {
    mutt_debug(LL_DEBUG1, "\t\033[1;36msearch\033[0m: %d %p\n",
               line->search_arr_size, (void *) line->search);
    dump_text_syntax(line->search, line->search_arr_size);
  }

  buf_pool_release(&buf);
}

void dump_pager(struct PagerPrivateData *priv)
{
  if (!priv)
    return;

  mutt_debug(LL_DEBUG1, "----------------------------------------------\n");
  mutt_debug(LL_DEBUG1, "Pager: %d lines (fd %d)\n", priv->lines_used, fileno(priv->fp));
  for (int i = 0; i < priv->lines_used; i++)
  {
    dump_line(i, &priv->lines[i]);
  }
  mutt_debug(LL_DEBUG1, "%d-%d unused (%d)\n", priv->lines_used,
             priv->lines_max - 1, priv->lines_max - priv->lines_used);
}
