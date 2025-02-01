/**
 * @file
 * Colour Dump Command
 *
 * @authors
 * Copyright (C) 2023 Richard Russon <rich@flatcap.org>
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
 * @page color_dump Colour Dump Command
 *
 * Colour Dump Command
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "gui/lib.h"
#include "dump.h"
#include "pfile/lib.h"
#include "attr.h"
#include "color.h"
#include "parse_color.h"
#include "quoted.h"
#include "regex4.h"
#include "simple2.h"
#ifdef USE_DEBUG_COLOR
#include "debug.h"
#endif

/**
 * color_log_color_attrs - Get a colourful string to represent a colour in the log
 * @param ac     Colour
 * @param swatch Buffer for swatch
 *
 * @note Do not free the returned string
 */
void color_log_color_attrs(struct AttrColor *ac, struct Buffer *swatch)
{
  buf_reset(swatch);

  if (ac->attrs & A_BLINK)
    buf_add_printf(swatch, "\033[5m");
  if (ac->attrs & A_BOLD)
    buf_add_printf(swatch, "\033[1m");
  if (ac->attrs & A_ITALIC)
    buf_add_printf(swatch, "\033[3m");
  if (ac->attrs == A_NORMAL)
    buf_add_printf(swatch, "\033[0m");
  if (ac->attrs & A_REVERSE)
    buf_add_printf(swatch, "\033[7m");
  if (ac->attrs & A_STANDOUT)
    buf_add_printf(swatch, "\033[1m");
  if (ac->attrs & A_UNDERLINE)
    buf_add_printf(swatch, "\033[4m");

  if (ac->fg.color >= 0)
  {
    switch (ac->fg.type)
    {
      case CT_SIMPLE:
      {
        buf_add_printf(swatch, "\033[%dm", 30 + ac->fg.color);
        break;
      }

      case CT_PALETTE:
      {
        buf_add_printf(swatch, "\033[38;5;%dm", ac->fg.color);
        break;
      }

      case CT_RGB:
      {
        int r = (ac->fg.color >> 16) & 0xff;
        int g = (ac->fg.color >> 8) & 0xff;
        int b = (ac->fg.color >> 0) & 0xff;
        buf_add_printf(swatch, "\033[38;2;%d;%d;%dm", r, g, b);
        break;
      }
    }
  }

  if (ac->bg.color >= 0)
  {
    switch (ac->bg.type)
    {
      case CT_SIMPLE:
      {
        buf_add_printf(swatch, "\033[%dm", 40 + ac->bg.color);
        break;
      }

      case CT_PALETTE:
      {
        buf_add_printf(swatch, "\033[48;5;%dm", ac->bg.color);
        break;
      }

      case CT_RGB:
      {
        int r = (ac->bg.color >> 16) & 0xff;
        int g = (ac->bg.color >> 8) & 0xff;
        int b = (ac->bg.color >> 0) & 0xff;
        buf_add_printf(swatch, "\033[48;2;%d;%d;%dm", r, g, b);
        break;
      }
    }
  }

  buf_addstr(swatch, "XXXXXX\033[0m");
}

/**
 * color_log_attrs_list - Get a string to represent some attributes in the log
 * @param attrs Attributes, e.g. A_UNDERLINE
 * @retval ptr Generated string
 *
 * @note Do not free the returned string
 */
const char *color_log_attrs_list(int attrs)
{
  static char text[64];

  text[0] = '\0';
  int pos = 0;
  // We can ignore the A_NORMAL case
  if (attrs & A_BLINK)
    pos += snprintf(text + pos, sizeof(text) - pos, "blink ");
  if (attrs & A_BOLD)
    pos += snprintf(text + pos, sizeof(text) - pos, "bold ");
  if (attrs & A_ITALIC)
    pos += snprintf(text + pos, sizeof(text) - pos, "italic ");
  if (attrs & A_REVERSE)
    pos += snprintf(text + pos, sizeof(text) - pos, "reverse ");
  if (attrs & A_STANDOUT)
    pos += snprintf(text + pos, sizeof(text) - pos, "standout ");
  if (attrs & A_UNDERLINE)
    pos += snprintf(text + pos, sizeof(text) - pos, "underline ");

  return text;
}

/**
 * color_log_name - Get a string to represent a colour name
 * @param buf    Buffer for the result
 * @param buflen Length of the Buffer
 * @param elem   Colour to use
 * @retval ptr Generated string
 */
const char *color_log_name(char *buf, int buflen, struct ColorElement *elem)
{
  if (elem->color < 0)
    return "default";

  switch (elem->type)
  {
    case CT_SIMPLE:
    {
      const char *prefix = NULL;
      switch (elem->prefix)
      {
        case COLOR_PREFIX_ALERT:
          prefix = "alert";
          break;
        case COLOR_PREFIX_BRIGHT:
          prefix = "bright";
          break;
        case COLOR_PREFIX_LIGHT:
          prefix = "light";
          break;
        default:
          prefix = "";
          break;
      }

      const char *name = mutt_map_get_name(elem->color, ColorNames);
      snprintf(buf, buflen, "%s%s", prefix, name);
      break;
    }

    case CT_PALETTE:
    {
      if (elem->color < 256)
        snprintf(buf, buflen, "color%d", elem->color);
      else
        snprintf(buf, buflen, "BAD:%d", elem->color); // LCOV_EXCL_LINE
      break;
    }

    case CT_RGB:
    {
      int r = (elem->color >> 16) & 0xff;
      int g = (elem->color >> 8) & 0xff;
      int b = (elem->color >> 0) & 0xff;
      snprintf(buf, buflen, "#%02x%02x%02x", r, g, b);
      break;
    }
  }

  return buf;
}

/**
 * quoted_colors_dump - Dump all the Quoted colours
 * @param pf PagerFile to write to
 */
void quoted_colors_dump(struct PagedFile *pf)
{
  struct Buffer *swatch = buf_pool_get();
  struct Buffer *buf = buf_pool_get();
  char color_fg[64] = { 0 };
  char color_bg[64] = { 0 };
  struct PagedLine *pl = NULL;

  pl = paged_file_new_line(pf);
  paged_line_add_text(pl, _("# Quoted Colors\n"));
  for (int i = 0; i < 10; i++)
  {
    struct AttrColor *ac = simple_color_get(MT_COLOR_QUOTED0 + i);
    if (!attr_color_is_set(ac))
      continue;

    color_log_color_attrs(ac, swatch);
    pl = paged_file_new_line(pf);
    buf_printf(buf, "color quoted%d %-20s %-16s %-16s # %s\n", i,
               color_log_attrs_list(ac->attrs),
               color_log_name(color_fg, sizeof(color_fg), &ac->fg),
               color_log_name(color_bg, sizeof(color_bg), &ac->bg), buf_string(swatch));
    paged_line_add_text(pl, buf_string(buf));
  }

  pl = paged_file_new_line(pf);
  paged_line_add_newline(pl);

  buf_pool_release(&buf);
  buf_pool_release(&swatch);
}

/**
 * regex_colors_dump - Dump all the Regex colours
 * @param pf PagerFile to write to
 */
void regex_colors_dump(struct PagedFile *pf)
{
  struct Buffer *swatch = buf_pool_get();
  struct Buffer *pattern = buf_pool_get();
  struct Buffer *buf = buf_pool_get();
  char color_fg[64] = { 0 };
  char color_bg[64] = { 0 };
  struct PagedLine *pl = NULL;

  for (enum ColorId cid = MT_COLOR_NONE; cid != MT_COLOR_MAX; cid++)
  {
    if (cid == MT_COLOR_STATUS)
      continue;

    if (!mutt_color_has_pattern(cid))
      continue;

    struct RegexColorList *rcl = regex_colors_get_list(cid);
    if (STAILQ_EMPTY(rcl))
      continue;

    const char *name = mutt_map_get_name(cid, ColorFields);
    if (!name)
      continue; // LCOV_EXCL_LINE

    pl = paged_file_new_line(pf);
    buf_printf(buf, _("# Regex Color %s\n"), name);
    paged_line_add_text(pl, buf_string(buf));

    struct RegexColor *rc = NULL;
    STAILQ_FOREACH(rc, rcl, entries)
    {
      struct AttrColor *ac = &rc->attr_color;

      buf_reset(pattern);
      pretty_var(rc->pattern, pattern);
      color_log_color_attrs(ac, swatch);
      pl = paged_file_new_line(pf);
      buf_printf(buf, "color %-16s %-20s %-16s %-16s %-30s # %s\n", name,
                 color_log_attrs_list(ac->attrs),
                 color_log_name(color_fg, sizeof(color_fg), &ac->fg),
                 color_log_name(color_bg, sizeof(color_bg), &ac->bg),
                 buf_string(pattern), buf_string(swatch));
      paged_line_add_text(pl, buf_string(buf));
    }

    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);
  }

  buf_pool_release(&buf);
  buf_pool_release(&swatch);
  buf_pool_release(&pattern);
}

/**
 * simple_colors_dump - Dump all the Simple colours
 * @param pf PagerFile to write to
 */
void simple_colors_dump(struct PagedFile *pf)
{
  struct Buffer *swatch = buf_pool_get();
  struct Buffer *buf = buf_pool_get();
  char color_fg[64] = { 0 };
  char color_bg[64] = { 0 };
  struct PagedLine *pl = NULL;

  int count = 0;
  for (enum ColorId cid = MT_COLOR_NONE + 1; cid < MT_COLOR_MAX; cid++)
  {
    if (COLOR_QUOTED(cid) || (cid == MT_COLOR_STATUS))
      continue;

    struct AttrColor *ac = simple_color_get(cid);
    if (attr_color_is_set(ac))
      count++;
  }

  if (count > 0)
  {
    pl = paged_file_new_line(pf);
    paged_line_add_text(pl, _("# Simple Colors\n"));

    for (enum ColorId cid = MT_COLOR_NONE + 1; cid < MT_COLOR_MAX; cid++)
    {
      if (COLOR_QUOTED(cid) || COLOR_COMPOSE(cid) || (cid == MT_COLOR_STATUS))
        continue;

      struct AttrColor *ac = simple_color_get(cid);
      if (!attr_color_is_set(ac))
        continue;

      const char *name = mutt_map_get_name(cid, ColorFields);
      if (!name)
        continue;

      color_log_color_attrs(ac, swatch);
      pl = paged_file_new_line(pf);
      buf_printf(buf, "color %-18s %-20s %-16s %-16s # %s\n", name,
                 color_log_attrs_list(ac->attrs),
                 color_log_name(color_fg, sizeof(color_fg), &ac->fg),
                 color_log_name(color_bg, sizeof(color_bg), &ac->bg), buf_string(swatch));
      paged_line_add_text(pl, buf_string(buf));
    }

    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);
  }

  count = 0;
  for (int i = MT_COLOR_COMPOSE_HEADER; i <= MT_COLOR_COMPOSE_SECURITY_SIGN; i++)
  {
    struct AttrColor *ac = simple_color_get(i);
    if (attr_color_is_set(ac))
      count++;
  }

  if (count > 0)
  {
    pl = paged_file_new_line(pf);
    paged_line_add_text(pl, _("# Compose Colors\n"));
    for (int i = 0; ColorFields[i].name; i++)
    {
      enum ColorId cid = ColorFields[i].value;

      if (!COLOR_COMPOSE(cid))
        continue;

      struct AttrColor *ac = simple_color_get(cid);
      if (!attr_color_is_set(ac))
        continue;

      color_log_color_attrs(ac, swatch);
      pl = paged_file_new_line(pf);
      buf_printf(buf, "color %-24s %-20s %-16s %-16s # %s\n",
                 ColorFields[i].name, color_log_attrs_list(ac->attrs),
                 color_log_name(color_fg, sizeof(color_fg), &ac->fg),
                 color_log_name(color_bg, sizeof(color_bg), &ac->bg), buf_string(swatch));
      paged_line_add_text(pl, buf_string(buf));
    }

    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);
  }

  buf_pool_release(&buf);
  buf_pool_release(&swatch);
}

/**
 * status_colors_dump - Dump all the Status colours
 * @param pf PagerFile to write to
 */
void status_colors_dump(struct PagedFile *pf)
{
  struct Buffer *swatch = buf_pool_get();
  struct Buffer *pattern = buf_pool_get();
  struct Buffer *buf = buf_pool_get();
  char color_fg[64] = { 0 };
  char color_bg[64] = { 0 };
  struct PagedLine *pl = NULL;

  bool set = false;

  const enum ColorId cid = MT_COLOR_STATUS;
  struct AttrColor *ac = simple_color_get(cid);
  if (attr_color_is_set(ac))
    set = true;

  struct RegexColorList *rcl = regex_colors_get_list(cid);
  if (!STAILQ_EMPTY(rcl))
    set = true;

  if (set)
  {
    pl = paged_file_new_line(pf);
    paged_line_add_text(pl, _("# Status Colors\n"));

    color_log_color_attrs(ac, swatch);
    pl = paged_file_new_line(pf);
    buf_printf(buf, "color status %-20s %-16s %-16s                                # %s\n",
               color_log_attrs_list(ac->attrs),
               color_log_name(color_fg, sizeof(color_fg), &ac->fg),
               color_log_name(color_bg, sizeof(color_bg), &ac->bg), buf_string(swatch));
    paged_line_add_text(pl, buf_string(buf));

    struct RegexColor *rc = NULL;
    STAILQ_FOREACH(rc, rcl, entries)
    {
      ac = &rc->attr_color;

      buf_reset(pattern);
      pretty_var(rc->pattern, pattern);
      color_log_color_attrs(ac, swatch);
      pl = paged_file_new_line(pf);
      if (rc->match == 0)
      {
        buf_printf(buf, "color status %-20s %-16s %-16s %-30s # %s\n",
                   color_log_attrs_list(ac->attrs),
                   color_log_name(color_fg, sizeof(color_fg), &ac->fg),
                   color_log_name(color_bg, sizeof(color_bg), &ac->bg),
                   buf_string(pattern), buf_string(swatch));
      }
      else
      {
        buf_printf(buf, "color status %-20s %-16s %-16s %-28s %d # %s\n",
                   color_log_attrs_list(ac->attrs),
                   color_log_name(color_fg, sizeof(color_fg), &ac->fg),
                   color_log_name(color_bg, sizeof(color_bg), &ac->bg),
                   buf_string(pattern), rc->match, buf_string(swatch));
      }
      paged_line_add_text(pl, buf_string(buf));
    }

    pl = paged_file_new_line(pf);
    paged_line_add_newline(pl);
  }

  buf_pool_release(&swatch);
  buf_pool_release(&pattern);
  buf_pool_release(&buf);
}

/**
 * color_dump - Display all the colours in the Pager
 * @param pf PagerFile to write to
 */
void color_dump(struct PagedFile *pf)
{
  if (!pf)
    return;

  simple_colors_dump(pf);
  quoted_colors_dump(pf);
  status_colors_dump(pf);
  regex_colors_dump(pf);

#ifdef USE_DEBUG_COLOR
  merged_colors_dump(pf);
  ansi_colors_dump(pf);
  curses_colors_dump(pf);
  log_paged_file(LL_DEBUG1, pf);
#endif
}
