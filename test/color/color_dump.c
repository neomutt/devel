/**
 * @file
 * Test code for Colour Dump
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

#define TEST_NO_MAIN
#include "config.h"
#include "acutest.h"
#include <stdbool.h>
#include <stddef.h>
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "color/lib.h"
#include "pfile/lib.h"

static struct ConfigDef Vars[] = {
  // clang-format off
  { "color_directcolor", DT_BOOL, true, 0, NULL, },
  { NULL },
  // clang-format on
};

void test_color_dump(void)
{
  // void color_dump(void);

  TEST_CHECK(cs_register_variables(NeoMutt->sub->cs, Vars));

  struct PagedFile *pf = NULL;

  pf = paged_file_new(NULL);
  color_dump(pf);
  paged_file_free(&pf);

  curses_colors_init();
  merged_colors_init();
  quoted_colors_init();
  regex_colors_init();
  simple_colors_init();

  struct AttrColor ac = { 0 };

  ac.fg.color = COLOR_RED;
  ac.fg.type = CT_SIMPLE;
  ac.bg.color = COLOR_CYAN;
  ac.bg.type = CT_SIMPLE;
  ac.attrs = A_BOLD;
  ac.fg.prefix = COLOR_PREFIX_ALERT;
  simple_color_set(MT_COLOR_INDICATOR, &ac);

  ac.attrs = A_BLINK;
  ac.fg.prefix = COLOR_PREFIX_BRIGHT;
  simple_color_set(MT_COLOR_MARKERS, &ac);

  ac.attrs = A_NORMAL;
  ac.fg.prefix = COLOR_PREFIX_LIGHT;
  simple_color_set(MT_COLOR_MESSAGE, &ac);

  ac.attrs = A_ITALIC;
  ac.fg.prefix = COLOR_PREFIX_NONE;
  ac.fg.color = COLOR_DEFAULT;
  simple_color_set(MT_COLOR_MESSAGE_LOG, &ac);

  ac.fg.color = 123;
  ac.fg.type = CT_PALETTE;
  ac.bg.color = 207;
  ac.bg.type = CT_PALETTE;
  ac.attrs = A_REVERSE;
  simple_color_set(MT_COLOR_COMPOSE_SECURITY_SIGN, &ac);
  ac.attrs = A_STANDOUT;
  simple_color_set(MT_COLOR_COMPOSE_SECURITY_BOTH, &ac);

  ac.fg.color = 0x8040f0;
  ac.fg.type = CT_RGB;
  ac.bg.color = 0xc35d08;
  ac.bg.type = CT_RGB;
  ac.attrs = A_UNDERLINE;
  simple_color_set(MT_COLOR_PROMPT, &ac);

  int rc = 0;
  regex_colors_parse_color_list(MT_COLOR_BODY, "apple", &ac, &rc, NULL);
  regex_colors_parse_color_list(MT_COLOR_BODY, "banana", &ac, &rc, NULL);

  regex_colors_parse_status_list(MT_COLOR_STATUS, "cherry", &ac, 0, NULL);
  regex_colors_parse_status_list(MT_COLOR_STATUS, "damson", &ac, 1, NULL);

  pf = paged_file_new(NULL);
  color_dump(pf);
  paged_file_free(&pf);
}
