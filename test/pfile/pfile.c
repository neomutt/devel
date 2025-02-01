/**
 * @file
 * Test code for the Paged File
 *
 * @authors
 * Copyright (C) 2024-2025 Richard Russon <rich@flatcap.org>
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
#include <stddef.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "debug/lib.h"
#include "color/lib.h"
#include "pfile/lib.h"
#include "test_common.h"

struct PfileTest
{
  const char *name;
  bool use_text;
  int search_start;
  int search_end;
};

static void dump_paged_markup(const struct PagedTextMarkup *ptm, struct Buffer *buf)
{
  if (!ptm || !buf)
    return;

  buf_add_printf(buf, "(%d:%d-%d)", ptm->cid, ptm->first, ptm->last);
}

static void dump_paged_line(const struct PagedLine *pl, struct Buffer *buf)
{
  if (!pl || !buf)
    return;

  buf_add_printf(buf, "{b%d:c%d:", pl->num_bytes, pl->num_cols);

  struct PagedTextMarkup *ptm = NULL;
  size_t count = ARRAY_SIZE(&pl->text);
  if (count > 0)
  {
    buf_addstr(buf, "T:{");
    ARRAY_FOREACH(ptm, &pl->text)
    {
      dump_paged_markup(ptm, buf);
      if ((ARRAY_FOREACH_IDX_ptm + 1) < count)
        buf_addstr(buf, ",");
    }
    buf_addstr(buf, "}");
  }

  count = ARRAY_SIZE(&pl->search);
  if (count > 0)
  {
    buf_addstr(buf, ",S:{");
    ARRAY_FOREACH(ptm, &pl->search)
    {
      dump_paged_markup(ptm, buf);
      if ((ARRAY_FOREACH_IDX_ptm + 1) < count)
        buf_addstr(buf, ",");
    }
    buf_addstr(buf, "}");
  }

  buf_addstr(buf, "}");
}

static void dump_paged_file(const struct PagedFile *pf, struct Buffer *buf)
{
  if (!pf || !buf)
    return;

  buf_add_printf(buf, "L:%d:{", ARRAY_SIZE(&pf->lines));

  struct PagedLine *pl = NULL;
  size_t count = ARRAY_SIZE(&pf->lines);
  ARRAY_FOREACH(pl, &pf->lines)
  {
    dump_paged_line(pl, buf);
    if ((ARRAY_FOREACH_IDX_pl + 1) < count)
      buf_addstr(buf, ",");
  }

  buf_addstr(buf, "}");
}

void test_pfile(void)
{
  static const char *result =
      "L:16:{{b21:c21:},{b21:c21:T:{(19:6-15)}},{b21:c21:T:{(19:6-15)},S:{(40:0-3)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:3-6)}},{b21:c21:T:{(19:6-15)},S:{(40:3-9)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:3-15)}},{b21:c21:T:{(19:6-15)},S:{(40:3-18)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:6-9)}},{b21:c21:T:{(19:6-15)},S:{(40:6-15)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:6-18)}},{b21:c21:T:{(19:6-15)},S:{(40:9-12)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:12-15)}},{b21:c21:T:{(19:6-15)},S:{(40:12-18)}},"
      "{b21:c21:T:{(19:6-15)},S:{(40:15-18)}},{b21:c21:T:{(19:6-15)},S:{(40:18-21)}},"
      "{b21:c21:,S:{(40:6-15)}}}";

  static const struct PfileTest Tests[] = {
    // clang-format off
    { "A", false, -1, -1 },
    { "B", true,  -1, -1 },
    { "C", true,   0,  3 },
    { "D", true,   3,  6 },
    { "E", true,   3,  9 },
    { "F", true,   3, 15 },
    { "G", true,   3, 18 },
    { "H", true,   6,  9 },
    { "I", true,   6, 15 },
    { "J", true,   6, 18 },
    { "K", true,   9, 12 },
    { "L", true,  12, 15 },
    { "M", true,  12, 18 },
    { "N", true,  15, 18 },
    { "O", true,  18, 21 },
    { "P", false,  6, 15 },
    // clang-format on
  };

  struct PagedFile *pf = paged_file_new(NULL);
  TEST_CHECK(pf != NULL);

  for (int i = 0; i < mutt_array_size(Tests); i++)
  {
    const struct PfileTest *st = &Tests[i];

    TEST_CASE(st->name);

    struct PagedLine *pl = paged_file_new_line(pf);
    TEST_CHECK(pl != NULL);

    if (st->use_text)
    {
      paged_line_add_text(pl, "AAAbbb");
      paged_line_add_colored_text(pl, MT_COLOR_INDICATOR, "CCCdddEEE");
      paged_line_add_text(pl, "fffGGG");
    }
    else
    {
      paged_line_add_text(pl, "AAAbbbCCCdddEEEfffGGG");
    }

    if (st->search_start >= 0)
    {
      paged_line_add_search(pl, st->search_start, st->search_end);
    }
  }

  struct Buffer *buf = buf_pool_get();
  dump_paged_file(pf, buf);
  TEST_CHECK_STR_EQ(buf_string(buf), result);
  buf_pool_release(&buf);
  paged_file_free(&pf);
}
