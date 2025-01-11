/**
 * @file
 * Simple Pager Debugging
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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
 * @page debug_spager Simple Pager Debugging
 *
 * Simple Pager Debugging
 */

#include "config.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "debug/lib.h"
#include "pfile/lib.h"
#include "spager/lib.h"

void dump_markup(struct PagedTextMarkupArray *ptma, const char *label)
{
  mutt_debug(LL_DEBUG1, "    %s (%d)\n", label, ARRAY_SIZE(ptma));

  struct Buffer *buf = buf_pool_get();

  struct PagedTextMarkup *ptm = NULL;
  ARRAY_FOREACH(ptm, ptma)
  {
    buf_reset(buf);
    buf_add_printf(buf, "        [%d-%d] ", ptm->first, ptm->last - 1);

    if (ptm->cid > 0)
    {
      buf_add_printf(buf, "%s(%d) ", name_color_id(ptm->cid), ptm->cid);
      if (ptm->ac_text)
        buf_add_printf(buf, "ac_text %p ", (void *) ptm->ac_text);
      if (ptm->ac_merged)
        buf_add_printf(buf, "ac_merged %p ", (void *) ptm->ac_merged);
    }
    else
    {
      buf_add_printf(buf, "[plain] ");
    }

    if (ptm->ansi_start)
    {
      buf_add_printf(buf, "ansi_start %p ", (void *) ptm->ansi_start);
      buf_add_printf(buf, "ansi_end %p ", (void *) ptm->ansi_end);
    }

    // if ((ARRAY_FOREACH_IDX + 1) < ARRAY_SIZE(ptma))
    //   buf_add_printf(buf, "        --------------\n");

    mutt_debug(LL_DEBUG1, "%s\n", buf_string(buf));
  }

  buf_pool_release(&buf);
}

void dump_lines(struct PagedLineArray *pla)
{
  mutt_debug(LL_DEBUG1, "lines (%d)\n", ARRAY_SIZE(pla));
  int count = 0;
  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, pla)
  {
    if (count++ > 10)
      break;
    mutt_debug(LL_DEBUG1, "    offset %ld\n", pl->offset);
    mutt_debug(LL_DEBUG1, "    %d bytes, %d cols\n", pl->num_bytes, pl->num_cols);
    if (pl->cid > 0)
    {
      mutt_debug(LL_DEBUG1, "    cid %s (%d)\n", name_color_id(pl->cid), pl->cid);
      if (pl->ac_line)
        mutt_debug(LL_DEBUG1, "    ac_line %p\n", (void *) pl->ac_line);
    }
    else
    {
      mutt_debug(LL_DEBUG1, "    [plain]\n");
    }

    dump_markup(&pl->text, "text");
    dump_markup(&pl->search, "search");
    mutt_debug(LL_DEBUG1, "======================\n");
  }
}

void dump_spager(struct PagedFile *pf)
{
  if (!pf)
    return;

  mutt_debug(LL_DEBUG1, "PagedFile\n");
  mutt_debug(LL_DEBUG1, "fd %d\n", fileno(pf->fp));
  dump_lines(&pf->lines);
}
