/**
 * @file
 * Window state data for the Simple Pager
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

/**
 * @page spager_wdata Window state data for the Simple Pager
 *
 * Window state data for the Simple Pager
 */

#include "config.h"
#include <string.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "wdata.h"
#include "pfile/lib.h"
#include "search.h"

/**
 * spager_wdata_free - Free Simple Pager Data
 * @param win Window
 * @param ptr Pager Data to free
 */
void spager_wdata_free(struct MuttWindow *win, void **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct SimplePagerWindowData *wdata = *ptr;

  spager_search_free(&wdata->search);
  notify_free(&wdata->notify);

  FREE(ptr);
}

/**
 * spager_wdata_new - Create new Simple Pager Data
 * @retval ptr New SimplePagerWindowData
 */
struct SimplePagerWindowData *spager_wdata_new(void)
{
  struct SimplePagerWindowData *wdata = MUTT_MEM_CALLOC(1, struct SimplePagerWindowData);

  wdata->search = spager_search_new();

  wdata->notify = notify_new();
  notify_set_parent(wdata->notify, NeoMutt->notify);

  return wdata;
}

/**
 * spager_observer_add - Add an observer of the Simple Pager
 * @param win         Simple Pager Window
 * @param callback    Callback function
 * @param global_data Data to be passed to the callback function
 * @retval true Success
 */
bool spager_observer_add(struct MuttWindow *win, observer_t callback, void *global_data)
{
  if (!win || !win->wdata)
    return false;

  struct SimplePagerWindowData *wdata = win->wdata;

  return notify_observer_add(wdata->notify, NT_SPAGER, callback, global_data);
}

/**
 * spager_observer_remove - Remove an observer of the Simple Pager
 * @param win         Simple Pager Window
 * @param callback    Callback function
 * @param global_data Data to be passed to the callback function
 * @retval true Success
 */
bool spager_observer_remove(struct MuttWindow *win, observer_t callback, void *global_data)
{
  if (!win || !win->wdata)
    return false;

  struct SimplePagerWindowData *wdata = win->wdata;

  return notify_observer_remove(wdata->notify, callback, global_data);
}

/**
 * spager_get_data - Get stats about the Simple Pager
 * @param[in]     win Simple Pager Window
 * @param[in,out] spe Place for the results
 */
void spager_get_data(struct MuttWindow *win, struct SimplePagerExport *spe)
{
  if (!win || !spe)
    return;

  memset(spe, 0, sizeof(struct SimplePagerExport));

  struct SimplePagerWindowData *wdata = win->wdata;
  struct SimplePagerSearch *search = wdata->search;
  struct PagedFile *pf = wdata->paged_file;
  struct PagedLineArray *pla = &pf->lines;

  int pl_index = 0;
  int seg_index = 0;
  if (paged_lines_find_virtual_row(pla, wdata->vrow, &pl_index, &seg_index))
  {
    struct PagedLine *pl = ARRAY_GET(pla, pl_index);
    spe->bytes_pos = pl->offset;
    spe->top_row = pl_index;
  }

  spe->num_lines = ARRAY_SIZE(pla);
  spe->num_vlines = paged_lines_count_virtual_rows(pla);
  spe->top_vrow = wdata->vrow;
  spe->bytes_total = mutt_file_get_size_fp(pf->fp);
  spe->percentage = 0;
  if (spe->bytes_total > 0)
    spe->percentage = (spe->bytes_pos * 100) / spe->bytes_total;

  struct PagedLine *pl = NULL;
  int count = 0;
  ARRAY_FOREACH(pl, pla)
  {
    count = ARRAY_SIZE(&pl->search);
    if (count == 0)
      continue;

    spe->search_rows++;
    spe->search_matches += count;
  }
  spe->direction = search->direction;
}
