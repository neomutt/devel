/**
 * @file
 * Simple Pager Dialog
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
 * @page spager_dlg_spager Simple Pager Dialog
 *
 * Simple Pager Dialog
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "dlg_spager.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "pfile/lib.h"
#include "ddata.h"
#include "dlg_observer.h"
#include "functions.h"
#include "mutt_logging.h"
#include "search.h"
#include "wdata.h"
#include "win_spager.h"
#ifdef USE_DEBUG_WINDOW
#include "debug/lib.h"
#endif

/// Help Bar for the Simple Pager's Help Bar
static const struct Mapping SimplePagerHelp[] = {
  // clang-format off
  { N_("Quit"),   OP_QUIT },
  { N_("PrevPg"), OP_PREV_PAGE },
  { N_("NextPg"), OP_NEXT_PAGE },
  { N_("Search"), OP_SEARCH },
  { N_("Save"),   OP_SAVE },
  { N_("Help"),   OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * update_sbar - Update the Simple Pager status bar
 * @param ddata Dialog Data
 * @param wdata Window Data
 */
void update_sbar(struct SimplePagerDialogData *ddata, struct SimplePagerWindowData *wdata)
{
  struct SimplePagerExport spe = { 0 };
  spager_get_data(ddata->win_pager, &spe);

  struct Buffer *buf = buf_pool_get();

  buf_add_printf(buf, "%s ", ddata->banner);
  buf_add_printf(buf, "L%d, ", spe.num_lines);
  buf_add_printf(buf, "VL%d, ", spe.num_vlines);
  buf_add_printf(buf, "R%d, ", spe.top_row);
  buf_add_printf(buf, "VR%d, ", spe.top_vrow);
  buf_add_printf(buf, "B:%d/", spe.bytes_pos);
  buf_add_printf(buf, "%d, ", spe.bytes_total);
  buf_add_printf(buf, "%d%% ", spe.percentage);

  if (spe.search_matches > 0)
  {
    int search_current = 1;
    int search_vcurrent = 1;

    struct PagedFile *pf = wdata->paged_file;
    struct PagedLine *pl = NULL;
    ARRAY_FOREACH_TO(pl, &pf->lines, spe.top_row)
    {
      size_t size = ARRAY_SIZE(&pl->search);
      search_current += (size > 0);
      search_vcurrent += size;
    }

    buf_add_printf(buf, "| S%c(%d/%d:%d/%d)",
                   (spe.direction == SD_SEARCH_FORWARDS) ? 'V' : '^', search_current,
                   spe.search_rows, search_vcurrent, spe.search_matches);
  }

#ifdef USE_DEBUG_WINDOW
  buf_add_printf(buf, " [%d,%d]", ddata->win_pager->state.cols,
                 ddata->win_pager->state.rows);
#endif

  sbar_set_title(ddata->win_sbar, buf_string(buf));
  buf_pool_release(&buf);
}

/**
 * spager_dlg_spager_new - Create a new Simple Pager Dialog
 * @param pf        File to display
 * @param banner    Text to display in the Status Bar
 * @param sub       Config Subset
 * @retval ptr New Simple Pager Dialog
 */
static struct MuttWindow *spager_dlg_spager_new(struct PagedFile *pf, const char *banner,
                                                struct ConfigSubset *sub)
{
  struct MuttWindow *dlg = mutt_window_new(WT_DLG_PAGER, MUTT_WIN_ORIENT_VERTICAL,
                                           MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                           MUTT_WIN_SIZE_UNLIMITED);

  struct SimplePagerDialogData *ddata = spager_ddata_new();
  ddata->banner = banner;
  ddata->percentage = 0;

  struct MuttWindow *win_sbar = sbar_new();
  ddata->win_sbar = win_sbar;
  sbar_set_title(win_sbar, banner);

  struct MuttWindow *win_pager = spager_window_new(pf, sub);
  win_pager->help_data = SimplePagerHelp;
  win_pager->help_menu = MENU_PAGER;

  ddata->win_pager = win_pager;

  dlg->wdata = ddata;
  dlg->wdata_free = spager_ddata_free;

#ifdef USE_DEBUG_WINDOW
  win_pager = debug_win_barrier_wrap(win_pager, 2, 1);
#endif

  const bool c_status_on_top = cs_subset_bool(sub, "status_on_top");
  if (c_status_on_top)
  {
    mutt_window_add_child(dlg, win_sbar);
    mutt_window_add_child(dlg, win_pager);
  }
  else
  {
    mutt_window_add_child(dlg, win_pager);
    mutt_window_add_child(dlg, win_sbar);
  }

  dlg_spager_add_observers(dlg);
  return dlg;
}

/**
 * dlg_spager - Display a Simple Pager
 * @param pf        Paged File to display
 * @param banner    Text to display in the Status Bar
 * @param sub       Config Subset
 */
void dlg_spager(struct PagedFile *pf, const char *banner, struct ConfigSubset *sub)
{
  struct MuttWindow *dlg = spager_dlg_spager_new(pf, banner, sub);
  dialog_push(dlg);

  struct SimplePagerDialogData *ddata = dlg->wdata;

  struct MuttWindow *old_focus = window_set_focus(ddata->win_pager);

  update_sbar(ddata, ddata->win_pager->wdata);

  // ---------------------------------------------------------------------------
  // Event Loop
  int rc = 0;
  do
  {
    window_redraw(NULL);

    int op = km_dokey(MENU_PAGER, GETCH_NO_FLAGS);
    mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(op), op);

    if (op < 0)
      continue;

    if (op == OP_NULL)
    {
      km_error_key(MENU_PAGER);
      continue;
    }
    mutt_clear_error();

    rc = spager_function_dispatcher(ddata->win_pager, op);
    if (rc == FR_UNKNOWN)
      rc = global_function_dispatcher(NULL, op);

  } while ((rc != FR_DONE) && (rc != FR_CONTINUE));
  // ---------------------------------------------------------------------------

  window_set_focus(old_focus);
  dialog_pop();
  mutt_window_free(&dlg);
}
