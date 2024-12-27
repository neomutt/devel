/**
 * @file
 * Simple Pager Window
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
 * @page spager_win_spager Simple Pager Window
 *
 * Simple Pager Window
 */

#include "config.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "win_spager.h"
#include "color/lib.h"
#include "pfile/lib.h"
#include "search.h"
#include "wdata.h"
#include "win_observer.h"
#ifdef USE_DEBUG_WINDOW
#include "debug/lib.h"
#endif

/// Don't highlight anything beyond this column
const int MAX_SYNTAX_COLUMNS = 4096;

/**
 * win_spager_recalc - Recalculate the Simple Pager display - Implements MuttWindow::recalc() - @ingroup window_recalc
 *
 * Recalculate:
 * - Wrap lines
 * - Merge colours
 * - Save Window dimensions
 *
 * Wrapping:
 * - Measure
 * - Wrap
 *
 * Colours:
 * - Base:   MT_COLOR_NORMAL              }
 * - File:   PagedFile.ac_file            }-- Merge into ac_merged
 * - Line:   PagedLine.ac_line            }
 * - Markup: PagedTextMarkupArray text    }
 * - Search: PagedTextMarkupArray search
 */
static int win_spager_recalc(struct MuttWindow *win)
{
  if (!win || !win->wdata)
    return -1;

  struct SimplePagerWindowData *wdata = win->wdata;
  struct PagedFile *pf = wdata->paged_file;

  LineWrapFlags lw_flags = LW_WRAP | LW_MARKERS;

  int wrap_width = win->state.cols;
  if (wdata->c_wrap > 0)
  {
    wrap_width = MIN(wrap_width, wdata->c_wrap);
  }
  else if (wdata->c_wrap < 0)
  {
    wrap_width = MAX(wrap_width + wdata->c_wrap, 10);
  }

  paged_lines_wrap(&pf->lines, wrap_width, lw_flags);

  if (!pf->ac_file)
    pf->ac_file = simple_color_get(MT_COLOR_NORMAL);

  const struct AttrColor *ac_search = simple_color_get(MT_COLOR_SEARCH);

  for (int i = 0; i < ARRAY_SIZE(&pf->lines); i++)
  {
    struct PagedLine *pl = ARRAY_GET(&pf->lines, i);

    if ((pl->cid > MT_COLOR_NONE) && !pl->ac_line)
      pl->ac_line = simple_color_get(pl->cid);

    if (!pl->ac_merged)
      pl->ac_merged = merged_color_overlay(pf->ac_file, pl->ac_line);

    struct PagedTextMarkup *ptm = NULL;
    ARRAY_FOREACH(ptm, &pl->text)
    {
      if ((ptm->cid > MT_COLOR_NONE) && !ptm->ac_text)
        ptm->ac_text = simple_color_get(ptm->cid);

      if (!ptm->ac_merged)
        ptm->ac_merged = merged_color_overlay(pl->ac_merged, ptm->ac_text);
    }

    ARRAY_FOREACH(ptm, &pl->search)
    {
      ptm->ac_text = ac_search;
    }
  }

  wdata->page_rows = win->state.rows;
  wdata->page_cols = win->state.cols;

  win->actions |= WA_REPAINT;
  mutt_debug(LL_DEBUG5, "recalc done, request WA_REPAINT\n");
  return 0;
}

/**
 * display_line2 - Display a line of text in the Simple Pager
 * @param win         Window to draw on
 * @param row         Row in the Window
 * @param text        Text to display
 * @param text_offset Start offset into the text
 * @param text_end    End offset into the text
 * @param pl          Line to display
 */
static void display_line2(struct MuttWindow *win, int row, const char *text,
                          int text_offset, int text_end, struct PagedLine *pl)
{
  struct SimplePagerWindowData *wdata = win->wdata;
  struct PagedTextMarkupArray *ptma_text = &pl->text;
  struct PagedTextMarkupArray *ptma_search = &pl->search;

  int i_text = 0;
  int i_search = 0;

  struct PagedTextMarkup *ptm_text = ARRAY_GET(ptma_text, i_text);
  struct PagedTextMarkup *ptm_search = ARRAY_GET(ptma_search, i_search);

  const struct AttrColor *ac = NULL;
  int last = 0;
  int pos = text_offset;
  int col = pos;

  if (text_offset > 0)
  {
    col--;
    mutt_window_move(win, row, 0);
    mutt_curses_set_color_by_id(MT_COLOR_MARKERS);
    mutt_window_addch(win, '+');
    mutt_refresh();
  }

  while (text && (pos < text_end))
  {
    // Skip any text syntax that's behind us
    while (pos_after_text_markup(pos, ptm_text))
    {
      i_text++;
      ptm_text = ARRAY_GET(ptma_text, i_text);
    }

    if (wdata->search->show_search)
    {
      // Skip any search syntax that's behind us
      while (pos_after_text_markup(pos, ptm_search))
      {
        i_search++;
        ptm_search = ARRAY_GET(ptma_search, i_search);
      }
    }

    last = text_end;

    // Prevent slowdown for degenerate text
    if (pos > MAX_SYNTAX_COLUMNS)
      break;

    // The text is highlighted
    if (pos_in_text_markup(pos, ptm_text))
    {
      ac = ptm_text->ac_merged;
      last = ptm_text->last;
    }
    else if (ptm_text)
    {
      last = MIN(last, ptm_text->first);
      ac = pl->ac_merged;
    }
    last = MIN(last, text_end);

    if (wdata->search->show_search)
    {
      // Search highlighting takes priority
      if (pos_in_text_markup(pos, ptm_search))
      {
        ac = merged_color_overlay(ac, ptm_search->ac_text);
        last = MIN(last, ptm_search->last);
      }
      else if (ptm_search)
      {
        last = MIN(last, ptm_search->first);
      }
    }

    if (!ac)
      ac = simple_color_get(pl->cid);

    // Display the actual text
    // from:   pos..last
    mutt_window_move(win, row, pos - col);
    mutt_curses_set_color(ac);
    mutt_window_addnstr(win, text + pos, last - pos);
#ifdef USE_DEBUG_WINDOW
    mutt_refresh();
#endif
    pos = last;
  }

  mutt_window_move(win, row, pos - col);
  mutt_curses_set_color(pl->ac_merged);
#ifndef USE_DEBUG_WINDOW
  mutt_window_clrtoeol(win);
#endif
}

/**
 * win_spager_repaint - Repaint the Simple Pager display - Implements MuttWindow::repaint() - @ingroup window_repaint
 */
static int win_spager_repaint(struct MuttWindow *win)
{
  mutt_debug(LL_DEBUG1, "\033[1;33mrepaint\033[0m\n");
  struct SimplePagerWindowData *wdata = win->wdata;
  if (!wdata)
    return 0;

#ifdef USE_DEBUG_WINDOW
  window_invalidate_all();
  debug_win_blanket(win, MT_COLOR_INDICATOR, 'O');
  mutt_refresh();
#endif

  struct PagedFile *pf = wdata->paged_file;
  FILE *fp = pf->fp;
  rewind(fp);

  const char *text = NULL;

  struct PagedLineArray *pla = &wdata->paged_file->lines;

  int pl_index = 0;
  int seg_index = 0;

  for (int screen_row = 0; screen_row < win->state.rows; screen_row++)
  {
    if (paged_lines_find_virtual_row(pla, screen_row + wdata->vrow, &pl_index, &seg_index))
    {
      struct PagedLine *pl = ARRAY_GET(pla, pl_index);
      struct Segment *seg = ARRAY_GET(&pl->segments, seg_index);

      paged_line_get_virtual_text(pl, seg);
      text = paged_line_get_text(pl);

      int text_offset = 0;
      if (seg)
        text_offset = seg->offset_bytes;

      int text_end = pl->num_bytes;
      struct Segment *seg_next = ARRAY_GET(&pl->segments, seg_index + 1);
      if (seg_next)
        text_end = seg_next->offset_bytes;

      display_line2(win, screen_row, text, text_offset, text_end, pl);
#ifdef USE_DEBUG_WINDOW
      mutt_refresh();
#endif
    }
    else
    {
      mutt_window_move(win, screen_row, 0);
      mutt_curses_set_color(pf->ac_file);
      if (wdata->c_tilde)
        mutt_window_addstr(win, "~");
#ifndef USE_DEBUG_WINDOW
      mutt_window_clrtoeol(win);
#endif
    }
  }

  win->actions |= WA_RECALC;

  mutt_debug(LL_DEBUG5, "repaint done\n");
  return 0;
}

/**
 * spager_window_new - Create a new Simple Pager Window
 * @param pf  PagedFile to use
 * @param sub Config Subset
 * @retval ptr New Simple Pager Window
 */
struct MuttWindow *spager_window_new(struct PagedFile *pf, struct ConfigSubset *sub)
{
  struct MuttWindow *win = mutt_window_new(WT_PAGER, MUTT_WIN_ORIENT_VERTICAL,
                                           MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                           MUTT_WIN_SIZE_UNLIMITED);

  struct SimplePagerWindowData *wdata = spager_wdata_new();
  wdata->paged_file = pf;
  wdata->sub = sub;

  win->wdata = wdata;
  win->wdata_free = spager_wdata_free;

  win->recalc = win_spager_recalc;
  win->repaint = win_spager_repaint;

  win_spager_add_observers(win, sub);

  update_cached_config(wdata, NULL);

  return win;
}
