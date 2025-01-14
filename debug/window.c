/**
 * @file
 * Dump the details of the nested Windows
 *
 * @authors
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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
 * @page debug_window Dump the Windows
 *
 * Dump the details of the nested Windows
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "lib.h"

// #define DEBUG_SHOW_SERIALISE

/// The Window that is currently focussed.
/// The focus spans from #RootWindow through MuttWindow.focus
static struct MuttWindow *WinFocus = NULL;

static void win_dump(struct MuttWindow *win, int indent)
{
  bool visible = mutt_window_is_visible(win);

  mutt_debug(LL_DEBUG1, "%*s%s[%d,%d] %s-%c \033[1;33m%s\033[0m (%d,%d)%s%s\n",
             indent, "", visible ? "✓" : "✗\033[1;30m", win->state.col_offset,
             win->state.row_offset, name_window_size(win),
             (win->orient == MUTT_WIN_ORIENT_VERTICAL) ? 'V' : 'H',
             mutt_window_win_name(win), win->state.cols, win->state.rows,
             visible ? "" : "\033[0m",
             (win == WinFocus) ? " <-- \033[1;31mFOCUS\033[0m" : "");

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    win_dump(np, indent + 4);
  }
}

#ifdef DEBUG_SHOW_SERIALISE
static const char *win_size(struct MuttWindow *win)
{
  if (!win)
    return "???";

  switch (win->size)
  {
    case MUTT_WIN_SIZE_FIXED:
      return "FIX";
    case MUTT_WIN_SIZE_MAXIMISE:
      return "MAX";
    case MUTT_WIN_SIZE_MINIMISE:
      return "MIN";
  }

  return "???";
}

static void win_serialise(struct MuttWindow *win, struct Buffer *buf)
{
  if (!mutt_window_is_visible(win))
    return;

  buf_add_printf(buf, "<%s {%dx,%dy} [%dC,%dR]", win_size(win), win->state.col_offset,
                 win->state.row_offset, win->state.cols, win->state.rows);
  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    win_serialise(np, buf);
  }
  buf_addstr(buf, ">");
}
#endif

void debug_win_dump(void)
{
  WinFocus = window_get_focus();
  mutt_debug(LL_DEBUG1, "\n");
  win_dump(RootWindow, 0);
  mutt_debug(LL_DEBUG1, "\n");
#ifdef DEBUG_SHOW_SERIALISE
  struct Buffer buf = buf_pool_get();
  win_serialise(RootWindow, buf);
  mutt_debug(LL_DEBUG1, "%s\n", buf_string(buf));
  buf_pool_release(&buf);
#endif
  WinFocus = NULL;
}

/**
 * debug_win_blanket - Blanket a Window with colour
 * @param win Window to fill
 * @param cid Colour ID, e.g. #MT_COLOR_ERROR
 * @param ch  Character to fill with
 */
void debug_win_blanket(struct MuttWindow *win, int cid, char ch)
{
  if (!win)
    return;

  for (int row = 0; row < win->state.rows; row++)
  {
    mutt_window_move(win, row, 0);
    mutt_curses_set_normal_backed_color_by_id(cid);

    for (int col = 0; col < win->state.cols; col++)
    {
      mutt_window_addch(win, ch);
    }
  }
}

/**
 * win_barrier_repaint - Repaint the Barrier Window - Implements MuttWindow::repaint() - @ingroup window_repaint
 */
static int win_barrier_repaint(struct MuttWindow *win)
{
  debug_win_blanket(win, MT_COLOR_ERROR, 'X');
  mutt_debug(LL_DEBUG5, "repaint done\n");
  return 0;
}

/**
 * debug_win_barrier_wrap - Create a Barrier of Windows around a Window
 * @param win_child Window to surround
 * @param width     Width of left/right barriers
 * @param height    Height of top/bottom barriers
 * @retval ptr Container Window
 */
struct MuttWindow *debug_win_barrier_wrap(struct MuttWindow *win_child, int width, int height)
{
  struct MuttWindow *win_top = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                               MUTT_WIN_SIZE_FIXED,
                                               MUTT_WIN_SIZE_UNLIMITED, height);
  struct MuttWindow *win_left = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                                MUTT_WIN_SIZE_FIXED, width,
                                                MUTT_WIN_SIZE_UNLIMITED);
  struct MuttWindow *win_right = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                                 MUTT_WIN_SIZE_FIXED, width,
                                                 MUTT_WIN_SIZE_UNLIMITED);
  struct MuttWindow *win_bottom = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                  MUTT_WIN_SIZE_FIXED,
                                                  MUTT_WIN_SIZE_UNLIMITED, height);
  win_top->repaint = win_barrier_repaint;
  win_left->repaint = win_barrier_repaint;
  win_right->repaint = win_barrier_repaint;
  win_bottom->repaint = win_barrier_repaint;

  struct MuttWindow *win_inner = mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_HORIZONTAL,
                                                 MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                 MUTT_WIN_SIZE_UNLIMITED);
  mutt_window_add_child(win_inner, win_left);
  mutt_window_add_child(win_inner, win_child);
  mutt_window_add_child(win_inner, win_right);

  struct MuttWindow *win_outer = mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_VERTICAL,
                                                 MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                 MUTT_WIN_SIZE_UNLIMITED);
  mutt_window_add_child(win_outer, win_top);
  mutt_window_add_child(win_outer, win_inner);
  mutt_window_add_child(win_outer, win_bottom);

  return win_outer;
}
