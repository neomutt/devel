/**
 * @file
 * Window management
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2024 Dennis Schön <mail@dennis-schoen.de>
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
 * @page gui_window Window management
 *
 * Window management
 */

#include "config.h"
#include <stdarg.h>
#include <string.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "mutt_window.h"
#include "curs_lib.h"
#include "globals.h"
#include "mutt_curses.h"
#include "reflow.h"
#include "rootwin.h"
#ifdef USE_DEBUG_WINDOW
#include "debug/lib.h"
#endif

/// Lookups for Window Names
static const struct Mapping WindowNames[] = {
  // clang-format off
  { "WT_ALL_DIALOGS",     WT_ALL_DIALOGS },
  { "WT_CONTAINER",       WT_CONTAINER },
  { "WT_CUSTOM",          WT_CUSTOM },
  { "WT_DLG_ALIAS",       WT_DLG_ALIAS },
  { "WT_DLG_ATTACHMENT",  WT_DLG_ATTACHMENT },
  { "WT_DLG_AUTOCRYPT",   WT_DLG_AUTOCRYPT },
  { "WT_DLG_BROWSER",     WT_DLG_BROWSER },
  { "WT_DLG_CERTIFICATE", WT_DLG_CERTIFICATE },
  { "WT_DLG_COMPOSE",     WT_DLG_COMPOSE },
  { "WT_DLG_GPGME",       WT_DLG_GPGME },
  { "WT_DLG_HISTORY",     WT_DLG_HISTORY },
  { "WT_DLG_INDEX",       WT_DLG_INDEX },
  { "WT_DLG_PAGER",       WT_DLG_PAGER },
  { "WT_DLG_PATTERN",     WT_DLG_PATTERN },
  { "WT_DLG_PGP",         WT_DLG_PGP },
  { "WT_DLG_POSTPONED",   WT_DLG_POSTPONED },
  { "WT_DLG_QUERY",       WT_DLG_QUERY },
  { "WT_DLG_SMIME",       WT_DLG_SMIME },
  { "WT_HELP_BAR",        WT_HELP_BAR },
  { "WT_INDEX",           WT_INDEX },
  { "WT_MENU",            WT_MENU },
  { "WT_MESSAGE",         WT_MESSAGE },
  { "WT_PAGER",           WT_PAGER },
  { "WT_ROOT",            WT_ROOT },
  { "WT_SIDEBAR",         WT_SIDEBAR },
  { "WT_STATUS_BAR",      WT_STATUS_BAR },
  { NULL, 0 },
  // clang-format on
};

/**
 * window_was_visible - Was the Window visible?
 * @param win Window
 * @retval true The Window was visible
 *
 * Using the `WindowState old`, check if a Window used to be visible.
 * For a Window to be visible, *it* must have been visible and its parent and
 * grandparent, etc.
 */
static bool window_was_visible(struct MuttWindow *win)
{
  if (!win)
    return false;

  for (; win; win = win->parent)
  {
    if (!win->old.visible)
      return false;
  }

  return true;
}

/**
 * window_notify - Notify observers of changes to a Window
 * @param win Window
 */
static void window_notify(struct MuttWindow *win)
{
  if (!win || !win->notify)
    return;

  const struct WindowState *old = &win->old;
  const struct WindowState *wstate = &win->state;
  WindowNotifyFlags flags = WN_NO_FLAGS;

  const bool was_visible = window_was_visible(win);
  const bool is_visible = mutt_window_is_visible(win);
  if (was_visible != is_visible)
    flags |= is_visible ? WN_VISIBLE : WN_HIDDEN;

  if ((wstate->row_offset != old->row_offset) || (wstate->col_offset != old->col_offset))
    flags |= WN_MOVED;

  if (wstate->rows > old->rows)
    flags |= WN_TALLER;
  else if (wstate->rows < old->rows)
    flags |= WN_SHORTER;

  if (wstate->cols > old->cols)
    flags |= WN_WIDER;
  else if (wstate->cols < old->cols)
    flags |= WN_NARROWER;

  if (flags == WN_NO_FLAGS)
    return;

  mutt_debug(LL_NOTIFY, "NT_WINDOW_STATE: %s, %p\n", mutt_window_win_name(win),
             (void *) win);
  struct EventWindow ev_w = { win, flags };
  notify_send(win->notify, NT_WINDOW, NT_WINDOW_STATE, &ev_w);
}

/**
 * window_notify_all - Notify observers of changes to a Window and its children
 * @param win Window
 */
void window_notify_all(struct MuttWindow *win)
{
  if (!win)
    win = RootWindow;

  window_notify(win);

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    window_notify_all(np);
  }
  win->old = win->state;
}

/**
 * window_set_visible - Set a Window visible or hidden
 * @param win     Window
 * @param visible If true, make Window visible, otherwise hidden
 */
void window_set_visible(struct MuttWindow *win, bool visible)
{
  if (!win)
    win = RootWindow;

  win->state.visible = visible;
}

/**
 * mutt_window_new - Create a new Window
 * @param type   Window type, e.g. #WT_ROOT
 * @param orient Window orientation, e.g. #MUTT_WIN_ORIENT_VERTICAL
 * @param size   Window size, e.g. #MUTT_WIN_SIZE_MAXIMISE
 * @param cols   Initial number of columns to allocate, can be #MUTT_WIN_SIZE_UNLIMITED
 * @param rows   Initial number of rows to allocate, can be #MUTT_WIN_SIZE_UNLIMITED
 * @retval ptr New Window
 */
struct MuttWindow *mutt_window_new(enum WindowType type, enum MuttWindowOrientation orient,
                                   enum MuttWindowSize size, int cols, int rows)
{
  struct MuttWindow *win = MUTT_MEM_CALLOC(1, struct MuttWindow);

  win->type = type;
  win->orient = orient;
  win->size = size;
  win->req_rows = rows;
  win->req_cols = cols;
  win->state.visible = true;
  win->notify = notify_new();
  TAILQ_INIT(&win->children);

  win->actions |= WA_RECALC | WA_REPAINT;

  return win;
}

/**
 * mutt_window_free - Free a Window and its children
 * @param ptr Window to free
 */
void mutt_window_free(struct MuttWindow **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct MuttWindow *win = *ptr;

  if (win->parent && (win->parent->focus == win))
    win->parent->focus = NULL;

  mutt_debug(LL_NOTIFY, "NT_WINDOW_DELETE: %s, %p\n", mutt_window_win_name(win),
             (void *) win);
  struct EventWindow ev_w = { win, WN_NO_FLAGS };
  notify_send(win->notify, NT_WINDOW, NT_WINDOW_DELETE, &ev_w);

  mutt_winlist_free(&win->children);

  if (win->wdata_free && win->wdata)
    win->wdata_free(win, &win->wdata); // Custom function to free private data

  notify_free(&win->notify);

  FREE(ptr);
}

/**
 * mutt_window_clearline - Clear a row of a Window
 * @param win Window
 * @param row Row to clear
 */
void mutt_window_clearline(struct MuttWindow *win, int row)
{
  mutt_window_move(win, row, 0);
  mutt_window_clrtoeol(win);
}

/**
 * mutt_window_clrtoeol - Clear to the end of the line
 * @param win Window
 *
 * @note Assumes the cursor has already been positioned within the window.
 */
void mutt_window_clrtoeol(struct MuttWindow *win)
{
  if (!win || !stdscr)
    return;

  if ((win->state.col_offset + win->state.cols) == COLS)
  {
    clrtoeol();
  }
  else
  {
    int row = 0;
    int col = 0;
    getyx(stdscr, row, col);
    int curcol = col;
    while (curcol < (win->state.col_offset + win->state.cols))
    {
      addch(' ');
      curcol++;
    }
    move(row, col);
  }
}

/**
 * mutt_window_get_coords - Get the cursor position in the Window
 * @param[in]  win Window
 * @param[out] row Row in Window
 * @param[out] col Column in Window
 *
 * Assumes the current position is inside the window.  Otherwise it will
 * happily return negative or values outside the window boundaries
 */
void mutt_window_get_coords(struct MuttWindow *win, int *row, int *col)
{
  int x = 0;
  int y = 0;

  getyx(stdscr, y, x);
  if (col)
    *col = x - win->state.col_offset;
  if (row)
    *row = y - win->state.row_offset;
}

/**
 * mutt_window_move - Move the cursor in a Window
 * @param win Window
 * @param row Row to move to
 * @param col Column to move to
 * @retval OK  Success
 * @retval ERR Error
 */
int mutt_window_move(struct MuttWindow *win, int row, int col)
{
  return move(win->state.row_offset + row, win->state.col_offset + col);
}

/**
 * mutt_window_reflow - Resize a Window and its children
 * @param win Window to resize
 */
void mutt_window_reflow(struct MuttWindow *win)
{
  if (OptNoCurses)
    return;

  if (!win)
    win = RootWindow;

  window_reflow(win);
  window_notify_all(win);

  // Allow Windows to resize themselves based on the first reflow
  window_reflow(win);
  window_notify_all(win);

#ifdef USE_DEBUG_WINDOW
  debug_win_dump();
#endif
}

/**
 * mutt_window_wrap_cols - Calculate the wrap column for a given screen width
 * @param width Screen width
 * @param wrap  Wrap config
 * @retval num Column that text should be wrapped at
 *
 * The wrap variable can be negative, meaning there should be a right margin.
 */
int mutt_window_wrap_cols(int width, short wrap)
{
  if (wrap < 0)
    return (width > -wrap) ? (width + wrap) : width;
  if (wrap)
    return (wrap < width) ? wrap : width;
  return width;
}

/**
 * mutt_window_addch - Write one character to a Window
 * @param win Window
 * @param ch  Character to write
 * @retval  0 Success
 * @retval -1 Error
 */
int mutt_window_addch(struct MuttWindow *win, int ch)
{
  return addch(ch);
}

/**
 * mutt_window_addnstr - Write a partial string to a Window
 * @param win Window
 * @param str String
 * @param num Maximum number of characters to write
 * @retval  0 Success
 * @retval -1 Error
 */
int mutt_window_addnstr(struct MuttWindow *win, const char *str, int num)
{
  if (!str)
    return -1;

  return addnstr(str, num);
}

/**
 * mutt_window_addstr - Write a string to a Window
 * @param win Window
 * @param str String
 * @retval  0 Success
 * @retval -1 Error
 */
int mutt_window_addstr(struct MuttWindow *win, const char *str)
{
  if (!str)
    return -1;

  return addstr(str);
}

/**
 * mutt_window_printf - Write a formatted string to a Window
 * @param win Window
 * @param fmt Format string
 * @param ... Arguments
 * @retval num Number of characters written
 */
int mutt_window_printf(struct MuttWindow *win, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int rc = vw_printw(stdscr, fmt, ap);
  va_end(ap);

  return rc;
}

/**
 * mutt_window_add_child - Add a child to Window
 * @param parent Window to add to
 * @param child  Window to add
 */
void mutt_window_add_child(struct MuttWindow *parent, struct MuttWindow *child)
{
  if (!parent || !child)
    return;

  TAILQ_INSERT_TAIL(&parent->children, child, entries);
  child->parent = parent;

  notify_set_parent(child->notify, parent->notify);

  mutt_debug(LL_NOTIFY, "NT_WINDOW_NEW: %s, %p\n", mutt_window_win_name(child),
             (void *) child);
  struct EventWindow ev_w = { child, WN_NO_FLAGS };
  notify_send(child->notify, NT_WINDOW, NT_WINDOW_ADD, &ev_w);
}

/**
 * mutt_window_remove_child - Remove a child from a Window
 * @param parent Window to remove from
 * @param child  Window to remove
 * @retval ptr Child Window
 */
struct MuttWindow *mutt_window_remove_child(struct MuttWindow *parent, struct MuttWindow *child)
{
  if (!parent || !child)
    return NULL;

  // A notification will be sent when the Window is freed
  TAILQ_REMOVE(&parent->children, child, entries);
  child->parent = NULL;

  if (parent->focus == child)
    parent->focus = NULL;

  notify_set_parent(child->notify, NULL);

  return child;
}

/**
 * mutt_winlist_free - Free a tree of Windows
 * @param head WindowList to free
 */
void mutt_winlist_free(struct MuttWindowList *head)
{
  if (!head)
    return;

  struct MuttWindow *np = NULL;
  struct MuttWindow *tmp = NULL;
  TAILQ_FOREACH_SAFE(np, head, entries, tmp)
  {
    TAILQ_REMOVE(head, np, entries);
    mutt_winlist_free(&np->children);
    mutt_window_free(&np);
  }
}

/**
 * mutt_window_is_visible - Is the Window visible?
 * @param win Window
 * @retval true The Window is visible
 *
 * For a Window to be visible, *it* must be visible and its parent and
 * grandparent, etc.
 */
bool mutt_window_is_visible(struct MuttWindow *win)
{
  if (!win)
    return false;

  for (; win; win = win->parent)
  {
    if (!win->state.visible)
      return false;
  }

  return true;
}

/**
 * window_find_child - Recursively find a child Window of a given type
 * @param win  Window to start searching
 * @param type Window type to find, e.g. #WT_STATUS_BAR
 * @retval ptr  Matching Window
 * @retval NULL No match
 */
struct MuttWindow *window_find_child(struct MuttWindow *win, enum WindowType type)
{
  if (!win)
    return NULL;
  if (win->type == type)
    return win;

  struct MuttWindow *np = NULL;
  struct MuttWindow *match = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    match = window_find_child(np, type);
    if (match)
      return match;
  }

  return NULL;
}

/**
 * window_find_parent - Find a (grand-)parent of a Window by type
 * @param win  Window
 * @param type Window type, e.g. #WT_DLG_INDEX
 * @retval ptr Window
 */
struct MuttWindow *window_find_parent(struct MuttWindow *win, enum WindowType type)
{
  for (; win; win = win->parent)
  {
    if (win->type == type)
      return win;
  }

  return NULL;
}

/**
 * window_recalc - Recalculate a tree of Windows
 * @param win Window to start at
 */
static void window_recalc(struct MuttWindow *win)
{
  if (!win || !win->state.visible)
    return;

  if (win->recalc && (win->actions & WA_RECALC))
    win->recalc(win);
  win->actions &= ~WA_RECALC;

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    window_recalc(np);
  }
}

/**
 * window_repaint - Repaint a tree of Windows
 * @param win   Window to start at
 */
static void window_repaint(struct MuttWindow *win)
{
  if (!win || !win->state.visible)
    return;

  if (win->repaint && (win->actions & WA_REPAINT))
    win->repaint(win);
  win->actions &= ~WA_REPAINT;

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    window_repaint(np);
  }
}

/**
 * window_recursor - Recursor the focussed Window
 *
 * Give the focussed Window an opportunity to set the position and
 * visibility of its cursor.
 */
static void window_recursor(void)
{
  // Give the focussed window an opportunity to set the cursor position
  struct MuttWindow *win = window_get_focus();
  if (!win)
    return;

  if (win->recursor && win->recursor(win))
    return;

  mutt_curses_set_cursor(MUTT_CURSOR_INVISIBLE);
}

/**
 * window_redraw - Reflow, recalc and repaint a tree of Windows
 * @param win Window to start at
 *
 * @note If win is NULL, all windows will be redrawn
 */
void window_redraw(struct MuttWindow *win)
{
  if (!win)
    win = RootWindow;

  window_reflow(win);
  window_notify_all(win);

  window_recalc(win);
  window_repaint(win);
  window_recursor();

  mutt_refresh();
}

/**
 * window_is_focused - Does the given Window have the focus?
 * @param win Window to check
 * @retval true Window has focus
 */
bool window_is_focused(const struct MuttWindow *win)
{
  if (!win)
    return false;

  struct MuttWindow *win_focus = window_get_focus();

  return (win_focus == win);
}

/**
 * window_get_focus - Get the currently focused Window
 * @retval ptr Window with focus
 */
struct MuttWindow *window_get_focus(void)
{
  struct MuttWindow *win = RootWindow;

  while (win && win->focus)
    win = win->focus;

  return win;
}

/**
 * window_set_focus - Set the Window focus
 * @param win Window to focus
 * @retval ptr  Old focused Window
 * @retval NULL Error, or focus not changed
 */
struct MuttWindow *window_set_focus(struct MuttWindow *win)
{
  if (!win)
    return NULL;

  struct MuttWindow *old_focus = window_get_focus();

  struct MuttWindow *parent = win->parent;
  struct MuttWindow *child = win;

  // Set the chain of focus, all the way to the root
  for (; parent; child = parent, parent = parent->parent)
    parent->focus = child;

  win->focus = NULL;

  if (win == old_focus)
    return NULL;

  mutt_debug(LL_NOTIFY, "NT_WINDOW_FOCUS: %s, %p\n", mutt_window_win_name(win),
             (void *) win);
  struct EventWindow ev_w = { win, WN_NO_FLAGS };
  notify_send(win->notify, NT_WINDOW, NT_WINDOW_FOCUS, &ev_w);
#ifdef USE_DEBUG_WINDOW
  debug_win_dump();
#endif

  return old_focus;
}

/**
 * mutt_window_clear - Clear a Window
 * @param win Window
 *
 * If the Window isn't visible, it won't be cleared.
 */
void mutt_window_clear(struct MuttWindow *win)
{
  if (!mutt_window_is_visible(win))
    return;

  for (int i = 0; i < win->state.rows; i++)
    mutt_window_clearline(win, i);
}

/**
 * mutt_window_win_name - Get the name of a Window
 * @param win Window
 * @retval ptr  String describing Window
 * @retval NULL Error, or unknown
 */
const char *mutt_window_win_name(const struct MuttWindow *win)
{
  if (!win)
    return "UNKNOWN";

  const char *name = mutt_map_get_name(win->type, WindowNames);
  if (name)
    return name;
  return "UNKNOWN";
}

/**
 * window_invalidate - Mark a window as in need of repaint
 * @param win   Window to start at
 */
static void window_invalidate(struct MuttWindow *win)
{
  if (!win)
    return;

  win->actions |= WA_RECALC | WA_REPAINT;

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    window_invalidate(np);
  }
}

/**
 * window_invalidate_all - Mark all windows as in need of repaint
 */
void window_invalidate_all(void)
{
  window_invalidate(RootWindow);
  clearok(stdscr, true);
  keypad(stdscr, true);
}

/**
 * window_status_on_top - Organise windows according to config variable
 * @param panel Window containing WT_MENU and WT_STATUS_BAR
 * @param sub   Config Subset
 * @retval true Window order was changed
 *
 * Set the positions of two Windows based on a config variable `$status_on_top`.
 *
 * @note The children are expected to have types: #WT_MENU, #WT_STATUS_BAR
 */
bool window_status_on_top(struct MuttWindow *panel, const struct ConfigSubset *sub)
{
  const bool c_status_on_top = cs_subset_bool(sub, "status_on_top");

  struct MuttWindow *win = TAILQ_FIRST(&panel->children);

  if ((c_status_on_top && (win->type == WT_STATUS_BAR)) ||
      (!c_status_on_top && (win->type != WT_STATUS_BAR)))
  {
    return false;
  }

  if (c_status_on_top)
  {
    win = TAILQ_LAST(&panel->children, MuttWindowList);
    TAILQ_REMOVE(&panel->children, win, entries);
    TAILQ_INSERT_HEAD(&panel->children, win, entries);
  }
  else
  {
    TAILQ_REMOVE(&panel->children, win, entries);
    TAILQ_INSERT_TAIL(&panel->children, win, entries);
  }

  mutt_window_reflow(panel);
  window_invalidate_all();
  return true;
}

/**
 * mutt_window_swap - Swap the position of two windows
 * @param parent Parent Window
 * @param win1   Window
 * @param win2   Window
 * @retval true Windows were switched
 */
bool mutt_window_swap(struct MuttWindow *parent, struct MuttWindow *win1,
                      struct MuttWindow *win2)
{
  if (!parent || !win1 || !win2)
    return false;

  // ensure both windows are children of the parent
  if (win1->parent != parent || win2->parent != parent)
    return false;

  struct MuttWindow *win1_next = TAILQ_NEXT(win1, entries);
  if (win1_next == win2)
  {
    // win1 is directly in front of win2, move it behind
    TAILQ_REMOVE(&parent->children, win1, entries);
    TAILQ_INSERT_AFTER(&parent->children, win2, win1, entries);
    return true;
  }

  struct MuttWindow *win2_next = TAILQ_NEXT(win2, entries);
  if (win2_next == win1)
  {
    // win2 is directly in front of win1, move it behind
    TAILQ_REMOVE(&parent->children, win2, entries);
    TAILQ_INSERT_AFTER(&parent->children, win1, win2, entries);
    return true;
  }

  TAILQ_REMOVE(&parent->children, win1, entries);
  TAILQ_REMOVE(&parent->children, win2, entries);

  if (win1_next)
    TAILQ_INSERT_BEFORE(win1_next, win2, entries);
  else
    TAILQ_INSERT_TAIL(&parent->children, win2, entries);

  if (win2_next)
    TAILQ_INSERT_BEFORE(win2_next, win1, entries);
  else
    TAILQ_INSERT_TAIL(&parent->children, win1, entries);

  return true;
}
