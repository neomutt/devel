/**
 * @file
 * Simple Pager Functions
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
 * @page spager_functions Simple Pager Functions
 *
 * Simple Pager Functions
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "functions.h"
#include "editor/lib.h"
#include "history/lib.h"
#include "menu/lib.h"
#include "pattern/lib.h"
#include "pfile/lib.h"
#include "protos.h"
#include "search.h"
#include "wdata.h"

/// Error message for unavailable functions
static const char *Not_available_in_this_menu = N_("Not available in this menu");

// -----------------------------------------------------------------------------
// Miscellaneous
/**
 * op_spager_exit - Exit this menu - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_exit(struct MuttWindow *win, int op)
{
  return FR_DONE;
}

/**
 * op_spager_help - Help screen - Implements ::pager_function_t - @ingroup pager_function_api
 */
static int op_spager_help(struct MuttWindow *win, int op)
{
  mutt_help(MENU_PAGER);
  return FR_SUCCESS;
}

/**
 * op_spager_save - Save the Pager text - Implements ::pager_function_t - @ingroup pager_function_api
 */
static int op_spager_save(struct MuttWindow *win, int op)
{
  mutt_message("WIP Saving");
  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------
// Movement
/**
 * spager_set_top_row - Set the top row of the view
 * @param wdata Window Data
 * @param vrow  Virtual row
 * @retval true View was moved
 *
 * @note WA_RECALC will be set if the position changes
 */
static int spager_set_top_row(struct SimplePagerWindowData *wdata, int vrow)
{
  struct PagedFile *pf = wdata->paged_file;

  const int vcount = paged_lines_count_virtual_rows(&pf->lines);

  vrow = CLAMP(vrow, 0, vcount - 1);

  if (vrow == wdata->vrow)
    return false;

  wdata->vrow = vrow;
  return true;
}

/**
 * op_spager_bottom - Jump to the bottom of the message - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_bottom(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;
  struct PagedFile *pf = wdata->paged_file;

  // Pick a new top, so the last entry is on the bottom line
  const int vcount = paged_lines_count_virtual_rows(&pf->lines);
  const int move = vcount - wdata->page_rows;

  if (!spager_set_top_row(wdata, move))
  {
    mutt_message(_("Bottom of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_half_down - Scroll down 1/2 page - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_half_down(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  // Down by half a page
  const int move = wdata->page_rows / 2;

  if (!spager_set_top_row(wdata, wdata->vrow + move))
  {
    mutt_message(_("Bottom of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_half_up - Scroll up 1/2 page - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_half_up(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  // Up by half a page
  const int move = wdata->page_rows / 2;

  if (!spager_set_top_row(wdata, wdata->vrow - move))
  {
    mutt_message(_("Top of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_next_line - Scroll down one line - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_next_line(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  if (!spager_set_top_row(wdata, wdata->vrow + 1))
  {
    mutt_message(_("Bottom of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_next_page - Move to the next page - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_next_page(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  const short c_pager_context = cs_subset_number(wdata->sub, "pager_context");

  // One page, minus the overlap
  int move = wdata->page_rows - c_pager_context;
  move = MAX(move, 1);

  if (!spager_set_top_row(wdata, wdata->vrow + move))
  {
    mutt_message(_("Bottom of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_prev_line - Scroll up one line - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_prev_line(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  if (!spager_set_top_row(wdata, wdata->vrow - 1))
  {
    mutt_message(_("Top of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_prev_page - Move to the previous page - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_prev_page(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  const short c_pager_context = cs_subset_number(wdata->sub, "pager_context");

  // One page, minus the overlap
  int move = wdata->page_rows - c_pager_context;
  move = MAX(move, 1);

  if (!spager_set_top_row(wdata, wdata->vrow - move))
  {
    mutt_message(_("Top of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

/**
 * op_spager_top - Jump to the top of the message - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_top(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;

  if (!spager_set_top_row(wdata, 0))
  {
    mutt_message(_("Top of message is shown"));
    return FR_NO_ACTION;
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------
// Searching
/**
 * op_spager_search - Search for a regular expression - Implements ::spager_function_t - @ingroup spager_function_api
 *
 * This function handles:
 * - OP_SEARCH
 * - OP_SEARCH_REVERSE
 */
static int op_spager_search(struct MuttWindow *win, int op)
{
  int rc = FR_NO_ACTION;

  struct SimplePagerWindowData *wdata = win->wdata;
  struct SimplePagerSearch *search = wdata->search;

  // struct PagedFile *pf = wdata->paged_file;

  struct Buffer *search_str = buf_pool_get();
  buf_strcpy(search_str, search->pattern);

  char *prompt = NULL;
  if (op == OP_SEARCH)
  {
    search->direction = SD_SEARCH_FORWARDS;
    prompt = _("Search for: ");
  }
  else
  {
    search->direction = SD_SEARCH_BACKWARDS;
    prompt = _("Reverse search for: ");
  }

  if (mw_get_field(prompt, search_str, MUTT_COMP_CLEAR, HC_PATTERN,
                   &CompletePatternOps, NULL) != 0)
  {
    goto done;
  }

  if (mutt_str_equal(buf_string(search_str), search->pattern))
  {
    if (search->compiled)
    {
      /* do an implicit search-next */
      if (op == OP_SEARCH)
        op = OP_SEARCH_NEXT;
      else
        op = OP_SEARCH_OPPOSITE;
    }
  }

  if (buf_is_empty(search_str))
    goto done;

  spager_search_set_lines(search, &wdata->paged_file->lines);
  struct Buffer *err = buf_pool_get();
  spager_search_search(search, buf_string(search_str), wdata->vrow, SD_SEARCH_FORWARDS, err);
  buf_pool_release(&err);

  int next_index = 0;
  int next_seg = 0;
  if (spager_search_next(search, wdata->vrow, search->direction, &next_index,
                         &next_seg) == SR_SEARCH_MATCHES)
  {
    if (search->direction == SD_SEARCH_FORWARDS)
    {
      if (next_index < wdata->vrow)
        mutt_message(_("Search wrapped to top"));
    }
    else
    {
      if (next_index > wdata->vrow)
        mutt_message(_("Search wrapped to bottom"));
    }

    wdata->vrow = next_index;
    struct EventSimplePager ev_sp = { win };
    notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
    search->show_search = true;
  }
  else
  {
    mutt_warning(_("Not found"));
  }

  struct EventSimplePager ev_sp = { win };
  notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
  win->actions |= WA_RECALC;
  rc = FR_SUCCESS;

done:
  buf_pool_release(&search_str);
  return rc;
}

/**
 * op_spager_search_next - Search for next match - Implements ::spager_function_t - @ingroup spager_function_api
 *
 * This function handles:
 * - OP_SEARCH_NEXT
 * - OP_SEARCH_OPPOSITE
 */
static int op_spager_search_next(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;
  struct SimplePagerSearch *search = wdata->search;

  if (!search->compiled)
  {
    // We don't have a search term
    op = (op == OP_SEARCH_NEXT) ? OP_SEARCH : OP_SEARCH_REVERSE;
    return op_spager_search(win, op);
  }

  // Keep searching in the same direction, unless
  enum SearchDirection dir = search->direction;
  if (op == OP_SEARCH_OPPOSITE)
  {
    dir = (dir == SD_SEARCH_FORWARDS) ? SD_SEARCH_BACKWARDS : SD_SEARCH_FORWARDS;
  }

  int next_index = 0;
  int next_seg = 0;
  if (spager_search_next(search, wdata->vrow, dir, &next_index, &next_seg) == SR_SEARCH_MATCHES)
  {
    if (dir == SD_SEARCH_FORWARDS)
    {
      if (next_index < wdata->vrow)
        mutt_message(_("Search wrapped to top"));

      // mutt_message(_("Search hit bottom without finding match"));
      // mutt_message(_("Search hit top without finding match"));
    }
    else
    {
      if (next_index > wdata->vrow)
        mutt_message(_("Search wrapped to bottom"));
    }

    wdata->vrow = next_index;
    struct EventSimplePager ev_sp = { win };
    notify_send(wdata->notify, NT_SPAGER, NT_SPAGER_MOVE, &ev_sp);
    search->show_search = true;
  }
  else
  {
    mutt_warning(_("Not found"));
  }

  return FR_SUCCESS;
}

/**
 * op_spager_search_toggle - Toggle search pattern coloring - Implements ::spager_function_t - @ingroup spager_function_api
 */
static int op_spager_search_toggle(struct MuttWindow *win, int op)
{
  struct SimplePagerWindowData *wdata = win->wdata;
  struct SimplePagerSearch *search = wdata->search;

  search->show_search = !search->show_search;
  win->actions |= WA_REPAINT;

  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * SimplePagerFunctions - All the NeoMutt functions that the Pager supports
 */
static const struct SimplePagerFunction SimplePagerFunctions[] = {
  // clang-format off
  { OP_EXIT,                op_spager_exit },
  { OP_HALF_DOWN,           op_spager_half_down },
  { OP_HALF_UP,             op_spager_half_up },
  { OP_HELP,                op_spager_help },
  { OP_MAIN_NEXT_UNDELETED, op_spager_next_line },
  { OP_MAIN_PREV_UNDELETED, op_spager_prev_line },
  { OP_NEXT_LINE,           op_spager_next_line },
  { OP_NEXT_PAGE,           op_spager_next_page },
  { OP_PAGER_BOTTOM,        op_spager_bottom },
  { OP_PAGER_TOP,           op_spager_top },
  { OP_PREV_LINE,           op_spager_prev_line },
  { OP_PREV_PAGE,           op_spager_prev_page },
  { OP_QUIT,                op_spager_exit },
  { OP_SAVE,                op_spager_save },
  { OP_SEARCH,              op_spager_search },
  { OP_SEARCH_NEXT,         op_spager_search_next },
  { OP_SEARCH_OPPOSITE,     op_spager_search_next },
  { OP_SEARCH_REVERSE,      op_spager_search },
  { OP_SEARCH_TOGGLE,       op_spager_search_toggle },
  { 0, NULL },
  // clang-format on
};

/**
 * spager_function_dispatcher - Perform a Pager function - Implements ::function_dispatcher_t - @ingroup dispatcher_api
 */
int spager_function_dispatcher(struct MuttWindow *win, int op)
{
  if (!win)
  {
    mutt_error("%s", _(Not_available_in_this_menu));
    return FR_ERROR;
  }

  int rc = FR_UNKNOWN;
  for (size_t i = 0; SimplePagerFunctions[i].op != OP_NULL; i++)
  {
    const struct SimplePagerFunction *fn = &SimplePagerFunctions[i];
    if (fn->op == op)
    {
      rc = fn->function(win, op);
      break;
    }
  }

  if (rc == FR_UNKNOWN) // Not our function
    return rc;

  const char *result = dispatcher_get_retval_name(rc);
  mutt_debug(LL_DEBUG1, "Handled %s (%d) -> %s\n", opcodes_get_name(op), op, NONULL(result));

  return rc;
}
