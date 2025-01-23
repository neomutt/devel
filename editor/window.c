/**
 * @file
 * GUI ask the user to enter a string
 *
 * @authors
 * Copyright (C) 2017-2023 Richard Russon <rich@flatcap.org>
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
 * @page editor_window GUI ask the user to enter a string
 *
 * GUI ask the user to enter a string
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "color/lib.h"
#include "complete/lib.h"
#include "history/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "sidebar/lib.h"
#include "functions.h"
#include "muttlib.h"
#include "state.h"
#include "wdata.h"

/// Help Bar for the Command Line Editor
static const struct Mapping EditorHelp[] = {
  // clang-format off
  { N_("Help"),        OP_HELP },
  { N_("Complete"),    OP_EDITOR_COMPLETE },
  { N_("Hist Up"),     OP_EDITOR_HISTORY_UP },
  { N_("Hist Down"),   OP_EDITOR_HISTORY_DOWN },
  { N_("Hist Search"), OP_EDITOR_HISTORY_SEARCH },
  { N_("Begin Line"),  OP_EDITOR_BOL },
  { N_("End Line"),    OP_EDITOR_EOL },
  { N_("Kill Line"),   OP_EDITOR_KILL_LINE },
  { N_("Kill Word"),   OP_EDITOR_KILL_WORD },
  { NULL, 0 },
  // clang-format on
};

/**
 * my_addwch - Display one wide character on screen
 * @param win Window
 * @param wc  Character to display
 * @retval OK  Success
 * @retval ERR Failure
 */
static int my_addwch(struct MuttWindow *win, wchar_t wc)
{
  int n = wcwidth(wc);
  if (IsWPrint(wc) && (n > 0))
    return mutt_addwch(win, wc);
  if (!(wc & ~0x7f))
    return mutt_window_printf(win, "^%c", ((int) wc + 0x40) & 0x7f);
  if (!(wc & ~0xffff))
    return mutt_window_printf(win, "\\u%04x", (int) wc);
  return mutt_window_printf(win, "\\u%08x", (int) wc);
}

/**
 * self_insert - Insert a normal character
 * @param wdata Enter window data
 * @param ch    Raw keypress
 * @retval true If done (enter pressed)
 */
bool self_insert(struct EnterWindowData *wdata, int ch)
{
  if (!wdata)
    return true;

  wdata->tabs = 0;
  wchar_t wc = 0;

  /* quietly ignore all other function keys */
  if (ch & ~0xff)
    return false;

  /* gather the bytes into a wide character */
  {
    char c = ch;
    size_t k = mbrtowc(&wc, &c, 1, wdata->mbstate);
    if (k == ICONV_BUF_TOO_SMALL)
    {
      return false;
    }
    else if ((k != 0) && (k != 1))
    {
      memset(wdata->mbstate, 0, sizeof(*wdata->mbstate));
      return false;
    }
  }

  if (wdata->first && (wdata->flags & MUTT_COMP_CLEAR))
  {
    wdata->first = false;
    if (IsWPrint(wc)) /* why? */
    {
      wdata->state->curpos = 0;
      wdata->state->lastchar = 0;
    }
  }

  if ((wc == '\r') || (wc == '\n'))
  {
    /* Convert from wide characters */
    buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->lastchar);
    if (!wdata->pass)
      mutt_hist_add(wdata->hclass, buf_string(wdata->buffer), true);

    if (wdata->cdata)
    {
      struct FileCompletionData *cdata = wdata->cdata;
      if (cdata->multiple)
      {
        char **tfiles = NULL;
        *cdata->numfiles = 1;
        tfiles = MUTT_MEM_CALLOC(*cdata->numfiles, char *);
        buf_expand_path_regex(wdata->buffer, false);
        tfiles[0] = buf_strdup(wdata->buffer);
        *cdata->files = tfiles;
      }
    }
    return true;
  }
  else if (wc && ((wc < ' ') || IsWPrint(wc))) /* why? */
  {
    if (wdata->state->lastchar >= wdata->state->wbuflen)
    {
      wdata->state->wbuflen = wdata->state->lastchar + 20;
      MUTT_MEM_REALLOC(&wdata->state->wbuf, wdata->state->wbuflen, wchar_t);
    }
    memmove(wdata->state->wbuf + wdata->state->curpos + 1,
            wdata->state->wbuf + wdata->state->curpos,
            (wdata->state->lastchar - wdata->state->curpos) * sizeof(wchar_t));
    wdata->state->wbuf[wdata->state->curpos++] = wc;
    wdata->state->lastchar++;
  }
  else
  {
    mutt_flushinp();
    mutt_beep(false);
  }

  return false;
}

/**
 * enter_recalc - Recalculate the Window data - Implements MuttWindow::recalc() - @ingroup window_recalc
 *
 * @sa $compose_format
 */
static int enter_recalc(struct MuttWindow *win)
{
  win->actions |= WA_REPAINT;
  mutt_debug(LL_DEBUG5, "recalc done, request WA_REPAINT\n");

  return 0;
}

/**
 * enter_repaint - Repaint the Window - Implements MuttWindow::repaint() - @ingroup window_repaint
 */
static int enter_repaint(struct MuttWindow *win)
{
  if (!mutt_window_is_visible(win))
    return 0;

  struct EnterWindowData *wdata = win->wdata;

  mutt_window_clearline(win, 0);
  mutt_curses_set_normal_backed_color_by_id(MT_COLOR_PROMPT);
  mutt_window_addstr(win, wdata->prompt);
  mutt_curses_set_color_by_id(MT_COLOR_NORMAL);

  int prompt_length = 0;
  mutt_window_get_coords(win, NULL, &prompt_length);

  int width = win->state.cols - prompt_length - 1;

  if (!wdata->pass)
  {
    if (wdata->redraw == ENTER_REDRAW_INIT)
    {
      /* Go to end of line */
      wdata->state->curpos = wdata->state->lastchar;
      wdata->state->begin = mutt_mb_width_ceiling(
          wdata->state->wbuf, wdata->state->lastchar,
          mutt_mb_wcswidth(wdata->state->wbuf, wdata->state->lastchar) - width + 1);
    }
    if ((wdata->state->curpos < wdata->state->begin) ||
        (mutt_mb_wcswidth(wdata->state->wbuf + wdata->state->begin,
                          wdata->state->curpos - wdata->state->begin) >= width))
    {
      wdata->state->begin = mutt_mb_width_ceiling(
          wdata->state->wbuf, wdata->state->lastchar,
          mutt_mb_wcswidth(wdata->state->wbuf, wdata->state->curpos) - (width / 2));
    }
    mutt_window_move(win, 0, prompt_length);
    int w = 0;
    for (size_t i = wdata->state->begin; i < wdata->state->lastchar; i++)
    {
      w += mutt_mb_wcwidth(wdata->state->wbuf[i]);
      if (w > width)
        break;
      my_addwch(win, wdata->state->wbuf[i]);
    }
    mutt_window_clrtoeol(win);
    mutt_window_move(win, 0,
                     prompt_length +
                         mutt_mb_wcswidth(wdata->state->wbuf + wdata->state->begin,
                                          wdata->state->curpos - wdata->state->begin));
  }

  mutt_window_get_coords(win, &wdata->row, &wdata->col);
  mutt_debug(LL_DEBUG5, "repaint done\n");

  return 0;
}

/**
 * enter_recursor - Recursor the Window - Implements MuttWindow::recursor() - @ingroup window_recursor
 */
static bool enter_recursor(struct MuttWindow *win)
{
  struct EnterWindowData *wdata = win->wdata;
  mutt_window_move(win, wdata->row, wdata->col);
  mutt_curses_set_cursor(MUTT_CURSOR_VISIBLE);
  return true;
}

/**
 * mw_get_field - Ask the user for a string - @ingroup gui_mw
 * @param[in]  prompt   Prompt
 * @param[in]  buf      Buffer for the result
 * @param[in]  hclass   History class to use
 * @param[in]  complete Flags, see #CompletionFlags
 * @param[in]  comp_api Auto-completion API
 * @param[in]  cdata    Auto-completion private data
 * @retval 0  Selection made
 * @retval -1 Aborted
 *
 * This function uses the message window.
 *
 * Ask the user to enter a free-form string.
 * This function supports auto-completion and saves the result to the history.
 *
 * It also supports readline style text editing.
 * See #OpEditor for a list of functions.
 */
int mw_get_field(const char *prompt, struct Buffer *buf, CompletionFlags complete,
                 enum HistoryClass hclass, const struct CompleteOps *comp_api, void *cdata)
{
  struct MuttWindow *win = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_FIXED,
                                           MUTT_WIN_SIZE_UNLIMITED, 1);

  GetChFlags flags = GETCH_NO_FLAGS;
  if (complete & MUTT_COMP_UNBUFFERED)
    flags = GETCH_IGNORE_MACRO;

  int rc = 0;

  struct EnterState *es = enter_state_new();

  win->help_data = EditorHelp;
  win->help_menu = MENU_EDITOR;

  msgcont_push_window(win);
  struct MuttWindow *old_focus = window_set_focus(win);

  mbstate_t mbstate = { 0 };
  // clang-format off
  struct EnterWindowData wdata = { buf, complete, es, hclass, comp_api, cdata, prompt, ENTER_REDRAW_NONE, (complete & MUTT_COMP_PASS), true, NULL, 0, &mbstate, 0, false, NULL, 0, 0 };
  // clang-format on

  win->wdata = &wdata;
  win->wdata_free = NULL; // No need, we hold the data
  win->recalc = enter_recalc;
  win->repaint = enter_repaint;
  win->recursor = enter_recursor;

  window_redraw(win);

  if (es->wbuf[0] == L'\0')
  {
    /* Initialise wbuf from buf */
    wdata.state->wbuflen = 0;
    wdata.state->lastchar = mutt_mb_mbstowcs(&wdata.state->wbuf, &wdata.state->wbuflen,
                                             0, buf_string(wdata.buffer));
    wdata.redraw = ENTER_REDRAW_INIT;
  }
  else
  {
    wdata.redraw = ENTER_REDRAW_LINE;
    wdata.first = false;
  }

  do
  {
    memset(&mbstate, 0, sizeof(mbstate));

    do
    {
      if (wdata.redraw != ENTER_REDRAW_NONE)
        win->actions |= WA_REPAINT;

      window_redraw(NULL);
      struct KeyEvent event = km_dokey_event(MENU_EDITOR, flags);
      if ((event.op == OP_TIMEOUT) || (event.op == OP_REPAINT))
      {
        continue;
      }

      if (event.op == OP_ABORT)
      {
        rc = -1;
        goto bye;
      }

      if (event.op == OP_NULL)
      {
        if (complete & MUTT_COMP_PASS)
          mutt_debug(LL_DEBUG5, "Got char *\n");
        else
          mutt_debug(LL_DEBUG5, "Got char %c (0x%02x)\n", event.ch, event.ch);

        if (self_insert(&wdata, event.ch))
        {
          rc = 0;
          goto bye;
        }
        win->actions |= WA_REPAINT;
        continue;
      }
      else
      {
        mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(event.op),
                   event.op);
      }

      wdata.first = false;
      if ((event.op != OP_EDITOR_COMPLETE) && (event.op != OP_EDITOR_COMPLETE_QUERY))
        wdata.tabs = 0;
      wdata.redraw = ENTER_REDRAW_LINE;
      int rc_disp = enter_function_dispatcher(win, event.op);
      switch (rc_disp)
      {
        case FR_NO_ACTION:
        {
          if (self_insert(&wdata, event.ch))
          {
            rc = 0;
            goto bye;
          }
          break;
        }
        case FR_CONTINUE: // repaint
          rc = 1;
          goto bye;

        case FR_SUCCESS:
          rc = 0;
          break;

        case FR_UNKNOWN:
        case FR_ERROR:
        default:
          mutt_beep(false);
      }
    } while (!wdata.done);

  bye:
    mutt_hist_reset_state(wdata.hclass);
    FREE(&wdata.tempbuf);
    completion_data_free(&wdata.cd);
  } while (rc == 1);

  msgcont_pop_window();
  window_set_focus(old_focus);
  mutt_window_free(&win);

  if (rc == 0)
    buf_fix_dptr(buf);
  else
    buf_reset(buf);

  enter_state_free(&es);

  return rc;
}

/**
 * mw_get_field_notify - Ask the user for a string and call a notify function on keypress
 * @param[in]  prompt   Prompt
 * @param[in]  buf      Buffer for the result
 * @param[in]  callback Callback function used for notification
 * @param[in]  data     Data to pass to callback function
 * @retval 0  Selection made
 * @retval -1 Aborted
 */
int mw_get_field_notify(const char *prompt, struct Buffer *buf,
                        void (*callback)(void *, const char *), void *data)
{
  struct Buffer *cbuf = buf_pool_get();
  buf_alloc(cbuf, 128);
  struct MuttWindow *win = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_FIXED,
                                           MUTT_WIN_SIZE_UNLIMITED, 1);

  int rc = 0;

  struct EnterState *es = enter_state_new();

  win->help_data = EditorHelp;
  win->help_menu = MENU_EDITOR;

  msgcont_push_window(win);
  struct MuttWindow *old_focus = window_set_focus(win);

  mbstate_t mbstate = { 0 };
  // clang-format off
  struct EnterWindowData wdata = { buf, 0, es, 0, NULL, NULL, prompt, ENTER_REDRAW_NONE, MUTT_COMP_NO_FLAGS, true, NULL, 0, &mbstate, 0, false, NULL, 0, 0 };
  // clang-format on

  win->wdata = &wdata;
  win->wdata_free = NULL; // No need, we hold the data
  win->actions |= WA_RECALC;
  win->recalc = enter_recalc;
  win->repaint = enter_repaint;
  win->recursor = enter_recursor;

  window_redraw(win);

  if (es->wbuf[0] == L'\0')
  {
    /* Initialise wbuf from buf */
    wdata.state->wbuflen = 0;
    wdata.state->lastchar = mutt_mb_mbstowcs(&wdata.state->wbuf, &wdata.state->wbuflen,
                                             0, buf_string(wdata.buffer));
    wdata.redraw = ENTER_REDRAW_INIT;
  }
  else
  {
    wdata.redraw = ENTER_REDRAW_LINE;
    wdata.first = false;
  }

  do
  {
    memset(&mbstate, 0, sizeof(mbstate));

    do
    {
      if (wdata.redraw != ENTER_REDRAW_NONE)
        win->actions |= WA_REPAINT;

      window_redraw(NULL);
      struct KeyEvent event = km_dokey_event(MENU_SIDEBAR, GETCH_IGNORE_MACRO);
      if ((event.op == OP_TIMEOUT) || (event.op == OP_REPAINT))
      {
        continue;
      }

      if (event.op == OP_ABORT)
      {
        rc = -1;
        goto bye;
      }

      if (event.op == OP_NULL)
      {
        mutt_debug(LL_DEBUG5, "Got char %c (0x%02x)\n", event.ch, event.ch);
        if (self_insert(&wdata, event.ch))
        {
          rc = 0;
          goto bye;
        }
        win->actions |= WA_REPAINT;
        goto notif;
      }
      else
      {
        mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", opcodes_get_name(event.op),
                   event.op);
      }

      int rc_disp = sb_function_dispatcher(data, event.op);

      if (rc_disp == FR_SUCCESS)
        rc_disp = FR_CONTINUE;
      else
        rc_disp = enter_function_dispatcher(win, event.op);

      wdata.redraw = ENTER_REDRAW_LINE;
      switch (rc_disp)
      {
        case FR_NO_ACTION:
        {
          if (self_insert(&wdata, event.ch))
          {
            rc = 0;
            goto bye;
          }
          break;
        }
        case FR_CONTINUE: // repaint
          rc = 1;
          goto bye;

        case FR_SUCCESS:
          break;

        case FR_UNKNOWN:
        case FR_ERROR:
        default:
          mutt_beep(false);
      }

    notif:
      if (callback)
      {
        buf_mb_wcstombs(cbuf, wdata.state->wbuf, wdata.state->lastchar);
        callback(data, buf_string(cbuf));
      }

    } while (!wdata.done);

  bye:
    FREE(&wdata.tempbuf);
    completion_data_free(&wdata.cd);
  } while (rc == 1);

  msgcont_pop_window();
  window_set_focus(old_focus);
  mutt_window_free(&win);

  if (rc == 0)
    buf_fix_dptr(buf);
  else
    buf_reset(buf);

  buf_pool_release(&cbuf);

  enter_state_free(&es);

  return rc;
}
