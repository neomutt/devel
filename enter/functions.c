/**
 * @file
 * Enter functions
 *
 * @authors
 * Copyright (C) 2022 Richard Russon <rich@flatcap.org>
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
 * @page enter_functions Enter functions
 *
 * Enter functions
 */

#include "config.h"
#include <string.h>
#include <wchar.h>
#include "mutt/lib.h"
#include "config/helpers.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "functions.h"
#include "browser/lib.h"
#include "complete/lib.h"
#include "history/lib.h"
#include "menu/lib.h"
#include "pattern/lib.h"
#include "enter.h"
#include "keymap.h"
#include "mutt_history.h"
#include "mutt_mailbox.h"
#include "muttlib.h"
#include "opcodes.h"
#include "protos.h"
#include "state.h" // IWYU pragma: keep
#include "wdata.h"

/**
 * replace_part - Search and replace on a buffer
 * @param es    Current state of the input buffer
 * @param from  Starting point for the replacement
 * @param buf   Replacement string
 */
static void replace_part(struct EnterState *es, size_t from, const char *buf)
{
  /* Save the suffix */
  size_t savelen = es->lastchar - es->curpos;
  wchar_t *savebuf = NULL;

  if (savelen)
  {
    savebuf = mutt_mem_calloc(savelen, sizeof(wchar_t));
    memcpy(savebuf, es->wbuf + es->curpos, savelen * sizeof(wchar_t));
  }

  /* Convert to wide characters */
  es->curpos = mutt_mb_mbstowcs(&es->wbuf, &es->wbuflen, from, buf);

  if (savelen)
  {
    /* Make space for suffix */
    if (es->curpos + savelen > es->wbuflen)
    {
      es->wbuflen = es->curpos + savelen;
      mutt_mem_realloc(&es->wbuf, es->wbuflen * sizeof(wchar_t));
    }

    /* Restore suffix */
    memcpy(es->wbuf + es->curpos, savebuf, savelen * sizeof(wchar_t));
    FREE(&savebuf);
  }

  es->lastchar = es->curpos + savelen;
}

// -----------------------------------------------------------------------------

/**
 * complete_file_simple - Complete a filename
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_file_simple(struct EnterWindowData *wdata)
{
  int rc = FR_SUCCESS;
  size_t i;
  for (i = wdata->state->curpos;
       (i > 0) && !mutt_mb_is_shell_char(wdata->state->wbuf[i - 1]); i--)
  {
  }
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf + i, wdata->state->curpos - i);
  if (wdata->tempbuf && (wdata->templen == (wdata->state->lastchar - i)) &&
      (memcmp(wdata->tempbuf, wdata->state->wbuf + i,
              (wdata->state->lastchar - i) * sizeof(wchar_t)) == 0))
  {
    dlg_select_file(wdata->buffer, MUTT_SEL_NO_FLAGS, wdata->m, NULL, NULL);
    if (buf_is_empty(wdata->buffer))
      replace_part(wdata->state, i, buf_string(wdata->buffer));
    return FR_CONTINUE;
  }

  if (mutt_complete(wdata->cd, wdata->buffer) == 0)
  {
    wdata->templen = wdata->state->lastchar - i;
    mutt_mem_realloc(&wdata->tempbuf, wdata->templen * sizeof(wchar_t));
    memcpy(wdata->tempbuf, wdata->state->wbuf + i, wdata->templen * sizeof(wchar_t));
  }
  else
  {
    rc = FR_ERROR;
  }

  replace_part(wdata->state, i, buf_string(wdata->buffer));
  return rc;
}

/**
 * complete_alias_complete - Complete an Alias
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_alias_complete(struct EnterWindowData *wdata)
{
  /* invoke the alias-menu to get more addresses */
  size_t i;
  for (i = wdata->state->curpos; (i > 0) && (wdata->state->wbuf[i - 1] != ',') &&
                                 (wdata->state->wbuf[i - 1] != ':');
       i--)
  {
  }
  for (; (i < wdata->state->lastchar) && (wdata->state->wbuf[i] == ' '); i++)
    ; // do nothing

  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf + i, wdata->state->curpos - i);
  int rc = alias_complete(wdata->buffer, NeoMutt.sub);
  replace_part(wdata->state, i, buf_string(wdata->buffer));
  if (rc != 1)
  {
    return FR_CONTINUE;
  }

  return FR_SUCCESS;
}

/**
 * complete_label - Complete a label
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_label(struct EnterWindowData *wdata)
{
  size_t i;
  for (i = wdata->state->curpos; (i > 0) && (wdata->state->wbuf[i - 1] != ',') &&
                                 (wdata->state->wbuf[i - 1] != ':');
       i--)
  {
  }
  for (; (i < wdata->state->lastchar) && (wdata->state->wbuf[i] == ' '); i++)
    ; // do nothing

  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf + i, wdata->state->curpos - i);
  int rc = mutt_label_complete(wdata->cd, wdata->buffer, wdata->tabs);
  replace_part(wdata->state, i, buf_string(wdata->buffer));
  if (rc != 1)
    return FR_CONTINUE;

  return FR_SUCCESS;
}

/**
 * complete_pattern - Complete a NeoMutt Pattern
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_pattern(struct EnterWindowData *wdata)
{
  size_t i = wdata->state->curpos;
  if (i && (wdata->state->wbuf[i - 1] == '~'))
  {
    if (dlg_select_pattern(wdata->buffer->data, wdata->buffer->dsize))
      replace_part(wdata->state, i - 1, wdata->buffer->data);
    buf_fix_dptr(wdata->buffer);
    return FR_CONTINUE;
  }

  for (; (i > 0) && (wdata->state->wbuf[i - 1] != '~'); i--)
    ; // do nothing

  if ((i > 0) && (i < wdata->state->curpos) &&
      (wdata->state->wbuf[i - 1] == '~') && (wdata->state->wbuf[i] == 'y'))
  {
    i++;
    buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf + i, wdata->state->curpos - i);
    int rc = mutt_label_complete(wdata->cd, wdata->buffer, wdata->tabs);
    replace_part(wdata->state, i, wdata->buffer->data);
    buf_fix_dptr(wdata->buffer);
    if (rc != 1)
    {
      return FR_CONTINUE;
    }
  }
  else
  {
    return FR_NO_ACTION;
  }

  return FR_SUCCESS;
}

/**
 * complete_alias_query - Complete an Alias Query
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_alias_query(struct EnterWindowData *wdata)
{
  size_t i = wdata->state->curpos;
  if (i != 0)
  {
    for (; (i > 0) && (wdata->state->wbuf[i - 1] != ','); i--)
      ; // do nothing

    for (; (i < wdata->state->curpos) && (wdata->state->wbuf[i] == ' '); i++)
      ; // do nothing
  }

  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf + i, wdata->state->curpos - i);
  query_complete(wdata->buffer, NeoMutt.sub);
  replace_part(wdata->state, i, buf_string(wdata->buffer));

  return FR_CONTINUE;
}

/**
 * complete_command - Complete a NeoMutt Command
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_command(struct EnterWindowData *wdata)
{
  int rc = FR_SUCCESS;
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
  size_t i = buf_len(wdata->buffer);
  if ((i != 0) && (buf_at(wdata->buffer, i - 1) == '=') &&
      (mutt_var_value_complete(wdata->cd, wdata->buffer, i) != 0))
  {
    wdata->tabs = 0;
  }
  else if (mutt_command_complete(wdata->cd, wdata->buffer, i, wdata->tabs) == 0)
  {
    rc = FR_ERROR;
  }

  replace_part(wdata->state, 0, buf_string(wdata->buffer));
  return rc;
}

/**
 * complete_file_mbox - Complete a Mailbox
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_file_mbox(struct EnterWindowData *wdata)
{
  int rc = FR_SUCCESS;
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);

  /* see if the path has changed from the last time */
  if ((!wdata->tempbuf && !wdata->state->lastchar) ||
      (wdata->tempbuf && (wdata->templen == wdata->state->lastchar) &&
       (memcmp(wdata->tempbuf, wdata->state->wbuf,
               wdata->state->lastchar * sizeof(wchar_t)) == 0)))
  {
    dlg_select_file(wdata->buffer,
                    ((wdata->flags & MUTT_COMP_FILE_MBOX) ? MUTT_SEL_FOLDER : MUTT_SEL_NO_FLAGS) |
                        (wdata->multiple ? MUTT_SEL_MULTI : MUTT_SEL_NO_FLAGS),
                    wdata->m, wdata->files, wdata->numfiles);
    if (buf_is_empty(wdata->buffer))
    {
      buf_pretty_mailbox(wdata->buffer);
      if (!wdata->pass)
        mutt_hist_add(wdata->hclass, buf_string(wdata->buffer), true);
      wdata->done = true;
      return FR_SUCCESS;
    }

    /* file selection cancelled */
    return FR_CONTINUE;
  }

  if (mutt_complete(wdata->cd, wdata->buffer) == 0)
  {
    wdata->templen = wdata->state->lastchar;
    mutt_mem_realloc(&wdata->tempbuf, wdata->templen * sizeof(wchar_t));
    memcpy(wdata->tempbuf, wdata->state->wbuf, wdata->templen * sizeof(wchar_t));
  }
  else
  {
    return FR_ERROR; // let the user know that nothing matched
  }
  replace_part(wdata->state, 0, buf_string(wdata->buffer));
  return rc;
}

#ifdef USE_NOTMUCH
/**
 * complete_nm_query - Complete a Notmuch Query
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_nm_query(struct EnterWindowData *wdata)
{
  int rc = FR_SUCCESS;
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
  size_t len = buf_len(wdata->buffer);
  if (!mutt_nm_query_complete(wdata->cd, wdata->buffer, len, wdata->tabs))
    rc = FR_ERROR;

  replace_part(wdata->state, 0, buf_string(wdata->buffer));
  return rc;
}

/**
 * complete_nm_tag - Complete a Notmuch Tag
 * @param wdata Enter window data
 * @retval num #FunctionRetval, e.g. #FR_SUCCESS
 */
static int complete_nm_tag(struct EnterWindowData *wdata)
{
  int rc = FR_SUCCESS;
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
  if (!mutt_nm_tag_complete(wdata->cd, wdata->buffer, wdata->tabs))
    rc = FR_ERROR;

  replace_part(wdata->state, 0, buf_string(wdata->buffer));
  return rc;
}
#endif

/**
 * op_editor_complete - Complete filename or alias - Implements ::enter_function_t - @ingroup enter_function_api
 *
 * This function handles:
 * - OP_EDITOR_COMPLETE
 * - OP_EDITOR_COMPLETE_QUERY
 */
static int op_editor_complete(struct EnterWindowData *wdata, int op)
{
  if (wdata->tabs == 0)
  {
    if (wdata->cd)
      completion_data_reset(wdata->cd);
    else
      wdata->cd = completion_data_new();
  }

  wdata->tabs++;
  wdata->redraw = ENTER_REDRAW_LINE;
  if (wdata->flags & MUTT_COMP_FILE_SIMPLE)
    return complete_file_simple(wdata);

  if (wdata->flags & (MUTT_COMP_FILE | MUTT_COMP_FILE_MBOX))
    return complete_file_mbox(wdata);

  if (wdata->flags & MUTT_COMP_ALIAS)
  {
    switch (op)
    {
      case OP_EDITOR_COMPLETE:
        return complete_alias_complete(wdata);
      case OP_EDITOR_COMPLETE_QUERY:
        return complete_alias_query(wdata);
      default:
        return FR_NO_ACTION;
    }
  }

  if ((wdata->flags & MUTT_COMP_LABEL))
    return complete_label(wdata);

  if ((wdata->flags & MUTT_COMP_PATTERN))
    return complete_pattern(wdata);

  if (wdata->flags & MUTT_COMP_COMMAND)
    return complete_command(wdata);

#ifdef USE_NOTMUCH
  if (wdata->flags & MUTT_COMP_NM_QUERY)
    return complete_nm_query(wdata);

  if (wdata->flags & MUTT_COMP_NM_TAG)
    return complete_nm_tag(wdata);
#endif

  return FR_NO_ACTION;
}

// -----------------------------------------------------------------------------

/**
 * op_editor_history_down - Scroll down through the history list - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_history_down(struct EnterWindowData *wdata, int op)
{
  wdata->state->curpos = wdata->state->lastchar;
  if (mutt_hist_at_scratch(wdata->hclass))
  {
    buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
    mutt_hist_save_scratch(wdata->hclass, buf_string(wdata->buffer));
  }
  replace_part(wdata->state, 0, mutt_hist_next(wdata->hclass));
  wdata->redraw = ENTER_REDRAW_INIT;
  return FR_SUCCESS;
}

/**
 * op_editor_history_search - Search through the history list - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_history_search(struct EnterWindowData *wdata, int op)
{
  wdata->state->curpos = wdata->state->lastchar;
  buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
  mutt_hist_complete(wdata->buffer->data, wdata->buffer->dsize, wdata->hclass);
  replace_part(wdata->state, 0, wdata->buffer->data);
  return FR_CONTINUE;
}

/**
 * op_editor_history_up - Scroll up through the history list - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_history_up(struct EnterWindowData *wdata, int op)
{
  wdata->state->curpos = wdata->state->lastchar;
  if (mutt_hist_at_scratch(wdata->hclass))
  {
    buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
    mutt_hist_save_scratch(wdata->hclass, buf_string(wdata->buffer));
  }
  replace_part(wdata->state, 0, mutt_hist_prev(wdata->hclass));
  wdata->redraw = ENTER_REDRAW_INIT;
  return FR_SUCCESS;
}

/**
 * op_editor_mailbox_cycle - Cycle among incoming mailboxes - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_mailbox_cycle(struct EnterWindowData *wdata, int op)
{
  if (wdata->flags & MUTT_COMP_FILE_MBOX)
  {
    wdata->first = true; /* clear input if user types a real key later */
    buf_mb_wcstombs(wdata->buffer, wdata->state->wbuf, wdata->state->curpos);
    mutt_mailbox_next(wdata->m, wdata->buffer);

    wdata->state->curpos = wdata->state->lastchar = mutt_mb_mbstowcs(
        &wdata->state->wbuf, &wdata->state->wbuflen, 0, buf_string(wdata->buffer));
    return FR_SUCCESS;
  }
  else if (!(wdata->flags & MUTT_COMP_FILE))
  {
    return FR_NO_ACTION;
  }

  return op_editor_complete(wdata, op);
}

// -----------------------------------------------------------------------------

/**
 * op_editor_backspace - Delete the char in front of the cursor - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_backspace(struct EnterWindowData *wdata, int op)
{
  int rc = editor_backspace(wdata->state);

  if ((rc == FR_ERROR) && editor_buffer_is_empty(wdata->state))
  {
    const bool c_abort_backspace = cs_subset_bool(NeoMutt.sub, "abort_backspace");
    if (c_abort_backspace)
    {
      buf_reset(wdata->buffer);
      wdata->done = true;
      rc = FR_SUCCESS;
    }
  }

  return rc;
}

/**
 * op_editor_backward_char - Move the cursor one character to the left - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_backward_char(struct EnterWindowData *wdata, int op)
{
  return editor_backward_char(wdata->state);
}

/**
 * op_editor_backward_word - Move the cursor to the beginning of the word - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_backward_word(struct EnterWindowData *wdata, int op)
{
  return editor_backward_word(wdata->state);
}

/**
 * op_editor_bol - Jump to the beginning of the line - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_bol(struct EnterWindowData *wdata, int op)
{
  return editor_bol(wdata->state);
}

/**
 * op_editor_capitalize_word - Capitalize the word - Implements ::enter_function_t - @ingroup enter_function_api
 * This function handles:
 * - OP_EDITOR_CAPITALIZE_WORD
 * - OP_EDITOR_DOWNCASE_WORD
 * - OP_EDITOR_UPCASE_WORD
 */
static int op_editor_capitalize_word(struct EnterWindowData *wdata, int op)
{
  enum EnterCase ec;
  switch (op)
  {
    case OP_EDITOR_CAPITALIZE_WORD:
      ec = EC_CAPITALIZE;
      break;
    case OP_EDITOR_DOWNCASE_WORD:
      ec = EC_DOWNCASE;
      break;
    case OP_EDITOR_UPCASE_WORD:
      ec = EC_UPCASE;
      break;
    default:
      return FR_ERROR;
  }
  return editor_case_word(wdata->state, ec);
}

/**
 * op_editor_delete_char - Delete the char under the cursor - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_delete_char(struct EnterWindowData *wdata, int op)
{
  return editor_delete_char(wdata->state);
}

/**
 * op_editor_eol - Jump to the end of the line - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_eol(struct EnterWindowData *wdata, int op)
{
  int rc = editor_eol(wdata->state);
  wdata->redraw = ENTER_REDRAW_INIT;
  return rc;
}

/**
 * op_editor_forward_char - Move the cursor one character to the right - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_forward_char(struct EnterWindowData *wdata, int op)
{
  return editor_forward_char(wdata->state);
}

/**
 * op_editor_forward_word - Move the cursor to the end of the word - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_forward_word(struct EnterWindowData *wdata, int op)
{
  return editor_forward_word(wdata->state);
}

/**
 * op_editor_kill_eol - Delete chars from cursor to end of line - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_kill_eol(struct EnterWindowData *wdata, int op)
{
  return editor_kill_eol(wdata->state);
}

/**
 * op_editor_kill_eow - Delete chars from the cursor to the end of the word - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_kill_eow(struct EnterWindowData *wdata, int op)
{
  return editor_kill_eow(wdata->state);
}

/**
 * op_editor_kill_line - Delete all chars on the line - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_kill_line(struct EnterWindowData *wdata, int op)
{
  return editor_kill_line(wdata->state);
}

/**
 * op_editor_kill_whole_line - Delete all chars on the line - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_kill_whole_line(struct EnterWindowData *wdata, int op)
{
  return editor_kill_whole_line(wdata->state);
}

/**
 * op_editor_kill_word - Delete the word in front of the cursor - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_kill_word(struct EnterWindowData *wdata, int op)
{
  return editor_kill_word(wdata->state);
}

/**
 * op_editor_quote_char - Quote the next typed key - Implements ::enter_function_t - @ingroup enter_function_api
 *
 * As part of the line-editor, this function uses the message window.
 *
 * @sa #gui_mw
 */
static int op_editor_quote_char(struct EnterWindowData *wdata, int op)
{
  struct KeyEvent event = { 0, OP_NULL };
  do
  {
    window_redraw(NULL);
    event = mutt_getch_timeout(1000); // 1 second
  } while (event.op == OP_TIMEOUT);
  if (event.op != OP_ABORT)
  {
    if (self_insert(wdata, event.ch))
    {
      wdata->done = true;
      return FR_SUCCESS;
    }
  }
  return FR_SUCCESS;
}

/**
 * op_editor_transpose_chars - Transpose character under cursor with previous - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_editor_transpose_chars(struct EnterWindowData *wdata, int op)
{
  return editor_transpose_chars(wdata->state);
}

/**
 * op_help - Display Help - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_help(struct EnterWindowData *wdata, int op)
{
  mutt_help(MENU_EDITOR);
  return FR_SUCCESS;
}

/**
 * op_redraw - Redraw the screen - Implements ::enter_function_t - @ingroup enter_function_api
 */
static int op_redraw(struct EnterWindowData *wdata, int op)
{
  clearok(stdscr, true);
  mutt_resize_screen();
  window_invalidate_all();
  window_redraw(NULL);
  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * EnterFunctions - All the NeoMutt functions that Enter supports
 */
static const struct EnterFunction EnterFunctions[] = {
  // clang-format off
  { OP_EDITOR_BACKSPACE,          op_editor_backspace },
  { OP_EDITOR_BACKWARD_CHAR,      op_editor_backward_char },
  { OP_EDITOR_BACKWARD_WORD,      op_editor_backward_word },
  { OP_EDITOR_BOL,                op_editor_bol },
  { OP_EDITOR_CAPITALIZE_WORD,    op_editor_capitalize_word },
  { OP_EDITOR_COMPLETE,           op_editor_complete },
  { OP_EDITOR_COMPLETE_QUERY,     op_editor_complete },
  { OP_EDITOR_DELETE_CHAR,        op_editor_delete_char },
  { OP_EDITOR_DOWNCASE_WORD,      op_editor_capitalize_word },
  { OP_EDITOR_EOL,                op_editor_eol },
  { OP_EDITOR_FORWARD_CHAR,       op_editor_forward_char },
  { OP_EDITOR_FORWARD_WORD,       op_editor_forward_word },
  { OP_EDITOR_HISTORY_DOWN,       op_editor_history_down },
  { OP_EDITOR_HISTORY_SEARCH,     op_editor_history_search },
  { OP_EDITOR_HISTORY_UP,         op_editor_history_up },
  { OP_EDITOR_KILL_EOL,           op_editor_kill_eol },
  { OP_EDITOR_KILL_EOW,           op_editor_kill_eow },
  { OP_EDITOR_KILL_LINE,          op_editor_kill_line },
  { OP_EDITOR_KILL_WHOLE_LINE,    op_editor_kill_whole_line },
  { OP_EDITOR_KILL_WORD,          op_editor_kill_word },
  { OP_EDITOR_MAILBOX_CYCLE,      op_editor_mailbox_cycle },
  { OP_EDITOR_QUOTE_CHAR,         op_editor_quote_char },
  { OP_EDITOR_TRANSPOSE_CHARS,    op_editor_transpose_chars },
  { OP_EDITOR_UPCASE_WORD,        op_editor_capitalize_word },
  { OP_HELP,                      op_help },
  { OP_REDRAW,                    op_redraw },
  { 0, NULL },
  // clang-format on
};

/**
 * enter_function_dispatcher - Perform an Enter function - Implements ::function_dispatcher_t - @ingroup dispatcher_api
 */
int enter_function_dispatcher(struct MuttWindow *win, int op)
{
  if (!win || !win->wdata)
    return FR_UNKNOWN;

  struct EnterWindowData *wdata = win->wdata;

  int rc = FR_UNKNOWN;
  for (size_t i = 0; EnterFunctions[i].op != OP_NULL; i++)
  {
    const struct EnterFunction *fn = &EnterFunctions[i];
    if (fn->op == op)
    {
      rc = fn->function(wdata, op);
      break;
    }
  }

  if (rc == FR_UNKNOWN) // Not our function
    return rc;

  const char *result = dispatcher_get_retval_name(rc);
  mutt_debug(LL_DEBUG1, "Handled %s (%d) -> %s\n", opcodes_get_name(op), op, NONULL(result));

  return rc;
}
