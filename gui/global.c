/**
 * @file
 * Global functions
 *
 * @authors
 * Copyright (C) 2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2022-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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
 * @page gui_global Global functions
 *
 * Global functions
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "core/lib.h"
#include "global.h"
#include "color/lib.h"
#include "index/lib.h"
#include "pfile/lib.h"
#include "spager/lib.h"
#include "curs_lib.h"
#include "external.h"
#include "mutt_curses.h"
#include "mutt_mailbox.h"
#include "mutt_window.h"
#include "muttlib.h"
#include "opcodes.h"

/**
 * op_check_stats - Calculate message statistics for all mailboxes - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_check_stats(int op)
{
  mutt_mailbox_check(get_current_mailbox(),
                     MUTT_MAILBOX_CHECK_POSTPONED | MUTT_MAILBOX_CHECK_STATS);
  return FR_SUCCESS;
}

/**
 * op_enter_command - Enter a neomuttrc command - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_enter_command(int op)
{
  mutt_enter_command();
  window_redraw(NULL);
  return FR_SUCCESS;
}

/**
 * op_redraw - Clear and redraw the screen - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_redraw(int op)
{
  clearok(stdscr, true);
  mutt_resize_screen();
  window_invalidate_all();
  window_redraw(NULL);
  return FR_SUCCESS;
}

/**
 * op_shell_escape - Invoke a command in a subshell - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_shell_escape(int op)
{
  if (mutt_shell_escape())
  {
    struct Mailbox *m_cur = get_current_mailbox();
    if (m_cur)
    {
      m_cur->last_checked = 0; // force a check on the next mx_mbox_check() call
      mutt_mailbox_check(m_cur, MUTT_MAILBOX_CHECK_POSTPONED);
    }
  }
  return FR_SUCCESS;
}

/**
 * op_show_log_messages - Show log (and debug) messages - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_show_log_messages(int op)
{
  const struct LogLineList lll = log_queue_get();
  if (STAILQ_EMPTY(&lll))
    return FR_NO_ACTION;

  struct PagedFile *pf = paged_file_new(NULL);
  struct Buffer *buf = buf_pool_get();

  struct LogLine *ll = NULL;
  STAILQ_FOREACH(ll, &lll, entries)
  {
    struct PagedLine *pl = paged_file_new_line(pf);

    if (ll->level <= LL_ERROR)
      pl->cid = MT_COLOR_ERROR;
    else if (ll->level == LL_WARNING)
      pl->cid = MT_COLOR_WARNING;
    else if (ll->level == LL_MESSAGE)
      pl->cid = MT_COLOR_MESSAGE;
    else
      pl->cid = MT_COLOR_DEBUG;

    mutt_date_localtime_format(buf->data, buf->dsize, "[%H:%M:%S]", ll->time);
    paged_line_add_text(pl, buf_string(buf));

    buf_printf(buf, "<%c> %s", LogLevelAbbr[ll->level + 3], ll->message);
    paged_line_add_text(pl, buf_string(buf));

    if (ll->level <= LL_MESSAGE)
      paged_line_add_newline(pl);
  }

  //QWQ pview.flags = MUTT_PAGER_BOTTOM;

  dlg_spager(pf, "messages", NeoMutt->sub);

  buf_pool_release(&buf);
  paged_file_free(&pf);

  return FR_SUCCESS;
}

/**
 * op_version - Show the NeoMutt version number - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_version(int op)
{
  mutt_message("%s", mutt_make_version());
  return FR_SUCCESS;
}

/**
 * op_what_key - display the keycode for a key press - Implements ::global_function_t - @ingroup global_function_api
 */
static int op_what_key(int op)
{
  mw_what_key();
  return FR_SUCCESS;
}

// -----------------------------------------------------------------------------

/**
 * GlobalFunctions - All the NeoMutt functions that the Global supports
 */
static const struct GlobalFunction GlobalFunctions[] = {
  // clang-format off
  { OP_CHECK_STATS,           op_check_stats },
  { OP_ENTER_COMMAND,         op_enter_command },
  { OP_REDRAW,                op_redraw },
  { OP_SHELL_ESCAPE,          op_shell_escape },
  { OP_SHOW_LOG_MESSAGES,     op_show_log_messages },
  { OP_VERSION,               op_version },
  { OP_WHAT_KEY,              op_what_key },
  { 0, NULL },
  // clang-format on
};

/**
 * global_function_dispatcher - Perform a Global function - Implements ::function_dispatcher_t - @ingroup dispatcher_api
 *
 * @note @a win is not used
 */
int global_function_dispatcher(struct MuttWindow *win, int op)
{
  int rc = FR_UNKNOWN;
  for (size_t i = 0; GlobalFunctions[i].op != OP_NULL; i++)
  {
    const struct GlobalFunction *fn = &GlobalFunctions[i];
    if (fn->op == op)
    {
      rc = fn->function(op);
      break;
    }
  }

  if (rc == FR_UNKNOWN) // Not our function
    return rc;

  const char *result = dispatcher_get_retval_name(rc);
  mutt_debug(LL_DEBUG1, "Handled %s (%d) -> %s\n", opcodes_get_name(op), op, NONULL(result));

  return FR_SUCCESS; // Whatever the outcome, we handled it
}
