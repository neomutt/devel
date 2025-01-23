/**
 * @file
 * NeoMutt Logging
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2019 Pietro Cerutti <gahr@gahr.ch>
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
 * @page neo_mutt_logging NeoMutt Logging
 *
 * NeoMutt Logging
 */

#include "config.h"
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "mutt_logging.h"
#include "color/lib.h"
#include "globals.h"
#include "muttlib.h"

static uint64_t LastError = 0; ///< Time of the last error message (in milliseconds since the Unix epoch)

static char *CurrentFile = NULL; ///< The previous log file name
static const int NumOfLogs = 5;  ///< How many log files to rotate

#define S_TO_MS 1000L

/**
 * error_pause - Wait for an error message to be read
 *
 * If '$sleep_time' seconds hasn't elapsed since LastError, then wait
 */
static void error_pause(void)
{
  const short c_sleep_time = cs_subset_number(NeoMutt->sub, "sleep_time");
  const uint64_t elapsed = mutt_date_now_ms() - LastError;
  const uint64_t sleep = c_sleep_time * S_TO_MS;
  if ((LastError == 0) || (elapsed >= sleep))
    return;

  mutt_refresh();
  mutt_date_sleep_ms(sleep - elapsed);
}

/**
 * mutt_clear_error - Clear the message line (bottom line of screen)
 */
void mutt_clear_error(void)
{
  /* Make sure the error message has had time to be read */
  if (OptMsgErr)
    error_pause();

  ErrorBufMessage = false;
  if (!OptNoCurses)
    msgwin_clear_text(NULL);
}

/**
 * log_disp_curses - Display a log line in the message line - Implements ::log_dispatcher_t - @ingroup logging_api
 */
int log_disp_curses(time_t stamp, const char *file, int line, const char *function,
                    enum LogLevel level, const char *format, ...)
{
  const short c_debug_level = cs_subset_number(NeoMutt->sub, "debug_level");
  if (level > c_debug_level)
    return 0;

  char buf[LOG_LINE_MAX_LEN] = { 0 };

  va_list ap;
  va_start(ap, format);
  int rc = vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);

  if ((level == LL_PERROR) && (rc >= 0) && (rc < sizeof(buf)))
  {
    char *buf2 = buf + rc;
    int len = sizeof(buf) - rc;
    const char *p = strerror(errno);
    if (!p)
      p = _("unknown error");

    rc += snprintf(buf2, len, ": %s (errno = %d)", p, errno);
  }

  const bool dupe = (mutt_str_equal(buf, ErrorBuf));
  if (!dupe)
  {
    /* Only log unique messages */
    log_disp_file(stamp, file, line, function, level, "%s", buf);
    if (stamp == 0)
      log_disp_queue(stamp, file, line, function, level, "%s", buf);
  }

  /* Don't display debugging message on screen */
  if (level > LL_MESSAGE)
    return 0;

  /* Only pause if this is a message following an error */
  if ((level > LL_ERROR) && OptMsgErr && !dupe)
    error_pause();

  mutt_str_copy(ErrorBuf, buf, sizeof(ErrorBuf));
  ErrorBufMessage = true;

  if (!OptKeepQuiet)
  {
    enum ColorId cid = MT_COLOR_NORMAL;
    switch (level)
    {
      case LL_ERROR:
        mutt_beep(false);
        cid = MT_COLOR_ERROR;
        break;
      case LL_WARNING:
        cid = MT_COLOR_WARNING;
        break;
      default:
        cid = MT_COLOR_MESSAGE;
        break;
    }

    msgwin_set_text(NULL, ErrorBuf, cid);
  }

  if ((level <= LL_ERROR) && !dupe)
  {
    OptMsgErr = true;
    LastError = mutt_date_now_ms();
  }
  else
  {
    OptMsgErr = false;
    LastError = 0;
  }

  window_redraw(msgwin_get_window());
  return rc;
}

/**
 * mutt_log_prep - Prepare to log
 */
void mutt_log_prep(void)
{
  char ver[64] = { 0 };
  snprintf(ver, sizeof(ver), "-%s%s", PACKAGE_VERSION, GitVer);
  log_file_set_version(ver);
}

/**
 * mutt_log_stop - Close the log file
 */
void mutt_log_stop(void)
{
  log_file_close(false);
  FREE(&CurrentFile);
}

/**
 * mutt_log_set_file - Change the logging file
 * @param file Name to use
 * @retval  0 Success, file opened
 * @retval -1 Error, see errno
 *
 * Close the old log, rotate the new logs and open the new log.
 */
int mutt_log_set_file(const char *file)
{
  const char *const c_debug_file = cs_subset_path(NeoMutt->sub, "debug_file");
  if (!mutt_str_equal(CurrentFile, c_debug_file))
  {
    struct Buffer *expanded = buf_pool_get();
    buf_addstr(expanded, c_debug_file);
    buf_expand_path(expanded);

    const char *name = mutt_file_rotate(buf_string(expanded), NumOfLogs);
    buf_pool_release(&expanded);
    if (!name)
      return -1;

    log_file_set_filename(name, false);
    FREE(&name);
    mutt_str_replace(&CurrentFile, c_debug_file);
  }

  cs_subset_str_string_set(NeoMutt->sub, "debug_file", file, NULL);

  return 0;
}

/**
 * mutt_log_set_level - Change the logging level
 * @param level Logging level
 * @param verbose If true, then log the event
 * @retval  0 Success
 * @retval -1 Error, level is out of range
 */
int mutt_log_set_level(enum LogLevel level, bool verbose)
{
  if (!CurrentFile)
  {
    const char *const c_debug_file = cs_subset_path(NeoMutt->sub, "debug_file");
    mutt_log_set_file(c_debug_file);
  }

  if (log_file_set_level(level, verbose) != 0)
    return -1;

  cs_subset_str_native_set(NeoMutt->sub, "debug_level", level, NULL);
  return 0;
}

/**
 * mutt_log_start - Enable file logging
 * @retval  0 Success, or already running
 * @retval -1 Failed to start
 *
 * This also handles file rotation.
 */
int mutt_log_start(void)
{
  const short c_debug_level = cs_subset_number(NeoMutt->sub, "debug_level");
  if (c_debug_level < 1)
    return 0;

  if (log_file_running())
    return 0;

  const char *const c_debug_file = cs_subset_path(NeoMutt->sub, "debug_file");
  mutt_log_set_file(c_debug_file);

  /* This will trigger the file creation */
  if (log_file_set_level(c_debug_level, true) < 0)
    return -1;

  return 0;
}

/**
 * level_validator - Validate the "debug_level" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
int level_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
  if ((value < 0) || (value >= LL_MAX))
  {
    buf_printf(err, _("Invalid value for option %s: %ld"), cdef->name, (long) value);
    return CSR_ERR_INVALID;
  }

  return CSR_SUCCESS;
}

/**
 * main_log_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
int main_log_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (mutt_str_equal(ev_c->name, "debug_file"))
  {
    const char *const c_debug_file = cs_subset_path(NeoMutt->sub, "debug_file");
    mutt_log_set_file(c_debug_file);
  }
  else if (mutt_str_equal(ev_c->name, "debug_level"))
  {
    const short c_debug_level = cs_subset_number(NeoMutt->sub, "debug_level");
    mutt_log_set_level(c_debug_level, true);
  }
  else
  {
    return 0;
  }

  mutt_debug(LL_DEBUG5, "log done\n");
  return 0;
}
