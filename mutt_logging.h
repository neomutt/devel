/**
 * @file
 * NeoMutt Logging
 *
 * @authors
 * Copyright (C) 2018-2023 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_MUTT_LOGGING_H
#define MUTT_MUTT_LOGGING_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "mutt/lib.h"

struct ConfigDef;
struct ConfigSet;

int log_disp_curses(time_t stamp, const char *file, int line, const char *function, enum LogLevel level, const char *format, ...)
                    __attribute__((__format__(__printf__, 6, 7)));

void mutt_log_prep(void);
int  mutt_log_start(void);
void mutt_log_stop(void);
int  mutt_log_set_level(enum LogLevel level, bool verbose);
int  mutt_log_set_file(const char *file);

int  main_log_observer(struct NotifyCallback *nc);
int  level_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err);

void mutt_clear_error(void);

#endif /* MUTT_MUTT_LOGGING_H */
