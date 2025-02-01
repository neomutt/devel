/**
 * @file
 * Colour Debugging
 *
 * @authors
 * Copyright (C) 2021-2023 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_COLOR_DEBUG_H
#define MUTT_COLOR_DEBUG_H

#include "config.h"
#include "mutt/lib.h"
#include "curses2.h"

struct PagedFile;

#ifdef USE_DEBUG_COLOR

const char *color_log_color(color_t fg, color_t bg);

void curses_color_dump(struct CursesColor *cc, const char *prefix);

void ansi_colors_dump  (struct PagedFile *pf);
void curses_colors_dump(struct PagedFile *pf);
void merged_colors_dump(struct PagedFile *pf);
void log_paged_file(enum LogLevel level, struct PagedFile *pf);

#define color_debug(LEVEL, ...) MuttLogger(0, __FILE__, __LINE__, __func__, LEVEL, __VA_ARGS__) ///< @ingroup logging_api

#else

static inline const char *color_log_color(color_t fg, color_t bg) { return ""; }

static inline void curses_color_dump(struct CursesColor *cc, const char *prefix) {}

static inline void ansi_colors_dump  (struct PagedFile *pf) {}
static inline void curses_colors_dump(struct PagedFile *pf) {}
static inline void merged_colors_dump(struct PagedFile *pf) {}
static inline void log_paged_file(enum LogLevel level, struct PagedFile *pf) {}

static inline int color_debug(enum LogLevel level, const char *format, ...) { return 0; }

#endif

#endif /* MUTT_COLOR_DEBUG_H */
