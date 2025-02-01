/**
 * @file
 * Markup for text for the Simple Pager
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

#ifndef MUTT_PFILE_PAGED_TEXT_H
#define MUTT_PFILE_PAGED_TEXT_H

#include <stdbool.h>
#include "mutt/lib.h"

/**
 * struct PagedTextMarkup - Highlighting for a piece of text
 *
 * PagedTextMarkup defines the markup of a line of text in a PagedLine.
 * This can be colours and/or attributes.
 *
 * The markup is defined by either a Colour ID, e.g. #MT_COLOR_SIGNATURE,
 * or a pair of ANSI escape sequences -- one to set and one to clear.
 */
struct PagedTextMarkup
{
  int first;                            ///< First byte in line to be coloured
  int last;                             ///< Last byte in line to be coloured

  int cid;                              ///< Colour ID, e.g. #MT_COLOR_SIGNATURE
  const struct AttrColor *ac_text;      ///< Curses colour of text
  const struct AttrColor *ac_merged;    ///< Curses colour of text

  const char *ansi_start;               ///< ANSI escape sequence to set   the colour/attributes/etc
  const char *ansi_end;                 ///< ANSI escape sequence to reset the colour/attributes/etc
};
ARRAY_HEAD(PagedTextMarkupArray, struct PagedTextMarkup);

void paged_text_markup_clear(struct PagedTextMarkupArray *ptma);

struct PagedTextMarkup *paged_text_markup_new(struct PagedTextMarkupArray *ptma);

/**
 * pos_in_text_markup - Is a position within a Markup?
 * @param pos Position
 * @param ptm Markup to check
 * @retval true Position is in the Markup
 */
static inline bool pos_in_text_markup(int pos, struct PagedTextMarkup *ptm)
{
  return (ptm && (pos >= ptm->first) && pos < ptm->last);
}

/**
 * pos_after_text_markup - Is a position after a Markup?
 * @param pos Position
 * @param ptm Markup to check
 * @retval true Position is after the Markup
 */
static inline bool pos_after_text_markup(int pos, struct PagedTextMarkup *ptm)
{
  return (ptm && (pos >= ptm->last));
}

#endif /* MUTT_PFILE_PAGED_TEXT_H */
