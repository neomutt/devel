/**
 * @file
 * Search a Paged File
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

#ifndef MUTT_SPAGER_SEARCH_H
#define MUTT_SPAGER_SEARCH_H

#include <stdbool.h>
#include "mutt/lib.h"

struct PagedLineArray;

/**
 * enum SearchDirection - Direction to Search text
 */
enum SearchDirection
{
  SD_SEARCH_FORWARDS,       ///< Search forwards
  SD_SEARCH_BACKWARDS,      ///< Search backwards
};

/**
 * enum SearchResult - Result of a Search
 */
enum SearchResult
{
  SR_SEARCH_ERROR,
  SR_SEARCH_NO_MATCHES,
  SR_SEARCH_MATCHES,
  SR_SEARCH_TOO_MANY_MATCHES,
};

/**
 * struct SimplePagerSearch - State of a Search
 */
struct SimplePagerSearch
{
  struct PagedLineArray *pla;      ///< Array of Lines to search

  const char *pattern;             ///< Search pattern
  regex_t regex;                   ///< Compiled search string
  bool compiled    : 1;            ///< Search regex is in use
  bool show_search : 1;            ///< Is search visible? (`<search-toggle>`)

  enum SearchDirection direction;  ///< Which direction to search
};

void                      spager_search_clear(struct SimplePagerSearch *sps);
void                      spager_search_free (struct SimplePagerSearch **ptr);
struct SimplePagerSearch *spager_search_new  (void);

void              spager_search_set_lines(struct SimplePagerSearch *sps, struct PagedLineArray *pla);
enum SearchResult spager_search_search   (struct SimplePagerSearch *sps, const char *pattern, int start_index, enum SearchDirection direction, struct Buffer *err);
enum SearchResult spager_search_next     (struct SimplePagerSearch *sps, int start_row, enum SearchDirection direction, int *next_index, int *next_seg);

#endif /* MUTT_SPAGER_SEARCH_H */
