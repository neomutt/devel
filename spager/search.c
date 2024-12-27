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

/**
 * @page spager_search Search a Paged File
 *
 * Search a Paged File
 */

#include "config.h"
#include <stddef.h>
#include "mutt/lib.h"
#include "search.h"
#include "pfile/lib.h"

// static const int SEARCH_TOO_MANY_MATCHES = 10000;

/**
 * spager_search_clear - Reset a Search object
 * @param sps Search Object
 */
void spager_search_clear(struct SimplePagerSearch *sps)
{
  if (!sps)
    return;

  FREE(&sps->pattern);

  if (sps->compiled)
  {
    regfree(&sps->regex);
    sps->compiled = false;
  }

  sps->direction = SD_SEARCH_FORWARDS;
  sps->pla = NULL;
}

/**
 * spager_search_free - Free a Search object
 * @param ptr Search object to free
 */
void spager_search_free(struct SimplePagerSearch **ptr)
{
  if (!ptr || !*ptr)
    return;

  spager_search_clear(*ptr);

  FREE(ptr);
}

/**
 * spager_search_new - Create a new Search object
 * @retval ptr New Search object
 */
struct SimplePagerSearch *spager_search_new(void)
{
  struct SimplePagerSearch *sps = MUTT_MEM_CALLOC(1, struct SimplePagerSearch);

  sps->show_search = true;

  return sps;
}

/**
 * spager_search_set_lines - Associate the Search with the Array of Lines
 * @param sps Search Object
 * @param pla Array of Lines
 */
void spager_search_set_lines(struct SimplePagerSearch *sps, struct PagedLineArray *pla)
{
  if (!sps || (sps->pla == pla))
    return;

  spager_search_clear(sps);
  sps->pla = pla;
}

/**
 * spager_search_search - Perform a search
 * @param sps         Search Object
 * @param pattern     Pattern to search for
 * @param start_index Array index to start searching
 * @param direction   Direction in which to search, e.g. #SD_SEARCH_FORWARDS
 * @param err         Buffer for error messages
 * @retval enum SearchResult, e.g. #SR_SEARCH_MATCHES
 */
enum SearchResult spager_search_search(struct SimplePagerSearch *sps,
                                       const char *pattern, int start_index,
                                       enum SearchDirection direction, struct Buffer *err)
{
  if (!sps || !pattern || !sps->pla)
    return SR_SEARCH_ERROR;

  if (sps->compiled)
  {
    FREE(&sps->pattern);
    regfree(&sps->regex);
  }

  int rflags = REG_NEWLINE;
  if (mutt_mb_is_lower(pattern))
    rflags |= REG_ICASE;

  int rc = REG_COMP(&sps->regex, pattern, rflags);
  if (rc != 0)
  {
    regerror(rc, &sps->regex, err->data, err->dsize);
    return SR_SEARCH_ERROR;
  }

  sps->compiled = true;
  sps->pattern = mutt_str_dup(pattern);

  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, sps->pla)
  {
    ARRAY_SHRINK(&pl->search, ARRAY_SIZE(&pl->search));
  }

  ARRAY_FOREACH(pl, sps->pla)
  {
    const char *text = paged_line_get_text(pl);
    if (!text)
      continue;

    int offset = 0;
    int flags = REG_NOTBOL;
    regmatch_t pmatch = { 0 };

    while (true)
    {
      rc = regexec(&sps->regex, text + offset, 1, &pmatch, flags);
      if (rc != 0)
        break;

      mutt_debug(LL_DEBUG1, "match for %s, line %d, offset %d\n", sps->pattern,
                 ARRAY_FOREACH_IDX_pl, pmatch.rm_so);
      paged_line_add_search(pl, offset + pmatch.rm_so, offset + pmatch.rm_eo);

      if (pmatch.rm_eo == pmatch.rm_so)
        offset++; /* avoid degenerate cases */
      else
        offset += pmatch.rm_eo;
      if (text[offset] == '\0')
        break;
    }
  }

  return SR_SEARCH_ERROR;
}

/**
 * spager_search_next - Find the next match
 * @param[in]  sps       Search Object
 * @param[in]  start_row Row to start searching
 * @param[in]  direction Direction in which to search, e.g. #SD_SEARCH_FORWARDS
 * @param[out] next_index Line Index of next match
 * @param[out] next_seg   Segment of next match
 * @retval enum Result, e.g. #SR_SEARCH_MATCHES
 */
enum SearchResult spager_search_next(struct SimplePagerSearch *sps, int start_row,
                                     enum SearchDirection direction,
                                     int *next_index, int *next_seg)
{
  if (!sps || !sps->pattern || !sps->pla)
    return SR_SEARCH_ERROR;

  if (direction == SD_SEARCH_FORWARDS)
  {
    struct PagedLine *pl = NULL;
    ARRAY_FOREACH_FROM(pl, sps->pla, start_row + 1)
    {
      if (ARRAY_SIZE(&pl->search) == 0)
        continue;

      *next_index = ARRAY_FOREACH_IDX_pl;
      return SR_SEARCH_MATCHES;
    }

    ARRAY_FOREACH_TO(pl, sps->pla, start_row - 1)
    {
      if (ARRAY_SIZE(&pl->search) == 0)
        continue;

      *next_index = ARRAY_FOREACH_IDX_pl;
      return SR_SEARCH_MATCHES;
    }
  }
  else
  {
    struct PagedLine *pl = NULL;
    int count = ARRAY_SIZE(sps->pla);

    for (int i = start_row - 1; i >= 0; i--)
    {
      pl = ARRAY_GET(sps->pla, i);
      if (ARRAY_SIZE(&pl->search) == 0)
        continue;

      *next_index = i;
      return SR_SEARCH_MATCHES;
    }

    for (int i = count - 1; i > start_row; i--)
    {
      pl = ARRAY_GET(sps->pla, i);
      if (ARRAY_SIZE(&pl->search) == 0)
        continue;

      *next_index = i;
      return SR_SEARCH_MATCHES;
    }
  }

  return SR_SEARCH_ERROR;
}
