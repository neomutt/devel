/**
 * @file
 * A Line of marked up text for the Simple Pager
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
 * @page pfile_paged_line Line of marked up text for the Simple Pager
 *
 * A Line of marked up text for the Simple Pager
 */

#include "config.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "paged_line.h"
#include "color/lib.h"
#include "paged_file.h"
#include "paged_text.h"

/**
 * paged_line_clear - Clear a PagedLine
 * @param pl PagedLine to clear
 *
 * Free the contents of a PagedLine, but not the object itself.
 * We don't own attr_color, so don't free it.
 */
void paged_line_clear(struct PagedLine *pl)
{
  if (!pl)
    return;

  paged_text_markup_clear(&pl->text);
  paged_text_markup_clear(&pl->search);

  FREE(&pl->cached_text);
  ARRAY_FREE(&pl->segments);
}

/**
 * paged_line_add_newline - Add a newline to a PagedLine
 * @param pl PagedLine to add to
 * @retval num Number of screen columns used
 */
int paged_line_add_newline(struct PagedLine *pl)
{
  if (!pl || !pl->paged_file)
    return 0;

  // The GUI doesn't care about newlines,
  // so add it to the file, but don't adjust the counters.
  fputs("\n", pl->paged_file->fp);

  return 0;
}

/**
 * paged_line_add_text - Add some plain text to a PagedLine
 * @param pl   PagedLine to add to
 * @param text Text to add
 * @retval num Number of screen columns used
 */
int paged_line_add_text(struct PagedLine *pl, const char *text)
{
  if (!pl || !pl->paged_file || !text)
    return 0;

  int bytes = mutt_str_len(text);
  int cols = mutt_strwidth(text);

  fputs(text, pl->paged_file->fp);

  pl->num_bytes += bytes;
  pl->num_cols += cols;

  return cols;
}

/**
 * paged_line_add_colored_text - Add some coloured text to a PagedLine
 * @param pl   PagedLine to add to
 * @param cid  Colour ID
 * @param text Text to add
 * @retval num Number of screen columns used
 */
int paged_line_add_colored_text(struct PagedLine *pl, int cid, const char *text)
{
  if (!pl || !pl->paged_file || !text)
    return 0;

  struct PagedTextMarkup *ptm = paged_text_markup_new(&pl->text);

  int bytes = mutt_str_len(text);
  int cols = mutt_strwidth(text);

  fputs(text, pl->paged_file->fp);

  ptm->first = pl->num_bytes;
  ptm->last = ptm->first + bytes;
  ptm->cid = cid;

  pl->num_bytes += bytes;
  pl->num_cols += cols;

  return cols;
}

/**
 * paged_line_add_search - Add a search match to a PagedLine
 * @param pl   PagedLine to add to
 * @param first First matching character
 * @param last  Last matching character (not included)
 */
void paged_line_add_search(struct PagedLine *pl, int first, int last)
{
  if (!pl || !pl->paged_file)
    return;

  struct PagedTextMarkup *ptm = paged_text_markup_new(&pl->search);

  ptm->first = first;
  ptm->last = last;
  ptm->cid = MT_COLOR_SEARCH;
}

/**
 * paged_line_add_ansi_text - Add some text with ANSI sequences to a PagedLine
 * @param pl         PagedLine to add to
 * @param ansi_start Start ANSI escape sequence
 * @param ansi_end   End   ANSI escape sequence
 * @param text       Text to add
 * @retval num Number of screen columns used
 */
int paged_line_add_ansi_text(struct PagedLine *pl, const char *ansi_start,
                             const char *ansi_end, const char *text)
{
  if (!pl || !pl->paged_file || !ansi_start || !text)
    return 0;

  struct PagedTextMarkup *ptm = paged_text_markup_new(&pl->text);

  int bytes = mutt_str_len(text);
  int cols = mutt_strwidth(text);

  fputs(text, pl->paged_file->fp);

  ptm->first = pl->num_bytes;
  ptm->last = ptm->first + bytes;

  ptm->ansi_start = mutt_str_dup(ansi_start);
  ptm->ansi_end = mutt_str_dup(ansi_end);

  pl->num_bytes += bytes;
  pl->num_cols += cols;

  return cols;
}

/**
 * paged_line_cache - Read and cache a Line of the File
 * @param pl PagedLine
 */
void paged_line_cache(struct PagedLine *pl)
{
  if (!pl || pl->cached_text)
    return;

  FILE *fp = pl->paged_file->fp;
  char *text = NULL;
  size_t size = 0;

  fseek(fp, pl->offset, SEEK_SET);
  pl->cached_text = mutt_file_read_line(text, &size, fp, NULL, MUTT_RL_NO_FLAGS);

  pl->num_bytes = mutt_str_len(pl->cached_text);
  pl->num_cols = mutt_strwidth(pl->cached_text);
}

/**
 * paged_line_wrap - Wrap the text of a Line
 * @param pl    PagedLine
 * @param width Width in screen columns
 * @param flags Control the wrapping
 */
void paged_line_wrap(struct PagedLine *pl, int width, LineWrapFlags flags)
{
  if (!pl)
    return;

  ARRAY_FREE(&pl->segments);
  if (pl->num_cols <= width)
    return;

  mutt_debug(LL_DEBUG1, "WRAP: %d into %d\n", pl->num_cols, width);

  paged_line_cache(pl);

  int total_bytes = 0;
  int total_cols = 0;

  size_t bytes = 0;
  size_t text_len = pl->num_bytes;
  size_t cols = 0;

  mutt_debug(LL_DEBUG1, "Wrapping: %s\n", pl->cached_text);
  mutt_debug(LL_DEBUG1, "%d bytes, %d cols\n", pl->num_bytes, pl->num_cols);

  while (total_bytes < text_len)
  {
    struct Segment seg = { total_bytes, total_cols };
    ARRAY_ADD(&pl->segments, seg);

    bytes = mutt_wstr_trunc(pl->cached_text + total_bytes,
                            text_len - total_bytes, width, &cols);

    if ((total_bytes == 0) && (flags & LW_MARKERS))
      width--;

    total_bytes += bytes;
    total_cols += cols;
  }

  struct Segment *seg = NULL;
  struct PagedFile *pf = pl->paged_file;
  struct PagedLineArray *pla = &pf->lines;
  ARRAY_FOREACH(seg, &pl->segments)
  {
    size_t pl_index = ARRAY_IDX(pla, pl);
    mutt_debug(LL_DEBUG1, "Line %ld -- Segment %d: %d bytes, %d cols\n", pl_index,
               ARRAY_FOREACH_IDX_seg, seg->offset_bytes, seg->offset_cols);
  }
}

/**
 * paged_line_get_text - Get the text for a Line
 * @param pl PagedLine
 */
const char *paged_line_get_text(struct PagedLine *pl)
{
  if (!pl)
    return NULL;

  paged_line_cache(pl);

  if (pl->cached_text)
    return pl->cached_text;

  return NULL;
}

/**
 * paged_line_get_virtual_text - Get the text for a Line
 * @param pl  PagedLine
 * @param seg Segment
 */
const char *paged_line_get_virtual_text(struct PagedLine *pl, struct Segment *seg)
{
  if (!pl)
    return NULL;

  paged_line_cache(pl);

  if (!pl->cached_text)
    return NULL;

  if (seg)
    return pl->cached_text + seg->offset_bytes;

  return pl->cached_text;
}

/**
 * paged_lines_count_virtual_rows - Count the number of Lines including wrapping
 * @param[in] pla Array of Lines
 */
int paged_lines_count_virtual_rows(struct PagedLineArray *pla)
{
  if (!pla)
    return 0;

  int count = 0;

  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, pla)
  {
    size_t num_segs = ARRAY_SIZE(&pl->segments);
    if (num_segs == 0)
      count++;
    else
      count += num_segs;
  }

  return count;
}

/**
 * paged_lines_find_virtual_row - Find one of an array of wrapped Lines
 * @param[in]  pla       Array of Lines
 * @param[in]  virt_row  Row number
 * @param[out] pl_index  Index of the Line
 * @param[out] seg_index Index of the Segment
 */
bool paged_lines_find_virtual_row(struct PagedLineArray *pla, int virt_row,
                                  int *pl_index, int *seg_index)
{
  if (!pla || !pl_index || !seg_index)
    return false;

  if (virt_row < 0)
  {
    // Give the user the first possible row
    *pl_index = 0;
    *seg_index = 0;
    return false;
  }

  int v = 0;
  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, pla)
  {
    size_t num_segs = ARRAY_SIZE(&pl->segments);
    if (num_segs == 0)
      num_segs++;

    if (virt_row < (v + num_segs))
    {
      *pl_index = ARRAY_FOREACH_IDX_pl;
      *seg_index = virt_row - v;
      return true;
    }

    v += num_segs;
  }

  // Give the user the last possible virtual row
  if (ARRAY_SIZE(pla) > 0)
    *pl_index = (ARRAY_SIZE(pla) > 0) ? ARRAY_SIZE(pla) - 1 : -1;
  else
    *pl_index = -1;

  if (pl && (ARRAY_SIZE(&pl->segments) > 0))
    *seg_index = ARRAY_SIZE(&pl->segments) - 1;
  else
    *seg_index = -1;

  return false;
}

/**
 * paged_lines_wrap - Wrap the text of an array of Lines
 * @param pla   Array of Lines
 * @param width Width in screen columns
 * @param flags Control the wrapping
 */
void paged_lines_wrap(struct PagedLineArray *pla, int width, LineWrapFlags flags)
{
  if (!pla)
    return;

  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, pla)
  {
    paged_line_wrap(pl, width, flags);
  }
}
