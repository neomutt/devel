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

#include <stdbool.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "paged_text.h"

#ifndef MUTT_PFILE_PAGED_LINE_H
#define MUTT_PFILE_PAGED_LINE_H

/**
 * typedef LineWrapFlags - Flags controlling the wrapping of text
 */
typedef uint8_t LineWrapFlags;        ///< Flags, e.g. #LW_NO_FLAGS
#define LW_NO_FLAGS               0   ///< No flags are set
#define LW_MARKERS         (1 <<  0)  ///< Display markers '+' at the beginning of wrapped lines
#define LW_WRAP            (1 <<  1)  ///< Should text be wrapped?
#define LW_SMART_WRAP      (1 <<  2)  ///< Should text be smart-wrapped? (wrapped at word boundaries)

/**
 * struct Segment - Part of a line of text
 */
struct Segment
{
  int offset_bytes;                     ///< Number of bytes into the line
  int offset_cols;                      ///< Number of screen columns into the line
};
ARRAY_HEAD(SegmentArray, struct Segment);

/**
 * struct PagedLine - A Line of text with markup
 *
 * One line of text with markup.
 */
struct PagedLine
{
  struct PagedFile *paged_file;         ///< Parent of the PagedLine
  long offset;                          ///< Offset into file (PagedFile.fp)

  int cid;                              ///< Default line colour, e.g. #MT_COLOR_SIGNATURE
  const struct AttrColor *ac_line;      ///< Curses colour of text
  const struct AttrColor *ac_merged;    ///< Default colour for the entire Window

  struct PagedTextMarkupArray text;     ///< Array of text with markup in the line
  struct PagedTextMarkupArray search;   ///< Array of search matches in the line

  char *cached_text;                    ///< Cached copy of the text
  int num_bytes;                        ///< Number of bytes (including newline)
  int num_cols;                         ///< Number of screen columns
  struct SegmentArray segments;         ///< Lengths of wrapped parts of the Line
};
ARRAY_HEAD(PagedLineArray, struct PagedLine);

void paged_line_clear(struct PagedLine *pl);

int paged_line_add_ansi_text   (struct PagedLine *pl, const char *ansi_start, const char *ansi_end, const char *text);
int paged_line_add_colored_text(struct PagedLine *pl, int cid, const char *text);
int paged_line_add_newline     (struct PagedLine *pl);
int paged_line_add_text        (struct PagedLine *pl, const char *text);

void paged_line_add_search     (struct PagedLine *pl, int first, int last);

void        paged_line_cache   (struct PagedLine *pl);
const char *paged_line_get_text(struct PagedLine *pl);
void        paged_line_wrap    (struct PagedLine *pl, int width, LineWrapFlags flags);
const char *paged_line_get_virtual_text(struct PagedLine *pl, struct Segment *seg);

int  paged_lines_count_virtual_rows(struct PagedLineArray *pla);
bool paged_lines_find_virtual_row  (struct PagedLineArray *pla, int virt_row, int *pl_index, int *seg_index);
void paged_lines_wrap              (struct PagedLineArray *pla, int width, LineWrapFlags flags);

#endif /* MUTT_PFILE_PAGED_LINE_H */
