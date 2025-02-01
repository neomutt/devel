/**
 * @file
 * Backing File for the Simple Pager
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

#ifndef MUTT_PFILE_PAGED_FILE_H
#define MUTT_PFILE_PAGED_FILE_H

#include <stdbool.h>
#include <stdio.h>
#include "paged_line.h"

/**
 * struct PagedFile - A File for the Simple Pager
 */
struct PagedFile
{
  FILE *fp;                             ///< File to be displayed
  bool close_fp;                        ///< Close the file on exit
  struct PagedLineArray lines;          ///< Markup
  const struct AttrColor *ac_file;      ///< Default colour for the entire Window
  const struct AttrColor *ac_markers;   ///< Colour for the wrapping markers
};

void              paged_file_free(struct PagedFile **pptr);
struct PagedFile *paged_file_new (FILE *fp);

struct PagedLine *paged_file_new_line(struct PagedFile *pf);

#endif /* MUTT_PFILE_PAGED_FILE_H */
