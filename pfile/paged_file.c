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

/**
 * @page pfile_paged_file Backing File for the Simple Pager
 *
 * Backing File for the Simple Pager
 */

#include "config.h"
#include "mutt/lib.h"
#include "core/lib.h"
#include "paged_file.h"
#include "paged_line.h"

/**
 * paged_file_free - Free a PagedFile
 * @param pptr PagedFile to free
 */
void paged_file_free(struct PagedFile **pptr)
{
  if (!pptr || !*pptr)
    return;

  struct PagedFile *pf = *pptr;

  if (pf->close_fp)
    mutt_file_fclose(&pf->fp);

  struct PagedLine *pl = NULL;
  ARRAY_FOREACH(pl, &pf->lines)
  {
    paged_line_clear(pl);
  }
  ARRAY_FREE(&pf->lines);

  FREE(pptr);
}

/**
 * paged_file_new - Create a new PagedFile
 * @param fp File to use (OPTIONAL)
 * @retval ptr New PagedFile
 * 
 * @note If fp is supplied, the caller must close it
 */
struct PagedFile *paged_file_new(FILE *fp)
{
  bool close_fp = false;

  if (fp)
    close_fp = true;
  else
    fp = mutt_file_mkstemp();

  if (!fp)
  {
    mutt_perror(_("Can't create temporary file"));
    return NULL;
  }

  struct PagedFile *pf = MUTT_MEM_CALLOC(1, struct PagedFile);

  pf->fp = fp;
  pf->close_fp = close_fp;
  ARRAY_INIT(&pf->lines);

  return pf;
}

/**
 * paged_file_new_line - Create a new PagedLine in the PagedFile
 * @param pf PagedFile
 * @retval ptr New PagedLine
 *
 * @note Do not free the PagedLine, it's owned by the PagedFile
 */
struct PagedLine *paged_file_new_line(struct PagedFile *pf)
{
  if (!pf || !pf->fp)
    return NULL;

  struct PagedLine pl = { 0 };
  pl.paged_file = pf;
  pl.offset = ftell(pf->fp);

  ARRAY_ADD(&pf->lines, pl);

  return ARRAY_LAST(&pf->lines);
}
