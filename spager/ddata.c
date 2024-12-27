/**
 * @file
 * Dialog state data for the Simple Pager
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
 * @page spager_ddata Dialog state data for the Simple Pager
 *
 * Dialog state data for the Simple Pager
 */

#include "config.h"
#include "mutt/lib.h"
#include "ddata.h"

/**
 * spager_ddata_free - Free Simple Pager Data
 * @param win Dialog
 * @param ptr Pager Data to free
 */
void spager_ddata_free(struct MuttWindow *win, void **ptr)
{
  if (!ptr || !*ptr)
    return;

  // struct SimplePagerDialogData *priv = *ptr;

  FREE(ptr);
}

/**
 * spager_ddata_new - Create new Simple Pager Data
 * @retval ptr New SimplePagerDialogData
 */
struct SimplePagerDialogData *spager_ddata_new(void)
{
  struct SimplePagerDialogData *priv = MUTT_MEM_CALLOC(1, struct SimplePagerDialogData);

  return priv;
}
