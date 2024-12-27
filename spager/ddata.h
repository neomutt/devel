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

#ifndef MUTT_SPAGER_DDATA_H
#define MUTT_SPAGER_DDATA_H

#include "config.h"

struct MuttWindow;

/**
 * struct SimplePagerDialogData - Dialog state data for the Simple Pager
 */
struct SimplePagerDialogData
{
  struct MuttWindow *win_pager;             ///< Simple Pager Window
  struct MuttWindow *win_sbar;              ///< Status Bar
  const char *banner;                       ///< Banner for the Status Bar
  int percentage;                           ///< How far through the file
};

void                          spager_ddata_free(struct MuttWindow *win, void **ptr);
struct SimplePagerDialogData *spager_ddata_new (void);

#endif /* MUTT_SPAGER_DDATA_H */
