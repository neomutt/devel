/**
 * @file
 * Private state data for the Index
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

#ifndef MUTT_INDEX_PRIVATE_DATA_H
#define MUTT_INDEX_PRIVATE_DATA_H

#include <stdbool.h>

struct IndexSharedData;
struct MuttWindow;

/**
 * struct IndexPrivateData - Private state data for the Index
 */
struct IndexPrivateData
{
  bool tag_prefix;               ///< tag-prefix has been pressed
  int  oldcount;                 ///< Old count of mails in the mailbox

  struct IndexSharedData *shared; ///< Shared Index data
  struct Menu *menu;              ///< Menu controlling the index
  struct MuttWindow *win_index;   ///< Window for the Index
};

void                     index_private_data_free(struct MuttWindow *win, void **ptr);
struct IndexPrivateData *index_private_data_new (struct IndexSharedData *shared);

#endif /* MUTT_INDEX_PRIVATE_DATA_H */
