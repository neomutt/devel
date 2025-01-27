/**
 * @file
 * GUI display a user-configurable status line
 *
 * @authors
 * Copyright (C) 2018-2024 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_INDEX_EXPANDO_STATUS_H
#define MUTT_INDEX_EXPANDO_STATUS_H

#include "expando/lib.h"

/**
 * struct MenuStatusLineData - Data for creating a Menu line
 */
struct MenuStatusLineData
{
  struct IndexSharedData *shared; ///< Data shared between Index, Pager and Sidebar
  struct Menu *menu;              ///< Current Menu
};

extern const struct ExpandoRenderCallback StatusRenderCallbacks[];

/**
 * enum StatusChars - Index into the `$status_chars` config variable
 */
enum StatusChars
{
  STATUS_CHAR_UNCHANGED,          ///< Mailbox is unchanged
  STATUS_CHAR_NEED_RESYNC,        ///< Mailbox has been changed and needs to be resynchronized
  STATUS_CHAR_READ_ONLY,          ///< Mailbox is read-only
  STATUS_CHAR_ATTACH,             ///< Mailbox opened in attach-message mode
  STATUS_CHAR_MAX,
};

#endif /* MUTT_INDEX_EXPANDO_STATUS_H */
