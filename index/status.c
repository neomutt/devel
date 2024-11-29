/**
 * @file
 * GUI display a user-configurable status line
 *
 * @authors
 * Copyright (C) 1996-2000,2007 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2017-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2018 Austin Ray <austin@austinray.io>
 * Copyright (C) 2020-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2021 Eric Blake <eblake@redhat.com>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
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
 * @page index_status GUI display a user-configurable status line
 *
 * GUI display a user-configurable status line
 */

#include "config.h"
#include <stddef.h>
#include "status.h"
#include "expando/lib.h"
#include "expando_status.h"
#include "globals.h"

/**
 * menu_status_line - Create the status line
 * @param[out] buf      Buffer in which to save string
 * @param[in]  shared   Shared Index data
 * @param[in]  menu     Current menu
 * @param[in]  max_cols Maximum number of columns to use (-1 means unlimited)
 * @param[in]  exp      Expando
 *
 * @sa status_format_str()
 */
void menu_status_line(struct Buffer *buf, struct IndexSharedData *shared,
                      struct Menu *menu, int max_cols, const struct Expando *exp)
{
  struct MenuStatusLineData data = { shared, menu };

  struct ExpandoRenderData StatusRenderData[] = {
    // clang-format off
    { ED_GLOBAL, StatusRenderCallbacks1, &data, MUTT_FORMAT_NO_FLAGS },
    { ED_INDEX,  StatusRenderCallbacks2, &data, MUTT_FORMAT_NO_FLAGS },
    { ED_MENU,   StatusRenderCallbacks3, &data, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  expando_filter(exp, StatusRenderData, max_cols, EnvList, buf);
}
