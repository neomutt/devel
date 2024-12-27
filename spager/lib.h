/**
 * @file
 * Simple Text Pager
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
 * @page lib_spager Simple Text Pager
 *
 * Display some simple text with paging.
 *
 * | File                  | Description                  |
 * | :-------------------- | :--------------------------- |
 * | spager/ddata.c        | @subpage spager_ddata        |
 * | spager/dlg_observer.c | @subpage spager_dlg_observer |
 * | spager/dlg_spager.c   | @subpage spager_dlg_spager   |
 * | spager/functions.c    | @subpage spager_functions    |
 * | spager/search.c       | @subpage spager_search       |
 * | spager/spbar.c        | @subpage spager_spbar        |
 * | spager/wdata.c        | @subpage spager_wdata        |
 * | spager/win_observer.c | @subpage spager_win_observer |
 * | spager/win_spager.c   | @subpage spager_win_spager   |
 */

#ifndef MUTT_SPAGER_LIB_H
#define MUTT_SPAGER_LIB_H

// IWYU pragma: begin_keep
#include "ddata.h"
#include "dlg_observer.h"
#include "dlg_spager.h"
#include "functions.h"
#include "search.h"
#include "spbar.h"
#include "wdata.h"
#include "win_observer.h"
#include "win_spager.h"
// IWYU pragma: end_keep

#endif /* MUTT_SPAGER_LIB_H */
