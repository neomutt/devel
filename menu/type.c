/**
 * @file
 * Menu types
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

/**
 * @page menu_type Menu types
 *
 * Menu types
 */

#include "config.h"
#include <stddef.h>
#include "mutt/lib.h"
#include "type.h"

/**
 * MenuNames - Menu name lookup table
 */
const struct Mapping MenuNames[] = {
  // clang-format off
  { "alias",            MENU_ALIAS },
  { "attach",           MENU_ATTACHMENT },
#ifdef USE_AUTOCRYPT
  { "autocrypt",        MENU_AUTOCRYPT },
#endif
  { "browser",          MENU_FOLDER },
  { "compose",          MENU_COMPOSE },
  { "dialog",           MENU_DIALOG },
  { "editor",           MENU_EDITOR },
  { "index",            MENU_INDEX },
  { "pager",            MENU_PAGER },
  { "postpone",         MENU_POSTPONED },
  { "pgp",              MENU_PGP },
  { "smime",            MENU_SMIME },
#ifdef CRYPT_BACKEND_GPGME
  { "key_select_pgp",   MENU_KEY_SELECT_PGP },
  { "key_select_smime", MENU_KEY_SELECT_SMIME },
#endif
  { "query",            MENU_QUERY },
  { "generic",          MENU_GENERIC },
  { "sidebar",          MENU_SIDEBAR },
  { NULL, 0 },
  // clang-format on
};

/// Number of entries in the #MenuNames array
const int MenuNamesLen = mutt_array_size(MenuNames) - 1;
