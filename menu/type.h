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

#ifndef MUTT_MENU_TYPE_H
#define MUTT_MENU_TYPE_H

#include "config.h"
#include "mutt/lib.h"

extern const struct Mapping MenuNames[];
extern const int MenuNamesLen;

/**
 * enum MenuType - Types of GUI selections
 */
enum MenuType
{
  MENU_ALIAS = 1,        ///< Select an email address by its alias
  MENU_ATTACHMENT,       ///< Select an attachment
#ifdef USE_AUTOCRYPT
  MENU_AUTOCRYPT,        ///< Autocrypt Account menu
#endif
  MENU_COMPOSE,          ///< Compose an email
  MENU_DIALOG,           ///< Simple Dialog
  MENU_EDITOR,           ///< Text entry area
  MENU_FOLDER,           ///< General file/mailbox browser
  MENU_GENERIC,          ///< Generic selection list
#ifdef CRYPT_BACKEND_GPGME
  MENU_KEY_SELECT_PGP,   ///< Select a PGP key
  MENU_KEY_SELECT_SMIME, ///< Select a SMIME key
#endif
  MENU_INDEX,            ///< Index panel (list of emails)
  MENU_PAGER,            ///< Pager pager (email viewer)
  MENU_PGP,              ///< PGP encryption menu
  MENU_POSTPONED,        ///< Select a postponed email
  MENU_QUERY,            ///< Select from results of external query
  MENU_SMIME,            ///< SMIME encryption menu
  MENU_SIDEBAR,          ///< Sidebar menu (list of mailboxes)
  MENU_MAX,
};

#endif /* MUTT_MENU_TYPE_H */
