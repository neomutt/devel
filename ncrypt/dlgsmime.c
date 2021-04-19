/**
 * @file
 * SMIME key selection dialog
 *
 * @authors
 * Copyright (C) 2020 Richard Russon <rich@flatcap.org>
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
 * @page crypt_dlgsmime SMIME key selection dialog
 *
 * SMIME key selection dialog
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "private.h"
#include "mutt/lib.h"
#include "config/lib.h"
#include "gui/lib.h"
#include "lib.h"
#include "keymap.h"
#include "mutt_logging.h"
#include "mutt_menu.h"
#include "opcodes.h"
#include "smime.h"

/// Help Bar for the Smime key selection dialog
static const struct Mapping SmimeHelp[] = {
  // clang-format off
  { N_("Exit"),   OP_EXIT },
  { N_("Select"), OP_GENERIC_SELECT_ENTRY },
  { N_("Help"),   OP_HELP },
  { NULL, 0 },
  // clang-format on
};

/**
 * smime_key_flags - Turn SMIME key flags into a string
 * @param flags Flags, see #KeyFlags
 * @retval ptr Flag string
 *
 * @note The string is statically allocated
 */
static char *smime_key_flags(KeyFlags flags)
{
  static char buf[3];

  if (!(flags & KEYFLAG_CANENCRYPT))
    buf[0] = '-';
  else
    buf[0] = 'e';

  if (!(flags & KEYFLAG_CANSIGN))
    buf[1] = '-';
  else
    buf[1] = 's';

  buf[2] = '\0';

  return buf;
}

/**
 * smime_make_entry - Format a menu item for the smime key list - Implements Menu::make_entry()
 */
static void smime_make_entry(struct Menu *menu, char *buf, size_t buflen, int line)
{
  struct SmimeKey **table = menu->mdata;
  struct SmimeKey *key = table[line];
  char *truststate = NULL;
  switch (key->trust)
  {
    case 'e':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Expired   ");
      break;
    case 'i':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Invalid   ");
      break;
    case 'r':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Revoked   ");
      break;
    case 't':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Trusted   ");
      break;
    case 'u':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Unverified");
      break;
    case 'v':
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Verified  ");
      break;
    default:
      /* L10N: Describes the trust state of a S/MIME key.
         This translation must be padded with spaces to the right such that it
         has the same length as the other translations.
         The translation strings which need to be padded are:
         Expired, Invalid, Revoked, Trusted, Unverified, Verified, and Unknown.  */
      truststate = _("Unknown   ");
  }
  snprintf(buf, buflen, " 0x%s %s %s %-35.35s %s", key->hash,
           smime_key_flags(key->flags), truststate, key->email, key->label);
}

/**
 * dlg_select_smime_key - Get the user to select a key
 * @param keys  List of keys to select from
 * @param query String to match
 * @retval ptr Key selected by user
 */
struct SmimeKey *dlg_select_smime_key(struct SmimeKey *keys, char *query)
{
  struct SmimeKey **table = NULL;
  int table_size = 0;
  int table_index = 0;
  struct SmimeKey *key = NULL;
  struct SmimeKey *selected_key = NULL;
  char buf[1024];
  const char *s = "";
  bool done = false;

  for (table_index = 0, key = keys; key; key = key->next)
  {
    if (table_index == table_size)
    {
      table_size += 5;
      mutt_mem_realloc(&table, sizeof(struct SmimeKey *) * table_size);
    }

    table[table_index++] = key;
  }

  struct MuttWindow *dlg = dialog_create_simple_index(MENU_SMIME, WT_DLG_SMIME, SmimeHelp);

  struct Menu *menu = dlg->wdata;
  menu->max = table_index;
  menu->make_entry = smime_make_entry;
  menu->mdata = table;
  /* sorting keys might be done later - TODO */

  char title[256];
  struct MuttWindow *sbar = TAILQ_LAST(&dlg->children, MuttWindowList);
  snprintf(title, sizeof(title), _("S/MIME certificates matching \"%s\""), query);
  sbar_set_title(sbar, title);

  mutt_clear_error();

  done = false;
  while (!done)
  {
    switch (mutt_menu_loop(menu))
    {
      case OP_GENERIC_SELECT_ENTRY:
        if (table[menu->current]->trust != 't')
        {
          switch (table[menu->current]->trust)
          {
            case 'e':
            case 'i':
            case 'r':
              s = _("ID is expired/disabled/revoked. Do you really want to use "
                    "the key?");
              break;
            case 'u':
              s = _("ID has undefined validity. Do you really want to use the "
                    "key?");
              break;
            case 'v':
              s = _("ID is not trusted. Do you really want to use the key?");
              break;
          }

          snprintf(buf, sizeof(buf), "%s", s);

          if (mutt_yesorno(buf, MUTT_NO) != MUTT_YES)
          {
            mutt_clear_error();
            break;
          }
        }

        selected_key = table[menu->current];
        done = true;
        break;
      case OP_EXIT:
        done = true;
        break;
    }
  }

  dialog_destroy_simple_index(&dlg);
  FREE(&table);

  return selected_key;
}
