/**
 * @file
 * Set up the key bindings
 *
 * @authors
 * Copyright (C) 2023 Richard Russon <rich@flatcap.org>
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
 * @page key_init Set up the key bindings
 *
 * Set up the key bindings
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "ncrypt/lib.h"

extern const struct MenuOpSeq AliasDefaultBindings[];
extern const struct MenuOpSeq AttachmentDefaultBindings[];
#ifdef USE_AUTOCRYPT
extern const struct MenuOpSeq AutocryptDefaultBindings[];
#endif
extern const struct MenuOpSeq BrowserDefaultBindings[];
extern const struct MenuOpSeq ComposeDefaultBindings[];
extern const struct MenuOpSeq EditorDefaultBindings[];
extern const struct MenuOpSeq IndexDefaultBindings[];
extern const struct MenuOpSeq PagerDefaultBindings[];
extern const struct MenuOpSeq PgpDefaultBindings[];
extern const struct MenuOpSeq PostponedDefaultBindings[];
extern const struct MenuOpSeq QueryDefaultBindings[];
extern const struct MenuOpSeq SidebarDefaultBindings[];
extern const struct MenuOpSeq SmimeDefaultBindings[];

/**
 * struct Extkey - Map key names from NeoMutt's style to Curses style
 */
struct Extkey
{
  const char *name; ///< NeoMutt key name
  const char *sym;  ///< Curses key name
};

/**
 * ExtKeys - Mapping between NeoMutt and Curses key names
 */
static const struct Extkey ExtKeys[] = {
  { "<c-up>", "kUP5" },
  { "<s-up>", "kUP" },
  { "<a-up>", "kUP3" },

  { "<s-down>", "kDN" },
  { "<a-down>", "kDN3" },
  { "<c-down>", "kDN5" },

  { "<c-right>", "kRIT5" },
  { "<s-right>", "kRIT" },
  { "<a-right>", "kRIT3" },

  { "<s-left>", "kLFT" },
  { "<a-left>", "kLFT3" },
  { "<c-left>", "kLFT5" },

  { "<s-home>", "kHOM" },
  { "<a-home>", "kHOM3" },
  { "<c-home>", "kHOM5" },

  { "<s-end>", "kEND" },
  { "<a-end>", "kEND3" },
  { "<c-end>", "kEND5" },

  { "<s-next>", "kNXT" },
  { "<a-next>", "kNXT3" },
  { "<c-next>", "kNXT5" },

  { "<s-prev>", "kPRV" },
  { "<a-prev>", "kPRV3" },
  { "<c-prev>", "kPRV5" },

  { 0, 0 },
};

/**
 * find_ext_name - Find the curses name for a key
 * @param key Key name
 * @retval ptr Curses name
 *
 * Look up NeoMutt's name for a key and find the ncurses extended name for it.
 *
 * @note This returns a static string.
 */
static const char *find_ext_name(const char *key)
{
  for (int j = 0; ExtKeys[j].name; j++)
  {
    if (strcasecmp(key, ExtKeys[j].name) == 0)
      return ExtKeys[j].sym;
  }
  return 0;
}

/**
 * init_extended_keys - Initialise map of ncurses extended keys
 *
 * Determine the keycodes for ncurses extended keys and fill in the KeyNames array.
 *
 * This function must be called *after* initscr(), or mutt_tigetstr() fails.
 * This creates a bit of a chicken-and-egg problem because km_init() is called
 * prior to start_curses().  This means that the default keybindings can't
 * include any of the extended keys because they won't be defined until later.
 */
void init_extended_keys(void)
{
#ifdef HAVE_USE_EXTENDED_NAMES
  use_extended_names(true);

  for (int j = 0; KeyNames[j].name; j++)
  {
    if (KeyNames[j].value == -1)
    {
      const char *keyname = find_ext_name(KeyNames[j].name);

      if (keyname)
      {
        const char *s = mutt_tigetstr((char *) keyname);
        if (s && ((long) (s) != -1))
        {
          int code = key_defined(s);
          if (code > 0)
            KeyNames[j].value = code;
        }
      }
    }
  }
#endif
}

/**
 * create_bindings - Attach a set of keybindings to a Menu
 * @param map   Key bindings
 * @param mtype Menu type, e.g. #MENU_PAGER
 */
static void create_bindings(const struct MenuOpSeq *map, enum MenuType mtype)
{
  STAILQ_INIT(&Keymaps[mtype]);

  for (int i = 0; map[i].op != OP_NULL; i++)
    if (map[i].seq)
      km_bindkey(map[i].seq, mtype, map[i].op);
}

/**
 * km_init - Initialise all the menu keybindings
 */
void km_init(void)
{
  memset(Keymaps, 0, sizeof(struct KeymapList) * MENU_MAX);

  create_bindings(AliasDefaultBindings, MENU_ALIAS);
  create_bindings(AttachmentDefaultBindings, MENU_ATTACHMENT);
#ifdef USE_AUTOCRYPT
  create_bindings(AutocryptDefaultBindings, MENU_AUTOCRYPT);
#endif
  create_bindings(BrowserDefaultBindings, MENU_FOLDER);
  create_bindings(DialogDefaultBindings, MENU_DIALOG);
  create_bindings(ComposeDefaultBindings, MENU_COMPOSE);
  create_bindings(EditorDefaultBindings, MENU_EDITOR);
  create_bindings(GenericDefaultBindings, MENU_GENERIC);
  create_bindings(IndexDefaultBindings, MENU_INDEX);
  create_bindings(PagerDefaultBindings, MENU_PAGER);
  create_bindings(PostponedDefaultBindings, MENU_POSTPONED);
  create_bindings(QueryDefaultBindings, MENU_QUERY);

  if (WithCrypto & APPLICATION_PGP)
    create_bindings(PgpDefaultBindings, MENU_PGP);
  if (WithCrypto & APPLICATION_SMIME)
    create_bindings(SmimeDefaultBindings, MENU_SMIME);

#ifdef CRYPT_BACKEND_GPGME
  create_bindings(PgpDefaultBindings, MENU_KEY_SELECT_PGP);
  create_bindings(SmimeDefaultBindings, MENU_KEY_SELECT_SMIME);
#endif

  create_bindings(SidebarDefaultBindings, MENU_SIDEBAR);
}

/**
 * mutt_keymaplist_free - Free a List of Keymaps
 * @param km_list List of Keymaps to free
 */
static void mutt_keymaplist_free(struct KeymapList *km_list)
{
  struct Keymap *np = NULL, *tmp = NULL;
  STAILQ_FOREACH_SAFE(np, km_list, entries, tmp)
  {
    STAILQ_REMOVE(km_list, np, Keymap, entries);
    mutt_keymap_free(&np);
  }
}

/**
 * mutt_keys_cleanup - Free the key maps
 */
void mutt_keys_cleanup(void)
{
  for (enum MenuType i = 1; i < MENU_MAX; i++)
  {
    mutt_keymaplist_free(&Keymaps[i]);
  }
}

/**
 * mutt_init_abort_key - Parse the abort_key config string
 *
 * Parse the string into `$abort_key` and put the keycode into AbortKey.
 */
void mutt_init_abort_key(void)
{
  keycode_t buf[2];
  const char *const c_abort_key = cs_subset_string(NeoMutt->sub, "abort_key");
  size_t len = parsekeys(c_abort_key, buf, mutt_array_size(buf));
  if (len == 0)
  {
    mutt_error(_("Abort key is not set, defaulting to Ctrl-G"));
    AbortKey = ctrl('G');
    return;
  }
  if (len > 1)
  {
    mutt_warning(_("Specified abort key sequence (%s) will be truncated to first key"),
                 c_abort_key);
  }
  AbortKey = buf[0];
}

/**
 * main_config_observer - Notification that a Config Variable has changed - Implements ::observer_t - @ingroup observer_api
 */
int main_config_observer(struct NotifyCallback *nc)
{
  if (nc->event_type != NT_CONFIG)
    return 0;
  if (!nc->event_data)
    return -1;

  struct EventConfig *ev_c = nc->event_data;

  if (!mutt_str_equal(ev_c->name, "abort_key"))
    return 0;

  mutt_init_abort_key();
  mutt_debug(LL_DEBUG5, "config done\n");
  return 0;
}
