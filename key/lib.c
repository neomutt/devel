/**
 * @file
 * Key helper functions
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
 * @page key_lib Key helper functions
 *
 * Key helper functions
 */

#include "config.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "ncrypt/lib.h"

extern const struct MenuFuncOp OpAlias[];
extern const struct MenuFuncOp OpAttachment[];
#ifdef USE_AUTOCRYPT
extern const struct MenuFuncOp OpAutocrypt[];
#endif
extern const struct MenuFuncOp OpBrowser[];
extern const struct MenuFuncOp OpCompose[];
extern const struct MenuFuncOp OpEditor[];
extern const struct MenuFuncOp OpIndex[];
extern const struct MenuFuncOp OpPager[];
extern const struct MenuFuncOp OpPgp[];
extern const struct MenuFuncOp OpPostponed[];
extern const struct MenuFuncOp OpQuery[];
extern const struct MenuFuncOp OpSmime[];

/**
 * KeyNames - Key name lookup table
 */
struct Mapping KeyNames[] = {
  { "<PageUp>", KEY_PPAGE },
  { "<PageDown>", KEY_NPAGE },
  { "<Up>", KEY_UP },
  { "<Down>", KEY_DOWN },
  { "<Right>", KEY_RIGHT },
  { "<Left>", KEY_LEFT },
  { "<Delete>", KEY_DC },
  { "<BackSpace>", KEY_BACKSPACE },
  { "<Insert>", KEY_IC },
  { "<Home>", KEY_HOME },
  { "<End>", KEY_END },
  { "<Enter>", '\n' },
  { "<Return>", '\r' },
#ifdef KEY_ENTER
  { "<KeypadEnter>", KEY_ENTER },
#else
  { "<KeypadEnter>", '\n' },
#endif
  { "<Esc>", '\033' }, // Escape
  { "<Tab>", '\t' },
  { "<Space>", ' ' },
#ifdef KEY_BTAB
  { "<BackTab>", KEY_BTAB },
#endif
#ifdef KEY_NEXT
  { "<Next>", KEY_NEXT },
#endif
  /* extensions supported by ncurses.  values are filled in during initialization */

  /* CTRL+key */
  { "<C-Up>", -1 },
  { "<C-Down>", -1 },
  { "<C-Left>", -1 },
  { "<C-Right>", -1 },
  { "<C-Home>", -1 },
  { "<C-End>", -1 },
  { "<C-Next>", -1 },
  { "<C-Prev>", -1 },

  /* SHIFT+key */
  { "<S-Up>", -1 },
  { "<S-Down>", -1 },
  { "<S-Left>", -1 },
  { "<S-Right>", -1 },
  { "<S-Home>", -1 },
  { "<S-End>", -1 },
  { "<S-Next>", -1 },
  { "<S-Prev>", -1 },

  /* ALT+key */
  { "<A-Up>", -1 },
  { "<A-Down>", -1 },
  { "<A-Left>", -1 },
  { "<A-Right>", -1 },
  { "<A-Home>", -1 },
  { "<A-End>", -1 },
  { "<A-Next>", -1 },
  { "<A-Prev>", -1 },
  { NULL, 0 },
};

keycode_t AbortKey; ///< code of key to abort prompts, normally Ctrl-G

/// Array of key mappings, one for each #MenuType
struct KeymapList Keymaps[MENU_MAX];

/**
 * mutt_keymap_free - Free a Keymap
 * @param ptr Keymap to free
 */
void mutt_keymap_free(struct Keymap **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct Keymap *km = *ptr;
  FREE(&km->macro);
  FREE(&km->desc);
  FREE(&km->keys);

  FREE(ptr);
}

/**
 * alloc_keys - Allocate space for a sequence of keys
 * @param len  Number of keys
 * @param keys Array of keys
 * @retval ptr Sequence of keys
 */
struct Keymap *alloc_keys(size_t len, keycode_t *keys)
{
  struct Keymap *p = MUTT_MEM_CALLOC(1, struct Keymap);
  p->len = len;
  p->keys = MUTT_MEM_CALLOC(len, keycode_t);
  memcpy(p->keys, keys, len * sizeof(keycode_t));
  return p;
}

/**
 * parse_fkey - Parse a function key string
 * @param s String to parse
 * @retval num Number of the key
 *
 * Given "<f8>", it will return 8.
 */
static int parse_fkey(char *s)
{
  char *t = NULL;
  int n = 0;

  if ((s[0] != '<') || (tolower(s[1]) != 'f'))
    return -1;

  for (t = s + 2; *t && isdigit((unsigned char) *t); t++)
  {
    n *= 10;
    n += *t - '0';
  }

  if (*t != '>')
    return -1;
  return n;
}

/**
 * parse_keycode - Parse a numeric keycode
 * @param s String to parse
 * @retval num Number of the key
 *
 * This function parses the string `<NNN>` and uses the octal value as the key
 * to bind.
 */
static int parse_keycode(const char *s)
{
  char *end_char = NULL;
  long int result = strtol(s + 1, &end_char, 8);
  /* allow trailing whitespace, eg.  < 1001 > */
  while (isspace(*end_char))
    end_char++;
  /* negative keycodes don't make sense, also detect overflow */
  if ((*end_char != '>') || (result < 0) || (result == LONG_MAX))
  {
    return -1;
  }

  return result;
}

/**
 * parsekeys - Parse a key string into key codes
 * @param str Key string
 * @param d   Array for key codes
 * @param max Maximum length of key sequence
 * @retval num Length of key sequence
 */
size_t parsekeys(const char *str, keycode_t *d, size_t max)
{
  int n;
  size_t len = max;
  char buf[128] = { 0 };
  char c;
  char *t = NULL;

  mutt_str_copy(buf, str, sizeof(buf));
  char *s = buf;

  while (*s && len)
  {
    *d = '\0';
    if ((*s == '<') && (t = strchr(s, '>')))
    {
      t++;
      c = *t;
      *t = '\0';

      n = mutt_map_get_value(s, KeyNames);
      if (n != -1)
      {
        s = t;
        *d = n;
      }
      else if ((n = parse_fkey(s)) > 0)
      {
        s = t;
        *d = KEY_F(n);
      }
      else if ((n = parse_keycode(s)) > 0)
      {
        s = t;
        *d = n;
      }

      *t = c;
    }

    if (!*d)
    {
      *d = (unsigned char) *s;
      s++;
    }
    d++;
    len--;
  }

  return max - len;
}

/**
 * km_compare_keys - Compare two keymaps' keyscodes and return the bigger one
 * @param k1    first keymap to compare
 * @param k2    second keymap to compare
 * @param pos   position where the two keycodes differ
 * @retval ptr Keymap with a bigger ASCII keycode
 */
struct Keymap *km_compare_keys(struct Keymap *k1, struct Keymap *k2, size_t *pos)
{
  *pos = 0;

  while (*pos < k1->len && *pos < k2->len)
  {
    if (k1->keys[*pos] < k2->keys[*pos])
      return k2;
    else if (k1->keys[*pos] > k2->keys[*pos])
      return k1;
    else
      *pos = *pos + 1;
  }

  return NULL;
}

/**
 * get_op - Get the function by its name
 * @param funcs Functions table
 * @param start Name of function to find
 * @param len   Length of string to match
 * @retval num Operation, e.g. OP_DELETE
 */
int get_op(const struct MenuFuncOp *funcs, const char *start, size_t len)
{
  for (int i = 0; funcs[i].name; i++)
  {
    if (mutt_istrn_equal(start, funcs[i].name, len) && (mutt_str_len(funcs[i].name) == len))
    {
      return funcs[i].op;
    }
  }

  return OP_NULL;
}

/**
 * mutt_get_func - Get the name of a function
 * @param funcs Functions table
 * @param op    Operation, e.g. OP_DELETE
 * @retval ptr  Name of function
 * @retval NULL Operation not found
 *
 * @note This returns a static string.
 */
const char *mutt_get_func(const struct MenuFuncOp *funcs, int op)
{
  for (int i = 0; funcs[i].name; i++)
  {
    if (funcs[i].op == op)
      return funcs[i].name;
  }

  return NULL;
}

/**
 * generic_tokenize_push_string - Parse and queue a 'push' command
 * @param s String to push into the key queue
 *
 * Parses s for `<function>` syntax and adds the whole sequence the macro buffer.
 */
void generic_tokenize_push_string(char *s)
{
  char *pp = NULL;
  char *p = s + mutt_str_len(s) - 1;
  size_t l;
  int i, op = OP_NULL;

  while (p >= s)
  {
    /* if we see something like "<PageUp>", look to see if it is a real
     * function name and return the corresponding value */
    if (*p == '>')
    {
      for (pp = p - 1; pp >= s && *pp != '<'; pp--)
        ; // do nothing

      if (pp >= s)
      {
        i = parse_fkey(pp);
        if (i > 0)
        {
          mutt_push_macro_event(KEY_F(i), 0);
          p = pp - 1;
          continue;
        }

        l = p - pp + 1;
        for (i = 0; KeyNames[i].name; i++)
        {
          if (mutt_istrn_equal(pp, KeyNames[i].name, l))
            break;
        }
        if (KeyNames[i].name)
        {
          /* found a match */
          mutt_push_macro_event(KeyNames[i].value, 0);
          p = pp - 1;
          continue;
        }

        /* See if it is a valid command
         * skip the '<' and the '>' when comparing */
        for (enum MenuType j = 0; MenuNames[j].name; j++)
        {
          const struct MenuFuncOp *funcs = km_get_table(MenuNames[j].value);
          if (funcs)
          {
            op = get_op(funcs, pp + 1, l - 2);
            if (op != OP_NULL)
              break;
          }
        }

        if (op != OP_NULL)
        {
          mutt_push_macro_event(0, op);
          p = pp - 1;
          continue;
        }
      }
    }
    mutt_push_macro_event((unsigned char) *p--, 0); /* independent 8 bits chars */
  }
}

/**
 * km_keyname - Get the human name for a key
 * @param[in]  c   Key code
 * @param[out] buf Buffer for the result
 */
void km_keyname(int c, struct Buffer *buf)
{
  const char *name = mutt_map_get_name(c, KeyNames);
  if (name)
  {
    buf_addstr(buf, name);
    return;
  }

  if ((c < 256) && (c > -128) && iscntrl((unsigned char) c))
  {
    if (c < 0)
      c += 256;

    if (c < 128)
    {
      buf_addch(buf, '^');
      buf_addch(buf, (c + '@') & 0x7f);
    }
    else
    {
      buf_add_printf(buf, "\\%d%d%d", c >> 6, (c >> 3) & 7, c & 7);
    }
  }
  else if ((c >= KEY_F0) && (c < KEY_F(256))) /* this maximum is just a guess */
  {
    buf_add_printf(buf, "<F%d>", c - KEY_F0);
  }
  else if ((c < 256) && (c >= -128) && IsPrint(c))
  {
    buf_add_printf(buf, "%c", (unsigned char) c);
  }
  else
  {
    buf_add_printf(buf, "<%ho>", (unsigned short) c);
  }
}

/**
 * km_expand_key - Get the key string bound to a Keymap
 * @param[in]  map Keybinding map
 * @param[out] buf Buffer for the result
 * @retval true Success
 */
bool km_expand_key(struct Keymap *map, struct Buffer *buf)
{
  if (!map || !buf)
    return false;

  for (int i = 0; i < map->len; i++)
  {
    km_keyname(map->keys[i], buf);
  }

  return true;
}

/**
 * km_expand_key_string - Get a human-readable key string
 * @param[in]  str Raw key string
 * @param[out] buf Buffer for the key string
 */
void km_expand_key_string(char *str, struct Buffer *buf)
{
  for (; *str; str++)
  {
    km_keyname(*str, buf);
  }
}

/**
 * km_find_func - Find a function's mapping in a Menu
 * @param mtype Menu type, e.g. #MENU_PAGER
 * @param func  Function, e.g. OP_DELETE
 * @retval ptr Keymap for the function
 */
struct Keymap *km_find_func(enum MenuType mtype, int func)
{
  struct Keymap *np = NULL;
  STAILQ_FOREACH(np, &Keymaps[mtype], entries)
  {
    if (np->op == func)
      break;
  }
  return np;
}

/**
 * km_get_table - Lookup a Menu's functions
 * @param mtype Menu type, e.g. #MENU_EDITOR
 * @retval ptr Array of functions
 */
const struct MenuFuncOp *km_get_table(enum MenuType mtype)
{
  switch (mtype)
  {
    case MENU_ALIAS:
      return OpAlias;
    case MENU_ATTACHMENT:
      return OpAttachment;
#ifdef USE_AUTOCRYPT
    case MENU_AUTOCRYPT:
      return OpAutocrypt;
#endif
    case MENU_COMPOSE:
      return OpCompose;
    case MENU_DIALOG:
      return OpDialog;
    case MENU_EDITOR:
      return OpEditor;
    case MENU_FOLDER:
      return OpBrowser;
    case MENU_GENERIC:
      return OpGeneric;
    case MENU_INDEX:
      return OpIndex;
    case MENU_PAGER:
      return OpPager;
    case MENU_PGP:
      return OpPgp;
    case MENU_POSTPONED:
      return OpPostponed;
    case MENU_QUERY:
      return OpQuery;
    case MENU_SMIME:
      return OpSmime;
    default:
      return NULL;
  }
}
