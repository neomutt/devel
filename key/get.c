/**
 * @file
 * Get a key from the user
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
 * @page key_get Get a key from the user
 *
 * Get a key from the user
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "gui/lib.h"
#include "key/lib.h"
#include "menu/lib.h"
#include "globals.h"
#ifdef USE_INOTIFY
#include "monitor.h"
#endif

// It's not possible to unget more than one char under some curses libs,
// so roll our own input buffering routines.

/** These are used for macros and exec/push commands.
 * They can be temporarily ignored by passing #GETCH_IGNORE_MACRO */
struct KeyEventArray MacroEvents = ARRAY_HEAD_INITIALIZER;

/** These are used in all other "normal" situations,
 * and are not ignored when passing #GETCH_IGNORE_MACRO */
static struct KeyEventArray UngetKeyEvents = ARRAY_HEAD_INITIALIZER;

/**
 * mutt_flushinp - Empty all the keyboard buffers
 */
void mutt_flushinp(void)
{
  ARRAY_SHRINK(&UngetKeyEvents, ARRAY_SIZE(&UngetKeyEvents));
  ARRAY_SHRINK(&MacroEvents, ARRAY_SIZE(&MacroEvents));
  flushinp();
}

/**
 * array_pop - Remove an event from the array
 * @param a Array
 * @retval ptr Event
 */
static struct KeyEvent *array_pop(struct KeyEventArray *a)
{
  if (ARRAY_EMPTY(a))
  {
    return NULL;
  }

  struct KeyEvent *event = ARRAY_LAST(a);
  ARRAY_SHRINK(a, 1);
  return event;
}

/**
 * array_add - Add an event to the end of the array
 * @param a  Array
 * @param ch Character
 * @param op Operation, e.g. OP_DELETE
 */
static void array_add(struct KeyEventArray *a, int ch, int op)
{
  struct KeyEvent event = { ch, op };
  ARRAY_ADD(a, event);
}

/**
 * array_to_endcond - Clear the array until an OP_END_COND
 * @param a Array
 */
static void array_to_endcond(struct KeyEventArray *a)
{
  while (!ARRAY_EMPTY(a))
  {
    if (array_pop(a)->op == OP_END_COND)
    {
      return;
    }
  }
}

/**
 * mutt_unget_ch - Return a keystroke to the input buffer
 * @param ch Key press
 *
 * This puts events into the `UngetKeyEvents` buffer
 */
void mutt_unget_ch(int ch)
{
  array_add(&UngetKeyEvents, ch, OP_NULL);
}

/**
 * mutt_unget_op - Return an operation to the input buffer
 * @param op Operation, e.g. OP_DELETE
 *
 * This puts events into the `UngetKeyEvents` buffer
 */
void mutt_unget_op(int op)
{
  array_add(&UngetKeyEvents, 0, op);
}

/**
 * mutt_unget_string - Return a string to the input buffer
 * @param s String to return
 *
 * This puts events into the `UngetKeyEvents` buffer
 */
void mutt_unget_string(const char *s)
{
  const char *p = s + mutt_str_len(s) - 1;

  while (p >= s)
  {
    mutt_unget_ch((unsigned char) *p--);
  }
}

/**
 * mutt_push_macro_event - Add the character/operation to the macro buffer
 * @param ch Character to add
 * @param op Operation to add
 *
 * Adds the ch/op to the macro buffer.
 * This should be used for macros, push, and exec commands only.
 */
void mutt_push_macro_event(int ch, int op)
{
  array_add(&MacroEvents, ch, op);
}

/**
 * mutt_flush_macro_to_endcond - Drop a macro from the input buffer
 *
 * All the macro text is deleted until an OP_END_COND command,
 * or the buffer is empty.
 */
void mutt_flush_macro_to_endcond(void)
{
  array_to_endcond(&MacroEvents);
}

#ifdef USE_INOTIFY
/**
 * mutt_monitor_getch - Get a character and poll the filesystem monitor
 * @retval num Character pressed
 * @retval ERR Timeout
 */
static int mutt_monitor_getch(void)
{
  /* ncurses has its own internal buffer, so before we perform a poll,
   * we need to make sure there isn't a character waiting */
  timeout(0);
  int ch = getch();
  timeout(1000); // 1 second
  if (ch == ERR)
  {
    if (mutt_monitor_poll() != 0)
      ch = ERR;
    else
      ch = getch();
  }
  return ch;
}
#endif /* USE_INOTIFY */

/**
 * mutt_getch - Read a character from the input buffer
 * @param flags Flags, e.g. #GETCH_IGNORE_MACRO
 * @retval obj KeyEvent to process
 *
 * The priority for reading events is:
 * 1. UngetKeyEvents buffer
 * 2. MacroEvents buffer
 * 3. Keyboard
 *
 * This function can return:
 * - Abort   `{ 0, OP_ABORT   }`
 * - Repaint `{ 0, OP_REPAINT }`
 * - Timeout `{ 0, OP_TIMEOUT }`
 */
struct KeyEvent mutt_getch(GetChFlags flags)
{
  static const struct KeyEvent event_abort = { 0, OP_ABORT };
  static const struct KeyEvent event_repaint = { 0, OP_REPAINT };
  static const struct KeyEvent event_timeout = { 0, OP_TIMEOUT };

  if (OptNoCurses)
    return event_abort;

  struct KeyEvent *event_key = array_pop(&UngetKeyEvents);
  if (event_key)
    return *event_key;

  if (!(flags & GETCH_IGNORE_MACRO))
  {
    event_key = array_pop(&MacroEvents);
    if (event_key)
      return *event_key;
  }

  int ch;
  SigInt = false;
  mutt_sig_allow_interrupt(true);
  timeout(1000); // 1 second
#ifdef USE_INOTIFY
  ch = mutt_monitor_getch();
#else
  ch = getch();
#endif
  mutt_sig_allow_interrupt(false);

  if (SigInt)
  {
    mutt_query_exit();
    return event_abort;
  }

  if (ch == KEY_RESIZE)
  {
    timeout(0);
    while ((ch = getch()) == KEY_RESIZE)
    {
      // do nothing
    }
  }

  if (ch == ERR)
  {
    if (!isatty(STDIN_FILENO)) // terminal was lost
      mutt_exit(1);

    if (SigWinch)
    {
      SigWinch = false;
      notify_send(NeoMutt->notify_resize, NT_RESIZE, 0, NULL);
      return event_repaint;
    }

    notify_send(NeoMutt->notify_timeout, NT_TIMEOUT, 0, NULL);
    return event_timeout;
  }

  if (ch == AbortKey)
    return event_abort;

  if (ch & 0x80)
  {
    const bool c_meta_key = cs_subset_bool(NeoMutt->sub, "meta_key");
    if (c_meta_key)
    {
      /* send ALT-x as ESC-x */
      ch &= ~0x80;
      mutt_unget_ch(ch);
      return (struct KeyEvent) { '\033', OP_NULL }; // Escape
    }
  }

  return (struct KeyEvent) { ch, OP_NULL };
}

/**
 * km_error_key - Handle an unbound key sequence
 * @param mtype Menu type, e.g. #MENU_PAGER
 */
void km_error_key(enum MenuType mtype)
{
  struct Keymap *key = km_find_func(mtype, OP_HELP);
  if (!key && (mtype != MENU_EDITOR) && (mtype != MENU_PAGER))
    key = km_find_func(MENU_GENERIC, OP_HELP);

  if (!key)
  {
    mutt_error(_("Key is not bound"));
    return;
  }

  struct Buffer *buf = buf_pool_get();
  km_expand_key(key, buf);
  mutt_error(_("Key is not bound.  Press '%s' for help."), buf_string(buf));
  buf_pool_release(&buf);
}

/**
 * retry_generic - Try to find the key in the generic menu bindings
 * @param mtype   Menu type, e.g. #MENU_PAGER
 * @param keys    Array of keys to return to the input queue
 * @param keyslen Number of keys in the array
 * @param lastkey Last key pressed (to return to input queue)
 * @param flags   Flags, e.g. #GETCH_IGNORE_MACRO
 * @retval num Operation, e.g. OP_DELETE
 */
static struct KeyEvent retry_generic(enum MenuType mtype, keycode_t *keys,
                                     int keyslen, int lastkey, GetChFlags flags)
{
  if (lastkey)
    mutt_unget_ch(lastkey);
  for (; keyslen; keyslen--)
    mutt_unget_ch(keys[keyslen - 1]);

  if ((mtype != MENU_EDITOR) && (mtype != MENU_GENERIC) && (mtype != MENU_PAGER))
  {
    return km_dokey_event(MENU_GENERIC, flags);
  }
  if ((mtype != MENU_EDITOR) && (mtype != MENU_GENERIC))
  {
    /* probably a good idea to flush input here so we can abort macros */
    mutt_flushinp();
  }

  return (struct KeyEvent) { mutt_getch(flags).ch, OP_NULL };
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
 * km_dokey_event - Determine what a keypress should do
 * @param mtype Menu type, e.g. #MENU_EDITOR
 * @param flags Flags, e.g. #GETCH_IGNORE_MACRO
 * @retval ptr Event
 */
struct KeyEvent km_dokey_event(enum MenuType mtype, GetChFlags flags)
{
  struct KeyEvent event = { 0, OP_NULL };
  struct Keymap *map = STAILQ_FIRST(&Keymaps[mtype]);
  int pos = 0;
  int n = 0;

  if (!map && (mtype != MENU_EDITOR))
    return retry_generic(mtype, NULL, 0, 0, flags);

  while (true)
  {
    event = mutt_getch(flags);

    // abort, timeout, repaint
    if (event.op < OP_NULL)
      return event;

    /* do we have an op already? */
    if (event.op != OP_NULL)
    {
      const char *func = NULL;
      const struct MenuFuncOp *funcs = NULL;

      /* is this a valid op for this menu type? */
      if ((funcs = km_get_table(mtype)) && (func = mutt_get_func(funcs, event.op)))
        return event;

      if ((mtype != MENU_EDITOR) && (mtype != MENU_PAGER) && (mtype != MENU_GENERIC))
      {
        /* check generic menu type */
        funcs = OpGeneric;
        func = mutt_get_func(funcs, event.op);
        if (func)
          return event;
      }

      /* Sigh. Valid function but not in this context.
       * Find the literal string and push it back */
      for (int i = 0; MenuNames[i].name; i++)
      {
        funcs = km_get_table(MenuNames[i].value);
        if (funcs)
        {
          func = mutt_get_func(funcs, event.op);
          if (func)
          {
            mutt_unget_ch('>');
            mutt_unget_string(func);
            mutt_unget_ch('<');
            break;
          }
        }
      }
      /* continue to chew */
      if (func)
        continue;
    }

    if (!map)
      return event;

    /* Nope. Business as usual */
    while (event.ch > map->keys[pos])
    {
      if ((pos > map->eq) || !STAILQ_NEXT(map, entries))
        return retry_generic(mtype, map->keys, pos, event.ch, flags);
      map = STAILQ_NEXT(map, entries);
    }

    if (event.ch != map->keys[pos])
      return retry_generic(mtype, map->keys, pos, event.ch, flags);

    if (++pos == map->len)
    {
      if (map->op != OP_MACRO)
        return (struct KeyEvent) { event.ch, map->op };

      /* #GETCH_IGNORE_MACRO turns off processing the MacroEvents buffer
       * in mutt_getch().  Generating new macro events during that time would
       * result in undesired behavior once the option is turned off.
       *
       * Originally this returned -1, however that results in an unbuffered
       * username or password prompt being aborted.  Returning OP_NULL allows
       * mw_get_field() to display the keybinding pressed instead.
       *
       * It may be unexpected for a macro's keybinding to be returned,
       * but less so than aborting the prompt.  */
      if (flags & GETCH_IGNORE_MACRO)
      {
        return (struct KeyEvent) { event.ch, OP_NULL };
      }

      if (n++ == 10)
      {
        mutt_flushinp();
        mutt_error(_("Macro loop detected"));
        return (struct KeyEvent) { '\0', OP_ABORT };
      }

      generic_tokenize_push_string(map->macro);
      map = STAILQ_FIRST(&Keymaps[mtype]);
      pos = 0;
    }
  }

  /* not reached */
}

/**
 * km_dokey - Determine what a keypress should do
 * @param mtype Menu type, e.g. #MENU_EDITOR
 * @param flags Flags, e.g. #GETCH_IGNORE_MACRO
 * @retval >0      Function to execute
 * @retval OP_NULL No function bound to key sequence
 * @retval -1      Error occurred while reading input
 * @retval -2      A timeout or sigwinch occurred
 */
int km_dokey(enum MenuType mtype, GetChFlags flags)
{
  return km_dokey_event(mtype, flags).op;
}
