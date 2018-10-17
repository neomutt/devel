/**
 * @file
 * String processing routines to generate the mail index
 *
 * @authors
 * Copyright (C) 1996-2000,2002,2007 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2016 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2016 Ian Zimmerman <itz@primate.net>
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

#include "config.h"
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mutt/mutt.h"
#include "config/lib.h"
#include "email/lib.h"
#include "mutt.h"
#include "hdrline.h"
#include "alias.h"
#include "context.h"
#include "curs_lib.h"
#include "format_flags.h"
#include "globals.h"
#include "mailbox.h"
#include "mutt_curses.h"
#include "mutt_parse.h"
#include "mutt_thread.h"
#include "mutt_window.h"
#include "muttlib.h"
#include "ncrypt/ncrypt.h"
#include "sort.h"

/* These Config Variables are only used in hdrline.c */
struct MbTable *FlagChars; ///< Config: User-configurable index flags: tagged, new, etc
struct MbTable *FromChars; ///< Config: User-configurable index flags: to address, cc address, etc
struct MbTable *ToChars; ///< Config: Indicator characters for the 'To' field in the index

/**
 * enum FlagChars - Index into the FlagChars variable ($flag_chars)
 */
enum FlagChars
{
  FlagCharTagged,
  FlagCharImportant,
  FlagCharDeleted,
  FlagCharDeletedAttach,
  FlagCharReplied,
  FlagCharOld,
  FlagCharNew,
  FlagCharOldThread,
  FlagCharNewThread,
  FlagCharSEmpty,
  FlagCharZEmpty
};

/**
 * mutt_is_mail_list - Is this the email address of a mailing list?
 * @param addr Address to test
 * @retval true If it's a mailing list
 */
bool mutt_is_mail_list(struct Address *addr)
{
  if (!mutt_regexlist_match(&UnMailLists, addr->mailbox))
    return mutt_regexlist_match(&MailLists, addr->mailbox);
  return false;
}

/**
 * mutt_is_subscribed_list - Is this the email address of a user-subscribed mailing list?
 * @param addr Address to test
 * @retval true If it's a subscribed mailing list
 */
bool mutt_is_subscribed_list(struct Address *addr)
{
  if (!mutt_regexlist_match(&UnMailLists, addr->mailbox) &&
      !mutt_regexlist_match(&UnSubscribedLists, addr->mailbox))
  {
    return mutt_regexlist_match(&SubscribedLists, addr->mailbox);
  }
  return false;
}

/**
 * check_for_mailing_list - Search list of addresses for a mailing list
 * @param addr    List of addreses to search
 * @param pfx     Prefix string
 * @param buf     Buffer to store results
 * @param buflen  Buffer length
 * @retval 1 Mailing list found
 * @retval 0 No list found
 *
 * Search for a mailing list in the list of addresses pointed to by addr.
 * If one is found, print pfx and the name of the list into buf.
 */
static bool check_for_mailing_list(struct Address *addr, const char *pfx, char *buf, int buflen)
{
  for (; addr; addr = addr->next)
  {
    if (mutt_is_subscribed_list(addr))
    {
      if (pfx && buf && buflen)
        snprintf(buf, buflen, "%s%s", pfx, mutt_get_name(addr));
      return true;
    }
  }
  return false;
}

/**
 * check_for_mailing_list_addr - Check an address list for a mailing list
 * @param addr   Address list
 * @param buf    Buffer for the result
 * @param buflen Length of buffer
 * @retval true Mailing list found
 *
 * If one is found, print the address of the list into buf.
 */
static bool check_for_mailing_list_addr(struct Address *addr, char *buf, int buflen)
{
  for (; addr; addr = addr->next)
  {
    if (mutt_is_subscribed_list(addr))
    {
      if (buf && buflen)
        snprintf(buf, buflen, "%s", addr->mailbox);
      return true;
    }
  }
  return false;
}

/**
 * first_mailing_list - Get the first mailing list in the list of addresses
 * @param buf    Buffer for the result
 * @param buflen Length of buffer
 * @param a      Address list
 * @retval true If a mailing list was found
 */
static bool first_mailing_list(char *buf, size_t buflen, struct Address *a)
{
  for (; a; a = a->next)
  {
    if (mutt_is_subscribed_list(a))
    {
      mutt_save_path(buf, buflen, a);
      return true;
    }
  }
  return false;
}

/**
 * add_index_color - Insert a color marker into a string
 * @param buf    Buffer to store marker
 * @param buflen Buffer length
 * @param flags  Flags, e.g. MUTT_FORMAT_INDEX
 * @param color  Color, e.g. MT_COLOR_MESSAGE
 * @retval num Characters written
 *
 * The colors are stored as "magic" strings embedded in the text.
 */
static size_t add_index_color(char *buf, size_t buflen, enum FormatFlag flags, char color)
{
  /* only add color markers if we are operating on main index entries. */
  if (!(flags & MUTT_FORMAT_INDEX))
    return 0;

  /* this item is going to be passed to an external filter */
  if (flags & MUTT_FORMAT_NOFILTER)
    return 0;

  if (color == MT_COLOR_INDEX)
  { /* buf might be uninitialized other cases */
    const size_t len = mutt_str_strlen(buf);
    buf += len;
    buflen -= len;
  }

  if (buflen <= 2)
    return 0;

  buf[0] = MUTT_SPECIAL_INDEX;
  buf[1] = color;
  buf[2] = '\0';

  return 2;
}

/**
 * enum FieldType - Header types
 */
enum FieldType
{
  DISP_TO,
  DISP_CC,
  DISP_BCC,
  DISP_FROM,
  DISP_PLAIN,
  DISP_NUM
};

/**
 * get_nth_wchar - Extract one char from a multi-byte table
 * @param table  Multi-byte table
 * @param index  Select this character
 * @retval ptr String pointer to the character
 *
 * Extract one multi-byte character from a string table.
 * If the index is invalid, then a space character will be returned.
 * If the character selected is '\n' (Ctrl-M), then "" will be returned.
 */
static const char *get_nth_wchar(struct MbTable *table, int index)
{
  if (!table || !table->chars || (index < 0) || (index >= table->len))
    return " ";

  if (table->chars[index][0] == '\r')
    return "";

  return table->chars[index];
}

/**
 * make_from_prefix - Create a prefix for an author field
 * @param disp   Type of field
 * @retval ptr Prefix string (do not free it)
 *
 * If $from_chars is set, pick an appropriate character from it.
 * If not, use the default prefix: "To", "Cc", etc
 */
static const char *make_from_prefix(enum FieldType disp)
{
  /* need 2 bytes at the end, one for the space, another for NUL */
  static char padded[8];
  static const char *long_prefixes[DISP_NUM] = {
    [DISP_TO] = "To ", [DISP_CC] = "Cc ", [DISP_BCC] = "Bcc ",
    [DISP_FROM] = "",  [DISP_PLAIN] = "",
  };

  if (!FromChars || !FromChars->chars || (FromChars->len == 0))
    return long_prefixes[disp];

  const char *pchar = get_nth_wchar(FromChars, disp);
  if (mutt_str_strlen(pchar) == 0)
    return "";

  snprintf(padded, sizeof(padded), "%s ", pchar);
  return padded;
}

/**
 * make_from - Generate a From: field (with optional prefix)
 * @param env      Envelope of the email
 * @param buf      Buffer to store the result
 * @param buflen   Size of the buffer
 * @param do_lists Should we check for mailing lists?
 * @param flags    Format flags, e.g. #MUTT_FORMAT_PLAIN
 *
 * Generate the %F or %L field in $index_format.
 * This is the author, or recipient of the email.
 *
 * The field can optionally be prefixed by a character from $from_chars.
 * If $from_chars is not set, the prefix will be, "To", "Cc", etc
 */
static void make_from(struct Envelope *env, char *buf, size_t buflen,
                      bool do_lists, enum FormatFlag flags)
{
  if (!env || !buf)
    return;

  bool me;
  enum FieldType disp;
  struct Address *name = NULL;

  me = mutt_addr_is_user(env->from);

  if (do_lists || me)
  {
    if (check_for_mailing_list(env->to, make_from_prefix(DISP_TO), buf, buflen))
      return;
    if (check_for_mailing_list(env->cc, make_from_prefix(DISP_CC), buf, buflen))
      return;
  }

  if (me && env->to)
  {
    disp = (flags & MUTT_FORMAT_PLAIN) ? DISP_PLAIN : DISP_TO;
    name = env->to;
  }
  else if (me && env->cc)
  {
    disp = DISP_CC;
    name = env->cc;
  }
  else if (me && env->bcc)
  {
    disp = DISP_BCC;
    name = env->bcc;
  }
  else if (env->from)
  {
    disp = DISP_FROM;
    name = env->from;
  }
  else
  {
    *buf = '\0';
    return;
  }

  snprintf(buf, buflen, "%s%s", make_from_prefix(disp), mutt_get_name(name));
}

/**
 * make_from_addr - Create a 'from' address for a reply email
 * @param hdr      Envelope of current email
 * @param buf      Buffer for the result
 * @param buflen   Length of buffer
 * @param do_lists If true, check for mailing lists
 */
static void make_from_addr(struct Envelope *hdr, char *buf, size_t buflen, bool do_lists)
{
  if (!hdr || !buf)
    return;

  bool me = mutt_addr_is_user(hdr->from);

  if (do_lists || me)
  {
    if (check_for_mailing_list_addr(hdr->to, buf, buflen))
      return;
    if (check_for_mailing_list_addr(hdr->cc, buf, buflen))
      return;
  }

  if (me && hdr->to)
    snprintf(buf, buflen, "%s", hdr->to->mailbox);
  else if (me && hdr->cc)
    snprintf(buf, buflen, "%s", hdr->cc->mailbox);
  else if (hdr->from)
    mutt_str_strfcpy(buf, hdr->from->mailbox, buflen);
  else
    *buf = 0;
}

/**
 * user_in_addr - Do any of the addresses refer to the user?
 * @param a Address list
 * @retval true If any of the addresses match one of the user's addresses
 */
static bool user_in_addr(struct Address *a)
{
  for (; a; a = a->next)
    if (mutt_addr_is_user(a))
      return true;
  return false;
}

/**
 * user_is_recipient - Is the user a recipient of the message
 * @param e Email to test
 * @retval 0 User is not in list
 * @retval 1 User is unique recipient
 * @retval 2 User is in the TO list
 * @retval 3 User is in the CC list
 * @retval 4 User is originator
 * @retval 5 Sent to a subscribed mailinglist
 * @retval 6 User is in the Reply-To list
 */
static int user_is_recipient(struct Email *e)
{
  if (!e || !e->env)
    return 0;

  struct Envelope *env = e->env;

  if (!e->recip_valid)
  {
    e->recip_valid = true;

    if (mutt_addr_is_user(env->from))
      e->recipient = 4;
    else if (user_in_addr(env->to))
    {
      if (env->to->next || env->cc)
        e->recipient = 2; /* non-unique recipient */
      else
        e->recipient = 1; /* unique recipient */
    }
    else if (user_in_addr(env->cc))
      e->recipient = 3;
    else if (check_for_mailing_list(env->to, NULL, NULL, 0))
      e->recipient = 5;
    else if (check_for_mailing_list(env->cc, NULL, NULL, 0))
      e->recipient = 5;
    else if (user_in_addr(env->reply_to))
      e->recipient = 6;
    else
      e->recipient = 0;
  }

  return e->recipient;
}

/**
 * apply_subject_mods - Apply regex modifications to the subject
 * @param env Envelope of email
 * @retval ptr  Modified subject
 * @retval NULL No modification made
 */
static char *apply_subject_mods(struct Envelope *env)
{
  if (!env)
    return NULL;

  if (STAILQ_EMPTY(&SubjectRegexList))
    return env->subject;

  if (!env->subject || *env->subject == '\0')
  {
    env->disp_subj = NULL;
    return NULL;
  }

  env->disp_subj = mutt_replacelist_apply(&SubjectRegexList, NULL, 0, env->subject);
  return env->disp_subj;
}

/**
 * thread_is_new - Does the email thread contain any new emails?
 * @param ctx Mailbox
 * @param e Email
 * @retval true If thread contains new mail
 */
static bool thread_is_new(struct Context *ctx, struct Email *e)
{
  return e->collapsed && (e->num_hidden > 1) &&
         (mutt_thread_contains_unread(ctx, e) == 1);
}

/**
 * thread_is_old - Does the email thread contain any unread emails?
 * @param ctx Mailbox
 * @param e Email
 * @retval true If thread contains unread mail
 */
static bool thread_is_old(struct Context *ctx, struct Email *e)
{
  return e->collapsed && (e->num_hidden > 1) &&
         (mutt_thread_contains_unread(ctx, e) == 2);
}

/**
 * index_format_str - Format a string for the index list - Implements ::format_t
 *
 * | Expando | Description
 * |:--------|:-----------------------------------------------------------------
 * | \%a     | Address of the author
 * | \%A     | Reply-to address (if present; otherwise: address of author)
 * | \%b     | Filename of the original message folder (think mailbox)
 * | \%B     | The list to which the letter was sent, or else the folder name (%b).
 * | \%C     | Current message number
 * | \%c     | Number of characters (bytes) in the message
 * | \%D     | Date and time of message using $date_format and local timezone
 * | \%d     | Date and time of message using $date_format and sender's timezone
 * | \%e     | Current message number in thread
 * | \%E     | Number of messages in current thread
 * | \%F     | Author name, or recipient name if the message is from you
 * | \%Fp    | Like %F, but plain. No contextual formatting is applied to recipient name
 * | \%f     | Sender (address + real name), either From: or Return-Path:
 * | \%g     | Message tags (e.g. notmuch tags/imap flags)
 * | \%Gx    | Individual message tag (e.g. notmuch tags/imap flags)
 * | \%H     | Spam attribute(s) of this message
 * | \%I     | Initials of author
 * | \%i     | Message-id of the current message
 * | \%J     | Message tags (if present, tree unfolded, and != parent's tags)
 * | \%K     | The list to which the letter was sent (if any; otherwise: empty)
 * | \%L     | Like %F, except 'lists' are displayed first
 * | \%l     | Number of lines in the message
 * | \%M     | Number of hidden messages if the thread is collapsed
 * | \%m     | Total number of message in the mailbox
 * | \%N     | Message score
 * | \%n     | Author's real name (or address if missing)
 * | \%O     | Like %L, except using address instead of name
 * | \%P     | Progress indicator for the built-in pager (how much of the file has been displayed)
 * | \%q     | Newsgroup name (if compiled with NNTP support)
 * | \%R     | Comma separated list of Cc: recipients
 * | \%r     | Comma separated list of To: recipients
 * | \%S     | Single character status of the message (N/O/D/d/!/r/-)
 * | \%s     | Subject of the message
 * | \%T     | The appropriate character from the $$to_chars string
 * | \%t     | 'To:' field (recipients)
 * | \%u     | User (login) name of the author
 * | \%v     | First name of the author, or the recipient if the message is from you
 * | \%W     | Name of organization of author ('Organization:' field)
 * | \%x     | 'X-Comment-To:' field (if present and compiled with NNTP support)
 * | \%X     | Number of MIME attachments
 * | \%Y     | 'X-Label:' field (if present, tree unfolded, and != parent's x-label)
 * | \%y     | 'X-Label:' field (if present)
 * | \%Z     | Combined message flags
 * | \%zc    | Message crypto flags
 * | \%zs    | Message status flags
 * | \%zt    | Message tag flags
 * | \%(fmt) | Date/time when the message was received
 * | \%[fmt] | Message date/time converted to the local time zone
 * | \%{fmt} | Message date/time converted to sender's time zone
 */
static const char *index_format_str(char *buf, size_t buflen, size_t col, int cols,
                                    char op, const char *src, const char *prec,
                                    const char *if_str, const char *else_str,
                                    unsigned long data, enum FormatFlag flags)
{
  struct HdrFormatInfo *hfi = (struct HdrFormatInfo *) data;
  char fmt[SHORT_STRING], tmp[LONG_STRING], *p, *tags = NULL;
  const char *wch = NULL;
  int i;
  int optional = (flags & MUTT_FORMAT_OPTIONAL);
  int threads = ((Sort & SORT_MASK) == SORT_THREADS);
  int is_index = (flags & MUTT_FORMAT_INDEX);
  size_t colorlen;

  struct Email *e = hfi->email;
  struct Context *ctx = hfi->ctx;

  if (!e || !e->env)
    return src;
  buf[0] = 0;
  switch (op)
  {
    case 'A':
    case 'I':
      if (op == 'A')
      {
        if (e->env->reply_to && e->env->reply_to->mailbox)
        {
          colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
          mutt_format_s(buf + colorlen, buflen - colorlen, prec,
                        mutt_addr_for_display(e->env->reply_to));
          add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
          break;
        }
      }
      else
      {
        if (mutt_mb_get_initials(mutt_get_name(e->env->from), tmp, sizeof(tmp)))
        {
          colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
          mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
          add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
          break;
        }
      }
      /* fallthrough */

    case 'a':
      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
      if (e->env->from && e->env->from->mailbox)
      {
        mutt_format_s(buf + colorlen, buflen - colorlen, prec,
                      mutt_addr_for_display(e->env->from));
      }
      else
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, "");
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'B':
    case 'K':
      if (!first_mailing_list(buf, buflen, e->env->to) &&
          !first_mailing_list(buf, buflen, e->env->cc))
      {
        buf[0] = 0;
      }
      if (buf[0])
      {
        mutt_str_strfcpy(tmp, buf, sizeof(tmp));
        mutt_format_s(buf, buflen, prec, tmp);
        break;
      }
      if (op == 'K')
      {
        if (optional)
          optional = 0;
        /* break if 'K' returns nothing */
        break;
      }
      /* if 'B' returns nothing */
      /* fallthrough */

    case 'b':
      if (ctx)
      {
        p = strrchr(ctx->mailbox->path, '/');
        if (p)
          mutt_str_strfcpy(buf, p + 1, buflen);
        else
          mutt_str_strfcpy(buf, ctx->mailbox->path, buflen);
      }
      else
        mutt_str_strfcpy(buf, "(null)", buflen);
      mutt_str_strfcpy(tmp, buf, sizeof(tmp));
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'c':
      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_SIZE);
      mutt_str_pretty_size(tmp, sizeof(tmp), (long) e->content->length);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'C':
      colorlen = add_index_color(fmt, sizeof(fmt), flags, MT_COLOR_INDEX_NUMBER);
      snprintf(fmt + colorlen, sizeof(fmt) - colorlen, "%%%sd", prec);
      add_index_color(fmt + colorlen, sizeof(fmt) - colorlen, flags, MT_COLOR_INDEX);
      snprintf(buf, buflen, fmt, e->msgno + 1);
      break;

    case 'd':
    case 'D':
    case '{':
    case '[':
    case '(':
    case '<':
      /* preprocess $date_format to handle %Z */
      {
        const char *cp = NULL;
        struct tm *tm = NULL;
        time_t T;
        int j = 0;

        if (optional && ((op == '[') || (op == '(')))
        {
          char *is = NULL;
          T = time(NULL);
          tm = localtime(&T);
          T -= (op == '(') ? e->received : e->date_sent;

          is = (char *) prec;
          int invert = 0;
          if (*is == '>')
          {
            invert = 1;
            is++;
          }

          while (*is && (*is != '?'))
          {
            int t = strtol(is, &is, 10);
            /* semi-broken (assuming 30 days in all months) */
            switch (*(is++))
            {
              case 'y':
                if (t > 1)
                {
                  t--;
                  t *= (60 * 60 * 24 * 365);
                }
                t += ((tm->tm_mon * 60 * 60 * 24 * 30) + (tm->tm_mday * 60 * 60 * 24) +
                      (tm->tm_hour * 60 * 60) + (tm->tm_min * 60) + tm->tm_sec);
                break;

              case 'm':
                if (t > 1)
                {
                  t--;
                  t *= (60 * 60 * 24 * 30);
                }
                t += ((tm->tm_mday * 60 * 60 * 24) + (tm->tm_hour * 60 * 60) +
                      (tm->tm_min * 60) + tm->tm_sec);
                break;

              case 'w':
                if (t > 1)
                {
                  t--;
                  t *= (60 * 60 * 24 * 7);
                }
                t += ((tm->tm_wday * 60 * 60 * 24) + (tm->tm_hour * 60 * 60) +
                      (tm->tm_min * 60) + tm->tm_sec);
                break;

              case 'd':
                if (t > 1)
                {
                  t--;
                  t *= (60 * 60 * 24);
                }
                t += ((tm->tm_hour * 60 * 60) + (tm->tm_min * 60) + tm->tm_sec);
                break;

              case 'H':
                if (t > 1)
                {
                  t--;
                  t *= (60 * 60);
                }
                t += ((tm->tm_min * 60) + tm->tm_sec);
                break;

              case 'M':
                if (t > 1)
                {
                  t--;
                  t *= (60);
                }
                t += (tm->tm_sec);
                break;

              default:
                break;
            }
            j += t;
          }

          if (j < 0)
            j *= -1;

          if (((T > j) || (T < (-1 * j))) ^ invert)
            optional = 0;
          break;
        }

        p = buf;

        cp = (op == 'd' || op == 'D') ? (NONULL(DateFormat)) : src;
        bool do_locales;
        if (*cp == '!')
        {
          do_locales = false;
          cp++;
        }
        else
          do_locales = true;

        size_t len = buflen - 1;
        while (len > 0 && (((op == 'd' || op == 'D') && *cp) ||
                           (op == '{' && *cp != '}') || (op == '[' && *cp != ']') ||
                           (op == '(' && *cp != ')') || (op == '<' && *cp != '>')))
        {
          if (*cp == '%')
          {
            cp++;
            if ((*cp == 'Z' || *cp == 'z') && (op == 'd' || op == '{'))
            {
              if (len >= 5)
              {
                sprintf(p, "%c%02u%02u", e->zoccident ? '-' : '+', e->zhours, e->zminutes);
                p += 5;
                len -= 5;
              }
              else
                break; /* not enough space left */
            }
            else
            {
              if (len >= 2)
              {
                *p++ = '%';
                *p++ = *cp;
                len -= 2;
              }
              else
                break; /* not enough space */
            }
            cp++;
          }
          else
          {
            *p++ = *cp++;
            len--;
          }
        }
        *p = 0;

        if (op == '[' || op == 'D')
          tm = localtime(&e->date_sent);
        else if (op == '(')
          tm = localtime(&e->received);
        else if (op == '<')
        {
          T = time(NULL);
          tm = localtime(&T);
        }
        else
        {
          /* restore sender's time zone */
          T = e->date_sent;
          if (e->zoccident)
            T -= (e->zhours * 3600 + e->zminutes * 60);
          else
            T += (e->zhours * 3600 + e->zminutes * 60);
          tm = gmtime(&T);
        }

        if (!do_locales)
          setlocale(LC_TIME, "C");
        strftime(tmp, sizeof(tmp), buf, tm);
        if (!do_locales)
          setlocale(LC_TIME, "");

        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_DATE);
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);

        if (len > 0 && op != 'd' && op != 'D') /* Skip ending op */
          src = cp + 1;
      }
      break;

    case 'e':
      snprintf(fmt, sizeof(fmt), "%%%sd", prec);
      snprintf(buf, buflen, fmt, mutt_messages_in_thread(ctx, e, 1));
      break;

    case 'E':
      if (!optional)
      {
        snprintf(fmt, sizeof(fmt), "%%%sd", prec);
        snprintf(buf, buflen, fmt, mutt_messages_in_thread(ctx, e, 0));
      }
      else if (mutt_messages_in_thread(ctx, e, 0) <= 1)
        optional = 0;
      break;

    case 'f':
      tmp[0] = 0;
      mutt_addr_write(tmp, sizeof(tmp), e->env->from, true);
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'F':
      if (!optional)
      {
        const bool is_plain = (src[0] == 'p');
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
        make_from(e->env, tmp, sizeof(tmp), false, (is_plain ? MUTT_FORMAT_PLAIN : 0));
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);

        if (is_plain)
          src++;
      }
      else if (mutt_addr_is_user(e->env->from))
      {
        optional = 0;
      }
      break;

    case 'g':
      tags = driver_tags_get_transformed(&e->tags);
      if (!optional)
      {
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_TAGS);
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, NONULL(tags));
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      }
      else if (!tags)
        optional = 0;
      FREE(&tags);
      break;

    case 'G':
    {
      char format[3];
      char *tag = NULL;

      if (!optional)
      {
        format[0] = op;
        format[1] = *src;
        format[2] = 0;

        tag = mutt_hash_find(TagFormats, format);
        if (tag)
        {
          tags = driver_tags_get_transformed_for(tag, &e->tags);
          colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_TAG);
          mutt_format_s(buf + colorlen, buflen - colorlen, prec, NONULL(tags));
          add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
          FREE(&tags);
        }
        src++;
      }
      else
      {
        format[0] = op;
        format[1] = *prec;
        format[2] = 0;

        tag = mutt_hash_find(TagFormats, format);
        if (tag)
        {
          tags = driver_tags_get_transformed_for(tag, &e->tags);
          if (!tags)
            optional = 0;
          FREE(&tags);
        }
      }
    }
    break;

    case 'H':
      /* (Hormel) spam score */
      if (optional)
        optional = e->env->spam ? 1 : 0;

      if (e->env->spam)
        mutt_format_s(buf, buflen, prec, NONULL(e->env->spam->data));
      else
        mutt_format_s(buf, buflen, prec, "");
      break;

    case 'i':
      mutt_format_s(buf, buflen, prec, e->env->message_id ? e->env->message_id : "<no.id>");
      break;

    case 'J':
      tags = driver_tags_get_transformed(&e->tags);
      if (tags)
      {
        i = 1; /* reduce reuse recycle */
        if (flags & MUTT_FORMAT_TREE)
        {
          char *parent_tags = NULL;
          if (e->thread->prev && e->thread->prev->message)
          {
            parent_tags = driver_tags_get_transformed(&e->thread->prev->message->tags);
          }
          if (!parent_tags && e->thread->parent && e->thread->parent->message)
          {
            parent_tags =
                driver_tags_get_transformed(&e->thread->parent->message->tags);
          }
          if (parent_tags && mutt_str_strcasecmp(tags, parent_tags) == 0)
            i = 0;
          FREE(&parent_tags);
        }
      }
      else
        i = 0;

      if (optional)
        optional = i;

      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_TAGS);
      if (i)
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, tags);
      else
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, "");
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      FREE(&tags);
      break;

    case 'l':
      if (!optional)
      {
        snprintf(fmt, sizeof(fmt), "%%%sd", prec);
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_SIZE);
        snprintf(buf + colorlen, buflen - colorlen, fmt, (int) e->lines);
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      }
      else if (e->lines <= 0)
        optional = 0;
      break;

    case 'L':
      if (!optional)
      {
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
        make_from(e->env, tmp, sizeof(tmp), true, flags);
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      }
      else if (!check_for_mailing_list(e->env->to, NULL, NULL, 0) &&
               !check_for_mailing_list(e->env->cc, NULL, NULL, 0))
      {
        optional = 0;
      }
      break;

    case 'm':
      if (ctx)
      {
        snprintf(fmt, sizeof(fmt), "%%%sd", prec);
        snprintf(buf, buflen, fmt, ctx->mailbox->msg_count);
      }
      else
        mutt_str_strfcpy(buf, "(null)", buflen);
      break;

    case 'n':
      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_AUTHOR);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec,
                    mutt_get_name(e->env->from));
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'M':
      snprintf(fmt, sizeof(fmt), "%%%sd", prec);
      if (!optional)
      {
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_COLLAPSED);
        if (threads && is_index && e->collapsed && e->num_hidden > 1)
        {
          snprintf(buf + colorlen, buflen - colorlen, fmt, e->num_hidden);
          add_index_color(buf, buflen - colorlen, flags, MT_COLOR_INDEX);
        }
        else if (is_index && threads)
        {
          mutt_format_s(buf + colorlen, buflen - colorlen, prec, " ");
          add_index_color(buf, buflen - colorlen, flags, MT_COLOR_INDEX);
        }
        else
          *buf = '\0';
      }
      else
      {
        if (!(threads && is_index && e->collapsed && e->num_hidden > 1))
          optional = 0;
      }
      break;

    case 'N':
      if (!optional)
      {
        snprintf(fmt, sizeof(fmt), "%%%sd", prec);
        snprintf(buf, buflen, fmt, e->score);
      }
      else
      {
        if (e->score == 0)
          optional = 0;
      }
      break;

    case 'O':
      if (!optional)
      {
        make_from_addr(e->env, tmp, sizeof(tmp), true);
        if (!SaveAddress && (p = strpbrk(tmp, "%@")))
          *p = 0;
        mutt_format_s(buf, buflen, prec, tmp);
      }
      else if (!check_for_mailing_list_addr(e->env->to, NULL, 0) &&
               !check_for_mailing_list_addr(e->env->cc, NULL, 0))
      {
        optional = 0;
      }
      break;

    case 'P':
      mutt_str_strfcpy(buf, hfi->pager_progress, buflen);
      break;

#ifdef USE_NNTP
    case 'q':
      mutt_format_s(buf, buflen, prec, e->env->newsgroups ? e->env->newsgroups : "");
      break;
#endif

    case 'r':
      tmp[0] = 0;
      mutt_addr_write(tmp, sizeof(tmp), e->env->to, true);
      if (optional && tmp[0] == '\0')
        optional = 0;
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'R':
      tmp[0] = 0;
      mutt_addr_write(tmp, sizeof(tmp), e->env->cc, true);
      if (optional && tmp[0] == '\0')
        optional = 0;
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 's':
    {
      char *subj = NULL;
      if (e->env->disp_subj)
        subj = e->env->disp_subj;
      else if (!STAILQ_EMPTY(&SubjectRegexList))
        subj = apply_subject_mods(e->env);
      else
        subj = e->env->subject;
      if (flags & MUTT_FORMAT_TREE && !e->collapsed)
      {
        if (flags & MUTT_FORMAT_FORCESUBJ)
        {
          colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_SUBJECT);
          mutt_format_s(buf + colorlen, buflen - colorlen, "", NONULL(subj));
          add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
          snprintf(tmp, sizeof(tmp), "%s%s", e->tree, buf);
          mutt_format_s_tree(buf, buflen, prec, tmp);
        }
        else
          mutt_format_s_tree(buf, buflen, prec, e->tree);
      }
      else
      {
        colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_SUBJECT);
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, NONULL(subj));
        add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      }
    }
    break;

    case 'S':
      if (e->deleted)
        wch = get_nth_wchar(FlagChars, FlagCharDeleted);
      else if (e->attach_del)
        wch = get_nth_wchar(FlagChars, FlagCharDeletedAttach);
      else if (e->tagged)
        wch = get_nth_wchar(FlagChars, FlagCharTagged);
      else if (e->flagged)
        wch = get_nth_wchar(FlagChars, FlagCharImportant);
      else if (e->replied)
        wch = get_nth_wchar(FlagChars, FlagCharReplied);
      else if (e->read && (ctx && ctx->msgnotreadyet != e->msgno))
        wch = get_nth_wchar(FlagChars, FlagCharSEmpty);
      else if (e->old)
        wch = get_nth_wchar(FlagChars, FlagCharOld);
      else
        wch = get_nth_wchar(FlagChars, FlagCharNew);

      snprintf(tmp, sizeof(tmp), "%s", wch);
      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_FLAGS);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 't':
      tmp[0] = 0;
      if (!check_for_mailing_list(e->env->to, "To ", tmp, sizeof(tmp)) &&
          !check_for_mailing_list(e->env->cc, "Cc ", tmp, sizeof(tmp)))
      {
        if (e->env->to)
          snprintf(tmp, sizeof(tmp), "To %s", mutt_get_name(e->env->to));
        else if (e->env->cc)
          snprintf(tmp, sizeof(tmp), "Cc %s", mutt_get_name(e->env->cc));
      }
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'T':
      snprintf(fmt, sizeof(fmt), "%%%ss", prec);
      snprintf(buf, buflen, fmt,
               (ToChars && ((i = user_is_recipient(e))) < ToChars->len) ?
                   ToChars->chars[i] :
                   " ");
      break;

    case 'u':
      if (e->env->from && e->env->from->mailbox)
      {
        mutt_str_strfcpy(tmp, mutt_addr_for_display(e->env->from), sizeof(tmp));
        p = strpbrk(tmp, "%@");
        if (p)
          *p = 0;
      }
      else
        tmp[0] = 0;
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'v':
      if (mutt_addr_is_user(e->env->from))
      {
        if (e->env->to)
          mutt_format_s(tmp, sizeof(tmp), prec, mutt_get_name(e->env->to));
        else if (e->env->cc)
          mutt_format_s(tmp, sizeof(tmp), prec, mutt_get_name(e->env->cc));
        else
          *tmp = 0;
      }
      else
        mutt_format_s(tmp, sizeof(tmp), prec, mutt_get_name(e->env->from));
      p = strpbrk(tmp, " %@");
      if (p)
        *p = 0;
      mutt_format_s(buf, buflen, prec, tmp);
      break;

    case 'W':
      if (!optional)
      {
        mutt_format_s(buf, buflen, prec, e->env->organization ? e->env->organization : "");
      }
      else if (!e->env->organization)
        optional = 0;
      break;

#ifdef USE_NNTP
    case 'x':
      if (!optional)
      {
        mutt_format_s(buf, buflen, prec, e->env->x_comment_to ? e->env->x_comment_to : "");
      }
      else if (!e->env->x_comment_to)
        optional = 0;
      break;
#endif

    case 'X':
    {
      int count = mutt_count_body_parts(ctx, e);

      /* The recursion allows messages without depth to return 0. */
      if (optional)
        optional = count != 0;

      snprintf(fmt, sizeof(fmt), "%%%sd", prec);
      snprintf(buf, buflen, fmt, count);
    }
    break;

    case 'y':
      if (optional)
        optional = e->env->x_label ? 1 : 0;

      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_LABEL);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec, NONULL(e->env->x_label));
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'Y':
      if (e->env->x_label)
      {
        i = 1; /* reduce reuse recycle */
        struct Email *etmp = NULL;
        if (flags & MUTT_FORMAT_TREE && (e->thread->prev && e->thread->prev->message &&
                                         e->thread->prev->message->env->x_label))
        {
          etmp = e->thread->prev->message;
        }
        else if (flags & MUTT_FORMAT_TREE &&
                 (e->thread->parent && e->thread->parent->message &&
                  e->thread->parent->message->env->x_label))
        {
          etmp = e->thread->parent->message;
        }
        if (etmp && (mutt_str_strcasecmp(e->env->x_label, etmp->env->x_label) == 0))
          i = 0;
      }
      else
        i = 0;

      if (optional)
        optional = i;

      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_LABEL);
      if (i)
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, NONULL(e->env->x_label));
      else
        mutt_format_s(buf + colorlen, buflen - colorlen, prec, "");
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'z':
      if (src[0] == 's') /* status: deleted/new/old/replied */
      {
        const char *ch = NULL;
        if (e->deleted)
          ch = get_nth_wchar(FlagChars, FlagCharDeleted);
        else if (e->attach_del)
          ch = get_nth_wchar(FlagChars, FlagCharDeletedAttach);
        else if (threads && thread_is_new(ctx, e))
          ch = get_nth_wchar(FlagChars, FlagCharNewThread);
        else if (threads && thread_is_old(ctx, e))
          ch = get_nth_wchar(FlagChars, FlagCharOldThread);
        else if (e->read && (ctx && (ctx->msgnotreadyet != e->msgno)))
        {
          if (e->replied)
            ch = get_nth_wchar(FlagChars, FlagCharReplied);
          else
            ch = get_nth_wchar(FlagChars, FlagCharZEmpty);
        }
        else
        {
          if (e->old)
            ch = get_nth_wchar(FlagChars, FlagCharOld);
          else
            ch = get_nth_wchar(FlagChars, FlagCharNew);
        }

        snprintf(tmp, sizeof(tmp), "%s", ch);
        src++;
      }
      else if (src[0] == 'c') /* crypto */
      {
        const char *ch = NULL;
        if ((WithCrypto != 0) && (e->security & GOODSIGN))
          ch = "S";
        else if ((WithCrypto != 0) && (e->security & ENCRYPT))
          ch = "P";
        else if ((WithCrypto != 0) && (e->security & SIGN))
          ch = "s";
        else if (((WithCrypto & APPLICATION_PGP) != 0) && ((e->security & PGP_KEY) == PGP_KEY))
        {
          ch = "K";
        }
        else
          ch = " ";

        snprintf(tmp, sizeof(tmp), "%s", ch);
        src++;
      }
      else if (src[0] == 't') /* tagged, flagged, recipient */
      {
        const char *ch = NULL;
        if (e->tagged)
          ch = get_nth_wchar(FlagChars, FlagCharTagged);
        else if (e->flagged)
          ch = get_nth_wchar(FlagChars, FlagCharImportant);
        else
          ch = get_nth_wchar(ToChars, user_is_recipient(e));

        snprintf(tmp, sizeof(tmp), "%s", ch);
        src++;
      }
      else /* fallthrough */
        break;

      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_FLAGS);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    case 'Z':
    {
      /* New/Old for threads; replied; New/Old for messages */
      const char *first = NULL;
      if (threads && thread_is_new(ctx, e))
        first = get_nth_wchar(FlagChars, FlagCharNewThread);
      else if (threads && thread_is_old(ctx, e))
        first = get_nth_wchar(FlagChars, FlagCharOldThread);
      else if (e->read && (ctx && (ctx->msgnotreadyet != e->msgno)))
      {
        if (e->replied)
          first = get_nth_wchar(FlagChars, FlagCharReplied);
        else
          first = get_nth_wchar(FlagChars, FlagCharZEmpty);
      }
      else
      {
        if (e->old)
          first = get_nth_wchar(FlagChars, FlagCharOld);
        else
          first = get_nth_wchar(FlagChars, FlagCharNew);
      }

      /* Marked for deletion; deleted attachments; crypto */
      const char *second = NULL;
      if (e->deleted)
        second = get_nth_wchar(FlagChars, FlagCharDeleted);
      else if (e->attach_del)
        second = get_nth_wchar(FlagChars, FlagCharDeletedAttach);
      else if ((WithCrypto != 0) && (e->security & GOODSIGN))
        second = "S";
      else if ((WithCrypto != 0) && (e->security & ENCRYPT))
        second = "P";
      else if ((WithCrypto != 0) && (e->security & SIGN))
        second = "s";
      else if (((WithCrypto & APPLICATION_PGP) != 0) && (e->security & PGP_KEY))
        second = "K";
      else
        second = " ";

      /* Tagged, flagged and recipient flag */
      const char *third = NULL;
      if (e->tagged)
        third = get_nth_wchar(FlagChars, FlagCharTagged);
      else if (e->flagged)
        third = get_nth_wchar(FlagChars, FlagCharImportant);
      else
        third = get_nth_wchar(ToChars, user_is_recipient(e));

      snprintf(tmp, sizeof(tmp), "%s%s%s", first, second, third);
    }

      colorlen = add_index_color(buf, buflen, flags, MT_COLOR_INDEX_FLAGS);
      mutt_format_s(buf + colorlen, buflen - colorlen, prec, tmp);
      add_index_color(buf + colorlen, buflen - colorlen, flags, MT_COLOR_INDEX);
      break;

    default:
      snprintf(buf, buflen, "%%%s%c", prec, op);
      break;
  }

  if (optional)
  {
    mutt_expando_format(buf, buflen, col, cols, if_str, index_format_str,
                        (unsigned long) hfi, flags);
  }
  else if (flags & MUTT_FORMAT_OPTIONAL)
  {
    mutt_expando_format(buf, buflen, col, cols, else_str, index_format_str,
                        (unsigned long) hfi, flags);
  }

  return src;
}

/**
 * mutt_make_string_flags - Create formatted strings using mailbox expandos
 * @param buf    Buffer for the result
 * @param buflen Buffer length
 * @param s      printf-line format string
 * @param ctx    Mailbox
 * @param e      Email
 * @param flags  Format flags
 */
void mutt_make_string_flags(char *buf, size_t buflen, const char *s,
                            struct Context *ctx, struct Email *e, enum FormatFlag flags)
{
  struct HdrFormatInfo hfi;

  hfi.email = e;
  hfi.ctx = ctx;
  hfi.pager_progress = 0;

  mutt_expando_format(buf, buflen, 0, MuttIndexWindow->cols, s,
                      index_format_str, (unsigned long) &hfi, flags);
}

/**
 * mutt_make_string_info - Create pager status bar string
 * @param buf    Buffer for the result
 * @param buflen Buffer length
 * @param cols   Number of screen columns
 * @param s      printf-line format string
 * @param hfi    Mailbox data to pass to the formatter
 * @param flags  Format flags
 */
void mutt_make_string_info(char *buf, size_t buflen, int cols, const char *s,
                           struct HdrFormatInfo *hfi, enum FormatFlag flags)
{
  mutt_expando_format(buf, buflen, 0, cols, s, index_format_str, (unsigned long) hfi, flags);
}
