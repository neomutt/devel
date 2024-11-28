/**
 * @file
 * String processing routines to generate the mail index
 *
 * @authors
 * Copyright (C) 1996-2000,2002,2007 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2016 Ian Zimmerman <itz@primate.net>
 * Copyright (C) 2016-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2017 Stefan Assmann <sassmann@kpanic.de>
 * Copyright (C) 2019 Victor Fernandes <criw@pm.me>
 * Copyright (C) 2019-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2021 Ashish Panigrahi <ashish.panigrahi@protonmail.com>
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
 * Copyright (C) 2023 наб <nabijaczleweli@nabijaczleweli.xyz>
 * Copyright (C) 2024 Dennis Schön <mail@dennis-schoen.de>
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
 * @page index_expando_index String processing routines to generate the mail index
 *
 * String processing routines to generate the mail index
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "private.h"
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "expando_index.h"
#include "attach/lib.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "ncrypt/lib.h"
#include "globals.h"
#include "hook.h"
#include "maillist.h"
#include "mutt_thread.h"
#include "muttlib.h"
#include "mx.h"
#include "subjectrx.h"
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif

static void mailbox_mailbox_name(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf);

/**
 * enum FieldType - Header types
 *
 * Strings for printing headers
 */
enum FieldType
{
  DISP_TO,    ///< To: string
  DISP_CC,    ///< Cc: string
  DISP_BCC,   ///< Bcc: string
  DISP_FROM,  ///< From: string
  DISP_PLAIN, ///< Empty string
  DISP_MAX,
};

/**
 * IndexDateChoice - Which email date to display in the Index
 */
enum IndexDateChoice
{
  SENT_SENDER, ///< Date sent in the sender's timezone
  SENT_LOCAL,  ///< Date sent in the local timezone
  RECV_LOCAL   ///< Date received in the local timezone
};

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
  static const char *long_prefixes[DISP_MAX] = {
    [DISP_TO] = "To ", [DISP_CC] = "Cc ", [DISP_BCC] = "Bcc ",
    [DISP_FROM] = "",  [DISP_PLAIN] = "",
  };

  const struct MbTable *c_from_chars = cs_subset_mbtable(NeoMutt->sub, "from_chars");

  if (!c_from_chars || !c_from_chars->chars || (c_from_chars->len == 0))
    return long_prefixes[disp];

  const char *pchar = mbtable_get_nth_wchar(c_from_chars, disp);
  if (mutt_str_len(pchar) == 0)
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
 * @param flags    Format flags, see #MuttFormatFlags
 *
 * Generate the %F or %L field in $index_format.
 * This is the author, or recipient of the email.
 *
 * The field can optionally be prefixed by a character from $from_chars.
 * If $from_chars is not set, the prefix will be, "To", "Cc", etc
 */
static void make_from(struct Envelope *env, char *buf, size_t buflen,
                      bool do_lists, MuttFormatFlags flags)
{
  if (!env || !buf)
    return;

  bool me;
  enum FieldType disp;
  struct AddressList *name = NULL;

  me = mutt_addr_is_user(TAILQ_FIRST(&env->from));

  if (do_lists || me)
  {
    if (check_for_mailing_list(&env->to, make_from_prefix(DISP_TO), buf, buflen))
      return;
    if (check_for_mailing_list(&env->cc, make_from_prefix(DISP_CC), buf, buflen))
      return;
  }

  if (me && !TAILQ_EMPTY(&env->to))
  {
    disp = (flags & MUTT_FORMAT_PLAIN) ? DISP_PLAIN : DISP_TO;
    name = &env->to;
  }
  else if (me && !TAILQ_EMPTY(&env->cc))
  {
    disp = DISP_CC;
    name = &env->cc;
  }
  else if (me && !TAILQ_EMPTY(&env->bcc))
  {
    disp = DISP_BCC;
    name = &env->bcc;
  }
  else if (!TAILQ_EMPTY(&env->from))
  {
    disp = DISP_FROM;
    name = &env->from;
  }
  else
  {
    *buf = '\0';
    return;
  }

  snprintf(buf, buflen, "%s%s", make_from_prefix(disp), mutt_get_name(TAILQ_FIRST(name)));
}

/**
 * make_from_addr - Create a 'from' address for a reply email
 * @param env      Envelope of current email
 * @param buf      Buffer for the result
 * @param buflen   Length of buffer
 * @param do_lists If true, check for mailing lists
 */
static void make_from_addr(struct Envelope *env, char *buf, size_t buflen, bool do_lists)
{
  if (!env || !buf)
    return;

  bool me = mutt_addr_is_user(TAILQ_FIRST(&env->from));

  if (do_lists || me)
  {
    if (check_for_mailing_list_addr(&env->to, buf, buflen))
      return;
    if (check_for_mailing_list_addr(&env->cc, buf, buflen))
      return;
  }

  if (me && !TAILQ_EMPTY(&env->to))
    snprintf(buf, buflen, "%s", buf_string(TAILQ_FIRST(&env->to)->mailbox));
  else if (me && !TAILQ_EMPTY(&env->cc))
    snprintf(buf, buflen, "%s", buf_string(TAILQ_FIRST(&env->cc)->mailbox));
  else if (!TAILQ_EMPTY(&env->from))
    mutt_str_copy(buf, buf_string(TAILQ_FIRST(&env->from)->mailbox), buflen);
  else
    *buf = '\0';
}

/**
 * user_in_addr - Do any of the addresses refer to the user?
 * @param al AddressList
 * @retval true Any of the addresses match one of the user's addresses
 */
static bool user_in_addr(struct AddressList *al)
{
  struct Address *a = NULL;
  TAILQ_FOREACH(a, al, entries)
  if (mutt_addr_is_user(a))
    return true;
  return false;
}

/**
 * user_is_recipient - Is the user a recipient of the message
 * @param e Email to test
 * @retval enum Character index into the `$to_chars` config variable
 */
static enum ToChars user_is_recipient(struct Email *e)
{
  if (!e || !e->env)
    return FLAG_CHAR_TO_NOT_IN_THE_LIST;

  struct Envelope *env = e->env;

  if (!e->recip_valid)
  {
    e->recip_valid = true;

    if (mutt_addr_is_user(TAILQ_FIRST(&env->from)))
    {
      e->recipient = FLAG_CHAR_TO_ORIGINATOR;
    }
    else if (user_in_addr(&env->to))
    {
      if (TAILQ_NEXT(TAILQ_FIRST(&env->to), entries) || !TAILQ_EMPTY(&env->cc))
        e->recipient = FLAG_CHAR_TO_TO; /* non-unique recipient */
      else
        e->recipient = FLAG_CHAR_TO_UNIQUE; /* unique recipient */
    }
    else if (user_in_addr(&env->cc))
    {
      e->recipient = FLAG_CHAR_TO_CC;
    }
    else if (check_for_mailing_list(&env->to, NULL, NULL, 0))
    {
      e->recipient = FLAG_CHAR_TO_SUBSCRIBED_LIST;
    }
    else if (check_for_mailing_list(&env->cc, NULL, NULL, 0))
    {
      e->recipient = FLAG_CHAR_TO_SUBSCRIBED_LIST;
    }
    else if (user_in_addr(&env->reply_to))
    {
      e->recipient = FLAG_CHAR_TO_REPLY_TO;
    }
    else
    {
      e->recipient = FLAG_CHAR_TO_NOT_IN_THE_LIST;
    }
  }

  return e->recipient;
}

/**
 * thread_is_new - Does the email thread contain any new emails?
 * @param e Email
 * @retval true Thread contains new mail
 */
static bool thread_is_new(struct Email *e)
{
  return e->collapsed && (e->num_hidden > 1) && (mutt_thread_contains_unread(e) == 1);
}

/**
 * thread_is_old - Does the email thread contain any unread emails?
 * @param e Email
 * @retval true Thread contains unread mail
 */
static bool thread_is_old(struct Email *e)
{
  return e->collapsed && (e->num_hidden > 1) && (mutt_thread_contains_unread(e) == 2);
}

/**
 * index_email_date - Index: Sent/Received Local/Sender date and time
 * @param node   ExpandoNode containing the callback
 * @param e      Email
 * @param which  Which date to use
 * @param flags  Flags, see #MuttFormatFlags
 * @param buf    Buffer for the result
 * @param format Format string
 */
static void index_email_date(const struct ExpandoNode *node, const struct Email *e,
                             enum IndexDateChoice which, MuttFormatFlags flags,
                             struct Buffer *buf, const char *format)
{
  char *fmt = mutt_str_dup(format);
  if (!fmt)
    return;

  struct tm tm = { 0 };
  switch (which)
  {
    case SENT_SENDER:
    {
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
      int offset = (e->zhours * 3600 + e->zminutes * 60) * (e->zoccident ? -1 : 1);
      const time_t now = e->date_sent + offset;
      tm = mutt_date_gmtime(now);
      tm.tm_gmtoff = offset;
      break;
#else
      FALLTHROUGH;
#endif
    }
    case SENT_LOCAL:
    {
      tm = mutt_date_localtime(e->date_sent);
      break;
    }
    case RECV_LOCAL:
    {
      tm = mutt_date_localtime(e->received);
      break;
    }
  }

  const bool use_c_locale = (*fmt == '!');

  if (which != RECV_LOCAL)
  {
    // The sender's time zone might only be available as a numerical offset, so "%Z" behaves like "%z".
    for (char *bigz = fmt; (bigz = strstr(bigz, "%Z")); bigz += 2)
    {
      bigz[1] = 'z';
    }
  }

  char out[128] = { 0 };
  if (use_c_locale)
  {
    strftime_l(out, sizeof(out), fmt + 1, &tm, NeoMutt->time_c_locale);
  }
  else
  {
    strftime(out, sizeof(out), fmt, &tm);
  }

  FREE(&fmt);

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_DATE);
  buf_strcpy(buf, out);
}

/**
 * email_attachment_count - Index: Number of MIME attachments - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_attachment_count(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return 0;

  struct Mailbox *m = efi->mailbox;

  struct Message *msg = mx_msg_open(m, e);
  if (!msg)
    return 0;

  const int num = mutt_count_body_parts(e, msg->fp);
  mx_msg_close(m, &msg);
  return num;
}

/**
 * email_body_characters - Index: Number of raw bytes - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_body_characters(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = (const struct EmailFormatInfo *) data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_SIZE);

  mutt_str_pretty_size(buf, email_get_size(e));
}

/**
 * email_combined_flags - Index: Status flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_combined_flags(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  const int msg_in_pager = efi->msg_in_pager;

  const struct MbTable *c_crypt_chars = cs_subset_mbtable(NeoMutt->sub, "crypt_chars");
  const struct MbTable *c_flag_chars = cs_subset_mbtable(NeoMutt->sub, "flag_chars");
  const struct MbTable *c_to_chars = cs_subset_mbtable(NeoMutt->sub, "to_chars");
  const bool threads = mutt_using_threads();

  const char *first = NULL;
  if (threads && thread_is_new(e))
  {
    first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_NEW_THREAD);
  }
  else if (threads && thread_is_old(e))
  {
    first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_OLD_THREAD);
  }
  else if (e->read && (msg_in_pager != e->msgno))
  {
    if (e->replied)
    {
      first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_REPLIED);
    }
    else
    {
      first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_ZEMPTY);
    }
  }
  else
  {
    if (e->old)
    {
      first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_OLD);
    }
    else
    {
      first = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_NEW);
    }
  }

  /* Marked for deletion; deleted attachments; crypto */
  const char *second = NULL;
  if (e->deleted)
    second = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED);
  else if (e->attach_del)
    second = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED_ATTACH);
  else if ((WithCrypto != 0) && (e->security & SEC_GOODSIGN))
    second = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_GOOD_SIGN);
  else if ((WithCrypto != 0) && (e->security & SEC_ENCRYPT))
    second = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_ENCRYPTED);
  else if ((WithCrypto != 0) && (e->security & SEC_SIGN))
    second = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_SIGNED);
  else if (((WithCrypto & APPLICATION_PGP) != 0) && (e->security & PGP_KEY))
    second = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_CONTAINS_KEY);
  else
    second = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_NO_CRYPTO);

  /* Tagged, flagged and recipient flag */
  const char *third = NULL;
  if (e->tagged)
    third = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_TAGGED);
  else if (e->flagged)
    third = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_IMPORTANT);
  else
    third = mbtable_get_nth_wchar(c_to_chars, user_is_recipient(e));

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_FLAGS);

  buf_printf(buf, "%s%s%s", first, second, third);
}

/**
 * email_crypto_flags - Index: Message crypto flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_crypto_flags(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  const struct MbTable *c_crypt_chars = cs_subset_mbtable(NeoMutt->sub, "crypt_chars");

  const char *ch = NULL;
  if ((WithCrypto != 0) && (e->security & SEC_GOODSIGN))
  {
    ch = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_GOOD_SIGN);
  }
  else if ((WithCrypto != 0) && (e->security & SEC_ENCRYPT))
  {
    ch = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_ENCRYPTED);
  }
  else if ((WithCrypto != 0) && (e->security & SEC_SIGN))
  {
    ch = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_SIGNED);
  }
  else if (((WithCrypto & APPLICATION_PGP) != 0) && ((e->security & PGP_KEY) == PGP_KEY))
  {
    ch = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_CONTAINS_KEY);
  }
  else
  {
    ch = mbtable_get_nth_wchar(c_crypt_chars, FLAG_CHAR_CRYPT_NO_CRYPTO);
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_FLAGS);
  buf_strcpy(buf, ch);
}

/**
 * email_date_format - Index: Sent date and time - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_date_format(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  const char *c_date_format = cs_subset_string(NeoMutt->sub, "date_format");
  const char *cp = NONULL(c_date_format);

  index_email_date(node, e, SENT_SENDER, flags, buf, cp);
}

/**
 * email_date_format_local - Index: Sent local date and time - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_date_format_local(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  const char *c_date_format = cs_subset_string(NeoMutt->sub, "date_format");
  const char *cp = NONULL(c_date_format);

  index_email_date(node, e, SENT_LOCAL, flags, buf, cp);
}

/**
 * email_date_format_local_num - Index: Local Date and time - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_date_format_local_num(const struct ExpandoNode *node,
                                        void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->date_sent;
}

/**
 * email_date_format_num - Index: Senders Date and time - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_date_format_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->date_sent;
}

/**
 * email_date_strf - Index: Sent date and time - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_date_strf(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  index_email_date(node, e, SENT_SENDER, flags, buf, node->text);
}

/**
 * email_date_strf_num - Index: Sender's date and time - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_date_strf_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->date_sent;
}

/**
 * email_date_strf_local - Index: Sent local date and time - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_date_strf_local(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  index_email_date(node, e, SENT_LOCAL, flags, buf, node->text);
}

/**
 * email_date_strf_local_num - Index: Local date and time - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_date_strf_local_num(const struct ExpandoNode *node,
                                      void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->date_sent;
}

/**
 * email_flag_chars - Index: Status flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_flag_chars(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  const struct MbTable *c_flag_chars = cs_subset_mbtable(NeoMutt->sub, "flag_chars");
  const int msg_in_pager = efi->msg_in_pager;

  const char *wch = NULL;
  if (e->deleted)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED);
  else if (e->attach_del)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED_ATTACH);
  else if (e->tagged)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_TAGGED);
  else if (e->flagged)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_IMPORTANT);
  else if (e->replied)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_REPLIED);
  else if (e->read && (msg_in_pager != e->msgno))
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_SEMPTY);
  else if (e->old)
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_OLD);
  else
    wch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_NEW);

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_FLAGS);

  buf_strcpy(buf, wch);
}

/**
 * email_from_list - Index: List address - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_from_list(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  char tmp[128] = { 0 };

  make_from(e->env, tmp, sizeof(tmp), true, flags);

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);
  buf_strcpy(buf, tmp);
}

/**
 * email_index_hook - Index: index-format-hook - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_index_hook(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  struct Mailbox *m = efi->mailbox;

  const struct Expando *exp = mutt_idxfmt_hook(node->text, m, e);
  if (!exp)
    return;

  struct ExpandoRenderData IndexRenderData[] = {
    // clang-format off
    { ED_EMAIL, IndexRenderCallbacks, data, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  expando_filter(exp, IndexRenderCallbacks, data, MUTT_FORMAT_NO_FLAGS,
                 buf->dsize, EnvList, buf);
}

/**
 * email_lines - Index: Number of lines - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_lines(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_SIZE);

  return e->lines;
}

/**
 * email_list_or_save_folder - Index: List Name or Save folder - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_list_or_save_folder(const struct ExpandoNode *node, void *data,
                                      MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  char tmp[128] = { 0 };
  char *p = NULL;

  make_from_addr(e->env, tmp, sizeof(tmp), true);
  const bool c_save_address = cs_subset_bool(NeoMutt->sub, "save_address");
  if (!c_save_address && (p = strpbrk(tmp, "%@")))
  {
    *p = '\0';
  }

  buf_strcpy(buf, tmp);
}

/**
 * email_message_flags - Index: Message tag flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_message_flags(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  const struct MbTable *c_flag_chars = cs_subset_mbtable(NeoMutt->sub, "flag_chars");
  const struct MbTable *c_to_chars = cs_subset_mbtable(NeoMutt->sub, "to_chars");

  const char *ch = NULL;
  if (e->tagged)
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_TAGGED);
  }
  else if (e->flagged)
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_IMPORTANT);
  }
  else
  {
    ch = mbtable_get_nth_wchar(c_to_chars, user_is_recipient(e));
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_FLAGS);
  buf_strcpy(buf, ch);
}

/**
 * email_number - Index: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_number(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_NUMBER);

  return e->msgno + 1;
}

/**
 * email_score - Index: Message score - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_score(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->score;
}

/**
 * email_size - Index: Number of bytes - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_size(const struct ExpandoNode *node, void *data,
                       MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_SIZE);

  mutt_str_pretty_size(buf, e->body->length);
}

/**
 * email_size_num - Index: Number of bytes - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_size_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->body)
    return 0;

  return e->body->length;
}

/**
 * email_status_flags - Index: Message status flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_status_flags(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  const bool threads = mutt_using_threads();
  const struct MbTable *c_flag_chars = cs_subset_mbtable(NeoMutt->sub, "flag_chars");
  const int msg_in_pager = efi->msg_in_pager;

  const char *ch = NULL;
  if (e->deleted)
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED);
  }
  else if (e->attach_del)
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_DELETED_ATTACH);
  }
  else if (threads && thread_is_new(e))
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_NEW_THREAD);
  }
  else if (threads && thread_is_old(e))
  {
    ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_OLD_THREAD);
  }
  else if (e->read && (msg_in_pager != e->msgno))
  {
    if (e->replied)
    {
      ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_REPLIED);
    }
    else
    {
      ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_ZEMPTY);
    }
  }
  else
  {
    if (e->old)
    {
      ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_OLD);
    }
    else
    {
      ch = mbtable_get_nth_wchar(c_flag_chars, FLAG_CHAR_NEW);
    }
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_FLAGS);
  buf_strcpy(buf, ch);
}

/**
 * email_strf_recv_local - Index: Received local date and time - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_strf_recv_local(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  index_email_date(node, e, RECV_LOCAL, flags, buf, node->text);
}

/**
 * email_strf_recv_local_num - Index: Local received date and time - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_strf_recv_local_num(const struct ExpandoNode *node,
                                      void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  return e->received;
}

/**
 * email_tags - Index: Message tags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_tags(const struct ExpandoNode *node, void *data,
                       MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_TAGS);
  driver_tags_get_transformed(&e->tags, buf);
}

/**
 * email_tags_transformed - Index: Individual tag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_tags_transformed(const struct ExpandoNode *node, void *data,
                                   MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  char *tag = mutt_hash_find(TagFormats, node->text);
  if (!tag)
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_TAG);
  driver_tags_get_transformed_for(&e->tags, tag, buf);
}

/**
 * email_thread_count - Index: Number of messages thread - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_thread_count(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  struct Mailbox *m = efi->mailbox;

  return mutt_messages_in_thread(m, e, MIT_NUM_MESSAGES);
}

/**
 * email_thread_hidden_count - Index: Number of hidden messages - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_thread_hidden_count(const struct ExpandoNode *node, void *data,
                                      MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return;

  const bool threads = mutt_using_threads();
  const bool is_index = (flags & MUTT_FORMAT_INDEX) != 0;

  if (threads && is_index && e->collapsed && (e->num_hidden > 1))
  {
    if (flags & MUTT_FORMAT_INDEX)
      node_expando_set_color(node, MT_COLOR_INDEX_COLLAPSED);
    const int num = e->num_hidden;
    buf_printf(buf, "%d", num);
  }
  else if (is_index && threads)
  {
    if (flags & MUTT_FORMAT_INDEX)
      node_expando_set_color(node, MT_COLOR_INDEX_COLLAPSED);
    const char *s = " ";
    buf_strcpy(buf, s);
  }
}

/**
 * email_thread_hidden_count_num - Index: Number of hidden messages - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_thread_hidden_count_num(const struct ExpandoNode *node,
                                          void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e)
    return 0;

  const bool threads = mutt_using_threads();
  const bool is_index = (flags & MUTT_FORMAT_INDEX) != 0;

  if (threads && is_index && e->collapsed && (e->num_hidden > 1))
  {
    if (flags & MUTT_FORMAT_INDEX)
      node_expando_set_color(node, MT_COLOR_INDEX_COLLAPSED);
    return e->num_hidden;
  }

  return 0;
}

/**
 * email_thread_number - Index: Thread index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long email_thread_number(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  struct Mailbox *m = efi->mailbox;

  return mutt_messages_in_thread(m, e, MIT_POSITION);
}

/**
 * email_thread_tags - Index: Tags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_thread_tags(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  bool have_tags = true;
  struct Buffer *tags = buf_pool_get();
  driver_tags_get_transformed(&e->tags, tags);
  if (!buf_is_empty(tags))
  {
    if (flags & MUTT_FORMAT_TREE)
    {
      struct Buffer *parent_tags = buf_pool_get();
      if (e->thread->prev && e->thread->prev->message)
      {
        driver_tags_get_transformed(&e->thread->prev->message->tags, parent_tags);
      }
      if (!parent_tags && e->thread->parent && e->thread->parent->message)
      {
        driver_tags_get_transformed(&e->thread->parent->message->tags, parent_tags);
      }
      if (parent_tags && buf_istr_equal(tags, parent_tags))
        have_tags = false;
      buf_pool_release(&parent_tags);
    }
  }
  else
  {
    have_tags = false;
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_TAGS);

  const char *s = have_tags ? buf_string(tags) : "";
  buf_strcpy(buf, s);

  buf_pool_release(&tags);
}

/**
 * email_to_chars - Index: $to_chars flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void email_to_chars(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e)
    return;

  const struct MbTable *c_to_chars = cs_subset_mbtable(NeoMutt->sub, "to_chars");

  int i;
  const char *s = (c_to_chars && ((i = user_is_recipient(e))) < c_to_chars->len) ?
                      c_to_chars->chars[i] :
                      " ";

  buf_strcpy(buf, s);
}

/**
 * envelope_cc_all - Index: Cc recipients - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_cc_all(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  mutt_addrlist_write(&e->env->cc, buf, true);
}

/**
 * envelope_first_name - Index: First name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_first_name(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *from = TAILQ_FIRST(&e->env->from);
  const struct Address *to = TAILQ_FIRST(&e->env->to);
  const struct Address *cc = TAILQ_FIRST(&e->env->cc);

  char tmp[128] = { 0 };
  char *p = NULL;

  if (mutt_addr_is_user(from))
  {
    if (to)
    {
      const char *s = mutt_get_name(to);
      mutt_str_copy(tmp, NONULL(s), sizeof(tmp));
    }
    else if (cc)
    {
      const char *s = mutt_get_name(cc);
      mutt_str_copy(tmp, NONULL(s), sizeof(tmp));
    }
  }
  else
  {
    const char *s = mutt_get_name(from);
    mutt_str_copy(tmp, NONULL(s), sizeof(tmp));
  }
  p = strpbrk(tmp, " %@");
  if (p)
  {
    *p = '\0';
  }

  buf_strcpy(buf, tmp);
}

/**
 * envelope_from - Index: Author Address - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_from(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *from = TAILQ_FIRST(&e->env->from);

  const char *s = NULL;
  if (from && from->mailbox)
  {
    s = mutt_addr_for_display(from);
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);
  buf_strcpy(buf, s);
}

/**
 * envelope_from_full - Index: Sender - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_from_full(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  mutt_addrlist_write(&e->env->from, buf, true);
}

/**
 * envelope_initials - Index: Initials of author - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_initials(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *from = TAILQ_FIRST(&e->env->from);

  char tmp[128] = { 0 };

  if (mutt_mb_get_initials(mutt_get_name(from), tmp, sizeof(tmp)))
  {
    if (flags & MUTT_FORMAT_INDEX)
      node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);

    buf_strcpy(buf, tmp);
    return;
  }

  envelope_from(node, data, flags, buf);
}

/**
 * envelope_list_address - Index: Email list - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_list_address(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  char tmp[128] = { 0 };

  if (first_mailing_list(tmp, sizeof(tmp), &e->env->to) ||
      first_mailing_list(tmp, sizeof(tmp), &e->env->cc))
  {
    buf_strcpy(buf, tmp);
    return;
  }

  mailbox_mailbox_name(node, data, flags, buf);
}

/**
 * envelope_list_empty - Index: Mailing list - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_list_empty(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  char tmp[128] = { 0 };

  if (first_mailing_list(tmp, sizeof(tmp), &e->env->to) ||
      first_mailing_list(tmp, sizeof(tmp), &e->env->cc))
  {
    buf_strcpy(buf, tmp);
  }
}

/**
 * envelope_message_id - Index: Message-id - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_message_id(const struct ExpandoNode *node, void *data,
                                MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const char *s = e->env->message_id ? e->env->message_id : "<no.id>";
  buf_strcpy(buf, s);
}

/**
 * envelope_name - Index: Author's real name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_name(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *from = TAILQ_FIRST(&e->env->from);

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);

  const char *s = mutt_get_name(from);
  buf_strcpy(buf, s);
}

/**
 * envelope_newsgroup - Index: Newsgroup name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_newsgroup(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const char *s = e->env->newsgroups;
  buf_strcpy(buf, s);
}

/**
 * envelope_organization - Index: Organization - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_organization(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const char *s = e->env->organization;
  buf_strcpy(buf, s);
}

/**
 * envelope_reply_to - Index: Reply-to address - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_reply_to(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *reply_to = TAILQ_FIRST(&e->env->reply_to);

  if (reply_to && reply_to->mailbox)
  {
    if (flags & MUTT_FORMAT_INDEX)
      node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);
    const char *s = mutt_addr_for_display(reply_to);
    buf_strcpy(buf, s);
    return;
  }

  envelope_from(node, data, flags, buf);
}

/**
 * envelope_sender - Index: Author name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_sender(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  char tmp[128] = { 0 };

  make_from(e->env, tmp, sizeof(tmp), false, MUTT_FORMAT_NO_FLAGS);

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);

  buf_strcpy(buf, tmp);
}

/**
 * envelope_sender_plain - Index: Plain author name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_sender_plain(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = (const struct EmailFormatInfo *) data;
  struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  char tmp[128] = { 0 };

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_AUTHOR);

  make_from(e->env, tmp, sizeof(tmp), false, MUTT_FORMAT_PLAIN);

  buf_strcpy(buf, tmp);
}

/**
 * envelope_spam - Index: Spam attributes - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_spam(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  buf_copy(buf, &e->env->spam);
}

/**
 * envelope_subject - Index: Subject - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_subject(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  if ((flags & MUTT_FORMAT_TREE) && !e->collapsed && !(flags & MUTT_FORMAT_FORCESUBJ))
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_SUBJECT);

  subjrx_apply_mods(e->env);

  if (e->env->disp_subj)
    buf_strcpy(buf, e->env->disp_subj);
  else
    buf_strcpy(buf, e->env->subject);
}

/**
 * envelope_thread_tree - Index: Thread tree - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_thread_tree(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  if (!(flags & MUTT_FORMAT_TREE) || e->collapsed)
    return;

  node_expando_set_color(node, MT_COLOR_TREE);
  node_expando_set_has_tree(node, true);
  buf_strcpy(buf, e->tree);
}

/**
 * envelope_thread_x_label - Index: X-Label (if different) - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_thread_x_label(const struct ExpandoNode *node, void *data,
                                    MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  bool label = true;
  if (e->env->x_label)
  {
    struct Email *e_tmp = NULL;
    if (flags & MUTT_FORMAT_TREE && (e->thread->prev && e->thread->prev->message &&
                                     e->thread->prev->message->env->x_label))
    {
      e_tmp = e->thread->prev->message;
    }
    else if (flags & MUTT_FORMAT_TREE && (e->thread->parent && e->thread->parent->message &&
                                          e->thread->parent->message->env->x_label))
    {
      e_tmp = e->thread->parent->message;
    }

    if (e_tmp && mutt_istr_equal(e->env->x_label, e_tmp->env->x_label))
    {
      label = false;
    }
  }
  else
  {
    label = false;
  }

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_LABEL);

  if (label)
  {
    const char *s = e->env->x_label;
    buf_strcpy(buf, s);
  }
}

/**
 * envelope_to - Index: To field - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_to(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *to = TAILQ_FIRST(&e->env->to);
  const struct Address *cc = TAILQ_FIRST(&e->env->cc);

  char tmp[128] = { 0 };

  if (!check_for_mailing_list(&e->env->to, "To ", tmp, sizeof(tmp)) &&
      !check_for_mailing_list(&e->env->cc, "Cc ", tmp, sizeof(tmp)))
  {
    if (to)
      snprintf(tmp, sizeof(tmp), "To %s", mutt_get_name(to));
    else if (cc)
      snprintf(tmp, sizeof(tmp), "Cc %s", mutt_get_name(cc));
    else
    {
      tmp[0] = '\0';
    }
  }

  buf_strcpy(buf, tmp);
}

/**
 * envelope_to_all - Index: To recipients - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_to_all(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  mutt_addrlist_write(&e->env->to, buf, true);
}

/**
 * envelope_username - Index: User name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_username(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const struct Address *from = TAILQ_FIRST(&e->env->from);
  if (!from || !from->mailbox)
    return;

  char tmp[128] = { 0 };
  char *p = NULL;

  mutt_str_copy(tmp, mutt_addr_for_display(from), sizeof(tmp));
  p = strpbrk(tmp, "%@");
  if (p)
  {
    *p = '\0';
  }

  buf_strcpy(buf, tmp);
}

/**
 * envelope_x_comment_to - Index: X-Comment-To - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_x_comment_to(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  const char *s = e->env->x_comment_to;
  buf_strcpy(buf, s);
}

/**
 * envelope_x_label - Index: X-Label - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void envelope_x_label(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  const struct Email *e = efi->email;
  if (!e || !e->env)
    return;

  if (flags & MUTT_FORMAT_INDEX)
    node_expando_set_color(node, MT_COLOR_INDEX_LABEL);

  const char *s = e->env->x_label;
  buf_strcpy(buf, s);
}

/**
 * mailbox_mailbox_name - Index: Filename - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void mailbox_mailbox_name(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;
  struct Mailbox *m = efi->mailbox;
  if (!m)
  {
    buf_addstr(buf, "(null)");
    return;
  }

  char *p = NULL;

#ifdef USE_NOTMUCH
  struct Email *e = efi->email;
  if (m->type == MUTT_NOTMUCH)
  {
    p = nm_email_get_folder_rel_db(m, e);
  }
#endif
  if (!p)
  {
    p = strrchr(mailbox_path(m), '/');
    if (p)
    {
      p++;
    }
  }
  buf_addstr(buf, p ? p : mailbox_path(m));
}

/**
 * mailbox_message_count - Index: Total number of message - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long mailbox_message_count(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct EmailFormatInfo *efi = data;
  const struct Mailbox *m = efi->mailbox;

  if (m)
    return m->msg_count;

  return 0;
}

/**
 * mailbox_percentage - Index: Progress indicator - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void mailbox_percentage(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct EmailFormatInfo *efi = data;

  const char *s = efi->pager_progress;
  buf_strcpy(buf, s);
}

/**
 * IndexRenderCallbacks - Callbacks for Index Expandos
 *
 * @sa IndexFormatDef, ExpandoDataEmail, ExpandoDataEnvelope, ExpandoDataGlobal, ExpandoDataMailbox
 */
const struct ExpandoRenderCallback IndexRenderCallbacks[] = {
  // clang-format off
  { ED_EMAIL,    ED_EMA_ATTACHMENT_COUNT,    NULL,                      email_attachment_count },
  { ED_EMAIL,    ED_EMA_BODY_CHARACTERS,     email_body_characters,     NULL },
  { ED_EMAIL,    ED_EMA_COMBINED_FLAGS,      email_combined_flags,      NULL },
  { ED_EMAIL,    ED_EMA_CRYPTO_FLAGS,        email_crypto_flags,        NULL },
  { ED_EMAIL,    ED_EMA_DATE_FORMAT,         email_date_format,         email_date_format_num },
  { ED_EMAIL,    ED_EMA_DATE_FORMAT_LOCAL,   email_date_format_local,   email_date_format_local_num },
  { ED_EMAIL,    ED_EMA_DATE_STRF,           email_date_strf,           email_date_strf_num },
  { ED_EMAIL,    ED_EMA_DATE_STRF_LOCAL,     email_date_strf_local,     email_date_strf_local_num },
  { ED_EMAIL,    ED_EMA_FLAG_CHARS,          email_flag_chars,          NULL },
  { ED_EMAIL,    ED_EMA_FROM_LIST,           email_from_list,           NULL },
  { ED_EMAIL,    ED_EMA_INDEX_HOOK,          email_index_hook,          NULL },
  { ED_EMAIL,    ED_EMA_LINES,               NULL,                      email_lines },
  { ED_EMAIL,    ED_EMA_LIST_OR_SAVE_FOLDER, email_list_or_save_folder, NULL },
  { ED_EMAIL,    ED_EMA_MESSAGE_FLAGS,       email_message_flags,       NULL },
  { ED_EMAIL,    ED_EMA_NUMBER,              NULL,                      email_number },
  { ED_EMAIL,    ED_EMA_SCORE,               NULL,                      email_score },
  { ED_EMAIL,    ED_EMA_SIZE,                email_size,                email_size_num },
  { ED_EMAIL,    ED_EMA_STATUS_FLAGS,        email_status_flags,        NULL },
  { ED_EMAIL,    ED_EMA_STRF_RECV_LOCAL,     email_strf_recv_local,     email_strf_recv_local_num },
  { ED_EMAIL,    ED_EMA_TAGS,                email_tags,                NULL },
  { ED_EMAIL,    ED_EMA_TAGS_TRANSFORMED,    email_tags_transformed,    NULL },
  { ED_EMAIL,    ED_EMA_THREAD_COUNT,        NULL,                      email_thread_count },
  { ED_EMAIL,    ED_EMA_THREAD_HIDDEN_COUNT, email_thread_hidden_count, email_thread_hidden_count_num },
  { ED_EMAIL,    ED_EMA_THREAD_NUMBER,       NULL,                      email_thread_number },
  { ED_EMAIL,    ED_EMA_THREAD_TAGS,         email_thread_tags,         NULL },
  { ED_EMAIL,    ED_EMA_TO_CHARS,            email_to_chars,            NULL },
  { ED_ENVELOPE, ED_ENV_CC_ALL,              envelope_cc_all,           NULL },
  { ED_ENVELOPE, ED_ENV_FIRST_NAME,          envelope_first_name,       NULL },
  { ED_ENVELOPE, ED_ENV_FROM,                envelope_from,             NULL },
  { ED_ENVELOPE, ED_ENV_FROM_FULL,           envelope_from_full,        NULL },
  { ED_ENVELOPE, ED_ENV_INITIALS,            envelope_initials,         NULL },
  { ED_ENVELOPE, ED_ENV_LIST_ADDRESS,        envelope_list_address,     NULL },
  { ED_ENVELOPE, ED_ENV_LIST_EMPTY,          envelope_list_empty,       NULL },
  { ED_ENVELOPE, ED_ENV_MESSAGE_ID,          envelope_message_id,       NULL },
  { ED_ENVELOPE, ED_ENV_NAME,                envelope_name,             NULL },
  { ED_ENVELOPE, ED_ENV_NEWSGROUP,           envelope_newsgroup,        NULL },
  { ED_ENVELOPE, ED_ENV_ORGANIZATION,        envelope_organization,     NULL },
  { ED_ENVELOPE, ED_ENV_REPLY_TO,            envelope_reply_to,         NULL },
  { ED_ENVELOPE, ED_ENV_SENDER,              envelope_sender,           NULL },
  { ED_ENVELOPE, ED_ENV_SENDER_PLAIN,        envelope_sender_plain,     NULL },
  { ED_ENVELOPE, ED_ENV_SPAM,                envelope_spam,             NULL },
  { ED_ENVELOPE, ED_ENV_SUBJECT,             envelope_subject,          NULL },
  { ED_ENVELOPE, ED_ENV_THREAD_TREE,         envelope_thread_tree,      NULL },
  { ED_ENVELOPE, ED_ENV_THREAD_X_LABEL,      envelope_thread_x_label,   NULL },
  { ED_ENVELOPE, ED_ENV_TO,                  envelope_to,               NULL },
  { ED_ENVELOPE, ED_ENV_TO_ALL,              envelope_to_all,           NULL },
  { ED_ENVELOPE, ED_ENV_USERNAME,            envelope_username,         NULL },
  { ED_ENVELOPE, ED_ENV_X_COMMENT_TO,        envelope_x_comment_to,     NULL },
  { ED_ENVELOPE, ED_ENV_X_LABEL,             envelope_x_label,          NULL },
  { ED_MAILBOX,  ED_MBX_MAILBOX_NAME,        mailbox_mailbox_name,      NULL },
  { ED_MAILBOX,  ED_MBX_MESSAGE_COUNT,       NULL,                      mailbox_message_count },
  { ED_MAILBOX,  ED_MBX_PERCENTAGE,          mailbox_percentage,        NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
