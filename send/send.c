/**
 * @file
 * Prepare and send an email
 *
 * @authors
 * Copyright (C) 2016-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2017-2023 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020 Jakub Jindra <jakub.jindra@socialbakers.com>
 * Copyright (C) 2020 Thomas Sanchez <thomas.sanchz@gmail.com>
 * Copyright (C) 2021 Ashish Panigrahi <ashish.panigrahi@protonmail.com>
 * Copyright (C) 2021 Charalampos Kardaris <ckardaris@outlook.com>
 * Copyright (C) 2021 Thomas Bracht Laumann Jespersen <t@laumann.xyz>
 * Copyright (C) 2021 Viktor Cheburkin <victor.cheburkin@gmail.com>
 * Copyright (C) 2022 David Purton <dcpurton@marshwiggle.net>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
 * Copyright (C) 2023 Whitney Cumber
 * Copyright (C) 2023 наб <nabijaczleweli@nabijaczleweli.xyz>
 * Copyright (C) 2024 Alejandro Colomar <alx@kernel.org>
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
 * @page send_send Prepare and send an email
 *
 * Prepare and send an email
 */

#include "config.h"
#include <errno.h>
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "send.h"
#include "attach/lib.h"
#include "browser/lib.h"
#include "compose/lib.h"
#include "editor/lib.h"
#include "expando/lib.h"
#include "history/lib.h"
#include "imap/lib.h"
#include "index/lib.h"
#include "ncrypt/lib.h"
#include "pager/lib.h"
#include "parse/lib.h"
#include "pattern/lib.h"
#include "postpone/lib.h"
#include "question/lib.h"
#include "body.h"
#include "copy.h"
#include "expando.h"
#include "globals.h"
#include "handler.h"
#include "header.h"
#include "hook.h"
#include "maillist.h"
#include "multipart.h"
#include "mutt_body.h"
#include "mutt_header.h"
#include "mutt_logging.h"
#include "muttlib.h"
#include "mx.h"
#include "nntp/mdata.h"
#include "protos.h"
#include "rfc3676.h"
#include "sendlib.h"
#include "sendmail.h"
#include "smtp.h"
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef USE_AUTOCRYPT
#include "autocrypt/lib.h"
#endif

/**
 * append_signature - Append a signature to an email
 * @param fp  File to write to
 * @param sub Config Subset
 */
static void append_signature(FILE *fp, struct ConfigSubset *sub)
{
  const char *const c_signature = cs_subset_path(sub, "signature");
  if (!c_signature)
    return;

  // If the user hasn't set $signature, don't warn them if it doesn't exist
  struct Buffer *def_sig = buf_pool_get();
  cs_str_initial_get(sub->cs, "signature", def_sig);
  mutt_path_canon(def_sig, HomeDir, false);
  bool notify_missing = !mutt_str_equal(c_signature, buf_string(def_sig));
  buf_pool_release(&def_sig);

  pid_t pid = 0;
  FILE *fp_tmp = mutt_open_read(c_signature, &pid);
  if (!fp_tmp)
  {
    if (notify_missing)
      mutt_perror("%s", c_signature);
    return;
  }

  const bool c_sig_dashes = cs_subset_bool(sub, "sig_dashes");
  if (c_sig_dashes)
    fputs("\n-- \n", fp);
  mutt_file_copy_stream(fp_tmp, fp);
  mutt_file_fclose(&fp_tmp);
  if (pid != -1)
    filter_wait(pid);
}

/**
 * remove_user - Remove any address which matches the current user
 * @param al         List of addresses
 * @param leave_only If set, don't remove the user's address if it it the only
 *                   one in the list
 */
static void remove_user(struct AddressList *al, bool leave_only)
{
  struct Address *a = NULL, *tmp = NULL;
  TAILQ_FOREACH_SAFE(a, al, entries, tmp)
  {
    if (mutt_addr_is_user(a) && (!leave_only || TAILQ_NEXT(a, entries)))
    {
      TAILQ_REMOVE(al, a, entries);
      mutt_addr_free(&a);
    }
  }
}

/**
 * add_mailing_lists - Search Address lists for mailing lists
 * @param out Address list where to append matching mailing lists
 * @param t   'To' Address list
 * @param c   'Cc' Address list
 */
static void add_mailing_lists(struct AddressList *out, const struct AddressList *t,
                              const struct AddressList *c)
{
  const struct AddressList *const als[] = { t, c };

  for (size_t i = 0; i < mutt_array_size(als); i++)
  {
    const struct AddressList *al = als[i];
    struct Address *a = NULL;
    TAILQ_FOREACH(a, al, entries)
    {
      if (!a->group && mutt_is_mail_list(a))
      {
        mutt_addrlist_append(out, mutt_addr_copy(a));
      }
    }
  }
}

/**
 * mutt_edit_address - Edit an email address
 * @param[in,out] al          AddressList to edit
 * @param[in]  field          Prompt for user
 * @param[in]  expand_aliases If true, expand Address aliases
 * @retval  0 Success
 * @retval -1 Failure
 */
int mutt_edit_address(struct AddressList *al, const char *field, bool expand_aliases)
{
  int rc = 0;
  struct Buffer *buf = buf_pool_get();
  buf_alloc(buf, 8192);
  char *err = NULL;
  int idna_ok = 0;

  do
  {
    mutt_addrlist_to_local(al);
    buf_reset(buf);
    mutt_addrlist_write(al, buf, false);
    if (!buf_is_empty(buf))
      buf_addstr(buf, ", ");

    if (mw_get_field(field, buf, MUTT_COMP_NO_FLAGS, HC_ALIAS, &CompleteAliasOps, NULL) != 0)
    {
      rc = -1;
      goto done;
    }
    mutt_addrlist_clear(al);
    mutt_addrlist_parse2(al, buf_string(buf));
    if (expand_aliases)
      mutt_expand_aliases(al);
    idna_ok = mutt_addrlist_to_intl(al, &err);
    if (idna_ok != 0)
    {
      mutt_error(_("Bad IDN: '%s'"), err);
      FREE(&err);
    }
  } while (idna_ok != 0);

done:
  buf_pool_release(&buf);
  return rc;
}

/**
 * edit_envelope - Edit Envelope fields
 * @param en    Envelope to edit
 * @param flags Flags, see #SendFlags
 * @param sub   Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
static int edit_envelope(struct Envelope *en, SendFlags flags, struct ConfigSubset *sub)
{
  int rc = -1;
  struct Buffer *buf = buf_pool_get();
  buf_alloc(buf, 8192);

  if (OptNewsSend)
  {
    if (en->newsgroups)
      buf_strcpy(buf, en->newsgroups);
    else
      buf_reset(buf);

    if (mw_get_field("Newsgroups: ", buf, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0)
    {
      goto done;
    }
    mutt_str_replace(&en->newsgroups, buf_string(buf));

    if (en->followup_to)
      buf_strcpy(buf, en->followup_to);
    else
      buf_reset(buf);

    const bool c_ask_followup_to = cs_subset_bool(sub, "ask_followup_to");
    if (c_ask_followup_to && (mw_get_field("Followup-To: ", buf, MUTT_COMP_NO_FLAGS,
                                           HC_OTHER, NULL, NULL) != 0))
    {
      goto done;
    }
    mutt_str_replace(&en->followup_to, buf_string(buf));

    if (en->x_comment_to)
      buf_strcpy(buf, en->x_comment_to);
    else
      buf_reset(buf);

    const bool c_x_comment_to = cs_subset_bool(sub, "x_comment_to");
    const bool c_ask_x_comment_to = cs_subset_bool(sub, "ask_x_comment_to");
    if (c_x_comment_to && c_ask_x_comment_to &&
        (mw_get_field("X-Comment-To: ", buf, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0))
    {
      goto done;
    }
    mutt_str_replace(&en->x_comment_to, buf_string(buf));
  }
  else
  {
    const bool c_fast_reply = cs_subset_bool(sub, "fast_reply");
    if (TAILQ_EMPTY(&en->to) || !c_fast_reply || (flags & SEND_REVIEW_TO))
    {
      if ((mutt_edit_address(&en->to, _("To: "), true) == -1))
        goto done;
    }

    const bool c_ask_cc = cs_subset_bool(sub, "ask_cc");
    if (TAILQ_EMPTY(&en->cc) || !c_fast_reply)
    {
      if (c_ask_cc && (mutt_edit_address(&en->cc, _("Cc: "), true) == -1))
        goto done;
    }

    const bool c_ask_bcc = cs_subset_bool(sub, "ask_bcc");
    if (TAILQ_EMPTY(&en->bcc) || !c_fast_reply)
    {
      if (c_ask_bcc && (mutt_edit_address(&en->bcc, _("Bcc: "), true) == -1))
        goto done;
    }

    if (TAILQ_EMPTY(&en->to) && TAILQ_EMPTY(&en->cc) && TAILQ_EMPTY(&en->bcc))
    {
      mutt_warning(_("No recipients specified"));
      goto done;
    }

    const bool c_reply_with_xorig = cs_subset_bool(sub, "reply_with_xorig");
    if (c_reply_with_xorig && (flags & (SEND_REPLY | SEND_LIST_REPLY | SEND_GROUP_REPLY)) &&
        (mutt_edit_address(&en->from, "From: ", true) == -1))
    {
      goto done;
    }
  }

  if (en->subject)
  {
    const bool c_fast_reply = cs_subset_bool(sub, "fast_reply");
    if (c_fast_reply)
    {
      rc = 0;
      goto done;
    }
    buf_strcpy(buf, en->subject);
  }
  else
  {
    const char *p = NULL;

    buf_reset(buf);
    struct ListNode *uh = NULL;
    STAILQ_FOREACH(uh, &UserHeader, entries)
    {
      size_t plen = mutt_istr_startswith(uh->data, "subject:");
      if (plen)
      {
        p = mutt_str_skip_email_wsp(uh->data + plen);
        buf_strcpy(buf, p);
      }
    }
  }

  if ((mw_get_field(_("Subject: "), buf, MUTT_COMP_NO_FLAGS, HC_OTHER, NULL, NULL) != 0) ||
      (buf_is_empty(buf) &&
       (query_quadoption(_("No subject, abort?"), sub, "abort_nosubject") != MUTT_NO)))
  {
    mutt_message(_("No subject, aborting"));
    goto done;
  }
  mutt_env_set_subject(en, buf_string(buf));
  rc = 0;

done:
  buf_pool_release(&buf);
  return rc;
}

/**
 * nntp_get_header - Get the trimmed header
 * @param s Header line with leading whitespace
 * @retval ptr Copy of string
 *
 * @note The caller should free the returned string.
 */
static char *nntp_get_header(const char *s)
{
  SKIPWS(s);
  return mutt_str_dup(s);
}

/**
 * process_user_recips - Process the user headers
 * @param env Envelope to populate
 */
static void process_user_recips(struct Envelope *env)
{
  struct ListNode *uh = NULL;
  STAILQ_FOREACH(uh, &UserHeader, entries)
  {
    size_t plen;
    if ((plen = mutt_istr_startswith(uh->data, "to:")))
      mutt_addrlist_parse(&env->to, uh->data + plen);
    else if ((plen = mutt_istr_startswith(uh->data, "cc:")))
      mutt_addrlist_parse(&env->cc, uh->data + plen);
    else if ((plen = mutt_istr_startswith(uh->data, "bcc:")))
      mutt_addrlist_parse(&env->bcc, uh->data + plen);
    else if ((plen = mutt_istr_startswith(uh->data, "newsgroups:")))
      env->newsgroups = nntp_get_header(uh->data + plen);
    else if ((plen = mutt_istr_startswith(uh->data, "followup-to:")))
      env->followup_to = nntp_get_header(uh->data + plen);
    else if ((plen = mutt_istr_startswith(uh->data, "x-comment-to:")))
      env->x_comment_to = nntp_get_header(uh->data + plen);
  }
}

/**
 * process_user_header - Process the user headers
 * @param env Envelope to populate
 */
static void process_user_header(struct Envelope *env)
{
  struct ListNode *uh = NULL;
  STAILQ_FOREACH(uh, &UserHeader, entries)
  {
    size_t plen;
    if ((plen = mutt_istr_startswith(uh->data, "from:")))
    {
      /* User has specified a default From: address.  Remove default address */
      mutt_addrlist_clear(&env->from);
      mutt_addrlist_parse(&env->from, uh->data + plen);
    }
    else if ((plen = mutt_istr_startswith(uh->data, "reply-to:")))
    {
      mutt_addrlist_clear(&env->reply_to);
      mutt_addrlist_parse(&env->reply_to, uh->data + plen);
    }
    else if ((plen = mutt_istr_startswith(uh->data, "message-id:")))
    {
      char *tmp = mutt_extract_message_id(uh->data + plen, NULL);
      if (mutt_addr_valid_msgid(tmp))
      {
        FREE(&env->message_id);
        env->message_id = tmp;
      }
      else
      {
        FREE(&tmp);
      }
    }
    else if (!mutt_istr_startswith(uh->data, "to:") &&
             !mutt_istr_startswith(uh->data, "cc:") &&
             !mutt_istr_startswith(uh->data, "bcc:") &&
             !mutt_istr_startswith(uh->data, "newsgroups:") &&
             !mutt_istr_startswith(uh->data, "followup-to:") &&
             !mutt_istr_startswith(uh->data, "x-comment-to:") &&
             !mutt_istr_startswith(uh->data, "supersedes:") &&
             !mutt_istr_startswith(uh->data, "subject:") &&
             !mutt_istr_startswith(uh->data, "return-path:"))
    {
      mutt_list_insert_tail(&env->userhdrs, mutt_str_dup(uh->data));
    }
  }
}

/**
 * mutt_forward_intro - Add the "start of forwarded message" text
 * @param e   Email
 * @param sub Config Subset
 * @param fp  File to write to
 */
void mutt_forward_intro(struct Email *e, FILE *fp, struct ConfigSubset *sub)
{
  const struct Expando *c_forward_attribution_intro = cs_subset_expando(sub, "forward_attribution_intro");
  if (!c_forward_attribution_intro || !fp)
    return;

  const char *const c_attribution_locale = cs_subset_string(sub, "attribution_locale");

  struct Buffer *buf = buf_pool_get();
  setlocale(LC_TIME, NONULL(c_attribution_locale));
  mutt_make_string(buf, -1, c_forward_attribution_intro, NULL, -1, e,
                   MUTT_FORMAT_NO_FLAGS, NULL);
  setlocale(LC_TIME, "");
  fputs(buf_string(buf), fp);
  fputs("\n\n", fp);
  buf_pool_release(&buf);
}

/**
 * mutt_forward_trailer - Add a "end of forwarded message" text
 * @param e   Email
 * @param sub Config Subset
 * @param fp  File to write to
 */
void mutt_forward_trailer(struct Email *e, FILE *fp, struct ConfigSubset *sub)
{
  const struct Expando *c_forward_attribution_trailer = cs_subset_expando(sub, "forward_attribution_trailer");
  if (!c_forward_attribution_trailer || !fp)
    return;

  const char *const c_attribution_locale = cs_subset_string(sub, "attribution_locale");

  struct Buffer *buf = buf_pool_get();
  setlocale(LC_TIME, NONULL(c_attribution_locale));
  mutt_make_string(buf, -1, c_forward_attribution_trailer, NULL, -1, e,
                   MUTT_FORMAT_NO_FLAGS, NULL);
  setlocale(LC_TIME, "");
  fputc('\n', fp);
  fputs(buf_string(buf), fp);
  fputc('\n', fp);
  buf_pool_release(&buf);
}

/**
 * include_forward - Write out a forwarded message
 * @param m      Mailbox
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
static int include_forward(struct Mailbox *m, struct Email *e, FILE *fp_out,
                           struct ConfigSubset *sub)
{
  CopyHeaderFlags chflags = CH_DECODE;
  CopyMessageFlags cmflags = MUTT_CM_NO_FLAGS;

  struct Message *msg = mx_msg_open(m, e);
  if (!msg)
  {
    return -1;
  }
  mutt_parse_mime_message(e, msg->fp);
  mutt_message_hook(m, e, MUTT_MESSAGE_HOOK);

  const bool c_forward_decode = cs_subset_bool(sub, "forward_decode");
  if ((WithCrypto != 0) && (e->security & SEC_ENCRYPT) && c_forward_decode)
  {
    /* make sure we have the user's passphrase before proceeding... */
    if (!crypt_valid_passphrase(e->security))
    {
      mx_msg_close(m, &msg);
      return -1;
    }
  }

  mutt_forward_intro(e, fp_out, sub);

  if (c_forward_decode)
  {
    cmflags |= MUTT_CM_DECODE | MUTT_CM_CHARCONV;

    const bool c_weed = cs_subset_bool(sub, "weed");
    if (c_weed)
    {
      chflags |= CH_WEED | CH_REORDER;
      cmflags |= MUTT_CM_WEED;
    }
  }

  const bool c_forward_quote = cs_subset_bool(sub, "forward_quote");
  if (c_forward_quote)
    cmflags |= MUTT_CM_PREFIX;

  mutt_copy_message(fp_out, e, msg, cmflags, chflags, 0);
  mx_msg_close(m, &msg);
  mutt_forward_trailer(e, fp_out, sub);
  return 0;
}

/**
 * inline_forward_attachments - Add attachments to an email, inline
 * @param[in]  m        Mailbox
 * @param[in]  e        Current Email
 * @param[out] plast    Pointer to the last Attachment
 * @param[out] forwardq Result of asking the user to forward the attachments, e.g. #MUTT_YES
 * @param[in]  sub      Config Subset
 * @retval  0 Success
 * @retval -1 Error
 */
static int inline_forward_attachments(struct Mailbox *m, struct Email *e,
                                      struct Body ***plast, enum QuadOption *forwardq,
                                      struct ConfigSubset *sub)
{
  struct Body **last = *plast;
  struct Body *body = NULL;
  struct AttachCtx *actx = NULL;
  int rc = 0, i;

  struct Message *msg = mx_msg_open(m, e);
  if (!msg)
  {
    return -1;
  }

  mutt_parse_mime_message(e, msg->fp);
  mutt_message_hook(m, e, MUTT_MESSAGE_HOOK);

  actx = MUTT_MEM_CALLOC(1, struct AttachCtx);
  actx->email = e;
  actx->fp_root = msg->fp;

  mutt_generate_recvattach_list(actx, actx->email, actx->email->body,
                                actx->fp_root, -1, 0, 0);

  for (i = 0; i < actx->idxlen; i++)
  {
    body = actx->idx[i]->body;
    if ((body->type != TYPE_MULTIPART) && mutt_prefer_as_attachment(body) &&
        !((body->type == TYPE_APPLICATION) &&
          (mutt_istr_equal(body->subtype, "pgp-signature") ||
           mutt_istr_equal(body->subtype, "x-pkcs7-signature") ||
           mutt_istr_equal(body->subtype, "pkcs7-signature"))))
    {
      /* Ask the quadoption only once */
      if (*forwardq == MUTT_ABORT)
      {
        /* L10N: This is the prompt for $forward_attachments.
           When inline forwarding ($mime_forward answered "no"), this prompts
           whether to add non-decodable attachments from the original email.
           Text/plain parts and the like will already be included in the
           message contents, but other attachment, such as PDF files, will also
           be added as attachments to the new mail, if this is answered yes.  */
        *forwardq = query_quadoption(_("Forward attachments?"), sub, "forward_attachments");
        if (*forwardq != MUTT_YES)
        {
          if (*forwardq == -1)
            rc = -1;
          goto cleanup;
        }
      }
      if (mutt_body_copy(actx->idx[i]->fp, last, body) == -1)
      {
        rc = -1;
        goto cleanup;
      }
      last = &((*last)->next);
    }
  }

cleanup:
  *plast = last;
  mx_msg_close(m, &msg);
  mutt_actx_free(&actx);
  return rc;
}

/**
 * format_attribution - Format an attribution prefix/suffix
 * @param exp    Expando to format
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 */
static void format_attribution(const struct Expando *exp, struct Email *e,
                               FILE *fp_out, struct ConfigSubset *sub)
{
  if (!exp || !fp_out)
    return;

  const char *const c_attribution_locale = cs_subset_string(sub, "attribution_locale");

  struct Buffer *buf = buf_pool_get();
  setlocale(LC_TIME, NONULL(c_attribution_locale));
  mutt_make_string(buf, -1, exp, NULL, -1, e, MUTT_FORMAT_NO_FLAGS, NULL);
  setlocale(LC_TIME, "");
  fputs(buf_string(buf), fp_out);
  fputc('\n', fp_out);
  buf_pool_release(&buf);
}

/**
 * mutt_make_attribution_intro - Add "on DATE, PERSON wrote" header
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 */
void mutt_make_attribution_intro(struct Email *e, FILE *fp_out, struct ConfigSubset *sub)
{
  format_attribution(cs_subset_expando(sub, "attribution_intro"), e, fp_out, sub);
}

/**
 * mutt_make_attribution_trailer - Add suffix to replied email text
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 */
void mutt_make_attribution_trailer(struct Email *e, FILE *fp_out, struct ConfigSubset *sub)
{
  format_attribution(cs_subset_expando(sub, "attribution_trailer"), e, fp_out, sub);
}

/**
 * mutt_make_greeting - Add greetings string
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 *
 * @sa $greeting
 */
static void mutt_make_greeting(struct Email *e, FILE *fp_out, struct ConfigSubset *sub)
{
  const struct Expando *c_greeting = cs_subset_expando(sub, "greeting");
  if (!c_greeting || !fp_out)
    return;

  struct Buffer *buf = buf_pool_get();

  struct ExpandoRenderData GreetingRenderData[] = {
    // clang-format off
    { ED_ENVELOPE, GreetingRenderCallbacks, e, MUTT_FORMAT_NO_FLAGS },
    { -1, NULL, NULL, 0 },
    // clang-format on
  };

  expando_filter(c_greeting, GreetingRenderCallbacks, e, TOKEN_NO_FLAGS,
                 buf->dsize, EnvList, buf);

  fputs(buf_string(buf), fp_out);
  fputc('\n', fp_out);
  buf_pool_release(&buf);
}

/**
 * include_reply - Generate the reply text for an email
 * @param m      Mailbox
 * @param e      Email
 * @param fp_out File to write to
 * @param sub    Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
static int include_reply(struct Mailbox *m, struct Email *e, FILE *fp_out,
                         struct ConfigSubset *sub)
{
  CopyMessageFlags cmflags = MUTT_CM_PREFIX | MUTT_CM_DECODE | MUTT_CM_CHARCONV | MUTT_CM_REPLYING;
  CopyHeaderFlags chflags = CH_DECODE;

  if ((WithCrypto != 0) && (e->security & SEC_ENCRYPT))
  {
    /* make sure we have the user's passphrase before proceeding... */
    if (!crypt_valid_passphrase(e->security))
      return -1;
  }

  struct Message *msg = mx_msg_open(m, e);
  if (!msg)
  {
    return -1;
  }
  mutt_parse_mime_message(e, msg->fp);
  mutt_message_hook(m, e, MUTT_MESSAGE_HOOK);

  mutt_make_attribution_intro(e, fp_out, sub);

  const bool c_header = cs_subset_bool(sub, "header");
  if (!c_header)
    cmflags |= MUTT_CM_NOHEADER;

  const bool c_weed = cs_subset_bool(sub, "weed");
  if (c_weed)
  {
    chflags |= CH_WEED | CH_REORDER;
    cmflags |= MUTT_CM_WEED;
  }

  mutt_copy_message(fp_out, e, msg, cmflags, chflags, 0);
  mx_msg_close(m, &msg);

  mutt_make_attribution_trailer(e, fp_out, sub);

  return 0;
}

/**
 * choose_default_to - Pick the best 'to:' value
 * @param from From Address
 * @param env  Envelope
 * @param sub  Config Subset
 * @retval ptr Addresses to use
 */
static const struct AddressList *choose_default_to(const struct Address *from,
                                                   const struct Envelope *env,
                                                   struct ConfigSubset *sub)
{
  const bool c_reply_self = cs_subset_bool(sub, "reply_self");
  if (!c_reply_self && mutt_addr_is_user(from))
  {
    /* mail is from the user, assume replying to recipients */
    return &env->to;
  }
  else
  {
    return &env->from;
  }
}

/**
 * default_to - Generate default email addresses
 * @param[in,out] to      'To' address
 * @param[in]     env     Envelope to populate
 * @param[in]     flags   Flags, see #SendFlags
 * @param[in]     hmfupto If true, add 'followup-to' address to 'to' address
 * @param[in]     sub     Config Subset
 * @retval  0 Success
 * @retval -1 Aborted
 */
static int default_to(struct AddressList *to, struct Envelope *env,
                      SendFlags flags, int hmfupto, struct ConfigSubset *sub)
{
  const struct Address *from = TAILQ_FIRST(&env->from);
  const struct Address *reply_to = TAILQ_FIRST(&env->reply_to);

  if (flags && !TAILQ_EMPTY(&env->mail_followup_to) && (hmfupto == MUTT_YES))
  {
    mutt_addrlist_copy(to, &env->mail_followup_to, true);
    return 0;
  }

  /* Exit now if we're setting up the default Cc list for list-reply
   * (only set if Mail-Followup-To is present and honoured).  */
  if (flags & SEND_LIST_REPLY)
    return 0;

  const struct AddressList *default_to = choose_default_to(from, env, sub);

  if (reply_to)
  {
    const bool from_is_reply_to = mutt_addr_cmp(from, reply_to);
    const bool multiple_reply_to = reply_to &&
                                   TAILQ_NEXT(TAILQ_FIRST(&env->reply_to), entries);

    const bool c_ignore_list_reply_to = cs_subset_bool(sub, "ignore_list_reply_to");
    const enum QuadOption c_reply_to = cs_subset_quad(sub, "reply_to");
    if ((from_is_reply_to && !multiple_reply_to && !reply_to->personal) ||
        (c_ignore_list_reply_to && mutt_is_mail_list(reply_to) &&
         (mutt_addrlist_search(&env->to, reply_to) || mutt_addrlist_search(&env->cc, reply_to))))
    {
      /* If the Reply-To: address is a mailing list, assume that it was
       * put there by the mailing list, and use the From: address
       *
       * We also take the from header if our correspondent has a reply-to
       * header which is identical to the electronic mail address given
       * in his From header, and the reply-to has no display-name.  */
      mutt_addrlist_copy(to, &env->from, false);
    }
    else if (!(from_is_reply_to && !multiple_reply_to) && (c_reply_to != MUTT_YES))
    {
      char prompt[256] = { 0 };
      /* There are quite a few mailing lists which set the Reply-To:
       * header field to the list address, which makes it quite impossible
       * to send a message to only the sender of the message.  This
       * provides a way to do that.  */
      /* L10N: Asks whether the user respects the reply-to header.
         If she says no, neomutt will reply to the from header's address instead. */
      snprintf(prompt, sizeof(prompt), _("Reply to %s%s?"),
               buf_string(reply_to->mailbox), multiple_reply_to ? ",..." : "");
      switch (query_quadoption(prompt, sub, "reply_to"))
      {
        case MUTT_YES:
          mutt_addrlist_copy(to, &env->reply_to, false);
          break;

        case MUTT_NO:
          mutt_addrlist_copy(to, default_to, false);
          break;

        default:
          return -1; /* abort */
      }
    }
    else
    {
      mutt_addrlist_copy(to, &env->reply_to, false);
    }
  }
  else
  {
    mutt_addrlist_copy(to, default_to, false);
  }

  return 0;
}

/**
 * mutt_fetch_recips - Generate recpients for a reply email
 * @param out   Envelope to populate
 * @param in    Envelope of source email
 * @param flags Flags, see #SendFlags
 * @param sub   Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
int mutt_fetch_recips(struct Envelope *out, struct Envelope *in,
                      SendFlags flags, struct ConfigSubset *sub)
{
  enum QuadOption hmfupto = MUTT_ABORT;
  const struct Address *followup_to = TAILQ_FIRST(&in->mail_followup_to);

  if ((flags & (SEND_LIST_REPLY | SEND_GROUP_REPLY | SEND_GROUP_CHAT_REPLY)) && followup_to)
  {
    char prompt[256] = { 0 };
    snprintf(prompt, sizeof(prompt), _("Follow-up to %s%s?"),
             buf_string(followup_to->mailbox),
             TAILQ_NEXT(TAILQ_FIRST(&in->mail_followup_to), entries) ? ",..." : "");

    hmfupto = query_quadoption(prompt, sub, "honor_followup_to");
    if (hmfupto == MUTT_ABORT)
      return -1;
  }

  if (flags & SEND_LIST_REPLY)
  {
    add_mailing_lists(&out->to, &in->to, &in->cc);

    if (followup_to && (hmfupto == MUTT_YES) &&
        (default_to(&out->cc, in, flags & SEND_LIST_REPLY, (hmfupto == MUTT_YES), sub) == MUTT_ABORT))
    {
      return -1; /* abort */
    }
  }
  else if (flags & SEND_TO_SENDER)
  {
    mutt_addrlist_copy(&out->to, &in->from, false);
  }
  else
  {
    if (default_to(&out->to, in, flags & (SEND_GROUP_REPLY | SEND_GROUP_CHAT_REPLY),
                   (hmfupto == MUTT_YES), sub) == -1)
    {
      return -1; /* abort */
    }

    if ((flags & (SEND_GROUP_REPLY | SEND_GROUP_CHAT_REPLY)) &&
        (!followup_to || (hmfupto != MUTT_YES)))
    {
      /* if(!mutt_addr_is_user(in->to)) */
      if (flags & SEND_GROUP_REPLY)
        mutt_addrlist_copy(&out->cc, &in->to, true);
      else
        mutt_addrlist_copy(&out->to, &in->to, true);
      mutt_addrlist_copy(&out->cc, &in->cc, true);
    }
  }
  return 0;
}

/**
 * add_references - Add the email's references to a list
 * @param head List of references
 * @param env    Envelope of message
 */
static void add_references(struct ListHead *head, struct Envelope *env)
{
  struct ListHead *src = STAILQ_EMPTY(&env->references) ? &env->in_reply_to : &env->references;
  mutt_list_copy_tail(head, src);
}

/**
 * add_message_id - Add the email's message ID to a list
 * @param head List of message IDs
 * @param env  Envelope of message
 */
static void add_message_id(struct ListHead *head, struct Envelope *env)
{
  if (env->message_id)
  {
    mutt_list_insert_head(head, mutt_str_dup(env->message_id));
  }
}

/**
 * mutt_fix_reply_recipients - Remove duplicate recipients
 * @param env Envelope to fix
 * @param sub Config Subset
 */
void mutt_fix_reply_recipients(struct Envelope *env, struct ConfigSubset *sub)
{
  const bool c_me_too = cs_subset_bool(sub, "me_too");
  if (!c_me_too)
  {
    const bool c_reply_self = cs_subset_bool(sub, "reply_self");

    /* the order is important here.  do the CC: first so that if the
     * the user is the only recipient, it ends up on the TO: field */
    remove_user(&env->cc, TAILQ_EMPTY(&env->to));
    remove_user(&env->to, TAILQ_EMPTY(&env->cc) || c_reply_self);
  }

  /* the CC field can get cluttered, especially with lists */
  mutt_addrlist_dedupe(&env->to);
  mutt_addrlist_dedupe(&env->cc);
  mutt_addrlist_remove_xrefs(&env->to, &env->cc);

  if (!TAILQ_EMPTY(&env->cc) && TAILQ_EMPTY(&env->to))
  {
    TAILQ_SWAP(&env->to, &env->cc, Address, entries);
  }
}

/**
 * mutt_make_forward_subject - Create a subject for a forwarded email
 * @param env Envelope for result
 * @param e   Email
 * @param sub Config Subset
 */
void mutt_make_forward_subject(struct Envelope *env, struct Email *e, struct ConfigSubset *sub)
{
  if (!env)
    return;

  const struct Expando *c_forward_format = cs_subset_expando(sub, "forward_format");

  struct Buffer *buf = buf_pool_get();
  /* set the default subject for the message. */
  mutt_make_string(buf, -1, c_forward_format, NULL, -1, e, MUTT_FORMAT_NO_FLAGS, NULL);
  mutt_env_set_subject(env, buf_string(buf));
  buf_pool_release(&buf);
}

/**
 * mutt_make_misc_reply_headers - Set subject for a reply
 * @param env    Envelope for result
 * @param env_cur Envelope of source email
 * @param sub    Config Subset
 */
void mutt_make_misc_reply_headers(struct Envelope *env, struct Envelope *env_cur,
                                  struct ConfigSubset *sub)
{
  if (!env || !env_cur)
    return;

  /* This takes precedence over a subject that might have
   * been taken from a List-Post header.  Is that correct?  */
  if (env_cur->real_subj)
  {
    char *subj = NULL;
    mutt_str_asprintf(&subj, "Re: %s", env_cur->real_subj);
    mutt_env_set_subject(env, subj);
    FREE(&subj);
  }
  else if (!env->subject)
  {
    const char *const c_empty_subject = cs_subset_string(sub, "empty_subject");
    mutt_env_set_subject(env, c_empty_subject);
  }
}

/**
 * mutt_add_to_reference_headers - Generate references for a reply email
 * @param env     Envelope for result
 * @param env_cur Envelope of source email
 * @param sub     Config Subset
 */
void mutt_add_to_reference_headers(struct Envelope *env, struct Envelope *env_cur,
                                   struct ConfigSubset *sub)
{
  add_references(&env->references, env_cur);
  add_message_id(&env->references, env_cur);
  add_message_id(&env->in_reply_to, env_cur);

  const bool c_x_comment_to = cs_subset_bool(sub, "x_comment_to");
  if (OptNewsSend && c_x_comment_to && !TAILQ_EMPTY(&env_cur->from))
    env->x_comment_to = mutt_str_dup(mutt_get_name(TAILQ_FIRST(&env_cur->from)));
}

/**
 * make_reference_headers - Generate reference headers for an email
 * @param ea  Array of source Emails
 * @param env Envelope for result
 * @param sub Config Subset
 */
static void make_reference_headers(struct EmailArray *ea, struct Envelope *env,
                                   struct ConfigSubset *sub)
{
  if (!ea || !env || ARRAY_EMPTY(ea))
    return;

  struct Email **ep = NULL;
  ARRAY_FOREACH(ep, ea)
  {
    struct Email *e = *ep;
    mutt_add_to_reference_headers(env, e->env, sub);
  }

  /* if there's more than entry in In-Reply-To (i.e. message has multiple
   * parents), don't generate a References: header as it's discouraged by
   * RFC2822, sect. 3.6.4 */
  if ((ARRAY_SIZE(ea) > 1) && !STAILQ_EMPTY(&env->in_reply_to) &&
      STAILQ_NEXT(STAILQ_FIRST(&env->in_reply_to), entries))
  {
    mutt_list_free(&env->references);
  }
}

/**
 * envelope_defaults - Fill in some defaults for a new email
 * @param env   Envelope for result
 * @param ea    Array of Emails to use
 * @param flags Flags, see #SendFlags
 * @param sub   Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
static int envelope_defaults(struct Envelope *env, struct EmailArray *ea,
                             SendFlags flags, struct ConfigSubset *sub)
{
  if (!ea || ARRAY_EMPTY(ea))
    return -1;

  struct Email *e_cur = *ARRAY_GET(ea, 0);
  bool single = (ARRAY_SIZE(ea) == 1);

  struct Envelope *env_cur = e_cur->env;
  if (!env_cur)
    return -1;

  if (flags & (SEND_REPLY | SEND_TO_SENDER))
  {
    if ((flags & SEND_NEWS))
    {
      /* in case followup set Newsgroups: with Followup-To: if it present */
      if (!env->newsgroups && !mutt_istr_equal(env_cur->followup_to, "poster"))
      {
        env->newsgroups = mutt_str_dup(env_cur->followup_to);
      }
    }
    else if (!single)
    {
      struct Email **ep = NULL;
      ARRAY_FOREACH(ep, ea)
      {
        struct Email *e = *ep;
        if (mutt_fetch_recips(env, e->env, flags, sub) == -1)
          return -1;
      }
    }
    else if (mutt_fetch_recips(env, env_cur, flags, sub) == -1)
    {
      return -1;
    }

    if ((flags & SEND_LIST_REPLY) && TAILQ_EMPTY(&env->to))
    {
      mutt_error(_("No mailing lists found"));
      return -1;
    }

    if (flags & SEND_REPLY)
    {
      mutt_make_misc_reply_headers(env, env_cur, sub);
      make_reference_headers(ea, env, sub);
    }
  }
  else if (flags & SEND_FORWARD)
  {
    mutt_make_forward_subject(env, e_cur, sub);

    const bool c_forward_references = cs_subset_bool(sub, "forward_references");
    if (c_forward_references)
      make_reference_headers(ea, env, sub);
  }

  return 0;
}

/**
 * generate_body - Create a new email body
 * @param fp_tmp Stream for outgoing message
 * @param e      Email for outgoing message
 * @param flags  Compose mode, see #SendFlags
 * @param m      Mailbox
 * @param ea     Array of Emails to use
 * @param sub    Config Subset
 * @retval  0 Success
 * @retval -1 Error
 */
static int generate_body(FILE *fp_tmp, struct Email *e, SendFlags flags,
                         struct Mailbox *m, struct EmailArray *ea, struct ConfigSubset *sub)
{
  /* An EmailList is required for replying and forwarding */
  if (!ea && (flags & (SEND_REPLY | SEND_FORWARD)))
    return -1;

  if (flags & SEND_REPLY)
  {
    enum QuadOption ans = query_quadoption(_("Include message in reply?"), sub, "include");
    if (ans == MUTT_ABORT)
      return -1;

    if (ans == MUTT_YES)
    {
      mutt_message(_("Including quoted message..."));
      struct Email **ep = NULL;
      size_t count = ARRAY_SIZE(ea) - 1;
      ARRAY_FOREACH(ep, ea)
      {
        if (include_reply(m, *ep, fp_tmp, sub) == -1)
        {
          mutt_error(_("Could not include all requested messages"));
          return -1;
        }
        if (ARRAY_FOREACH_IDX_ep < count)
        {
          fputc('\n', fp_tmp);
        }
      }
    }
  }
  else if (flags & SEND_FORWARD)
  {
    enum QuadOption ans = query_quadoption(_("Forward as attachment?"), sub, "mime_forward");
    if (ans == MUTT_YES)
    {
      struct Body *last = e->body;

      mutt_message(_("Preparing forwarded message..."));

      while (last && last->next)
        last = last->next;

      struct Email **ep = NULL;
      ARRAY_FOREACH(ep, ea)
      {
        struct Body *tmp = mutt_make_message_attach(m, *ep, false, sub);
        if (last)
        {
          last->next = tmp;
          last = tmp;
        }
        else
        {
          last = tmp;
          e->body = tmp;
        }
      }
    }
    else if (ans != MUTT_ABORT)
    {
      enum QuadOption forwardq = MUTT_ABORT;
      struct Body **last = NULL;

      const bool c_forward_decode = cs_subset_bool(sub, "forward_decode");
      const enum QuadOption c_forward_attachments = cs_subset_quad(sub, "forward_attachments");
      if (c_forward_decode && (c_forward_attachments != MUTT_NO))
      {
        last = &e->body;
        while (*last)
          last = &((*last)->next);
      }

      struct Email **ep = NULL;
      ARRAY_FOREACH(ep, ea)
      {
        struct Email *e_cur = *ep;
        include_forward(m, e_cur, fp_tmp, sub);
        if (c_forward_decode && (c_forward_attachments != MUTT_NO))
        {
          if (inline_forward_attachments(m, e_cur, &last, &forwardq, sub) != 0)
            return -1;
        }
      }
    }
    else
    {
      return -1;
    }
  }
  else if (((WithCrypto & APPLICATION_PGP) != 0) && (flags & SEND_KEY))
  {
    struct Body *b = NULL;

    if (((WithCrypto & APPLICATION_PGP) != 0) && !(b = crypt_pgp_make_key_attachment()))
    {
      return -1;
    }

    b->next = e->body;
    e->body = b;
  }

  mutt_clear_error();

  return 0;
}

/**
 * mutt_set_followup_to - Set followup-to field
 * @param env Envelope to modify
 * @param sub Config Subset
 */
void mutt_set_followup_to(struct Envelope *env, struct ConfigSubset *sub)
{
  /* Only generate the Mail-Followup-To if the user has requested it, and
   * it hasn't already been set */

  const bool c_followup_to = cs_subset_bool(sub, "followup_to");
  if (!c_followup_to)
    return;
  if (OptNewsSend)
  {
    if (!env->followup_to && env->newsgroups && (strrchr(env->newsgroups, ',')))
      env->followup_to = mutt_str_dup(env->newsgroups);
    return;
  }

  if (TAILQ_EMPTY(&env->mail_followup_to))
  {
    if (mutt_is_list_recipient(false, env))
    {
      /* this message goes to known mailing lists, so create a proper
       * mail-followup-to header */

      mutt_addrlist_copy(&env->mail_followup_to, &env->to, false);
      mutt_addrlist_copy(&env->mail_followup_to, &env->cc, true);
    }

    /* remove ourselves from the mail-followup-to header */
    remove_user(&env->mail_followup_to, false);

    /* If we are not subscribed to any of the lists in question, re-add
     * ourselves to the mail-followup-to header.  The mail-followup-to header
     * generated is a no-op with group-reply, but makes sure list-reply has the
     * desired effect.  */

    if (!TAILQ_EMPTY(&env->mail_followup_to) &&
        !mutt_is_subscribed_list_recipient(false, env))
    {
      struct AddressList *al = NULL;
      if (!TAILQ_EMPTY(&env->reply_to))
        al = &env->reply_to;
      else if (!TAILQ_EMPTY(&env->from))
        al = &env->from;

      if (al)
      {
        struct Address *a = NULL;
        TAILQ_FOREACH_REVERSE(a, al, AddressList, entries)
        {
          mutt_addrlist_prepend(&env->mail_followup_to, mutt_addr_copy(a));
        }
      }
      else
      {
        mutt_addrlist_prepend(&env->mail_followup_to, mutt_default_from(sub));
      }
    }

    mutt_addrlist_dedupe(&env->mail_followup_to);
  }
}

/**
 * set_reverse_name - Try to set the 'from' field from the recipients
 * @param al  AddressList to prepend the found address
 * @param env Envelope to use
 * @param sub Config Subset
 *
 * Look through the recipients of the message we are replying to, and if we
 * find an address that matches $alternates, we use that as the default from
 * field
 */
static void set_reverse_name(struct AddressList *al, struct Envelope *env,
                             struct ConfigSubset *sub)
{
  struct Address *a = NULL;
  if (TAILQ_EMPTY(al))
  {
    TAILQ_FOREACH(a, &env->to, entries)
    {
      if (mutt_addr_is_user(a))
      {
        mutt_addrlist_append(al, mutt_addr_copy(a));
        break;
      }
    }
  }

  if (TAILQ_EMPTY(al))
  {
    TAILQ_FOREACH(a, &env->cc, entries)
    {
      if (mutt_addr_is_user(a))
      {
        mutt_addrlist_append(al, mutt_addr_copy(a));
        break;
      }
    }
  }

  if (TAILQ_EMPTY(al))
  {
    struct Address *from = TAILQ_FIRST(&env->from);
    if (from && mutt_addr_is_user(from))
    {
      mutt_addrlist_append(al, mutt_addr_copy(from));
    }
  }

  if (!TAILQ_EMPTY(al))
  {
    /* when $reverse_real_name is not set, clear the personal name so that it
     * may be set via a reply- or send-hook.  */

    const bool c_reverse_real_name = cs_subset_bool(sub, "reverse_real_name");
    if (!c_reverse_real_name)
      FREE(&TAILQ_FIRST(al)->personal);
  }
}

/**
 * mutt_default_from - Get a default 'from' Address
 * @param sub Config Subset
 * @retval ptr Newly allocated Address
 */
struct Address *mutt_default_from(struct ConfigSubset *sub)
{
  /* Note: We let $from override $real_name here.
   *       Is this the right thing to do?
   */

  const struct Address *c_from = cs_subset_address(sub, "from");
  if (c_from)
  {
    return mutt_addr_copy(c_from);
  }

  char domain[1024] = { 0 };
  const char *mailbox = Username;
  const bool c_use_domain = cs_subset_bool(sub, "use_domain");
  if (c_use_domain)
  {
    snprintf(domain, sizeof(domain), "%s@%s", NONULL(Username),
             NONULL(mutt_fqdn(true, sub)));
    mailbox = domain;
  }

  return mutt_addr_create(NULL, mailbox);
}

/**
 * invoke_mta - Send an email
 * @param m   Mailbox
 * @param e   Email
 * @param sub Config Subset
 * @retval  0 Success
 * @retval -1 Failure
 */
static int invoke_mta(struct Mailbox *m, struct Email *e, struct ConfigSubset *sub)
{
  struct Buffer *tempfile = NULL;
  int rc = -1;

  /* Write out the message in MIME form. */
  tempfile = buf_pool_get();
  buf_mktemp(tempfile);
  FILE *fp_tmp = mutt_file_fopen(buf_string(tempfile), "w");
  if (!fp_tmp)
    goto cleanup;

  const bool c_write_bcc = cs_subset_bool(sub, "write_bcc");
  const char *const c_smtp_url = cs_subset_string(sub, "smtp_url");
  if (c_smtp_url)
    cs_subset_str_native_set(sub, "write_bcc", false, NULL);

  mutt_rfc822_write_header(fp_tmp, e->env, e->body, MUTT_WRITE_HEADER_NORMAL,
                           false, mutt_should_hide_protected_subject(e), sub);

  cs_subset_str_native_set(sub, "write_bcc", c_write_bcc, NULL);

  fputc('\n', fp_tmp); /* tie off the header. */

  if ((mutt_write_mime_body(e->body, fp_tmp, sub) == -1))
    goto cleanup;

  if (mutt_file_fclose(&fp_tmp) != 0)
  {
    mutt_perror("%s", buf_string(tempfile));
    unlink(buf_string(tempfile));
    goto cleanup;
  }

  if (OptNewsSend)
    goto sendmail;

  if (c_smtp_url)
  {
    rc = mutt_smtp_send(&e->env->from, &e->env->to, &e->env->cc, &e->env->bcc,
                        buf_string(tempfile), (e->body->encoding == ENC_8BIT), sub);
    goto cleanup;
  }

sendmail:
  rc = mutt_invoke_sendmail(m, &e->env->from, &e->env->to, &e->env->cc, &e->env->bcc,
                            buf_string(tempfile), (e->body->encoding == ENC_8BIT), sub);
cleanup:
  if (fp_tmp)
  {
    mutt_file_fclose(&fp_tmp);
    unlink(buf_string(tempfile));
  }
  buf_pool_release(&tempfile);
  return rc;
}

/**
 * mutt_encode_descriptions - RFC2047 encode the content-descriptions
 * @param b       Body of email
 * @param recurse If true, encode children parts
 * @param sub     Config Subset
 */
void mutt_encode_descriptions(struct Body *b, bool recurse, struct ConfigSubset *sub)
{
  const struct Slist *const c_send_charset = cs_subset_slist(sub, "send_charset");
  for (struct Body *t = b; t; t = t->next)
  {
    if (t->description)
    {
      rfc2047_encode(&t->description, NULL, sizeof("Content-Description:"), c_send_charset);
    }
    if (recurse && t->parts)
      mutt_encode_descriptions(t->parts, recurse, sub);
  }
}

/**
 * decode_descriptions - RFC2047 decode them in case of an error
 * @param b MIME parts to decode
 */
static void decode_descriptions(struct Body *b)
{
  for (struct Body *t = b; t; t = t->next)
  {
    if (t->description)
    {
      rfc2047_decode(&t->description);
    }
    if (t->parts)
      decode_descriptions(t->parts);
  }
}

/**
 * fix_end_of_file - Ensure a file ends with a linefeed
 * @param data Name of file to fix
 */
static void fix_end_of_file(const char *data)
{
  FILE *fp = mutt_file_fopen(data, "a+");
  if (!fp)
    return;

  if ((mutt_file_get_size_fp(fp) > 0) && mutt_file_seek(fp, -1, SEEK_END))
  {
    int c = fgetc(fp);
    if (c != '\n')
      fputc('\n', fp);
  }
  mutt_file_fclose(&fp);
}

/**
 * mutt_resend_message - Resend an email
 * @param fp    File containing email
 * @param m     Mailbox
 * @param e_cur Email to resend
 * @param sub   Config Subset
 * @retval  0 Message was successfully sent
 * @retval -1 Message was aborted or an error occurred
 * @retval  1 Message was postponed
 */
int mutt_resend_message(FILE *fp, struct Mailbox *m, struct Email *e_cur,
                        struct ConfigSubset *sub)
{
  struct Email *e_new = email_new();

  if (mutt_prepare_template(fp, m, e_new, e_cur, true) < 0)
  {
    email_free(&e_new);
    return -1;
  }

  if (WithCrypto)
  {
    /* mutt_prepare_template doesn't always flip on an application bit.
     * so fix that here */
    if (!(e_new->security & (APPLICATION_SMIME | APPLICATION_PGP)))
    {
      const bool c_smime_is_default = cs_subset_bool(sub, "smime_is_default");
      if (((WithCrypto & APPLICATION_SMIME) != 0) && c_smime_is_default)
        e_new->security |= APPLICATION_SMIME;
      else if (WithCrypto & APPLICATION_PGP)
        e_new->security |= APPLICATION_PGP;
      else
        e_new->security |= APPLICATION_SMIME;
    }

    const bool c_crypt_opportunistic_encrypt = cs_subset_bool(sub, "crypt_opportunistic_encrypt");
    if (c_crypt_opportunistic_encrypt)
    {
      e_new->security |= SEC_OPPENCRYPT;
      crypt_opportunistic_encrypt(e_new);
    }
  }

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ARRAY_ADD(&ea, e_cur);
  int rc = mutt_send_message(SEND_RESEND, e_new, NULL, m, &ea, sub);
  ARRAY_FREE(&ea);

  return rc;
}

/**
 * is_reply - Is one email a reply to another?
 * @param reply Email to test
 * @param orig  Original email
 * @retval true  It is a reply
 * @retval false It is not a reply
 */
static bool is_reply(struct Email *reply, struct Email *orig)
{
  if (!reply || !reply->env || !orig || !orig->env)
    return false;
  return mutt_list_find(&orig->env->references, reply->env->message_id) ||
         mutt_list_find(&orig->env->in_reply_to, reply->env->message_id);
}

/**
 * search_attach_keyword - Search an email for 'attachment' keywords
 * @param filename Filename
 * @param sub      Config Subset
 * @retval true The regex matches in the email
 *
 * Search an email for the regex in $abort_noattach_regex.
 * A match might indicate that the user should have attached something.
 *
 * @note Quoted lines (as defined by $quote_regex) are ignored
 */
static bool search_attach_keyword(char *filename, struct ConfigSubset *sub)
{
  const struct Regex *c_abort_noattach_regex = cs_subset_regex(sub, "abort_noattach_regex");
  const struct Regex *c_quote_regex = cs_subset_regex(sub, "quote_regex");

  /* Search for the regex in `$abort_noattach_regex` within a file */
  if (!c_abort_noattach_regex || !c_abort_noattach_regex->regex ||
      !c_quote_regex || !c_quote_regex->regex)
  {
    return false;
  }

  FILE *fp_att = mutt_file_fopen(filename, "r");
  if (!fp_att)
    return false;

  char *inputline = MUTT_MEM_MALLOC(1024, char);
  bool found = false;
  while (!feof(fp_att) && fgets(inputline, 1024, fp_att))
  {
    if (!mutt_is_quote_line(inputline, NULL) &&
        mutt_regex_match(c_abort_noattach_regex, inputline))
    {
      found = true;
      break;
    }
  }
  FREE(&inputline);
  mutt_file_fclose(&fp_att);
  return found;
}

/**
 * save_fcc - Save an Email to a 'sent mail' folder
 * @param[in]  m             Current Mailbox
 * @param[in]  e             Email to save
 * @param[in]  fcc           Folder to save to (can be comma-separated list)
 * @param[in]  clear_content Cleartext content of Email
 * @param[in]  pgpkeylist    List of pgp keys
 * @param[in]  flags         Send mode, see #SendFlags
 * @param[out] finalpath     Path of final folder
 * @param[in]  sub           Config Subset
 * @retval  0 Success
 * @retval -1 Error
 */
static int save_fcc(struct Mailbox *m, struct Email *e, struct Buffer *fcc,
                    struct Body *clear_content, char *pgpkeylist,
                    SendFlags flags, char **finalpath, struct ConfigSubset *sub)
{
  int rc = 0;
  struct Body *save_content = NULL;

  buf_expand_path(fcc);

  /* Don't save a copy when we are in batch-mode, and the FCC
   * folder is on an IMAP server: This would involve possibly lots
   * of user interaction, which is not available in batch mode.
   *
   * Note: A patch to fix the problems with the use of IMAP servers
   * from non-curses mode is available from Brendan Cully.  However,
   * I'd like to think a bit more about this before including it.  */

  if ((flags & SEND_BATCH) && !buf_is_empty(fcc) &&
      (imap_path_probe(buf_string(fcc), NULL) == MUTT_IMAP))
  {
    mutt_error(_("Warning: Fcc to an IMAP mailbox is not supported in batch mode"));
    /* L10N: Printed after the "Fcc to an IMAP mailbox is not supported" message.
       To make it clearer that the message doesn't mean NeoMutt is aborting
       sending the mail too.
       %s is the full mailbox URL, including imap(s)://
    */
    mutt_error(_("Skipping Fcc to %s"), buf_string(fcc));
    buf_reset(fcc);
    return rc;
  }

  if (buf_is_empty(fcc) || mutt_str_equal("/dev/null", buf_string(fcc)))
    return rc;

  struct Body *tmpbody = e->body;
  struct Body *save_sig = NULL;
  struct Body *save_parts = NULL;

  const bool c_fcc_before_send = cs_subset_bool(sub, "fcc_before_send");
  /* Before sending, we don't allow message manipulation because it
   * will break message signatures.  This is especially complicated by
   * Protected Headers. */
  if (!c_fcc_before_send)
  {
    const bool c_fcc_clear = cs_subset_bool(sub, "fcc_clear");
    if ((WithCrypto != 0) &&
        (e->security & (SEC_ENCRYPT | SEC_SIGN | SEC_AUTOCRYPT)) && c_fcc_clear)
    {
      e->body = clear_content;
      e->security &= ~(SEC_ENCRYPT | SEC_SIGN | SEC_AUTOCRYPT);
      mutt_env_free(&e->body->mime_headers);
      mutt_param_delete(&e->body->parameter, "protected-headers");
    }

    const enum QuadOption c_fcc_attach = cs_subset_quad(sub, "fcc_attach");

    /* check to see if the user wants copies of all attachments */
    bool save_atts = true;
    if (e->body->type == TYPE_MULTIPART)
    {
      /* In batch mode, save attachments if the quadoption is yes or ask-yes */
      if (flags & SEND_BATCH)
      {
        if ((c_fcc_attach == MUTT_NO) || (c_fcc_attach == MUTT_ASKNO))
          save_atts = false;
      }
      else if (query_quadoption(_("Save attachments in Fcc?"), sub, "fcc_attach") != MUTT_YES)
      {
        save_atts = false;
      }
    }
    if (!save_atts)
    {
      if ((WithCrypto != 0) && (e->security & (SEC_ENCRYPT | SEC_SIGN | SEC_AUTOCRYPT)) &&
          (mutt_str_equal(e->body->subtype, "encrypted") ||
           mutt_str_equal(e->body->subtype, "signed")))
      {
        if ((clear_content->type == TYPE_MULTIPART) &&
            (query_quadoption(_("Save attachments in Fcc?"), sub, "fcc_attach") != MUTT_YES))
        {
          if (!(e->security & SEC_ENCRYPT) && (e->security & SEC_SIGN))
          {
            /* save initial signature and attachments */
            save_sig = e->body->parts->next;
            save_parts = clear_content->parts->next;
          }

          /* this means writing only the main part */
          e->body = clear_content->parts;

          if (mutt_protect(e, pgpkeylist, false) == -1)
          {
            /* we can't do much about it at this point, so
           * fallback to saving the whole thing to fcc */
            e->body = tmpbody;
            save_sig = NULL;
            goto full_fcc;
          }

          save_content = e->body;
        }
      }
      else
      {
        if (query_quadoption(_("Save attachments in Fcc?"), sub, "fcc_attach") != MUTT_YES)
          e->body = e->body->parts;
      }
    }
  }

full_fcc:
  if (e->body)
  {
    /* update received time so that when storing to a mbox-style folder
     * the From_ line contains the current time instead of when the
     * message was first postponed.  */
    e->received = mutt_date_now();
    rc = mutt_write_multiple_fcc(buf_string(fcc), e, NULL, false, NULL, finalpath, sub);
    while (rc && !(flags & SEND_BATCH))
    {
      mutt_clear_error();
      int choice = mw_multi_choice(
          /* L10N: Called when saving to $record or Fcc failed after sending.
             (r)etry tries the same mailbox again.
             alternate (m)ailbox prompts for a different mailbox to try.
             (s)kip aborts saving.  */
          _("Fcc failed. (r)etry, alternate (m)ailbox, or (s)kip?"),
          /* L10N: These correspond to the "Fcc failed" multi-choice prompt
             (r)etry, alternate (m)ailbox, or (s)kip.
             Any similarity to famous leaders of the FSF is coincidental.  */
          _("rms"));
      switch (choice)
      {
        case 2: /* alternate (m)ailbox */
          /* L10N: This is the prompt to enter an "alternate (m)ailbox" when the
             initial Fcc fails.  */
          rc = mw_enter_fname(_("Fcc mailbox"), fcc, true, m, false, NULL, NULL,
                              MUTT_SEL_NO_FLAGS);
          if ((rc == -1) || buf_is_empty(fcc))
          {
            rc = 0;
            break;
          }
          FALLTHROUGH;

        case 1: /* (r)etry */
          rc = mutt_write_multiple_fcc(buf_string(fcc), e, NULL, false, NULL, finalpath, sub);
          break;

        case -1: /* abort */
        case 3:  /* (s)kip */
          rc = 0;
          break;
      }
    }
  }

  if (!c_fcc_before_send)
  {
    e->body = tmpbody;

    if ((WithCrypto != 0) && save_sig)
    {
      /* cleanup the second signature structures */
      if (save_content->parts)
      {
        mutt_body_free(&save_content->parts->next);
        save_content->parts = NULL;
      }
      mutt_body_free(&save_content);

      /* restore old signature and attachments */
      e->body->parts->next = save_sig;
      e->body->parts->parts->next = save_parts;
    }
    else if ((WithCrypto != 0) && save_content)
    {
      /* destroy the new encrypted body. */
      mutt_body_free(&save_content);
    }
  }

  return 0;
}

/**
 * postpone_message - Save an Email for another day
 * @param e_post Email to postpone
 * @param e_cur  Current Email in the index
 * @param fcc    Folder for 'sent mail'
 * @param flags  Send mode, see #SendFlags
 * @param sub    Config Subset
 * @retval  0 Success
 * @retval -1 Error
 */
static int postpone_message(struct Email *e_post, struct Email *e_cur,
                            const char *fcc, SendFlags flags, struct ConfigSubset *sub)
{
  char *pgpkeylist = NULL;
  const char *encrypt_as = NULL;
  struct Body *clear_content = NULL;

  const char *const c_postponed = cs_subset_string(sub, "postponed");
  if (!c_postponed)
  {
    mutt_error(_("Can't postpone.  $postponed is unset"));
    return -1;
  }

  if (e_post->body->next)
    e_post->body = mutt_make_multipart(e_post->body);

  mutt_encode_descriptions(e_post->body, true, sub);

  const bool c_postpone_encrypt = cs_subset_bool(sub, "postpone_encrypt");
  if ((WithCrypto != 0) && c_postpone_encrypt &&
      (e_post->security & (SEC_ENCRYPT | SEC_AUTOCRYPT)))
  {
    if (((WithCrypto & APPLICATION_PGP) != 0) && (e_post->security & APPLICATION_PGP))
    {
      const char *const c_pgp_default_key = cs_subset_string(sub, "pgp_default_key");
      encrypt_as = c_pgp_default_key;
    }
    else if (((WithCrypto & APPLICATION_SMIME) != 0) && (e_post->security & APPLICATION_SMIME))
    {
      const char *const c_smime_default_key = cs_subset_string(sub, "smime_default_key");
      encrypt_as = c_smime_default_key;
    }
    if (!encrypt_as)
    {
      const char *const c_postpone_encrypt_as = cs_subset_string(sub, "postpone_encrypt_as");
      encrypt_as = c_postpone_encrypt_as;
    }

#ifdef USE_AUTOCRYPT
    if (e_post->security & SEC_AUTOCRYPT)
    {
      if (mutt_autocrypt_set_sign_as_default_key(e_post))
      {
        if (mutt_istr_equal(e_post->body->subtype, "mixed"))
          e_post->body = mutt_remove_multipart(e_post->body);
        decode_descriptions(e_post->body);
        mutt_error(_("Error encrypting message. Check your crypt settings."));
        return -1;
      }
      encrypt_as = AutocryptDefaultKey;
    }
#endif

    if (encrypt_as)
    {
      pgpkeylist = mutt_str_dup(encrypt_as);
      clear_content = e_post->body;
      if (mutt_protect(e_post, pgpkeylist, true) == -1)
      {
        FREE(&pgpkeylist);
        if (mutt_istr_equal(e_post->body->subtype, "mixed"))
          e_post->body = mutt_remove_multipart(e_post->body);
        decode_descriptions(e_post->body);
        mutt_error(_("Error encrypting message. Check your crypt settings."));
        return -1;
      }

      FREE(&pgpkeylist);

      mutt_encode_descriptions(e_post->body, false, sub);
    }
  }

  /* make sure the message is written to the right part of a maildir
   * postponed folder.  */
  e_post->read = false;
  e_post->old = false;

  mutt_prepare_envelope(e_post->env, false, sub);
  mutt_env_to_intl(e_post->env, NULL, NULL); /* Handle bad IDNAs the next time. */

  if (mutt_write_fcc(NONULL(c_postponed), e_post,
                     (e_cur && (flags & SEND_REPLY)) ? e_cur->env->message_id : NULL,
                     true, fcc, NULL, sub) < 0)
  {
    if (clear_content)
    {
      mutt_body_free(&e_post->body);
      e_post->body = clear_content;
    }
    mutt_env_free(&e_post->body->mime_headers); /* protected headers */
    mutt_param_delete(&e_post->body->parameter, "protected-headers");
    if (mutt_istr_equal(e_post->body->subtype, "mixed"))
      e_post->body = mutt_remove_multipart(e_post->body);
    decode_descriptions(e_post->body);
    mutt_unprepare_envelope(e_post->env);
    return -1;
  }

  mutt_update_num_postponed();

  if (clear_content)
    mutt_body_free(&clear_content);

  return 0;
}

/**
 * is_text_plain - Is a Body a text/plain MIME part?
 * @param b Body to check
 * @retval true  Body is text/plain
 * @retval false Body is not
 */
static bool is_text_plain(const struct Body *b)
{
  return (b->type == TYPE_TEXT) && mutt_istr_equal(b->subtype, "plain");
}

/**
 * abort_for_missing_attachments - Should we abort sending because of missing attachments?
 * @param b Body
 * @param sub Config Subset
 * @retval true Abort because of missing attachments
 */
static bool abort_for_missing_attachments(const struct Body *b, struct ConfigSubset *sub)
{
  const enum QuadOption c_abort_noattach = cs_subset_quad(sub, "abort_noattach");

  if (c_abort_noattach == MUTT_NO)
    return false;

  if (b->next)
    return false;

  bool has_keyword = false;

  /* search text/plain parts, whether they are main or alternative parts */
  if (is_text_plain(b))
  {
    has_keyword |= search_attach_keyword(b->filename, sub);
  }
  else
  {
    for (b = b->parts; b; b = b->next)
    {
      if (is_text_plain(b))
      {
        has_keyword |= search_attach_keyword(b->filename, sub);
      }
    }
  }

  if (!has_keyword)
    return false;

  if (c_abort_noattach == MUTT_YES)
  {
    mutt_error(_("Message contains text matching \"$abort_noattach_regex\". Not sending."));
    return true;
  }

  return query_quadoption(_("No attachments, cancel sending?"), sub, "abort_noattach") != MUTT_NO;
}

/**
 * mutt_send_message - Send an email
 * @param flags    Send mode, see #SendFlags
 * @param e_templ  Template to use for new message
 * @param tempfile File specified by -i or -H
 * @param m        Current mailbox
 * @param ea       Array of Emails to send
 * @param sub      Config Subset
 * @retval  0 Message was successfully sent
 * @retval -1 Message was aborted or an error occurred
 * @retval  1 Message was postponed
 */
int mutt_send_message(SendFlags flags, struct Email *e_templ, const char *tempfile,
                      struct Mailbox *m, struct EmailArray *ea, struct ConfigSubset *sub)
{
  struct Buffer *fcc = buf_pool_get(); /* where to copy this message */
  FILE *fp_tmp = NULL;
  struct Body *pbody = NULL;
  int i;
  bool free_clear_content = false;

  struct Body *clear_content = NULL;
  char *pgpkeylist = NULL;
  /* save current value of "pgp_sign_as"  and "smime_default_key" */
  char *pgp_sign_as = NULL;
  char *smime_sign_as = NULL;
  const char *tag = NULL;
  char *err = NULL;
  const char *ctype = NULL;
  char *finalpath = NULL;
  struct Email *e_cur = NULL;

  if (ea && (ARRAY_SIZE(ea) == 1))
    e_cur = *ARRAY_GET(ea, 0);

  int rc = -1;

  if (flags & SEND_NEWS)
    OptNewsSend = true;
  else
    OptNewsSend = false;

  const enum QuadOption c_recall = cs_subset_quad(sub, "recall");

  if (!flags && !e_templ && (c_recall != MUTT_NO) && mutt_num_postponed(m, true))
  {
    /* If the user is composing a new message, check to see if there
     * are any postponed messages first.  */
    enum QuadOption ans = query_quadoption(_("Recall postponed message?"), sub, "recall");
    if (ans == MUTT_ABORT)
      return rc;

    if (ans == MUTT_YES)
      flags |= SEND_POSTPONED;
  }

  if (flags & SEND_POSTPONED)
  {
    if (WithCrypto & APPLICATION_PGP)
    {
      const char *const c_pgp_sign_as = cs_subset_string(sub, "pgp_sign_as");
      pgp_sign_as = mutt_str_dup(c_pgp_sign_as);
    }
    if (WithCrypto & APPLICATION_SMIME)
    {
      const char *const c_smime_sign_as = cs_subset_string(sub, "smime_sign_as");
      smime_sign_as = mutt_str_dup(c_smime_sign_as);
    }
  }

  /* Delay expansion of aliases until absolutely necessary--shouldn't
   * be necessary unless we are prompting the user or about to execute a
   * send-hook.  */

  if (!e_templ)
  {
    e_templ = email_new();

    if (flags == SEND_POSTPONED)
    {
      rc = mutt_get_postponed(m, e_templ, &e_cur, fcc);
      if (rc < 0)
      {
        flags = SEND_POSTPONED;
        goto cleanup;
      }
      flags = rc;
      /* If postponed message is a news article, it have
       * a "Newsgroups:" header line, then set appropriate flag.  */
      if (e_templ->env->newsgroups)
      {
        flags |= SEND_NEWS;
        OptNewsSend = true;
      }
      else
      {
        flags &= ~SEND_NEWS;
        OptNewsSend = false;
      }
    }

    if (flags & (SEND_POSTPONED | SEND_RESEND))
    {
      struct Body *b = e_templ->body;
      while (b->parts)
        b = b->parts;
      fp_tmp = mutt_file_fopen(b->filename, "a+");
      if (!fp_tmp)
      {
        mutt_perror("%s", b->filename);
        goto cleanup;
      }
    }

    if (!e_templ->env)
      e_templ->env = mutt_env_new();
  }

  /* Parse and use an eventual list-post header */
  if ((flags & SEND_LIST_REPLY) && e_cur && e_cur->env && e_cur->env->list_post)
  {
    /* Use any list-post header as a template */
    mutt_parse_mailto(e_templ->env, NULL, e_cur->env->list_post);
    /* We don't let them set the sender's address. */
    mutt_addrlist_clear(&e_templ->env->from);
  }

  if (!(flags & (SEND_KEY | SEND_POSTPONED | SEND_RESEND)))
  {
    /* When SEND_DRAFT_FILE is set, the caller has already
     * created the "parent" body structure.  */
    if (!(flags & SEND_DRAFT_FILE))
    {
      pbody = mutt_body_new();
      pbody->next = e_templ->body; /* don't kill command-line attachments */
      e_templ->body = pbody;

      const char *const c_content_type = cs_subset_string(sub, "content_type");
      ctype = c_content_type;
      if (!ctype)
        ctype = "text/plain";
      mutt_parse_content_type(ctype, e_templ->body);
      e_templ->body->unlink = true;
      e_templ->body->use_disp = false;
      e_templ->body->disposition = DISP_INLINE;

      if (tempfile)
      {
        fp_tmp = mutt_file_fopen(tempfile, "a+");
        e_templ->body->filename = mutt_str_dup(tempfile);
        if (flags & SEND_NO_FREE_HEADER)
          e_templ->body->unlink = false;
      }
      else
      {
        struct Buffer *buf = buf_pool_get();
        buf_mktemp(buf);
        fp_tmp = mutt_file_fopen(buf_string(buf), "w+");
        e_templ->body->filename = buf_strdup(buf);
        buf_pool_release(&buf);
      }
    }
    else
    {
      struct Body *b = e_templ->body;
      while (b->parts)
        b = b->parts;
      fp_tmp = mutt_file_fopen(b->filename, "a+");
    }

    if (!fp_tmp)
    {
      mutt_debug(LL_DEBUG1, "can't create tempfile %s (errno=%d)\n",
                 e_templ->body->filename, errno);
      mutt_perror("%s", e_templ->body->filename);
      goto cleanup;
    }
  }

  const bool c_reverse_name = cs_subset_bool(sub, "reverse_name");
  /* this is handled here so that the user can match ~f in send-hook */
  if (e_cur && c_reverse_name && !(flags & (SEND_POSTPONED | SEND_RESEND)))
  {
    /* We shouldn't have to worry about alias expansion here since we are
     * either replying to a real or postponed message, therefore no aliases
     * should exist since the user has not had the opportunity to add
     * addresses to the list.  We just have to ensure the postponed messages
     * have their aliases expanded.  */

    if (!TAILQ_EMPTY(&e_templ->env->from))
    {
      mutt_debug(LL_DEBUG5, "e_templ->env->from before set_reverse_name: %s\n",
                 buf_string(TAILQ_FIRST(&e_templ->env->from)->mailbox));
      mutt_addrlist_clear(&e_templ->env->from);
    }
    set_reverse_name(&e_templ->env->from, e_cur->env, sub);
  }

  const bool c_reply_with_xorig = cs_subset_bool(sub, "reply_with_xorig");
  if (e_cur && c_reply_with_xorig && !(flags & (SEND_POSTPONED | SEND_RESEND | SEND_FORWARD)))
  {
    /* We shouldn't have to worry about freeing 'e_templ->env->from' before
     * setting it here since this code will only execute when doing some
     * sort of reply. The pointer will only be set when using the -H command
     * line option.
     *
     * If there is already a from address recorded in 'e_templ->env->from',
     * then it theoretically comes from `$reverse_name` handling, and we don't use
     * the 'X-Original-To header'.  */
    if (!TAILQ_EMPTY(&e_cur->env->x_original_to) && TAILQ_EMPTY(&e_templ->env->from))
    {
      mutt_addrlist_copy(&e_templ->env->from, &e_cur->env->x_original_to, false);
      mutt_debug(LL_DEBUG5, "e_templ->env->from extracted from X-Original-To: header: %s\n",
                 buf_string(TAILQ_FIRST(&e_templ->env->from)->mailbox));
    }
  }

  if (!e_templ->env->message_id)
    e_templ->env->message_id = mutt_gen_msgid();

  const bool c_resume_draft_files = cs_subset_bool(sub, "resume_draft_files");
  if (!(flags & (SEND_POSTPONED | SEND_RESEND)) &&
      !((flags & SEND_DRAFT_FILE) && c_resume_draft_files))
  {
    if ((flags & (SEND_REPLY | SEND_FORWARD | SEND_TO_SENDER)) &&
        (envelope_defaults(e_templ->env, ea, flags, sub) == -1))
    {
      goto cleanup;
    }

    const bool c_hdrs = cs_subset_bool(sub, "hdrs");
    if (c_hdrs)
      process_user_recips(e_templ->env);

    /* Expand aliases and remove duplicates/crossrefs */
    mutt_expand_aliases_env(e_templ->env);

    if (flags & SEND_REPLY)
      mutt_fix_reply_recipients(e_templ->env, sub);

    if ((flags & SEND_NEWS) && (m && m->type == MUTT_NNTP) && !e_templ->env->newsgroups)
    {
      e_templ->env->newsgroups = mutt_str_dup(((struct NntpMboxData *) m->mdata)->group);
    }

    const bool c_auto_edit = cs_subset_bool(sub, "auto_edit");
    const bool c_edit_headers = cs_subset_bool(sub, "edit_headers");
    const bool c_fast_reply = cs_subset_bool(sub, "fast_reply");
    if (!(flags & SEND_BATCH) && !(c_auto_edit && c_edit_headers) &&
        !((flags & SEND_REPLY) && c_fast_reply))
    {
      if (edit_envelope(e_templ->env, flags, sub) == -1)
        goto cleanup;
    }

    /* the from address must be set here regardless of whether or not
     * $use_from is set so that the '~P' (from you) operator in send-hook
     * patterns will work.  if $use_from is unset, the from address is killed
     * after send-hooks are evaluated */

    const bool killfrom = TAILQ_EMPTY(&e_templ->env->from);
    if (killfrom)
    {
      mutt_addrlist_append(&e_templ->env->from, mutt_default_from(sub));
    }

    if ((flags & SEND_REPLY) && e_cur)
    {
      /* change setting based upon message we are replying to */
      mutt_message_hook(m, e_cur, MUTT_REPLY_HOOK);

      /* set the replied flag for the message we are generating so that the
       * user can use ~Q in a send-hook to know when reply-hook's are also
       * being used.  */
      e_templ->replied = true;
    }

    /* change settings based upon recipients */

    mutt_message_hook(NULL, e_templ, MUTT_SEND_HOOK);

    /* Unset the replied flag from the message we are composing since it is
     * no longer required.  This is done here because the FCC'd copy of
     * this message was erroneously get the 'R'eplied flag when stored in
     * a maildir-style mailbox.  */
    e_templ->replied = false;

    /* $use_from and/or $from might have changed in a send-hook */
    if (killfrom)
    {
      mutt_addrlist_clear(&e_templ->env->from);

      const bool c_use_from = cs_subset_bool(sub, "use_from");
      if (c_use_from && !(flags & (SEND_POSTPONED | SEND_RESEND)))
        mutt_addrlist_append(&e_templ->env->from, mutt_default_from(sub));
    }

    if (c_hdrs)
      process_user_header(e_templ->env);

    if ((flags & SEND_BATCH) && !(flags & SEND_CONSUMED_STDIN))
    {
      if (mutt_file_copy_stream(stdin, fp_tmp) < 0)
      {
        mutt_error(_("Error sending message"));
        goto cleanup;
      }
    }

    if (!(flags & SEND_BATCH))
      mutt_make_greeting(e_templ, fp_tmp, sub);

    const bool c_sig_on_top = cs_subset_bool(sub, "sig_on_top");
    const char *const c_editor = cs_subset_string(sub, "editor");
    if (c_sig_on_top && !(flags & (SEND_KEY | SEND_BATCH)) && c_editor)
    {
      append_signature(fp_tmp, sub);
    }

    /* include replies/forwarded messages, unless we are given a template */
    if (!tempfile && (m || !(flags & (SEND_REPLY | SEND_FORWARD))) &&
        (generate_body(fp_tmp, e_templ, flags, m, ea, sub) == -1))
    {
      goto cleanup;
    }

    if (!c_sig_on_top && !(flags & (SEND_KEY | SEND_BATCH)) && c_editor)
    {
      append_signature(fp_tmp, sub);
    }
  }

  /* Only set format=flowed for new messages.  postponed/resent/draftfiles
   * should respect the original email.
   *
   * This is set here so that send-hook can be used to turn the option on.  */
  if (!(flags & (SEND_KEY | SEND_POSTPONED | SEND_RESEND | SEND_DRAFT_FILE)))
  {
    const bool c_text_flowed = cs_subset_bool(sub, "text_flowed");
    if (c_text_flowed && is_text_plain(e_templ->body))
    {
      mutt_param_set(&e_templ->body->parameter, "format", "flowed");
    }
  }

  /* This hook is even called for postponed messages, and can, e.g., be used
   * for setting the editor, the sendmail path, or the envelope sender.  */
  mutt_message_hook(NULL, e_templ, MUTT_SEND2_HOOK);

  /* wait until now to set the real name portion of our return address so
   * that $real_name can be set in a send-hook */
  {
    struct Address *from = TAILQ_FIRST(&e_templ->env->from);
    if (from && !from->personal && !(flags & (SEND_RESEND | SEND_POSTPONED)))
    {
      const char *const c_real_name = cs_subset_string(sub, "real_name");
      if (c_real_name)
        from->personal = buf_new(c_real_name);
    }
  }

  if (!(((WithCrypto & APPLICATION_PGP) != 0) && (flags & SEND_KEY)))
    mutt_file_fclose(&fp_tmp);

  if (!(flags & SEND_BATCH))
  {
    struct stat st = { 0 };
    time_t mtime;
    struct Body *b = e_templ->body;
    while (b->parts)
      b = b->parts;
    mtime = mutt_file_decrease_mtime(b->filename, NULL);
    if (mtime == (time_t) -1)
    {
      mutt_perror("%s", b->filename);
      goto cleanup;
    }

    mutt_update_encoding(b, sub);

    const bool c_edit_headers = cs_subset_bool(sub, "edit_headers");
    const bool c_auto_edit = cs_subset_bool(sub, "auto_edit");

    /* Select whether or not the user's editor should be called now.  We
     * don't want to do this when:
     * 1) we are sending a key/cert
     * 2) we are forwarding a message and the user doesn't want to edit it.
     *    This is controlled by the quadoption $forward_edit.  However, if
     *    both $edit_headers and $auto_edit are set, we want to ignore the
     *    setting of $forward_edit because the user probably needs to add the
     *    recipients.  */
    if (!(flags & SEND_KEY) &&
        (((flags & SEND_FORWARD) == 0) || (c_edit_headers && c_auto_edit) ||
         (query_quadoption(_("Edit forwarded message?"), sub, "forward_edit") == MUTT_YES)))
    {
      /* If the this isn't a text message, look for a mailcap edit command */
      const char *const c_editor = cs_subset_string(sub, "editor");
      b = e_templ->body;
      while (b->parts)
        b = b->parts;
      if (mutt_needs_mailcap(b))
      {
        if (!mutt_edit_attachment(b))
          goto cleanup;
      }
      else if (c_edit_headers)
      {
        mutt_env_to_local(e_templ->env);
        mutt_edit_headers(c_editor, b->filename, e_templ, fcc);
        mutt_env_to_intl(e_templ->env, NULL, NULL);
      }
      else
      {
        mutt_edit_file(c_editor, b->filename);
        if (stat(b->filename, &st) == 0)
        {
          if (mtime != st.st_mtime)
            fix_end_of_file(b->filename);
        }
        else
        {
          mutt_perror("%s", b->filename);
        }
      }

      mutt_message_hook(NULL, e_templ, MUTT_SEND2_HOOK);
    }

    if (!(flags & (SEND_POSTPONED | SEND_FORWARD | SEND_KEY | SEND_RESEND | SEND_DRAFT_FILE)))
    {
      if (stat(e_templ->body->filename, &st) == 0)
      {
        /* if the file was not modified, bail out now */
        if ((mtime == st.st_mtime) && !e_templ->body->next &&
            (query_quadoption(_("Abort unmodified message?"), sub, "abort_unmodified") == MUTT_YES))
        {
          mutt_message(_("Aborted unmodified message"));
          goto cleanup;
        }
      }
      else
      {
        mutt_perror("%s", e_templ->body->filename);
      }
    }
  }

  /* Set the message security unless:
   * 1) crypto support is not enabled (WithCrypto==0)
   * 2) pgp: header field was present during message editing with $edit_headers (e_templ->security != 0)
   * 3) we are resending a message
   * 4) we are recalling a postponed message (don't override the user's saved settings)
   * 5) we are in batch mode
   * But 3, 4, and 5, can be overridden with '-C' in the command line (flags & SEND_CLI_CRYPTO)
   *
   * This is done after allowing the user to edit the message so that security
   * settings can be configured with send2-hook and $edit_headers.  */
  if ((WithCrypto != 0) && (e_templ->security == 0) &&
      ((flags & SEND_CLI_CRYPTO) || !(flags & (SEND_BATCH | SEND_POSTPONED | SEND_RESEND))))
  {
    bool c_autocrypt = false;
    bool c_autocrypt_reply = false;

#ifdef USE_AUTOCRYPT
    c_autocrypt = cs_subset_bool(sub, "autocrypt");
    c_autocrypt_reply = cs_subset_bool(sub, "autocrypt_reply");
#endif

    if (c_autocrypt && c_autocrypt_reply && e_cur && (e_cur->security & SEC_AUTOCRYPT))
    {
      e_templ->security |= (SEC_AUTOCRYPT | SEC_AUTOCRYPT_OVERRIDE | APPLICATION_PGP);
    }
    else
    {
      const bool c_crypt_auto_sign = cs_subset_bool(sub, "crypt_auto_sign");
      const bool c_crypt_auto_encrypt = cs_subset_bool(sub, "crypt_auto_encrypt");
      const bool c_crypt_reply_encrypt = cs_subset_bool(sub, "crypt_reply_encrypt");
      const bool c_crypt_reply_sign = cs_subset_bool(sub, "crypt_reply_sign");
      const bool c_crypt_reply_sign_encrypted = cs_subset_bool(sub, "crypt_reply_sign_encrypted");

      if (c_crypt_auto_sign)
        e_templ->security |= SEC_SIGN;
      if (c_crypt_auto_encrypt)
        e_templ->security |= SEC_ENCRYPT;
      if (c_crypt_reply_encrypt && e_cur && (e_cur->security & SEC_ENCRYPT))
        e_templ->security |= SEC_ENCRYPT;
      if (c_crypt_reply_sign && e_cur && (e_cur->security & SEC_SIGN))
        e_templ->security |= SEC_SIGN;
      if (c_crypt_reply_sign_encrypted && e_cur && (e_cur->security & SEC_ENCRYPT))
        e_templ->security |= SEC_SIGN;

      const bool c_crypt_opportunistic_encrypt = cs_subset_bool(sub, "crypt_opportunistic_encrypt");

      if (((WithCrypto & APPLICATION_PGP) != 0) &&
          ((e_templ->security & (SEC_ENCRYPT | SEC_SIGN)) || c_crypt_opportunistic_encrypt))
      {
        const bool c_pgp_auto_inline = cs_subset_bool(sub, "pgp_auto_inline");
        const bool c_pgp_reply_inline = cs_subset_bool(sub, "pgp_reply_inline");

        if (c_pgp_auto_inline)
          e_templ->security |= SEC_INLINE;
        if (c_pgp_reply_inline && e_cur && (e_cur->security & SEC_INLINE))
          e_templ->security |= SEC_INLINE;
      }
    }

    const bool c_crypt_opportunistic_encrypt = cs_subset_bool(sub, "crypt_opportunistic_encrypt");

    if (e_templ->security || c_crypt_opportunistic_encrypt)
    {
      const bool c_crypt_auto_pgp = cs_subset_bool(sub, "crypt_auto_pgp");
      const bool c_crypt_auto_smime = cs_subset_bool(sub, "crypt_auto_smime");

      /* When replying / forwarding, use the original message's
       * crypto system.  According to the documentation,
       * smime_is_default should be disregarded here.
       *
       * Problem: At least with forwarding, this doesn't really
       * make much sense. Should we have an option to completely
       * disable individual mechanisms at run-time?  */
      if (e_cur)
      {
        if (((WithCrypto & APPLICATION_PGP) != 0) && c_crypt_auto_pgp &&
            (e_cur->security & APPLICATION_PGP))
        {
          e_templ->security |= APPLICATION_PGP;
        }
        else if (((WithCrypto & APPLICATION_SMIME) != 0) &&
                 c_crypt_auto_smime && (e_cur->security & APPLICATION_SMIME))
        {
          e_templ->security |= APPLICATION_SMIME;
        }
      }

      const bool c_smime_is_default = cs_subset_bool(sub, "smime_is_default");

      /* No crypto mechanism selected? Use availability + smime_is_default
       * for the decision.  */
      if (!(e_templ->security & (APPLICATION_SMIME | APPLICATION_PGP)))
      {
        if (((WithCrypto & APPLICATION_SMIME) != 0) && c_crypt_auto_smime && c_smime_is_default)
        {
          e_templ->security |= APPLICATION_SMIME;
        }
        else if (((WithCrypto & APPLICATION_PGP) != 0) && c_crypt_auto_pgp)
        {
          e_templ->security |= APPLICATION_PGP;
        }
        else if (((WithCrypto & APPLICATION_SMIME) != 0) && c_crypt_auto_smime)
        {
          e_templ->security |= APPLICATION_SMIME;
        }
      }
    }

    /* opportunistic encrypt relies on SMIME or PGP already being selected */
    if (c_crypt_opportunistic_encrypt)
    {
      /* If something has already enabled encryption, e.g. `$crypt_auto_encrypt`
       * or `$crypt_reply_encrypt`, then don't enable opportunistic encrypt for
       * the message.  */
      if (!(e_templ->security & (SEC_ENCRYPT | SEC_AUTOCRYPT)))
      {
        e_templ->security |= SEC_OPPENCRYPT;
        crypt_opportunistic_encrypt(e_templ);
      }
    }

    /* No permissible mechanisms found.  Don't sign or encrypt. */
    if (!(e_templ->security & (APPLICATION_SMIME | APPLICATION_PGP)))
      e_templ->security = SEC_NO_FLAGS;
  }

  /* Deal with the corner case where the crypto module backend is not available.
   * This can happen if configured without PGP/SMIME and with GPGME, but
   * $crypt_use_gpgme is unset.  */
  if (e_templ->security && !crypt_has_module_backend(e_templ->security))
  {
    mutt_error(_("No crypto backend configured.  Disabling message security setting."));
    e_templ->security = SEC_NO_FLAGS;
  }

  /* specify a default fcc.  if we are in batchmode, only save a copy of
   * the message if the value of $copy is yes or ask-yes */

  const enum QuadOption c_copy = cs_subset_quad(sub, "copy");

  if (buf_is_empty(fcc) && !(flags & SEND_POSTPONED_FCC) &&
      (!(flags & SEND_BATCH) || (c_copy & 0x1)))
  {
    /* set the default FCC */
    const bool killfrom = TAILQ_EMPTY(&e_templ->env->from);
    if (killfrom)
    {
      mutt_addrlist_append(&e_templ->env->from, mutt_default_from(sub));
    }
    mutt_select_fcc(fcc, e_templ);
    if (killfrom)
    {
      mutt_addrlist_clear(&e_templ->env->from);
    }
  }

  mutt_rfc3676_space_stuff(e_templ);

  mutt_update_encoding(e_templ->body, sub);

  if (!(flags & SEND_BATCH))
  {
  main_loop:

    buf_pretty_mailbox(fcc);
    i = dlg_compose(e_templ, fcc,
                    ((flags & SEND_NO_FREE_HEADER) ? MUTT_COMPOSE_NOFREEHEADER : 0), sub);
    if (i == -1)
    {
      /* abort */
      if (flags & SEND_NEWS)
        mutt_message(_("Article not posted"));
      else
        mutt_message(_("Mail not sent"));
      goto cleanup;
    }
    else if (i == 1)
    {
      if (postpone_message(e_templ, e_cur, buf_string(fcc), flags, sub) != 0)
        goto main_loop;
      mutt_message(_("Message postponed"));
      rc = 1;
      goto cleanup;
    }
  }

  if (!(flags & SEND_NEWS))
  {
    if ((mutt_addrlist_count_recips(&e_templ->env->to) == 0) &&
        (mutt_addrlist_count_recips(&e_templ->env->cc) == 0) &&
        (mutt_addrlist_count_recips(&e_templ->env->bcc) == 0))
    {
      if (flags & SEND_BATCH)
      {
        puts(_("No recipients specified"));
        goto cleanup;
      }

      mutt_warning(_("No recipients specified"));
      goto main_loop;
    }
  }

  if (mutt_env_to_intl(e_templ->env, &tag, &err))
  {
    mutt_error(_("Bad IDN in '%s': '%s'"), tag, err);
    FREE(&err);
    if (flags & SEND_BATCH)
      goto cleanup;
    goto main_loop;
  }

  const enum QuadOption c_abort_nosubject = cs_subset_quad(sub, "abort_nosubject");

  if (!e_templ->env->subject && !(flags & SEND_BATCH) &&
      (query_quadoption(_("No subject, abort sending?"), sub, "abort_nosubject") != MUTT_NO))
  {
    /* if the abort is automatic, print an error message */
    if (c_abort_nosubject == MUTT_YES)
      mutt_error(_("No subject specified"));
    goto main_loop;
  }

  if ((flags & SEND_NEWS) && !e_templ->env->subject)
  {
    mutt_error(_("No subject specified"));
    goto main_loop;
  }

  if ((flags & SEND_NEWS) && !e_templ->env->newsgroups)
  {
    mutt_error(_("No newsgroup specified"));
    goto main_loop;
  }

  if (!(flags & SEND_BATCH) && abort_for_missing_attachments(e_templ->body, sub))
  {
    goto main_loop;
  }

  if (e_templ->body->next)
    e_templ->body = mutt_make_multipart(e_templ->body);

  /* Ok, we need to do it this way instead of handling all fcc stuff in
   * one place in order to avoid going to main_loop with encoded "env"
   * in case of error.  Ugh.  */

  mutt_encode_descriptions(e_templ->body, true, sub);

  /* Make sure that clear_content and free_clear_content are
   * properly initialized -- we may visit this particular place in
   * the code multiple times, including after a failed call to
   * mutt_protect().  */

  clear_content = NULL;
  free_clear_content = false;

  if (WithCrypto)
  {
    if (e_templ->security & (SEC_ENCRYPT | SEC_SIGN | SEC_AUTOCRYPT))
    {
      /* save the decrypted attachments */
      clear_content = e_templ->body;

      if ((crypt_get_keys(e_templ, &pgpkeylist, false) == -1) ||
          (mutt_protect(e_templ, pgpkeylist, false) == -1))
      {
        if (mutt_istr_equal(e_templ->body->subtype, "mixed"))
          e_templ->body = mutt_remove_multipart(e_templ->body);

        FREE(&pgpkeylist);

        decode_descriptions(e_templ->body);

        if (flags & SEND_BATCH)
        {
          mutt_message(_("Missing encryption key; mail not sent"));
          rc = -1;
          goto cleanup;
        }

        goto main_loop;
      }
      mutt_encode_descriptions(e_templ->body, false, sub);
    }

    /* at this point, e_templ->body is one of the following three things:
     * - multipart/signed.     In this case, clear_content is a child
     * - multipart/encrypted.  In this case, clear_content exists independently
     * - application/pgp.      In this case, clear_content exists independently
     * - something else.       In this case, it's the same as clear_content */

    /* This is ugly -- lack of "reporting back" from mutt_protect(). */

    if (clear_content && (e_templ->body != clear_content) &&
        (e_templ->body->parts != clear_content))
      free_clear_content = true;
  }

  if (!OptNoCurses)
    mutt_message(_("Sending message..."));

  mutt_prepare_envelope(e_templ->env, true, sub);

  const bool c_fcc_before_send = cs_subset_bool(sub, "fcc_before_send");
  if (c_fcc_before_send)
    save_fcc(m, e_templ, fcc, clear_content, pgpkeylist, flags, &finalpath, sub);

  i = invoke_mta(m, e_templ, sub);
  if (i < 0)
  {
    if (!(flags & SEND_BATCH))
    {
      if (!WithCrypto)
        ; // do nothing
      else if ((e_templ->security & (SEC_ENCRYPT | SEC_AUTOCRYPT)) ||
               ((e_templ->security & SEC_SIGN) && (e_templ->body->type == TYPE_APPLICATION)))
      {
        if (e_templ->body != clear_content)
        {
          mutt_body_free(&e_templ->body); /* destroy PGP data */
          e_templ->body = clear_content;  /* restore clear text. */
        }
      }
      else if ((e_templ->security & SEC_SIGN) && (e_templ->body->type == TYPE_MULTIPART))
      {
        mutt_body_free(&e_templ->body->parts->next); /* destroy sig */
        if (mutt_istr_equal(e_templ->body->subtype, "mixed") ||
            mutt_istr_equal(e_templ->body->subtype, "signed"))
        {
          e_templ->body = mutt_remove_multipart(e_templ->body);
        }
      }

      FREE(&pgpkeylist);
      mutt_env_free(&e_templ->body->mime_headers); /* protected headers */
      mutt_param_delete(&e_templ->body->parameter, "protected-headers");
      if (mutt_istr_equal(e_templ->body->subtype, "mixed"))
        e_templ->body = mutt_remove_multipart(e_templ->body);
      decode_descriptions(e_templ->body);
      mutt_unprepare_envelope(e_templ->env);
      FREE(&finalpath);
      goto main_loop;
    }
    else
    {
      puts(_("Could not send the message"));
      goto cleanup;
    }
  }

  if (!c_fcc_before_send)
    save_fcc(m, e_templ, fcc, clear_content, pgpkeylist, flags, &finalpath, sub);

  if (!OptNoCurses)
  {
    mutt_message((i != 0)            ? _("Sending in background") :
                 (flags & SEND_NEWS) ? _("Article posted") :
                                       _("Mail sent"));
#ifdef USE_NOTMUCH
    const bool c_nm_record = cs_subset_bool(sub, "nm_record");
    if (c_nm_record)
      nm_record_message(m, finalpath, e_cur);
#endif
    mutt_sleep(0);
  }

  if (WithCrypto)
    FREE(&pgpkeylist);

  if ((WithCrypto != 0) && free_clear_content)
    mutt_body_free(&clear_content);

  /* set 'replied' flag only if the user didn't change/remove
   * In-Reply-To: and References: headers during edit */
  if (flags & SEND_REPLY)
  {
    if (!(flags & SEND_POSTPONED) && m)
    {
      struct Email **ep = NULL;
      ARRAY_FOREACH(ep, ea)
      {
        struct Email *e = *ep;
        mutt_set_flag(m, e, MUTT_REPLIED, is_reply(e, e_templ), true);
      }
    }
  }

  rc = 0;

cleanup:
  buf_pool_release(&fcc);

  if (flags & SEND_POSTPONED)
  {
    if (WithCrypto & APPLICATION_PGP)
    {
      cs_subset_str_string_set(sub, "pgp_sign_as", pgp_sign_as, NULL);
      FREE(&pgp_sign_as);
    }
    if (WithCrypto & APPLICATION_SMIME)
    {
      cs_subset_str_string_set(sub, "smime_sign_as", smime_sign_as, NULL);
      FREE(&smime_sign_as);
    }
  }

  mutt_file_fclose(&fp_tmp);
  if (!(flags & SEND_NO_FREE_HEADER))
    email_free(&e_templ);

  FREE(&finalpath);
  return rc;
}

/**
 * send_simple_email - Compose an email given a few basic ingredients
 * @param m      Mailbox
 * @param ea     Array of source Emails
 * @param mailto mailto address to parse (can include fields such as subject)
 * @param subj   Subject, if not overridden by mailto
 * @param body   text/plain body
 * @retval true Success
 * @retval false Failure
 */
static bool send_simple_email(struct Mailbox *m, struct EmailArray *ea,
                              const char *mailto, const char *subj, const char *body)
{
  struct Email *e = email_new();

  /* envelope */
  e->env = mutt_env_new();
  mutt_parse_mailto(e->env, NULL, mailto);
  if (!e->env->subject)
  {
    mutt_env_set_subject(e->env, subj);
  }
  if (TAILQ_EMPTY(&e->env->to) && !mutt_addrlist_parse(&e->env->to, NULL))
  {
    mutt_warning(_("No recipient specified"));
  }

  /* body */
  e->body = mutt_body_new();
  char ctype[] = "text/plain";
  mutt_parse_content_type(ctype, e->body);

  struct Buffer *tempfile = buf_pool_get();
  buf_mktemp(tempfile);
  if (body)
  {
    FILE *fp = mutt_file_fopen(buf_string(tempfile), "w+");
    if (!fp)
    {
      email_free(&e);
      buf_pool_release(&tempfile);
      return false;
    }
    fprintf(fp, "%s\n", body);
    mutt_file_fclose(&fp);
  }
  e->body->filename = buf_strdup(tempfile);
  e->body->unlink = true;
  buf_pool_release(&tempfile);

  const int rc = mutt_send_message(SEND_DRAFT_FILE, e, NULL, m, ea, NeoMutt->sub);
  return rc >= 0;
}

/**
 * mutt_send_list_subscribe - Send a mailing-list subscription email
 * @param m Mailbox
 * @param e Email carrying mailing-list subscription headers
 * @retval true Success
 * @retval false Failure
 */
bool mutt_send_list_subscribe(struct Mailbox *m, struct Email *e)
{
  if (!e || !e->env)
  {
    return false;
  }

  const char *mailto = e->env->list_subscribe;
  if (!mailto)
  {
    mutt_warning(_("No List-Subscribe header found"));
    return false;
  }

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ARRAY_ADD(&ea, e);
  bool rc = send_simple_email(m, &ea, mailto, "Subscribe", "subscribe");
  ARRAY_FREE(&ea);

  return rc;
}

/**
 * mutt_send_list_unsubscribe - Send a mailing-list unsubscription email
 * @param m Mailbox
 * @param e Email carrying mailing-list unsubscription headers
 * @retval true Success
 * @retval false Failure
 */
bool mutt_send_list_unsubscribe(struct Mailbox *m, struct Email *e)
{
  if (!e || !e->env)
  {
    return false;
  }

  const char *mailto = e->env->list_unsubscribe;
  if (!mailto)
  {
    mutt_warning(_("No List-Unsubscribe header found"));
    return false;
  }

  struct EmailArray ea = ARRAY_HEAD_INITIALIZER;
  ARRAY_ADD(&ea, e);
  bool rc = send_simple_email(m, &ea, mailto, "Unsubscribe", "unsubscribe");
  ARRAY_FREE(&ea);

  return rc;
}
