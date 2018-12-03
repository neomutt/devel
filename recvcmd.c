/**
 * @file
 * Send/reply with an attachment
 *
 * @authors
 * Copyright (C) 1999-2004 Thomas Roessler <roessler@does-not-exist.org>
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
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "mutt/mutt.h"
#include "config/lib.h"
#include "email/lib.h"
#include "mutt.h"
#include "alias.h"
#include "context.h"
#include "copy.h"
#include "curs_lib.h"
#include "globals.h"
#include "handler.h"
#include "hdrline.h"
#include "mutt_body.h"
#include "mutt_logging.h"
#include "mutt_window.h"
#include "muttlib.h"
#include "options.h"
#include "protos.h"
#include "send.h"
#include "sendlib.h"
#include "state.h"
#ifdef ENABLE_NLS
#include <libintl.h>
#endif

/* These Config Variables are only used in recvcmd.c */
unsigned char MimeForwardRest; ///< Config: Forward all attachments, even if they can't be decoded

/**
 * check_msg - Are we working with an RFC822 message
 * @param b   Body of email
 * @param err If true, display a message if this isn't an RFC822 message
 * @retval true This is an RFC822 message
 *
 * some helper functions to verify that we are exclusively operating on
 * message/rfc822 attachments
 */
static bool check_msg(struct Body *b, bool err)
{
  if (!mutt_is_message_type(b->type, b->subtype))
  {
    if (err)
      mutt_error(_("You may only bounce message/rfc822 parts"));
    return false;
  }
  return true;
}

/**
 * check_all_msg - Are all the Attachments RFC822 messages?
 * @param actx Attachment context
 * @param cur  Current message
 * @param err  If true, report errors
 * @retval true If all parts are RFC822 messages
 */
static bool check_all_msg(struct AttachCtx *actx, struct Body *cur, bool err)
{
  if (cur && !check_msg(cur, err))
    return false;
  else if (!cur)
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
      {
        if (!check_msg(actx->idx[i]->content, err))
          return false;
      }
    }
  }
  return true;
}

/**
 * check_can_decode - Can we decode all tagged attachments?
 * @param actx Attachment context
 * @param cur  Body of email
 * @retval true All tagged attachments are decodable
 */
static bool check_can_decode(struct AttachCtx *actx, struct Body *cur)
{
  if (cur)
    return mutt_can_decode(cur);

  for (short i = 0; i < actx->idxlen; i++)
    if (actx->idx[i]->content->tagged && !mutt_can_decode(actx->idx[i]->content))
      return false;

  return true;
}

/**
 * count_tagged - Count the number of tagged attachments
 * @param actx Attachment context
 * @retval num Number of tagged attachments
 */
static short count_tagged(struct AttachCtx *actx)
{
  short count = 0;
  for (short i = 0; i < actx->idxlen; i++)
    if (actx->idx[i]->content->tagged)
      count++;

  return count;
}

/**
 * count_tagged_children - tagged children below a multipart/message attachment
 * @param actx Attachment context
 * @param i    Index of first attachment
 * @retval num Number of tagged attachments
 */
static short count_tagged_children(struct AttachCtx *actx, short i)
{
  short level = actx->idx[i]->level;
  short count = 0;

  while ((++i < actx->idxlen) && (level < actx->idx[i]->level))
    if (actx->idx[i]->content->tagged)
      count++;

  return count;
}

/**
 * mutt_attach_bounce - Bounce function, from the attachment menu
 * @param fp   Handle of message
 * @param actx Attachment context
 * @param cur  Body of email
 */
void mutt_attach_bounce(FILE *fp, struct AttachCtx *actx, struct Body *cur)
{
  char prompt[STRING];
  char buf[HUGE_STRING];
  char *err = NULL;
  struct Address *addr = NULL;
  int ret = 0;
  int p = 0;

  if (!check_all_msg(actx, cur, true))
    return;

  /* one or more messages? */
  p = cur ? 1 : count_tagged(actx);

  /* RFC5322 mandates a From: header, so warn before bouncing
   * messages without one */
  if (cur)
  {
    if (!cur->email->env->from)
    {
      mutt_error(_("Warning: message contains no From: header"));
      mutt_clear_error();
    }
  }
  else
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
      {
        if (!actx->idx[i]->content->email->env->from)
        {
          mutt_error(_("Warning: message contains no From: header"));
          mutt_clear_error();
          break;
        }
      }
    }
  }

  if (p)
    mutt_str_strfcpy(prompt, _("Bounce message to: "), sizeof(prompt));
  else
    mutt_str_strfcpy(prompt, _("Bounce tagged messages to: "), sizeof(prompt));

  buf[0] = '\0';
  if (mutt_get_field(prompt, buf, sizeof(buf), MUTT_ALIAS) || buf[0] == '\0')
    return;

  addr = mutt_addr_parse_list(addr, buf);
  if (!addr)
  {
    mutt_error(_("Error parsing address"));
    return;
  }

  addr = mutt_expand_aliases(addr);

  if (mutt_addrlist_to_intl(addr, &err) < 0)
  {
    mutt_error(_("Bad IDN: '%s'"), err);
    FREE(&err);
    mutt_addr_free(&addr);
    return;
  }

  buf[0] = 0;
  mutt_addr_write(buf, sizeof(buf), addr, true);

#define EXTRA_SPACE (15 + 7 + 2)
  /* See commands.c.  */
  snprintf(prompt, sizeof(prompt) - 4,
           ngettext("Bounce message to %s", "Bounce messages to %s", p), buf);

  if (mutt_strwidth(prompt) > MuttMessageWindow->cols - EXTRA_SPACE)
  {
    mutt_simple_format(prompt, sizeof(prompt) - 4, 0, MuttMessageWindow->cols - EXTRA_SPACE,
                       FMT_LEFT, 0, prompt, sizeof(prompt), 0);
    mutt_str_strcat(prompt, sizeof(prompt), "...?");
  }
  else
    mutt_str_strcat(prompt, sizeof(prompt), "?");

  if (query_quadoption(Bounce, prompt) != MUTT_YES)
  {
    mutt_addr_free(&addr);
    mutt_window_clearline(MuttMessageWindow, 0);
    mutt_message(ngettext("Message not bounced", "Messages not bounced", p));
    return;
  }

  mutt_window_clearline(MuttMessageWindow, 0);

  if (cur)
    ret = mutt_bounce_message(fp, cur->email, addr);
  else
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
        if (mutt_bounce_message(actx->idx[i]->fp, actx->idx[i]->content->email, addr))
          ret = 1;
    }
  }

  if (!ret)
    mutt_message(ngettext("Message bounced", "Messages bounced", p));
  else
    mutt_error(ngettext("Error bouncing message", "Error bouncing messages", p));

  mutt_addr_free(&addr);
}

/**
 * mutt_attach_resend - resend-message, from the attachment menu
 * @param fp   File containing email
 * @param actx Attachment context
 * @param cur  Attachment
 */
void mutt_attach_resend(FILE *fp, struct AttachCtx *actx, struct Body *cur)
{
  if (!check_all_msg(actx, cur, true))
    return;

  if (cur)
    mutt_resend_message(fp, Context, cur->email);
  else
  {
    for (short i = 0; i < actx->idxlen; i++)
      if (actx->idx[i]->content->tagged)
        mutt_resend_message(actx->idx[i]->fp, Context, actx->idx[i]->content->email);
  }
}

/**
 ** forward-message, from the attachment menu
 **/

/**
 * find_common_parent - find a common parent message for the tagged attachments
 * @param actx    Attachment context
 * @param nattach Number of tagged attachments
 * @retval ptr Parent attachment
 * @retval NULL Failure, no common parent
 */
static struct AttachPtr *find_common_parent(struct AttachCtx *actx, short nattach)
{
  short i;
  short nchildren;

  for (i = 0; i < actx->idxlen; i++)
    if (actx->idx[i]->content->tagged)
      break;

  while (--i >= 0)
  {
    if (mutt_is_message_type(actx->idx[i]->content->type, actx->idx[i]->content->subtype))
    {
      nchildren = count_tagged_children(actx, i);
      if (nchildren == nattach)
        return actx->idx[i];
    }
  }

  return NULL;
}

/**
 * is_parent - Check whether one attachment is the parent of another
 * @param i    Index of parent Attachment
 * @param actx Attachment context
 * @param cur  Potential child Attachemnt
 * @retval true Attachment
 *
 * check whether attachment i is a parent of the attachment pointed to by cur
 *
 * Note: This and the calling procedure could be optimized quite a bit.
 * For now, it's not worth the effort.
 */
static int is_parent(short i, struct AttachCtx *actx, struct Body *cur)
{
  short level = actx->idx[i]->level;

  while ((++i < actx->idxlen) && actx->idx[i]->level > level)
  {
    if (actx->idx[i]->content == cur)
      return true;
  }

  return false;
}

/**
 * find_parent - Find the parent of an Attachment
 * @param actx    Attachment context
 * @param cur     Attachment (OPTIONAL)
 * @param nattach Use the nth attachment
 * @retval ptr  Parent attachment
 * @retval NULL No parent exists
 */
static struct AttachPtr *find_parent(struct AttachCtx *actx, struct Body *cur, short nattach)
{
  struct AttachPtr *parent = NULL;

  if (cur)
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (mutt_is_message_type(actx->idx[i]->content->type,
                               actx->idx[i]->content->subtype) &&
          is_parent(i, actx, cur))
      {
        parent = actx->idx[i];
      }
      if (actx->idx[i]->content == cur)
        break;
    }
  }
  else if (nattach)
    parent = find_common_parent(actx, nattach);

  return parent;
}

/**
 * include_header - Write an email header to a file, optionally quoting it
 * @param quote  If true, prefix the lines
 * @param ifp    File to read from
 * @param e    Email
 * @param ofp    File to write to
 * @param prefix Prefix for each line (OPTIONAL)
 */
static void include_header(bool quote, FILE *ifp, struct Email *e, FILE *ofp, char *prefix)
{
  int chflags = CH_DECODE;
  char prefix2[SHORT_STRING];

  if (Weed)
    chflags |= CH_WEED | CH_REORDER;

  if (quote)
  {
    if (prefix)
      mutt_str_strfcpy(prefix2, prefix, sizeof(prefix2));
    else if (!TextFlowed)
    {
      mutt_make_string_flags(prefix2, sizeof(prefix2), NONULL(IndentString),
                             Context, e, 0);
    }
    else
      mutt_str_strfcpy(prefix2, ">", sizeof(prefix2));

    chflags |= CH_PREFIX;
  }

  mutt_copy_header(ifp, e, ofp, chflags, quote ? prefix2 : NULL);
}

/**
 * copy_problematic_attachments - Attach the body parts which can't be decoded
 * @param[out] last  Body pointer to update
 * @param[in]  actx  Attachment context
 * @param[in]  force If true, attach parts that can't be decoded
 * @retval ptr Pointer to last Body part
 *
 * This code is shared by forwarding and replying.
 */
static struct Body **copy_problematic_attachments(struct Body **last,
                                                  struct AttachCtx *actx, bool force)
{
  for (short i = 0; i < actx->idxlen; i++)
  {
    if (actx->idx[i]->content->tagged && (force || !mutt_can_decode(actx->idx[i]->content)))
    {
      if (mutt_body_copy(actx->idx[i]->fp, last, actx->idx[i]->content) == -1)
        return NULL; /* XXXXX - may lead to crashes */
      last = &((*last)->next);
    }
  }
  return last;
}

/**
 * attach_forward_bodies - forward one or several MIME bodies
 * @param fp      File to read from
 * @param e     Email
 * @param actx    Attachment Context
 * @param cur     Body of email
 * @param nattach Number of tagged attachments
 *
 * (non-message types)
 */
static void attach_forward_bodies(FILE *fp, struct Email *e, struct AttachCtx *actx,
                                  struct Body *cur, short nattach)
{
  bool mime_fwd_all = false;
  bool mime_fwd_any = true;
  struct Email *parent_hdr = NULL;
  FILE *parent_fp = NULL;
  char tmpbody[PATH_MAX];
  char prefix[STRING];
  int rc = 0;

  /* First, find the parent message.
   * Note: This could be made an option by just
   * putting the following lines into an if block.
   */
  struct AttachPtr *parent = find_parent(actx, cur, nattach);
  if (parent)
  {
    parent_hdr = parent->content->email;
    parent_fp = parent->fp;
  }
  else
  {
    parent_hdr = e;
    parent_fp = actx->root_fp;
  }

  struct Email *tmphdr = mutt_email_new();
  tmphdr->env = mutt_env_new();
  mutt_make_forward_subject(tmphdr->env, Context, parent_hdr);

  mutt_mktemp(tmpbody, sizeof(tmpbody));
  FILE *tmpfp = mutt_file_fopen(tmpbody, "w");
  if (!tmpfp)
  {
    mutt_error(_("Can't open temporary file %s"), tmpbody);
    mutt_email_free(&tmphdr);
    return;
  }

  mutt_forward_intro(Context, parent_hdr, tmpfp);

  /* prepare the prefix here since we'll need it later. */

  if (ForwardQuote)
  {
    if (!TextFlowed)
    {
      mutt_make_string_flags(prefix, sizeof(prefix), NONULL(IndentString),
                             Context, parent_hdr, 0);
    }
    else
      mutt_str_strfcpy(prefix, ">", sizeof(prefix));
  }

  include_header(ForwardQuote, parent_fp, parent_hdr, tmpfp, prefix);

  /* Now, we have prepared the first part of the message body: The
   * original message's header.
   *
   * The next part is more interesting: either include the message bodies,
   * or attach them.
   */
  if ((!cur || mutt_can_decode(cur)) &&
      (rc = query_quadoption(MimeForward, _("Forward as attachments?"))) == MUTT_YES)
  {
    mime_fwd_all = true;
  }
  else if (rc == -1)
  {
    goto bail;
  }

  /* shortcut MIMEFWDREST when there is only one attachment.
   * Is this intuitive?
   */
  if (!mime_fwd_all && !cur && (nattach > 1) && !check_can_decode(actx, cur))
  {
    rc = query_quadoption(
        MimeForwardRest,
        _("Can't decode all tagged attachments.  MIME-forward the others?"));
    if (rc == MUTT_ABORT)
      goto bail;
    else if (rc == MUTT_NO)
      mime_fwd_any = false;
  }

  /* initialize a state structure */

  struct State st = { 0 };
  if (ForwardQuote)
    st.prefix = prefix;
  st.flags = MUTT_CHARCONV;
  if (Weed)
    st.flags |= MUTT_WEED;
  st.fpout = tmpfp;

  /* where do we append new MIME parts? */
  struct Body **last = &tmphdr->content;

  if (cur)
  {
    /* single body case */

    if (!mime_fwd_all && mutt_can_decode(cur))
    {
      st.fpin = fp;
      mutt_body_handler(cur, &st);
      state_putc('\n', &st);
    }
    else
    {
      if (mutt_body_copy(fp, last, cur) == -1)
        goto bail;
    }
  }
  else
  {
    /* multiple body case */

    if (!mime_fwd_all)
    {
      for (int i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged && mutt_can_decode(actx->idx[i]->content))
        {
          st.fpin = actx->idx[i]->fp;
          mutt_body_handler(actx->idx[i]->content, &st);
          state_putc('\n', &st);
        }
      }
    }

    if (mime_fwd_any && !copy_problematic_attachments(last, actx, mime_fwd_all))
      goto bail;
  }

  mutt_forward_trailer(Context, parent_hdr, tmpfp);

  mutt_file_fclose(&tmpfp);
  tmpfp = NULL;

  /* now that we have the template, send it. */
  ci_send_message(0, tmphdr, tmpbody, NULL, parent_hdr);
  return;

bail:

  if (tmpfp)
  {
    mutt_file_fclose(&tmpfp);
    mutt_file_unlink(tmpbody);
  }

  mutt_email_free(&tmphdr);
}

/**
 * attach_forward_msgs - Forward one or several message-type attachments
 * @param fp    File handle to attachment
 * @param actx  Attachment Context
 * @param cur   Attachment to forward (OPTIONAL)
 * @param flags Send mode, e.g. #SEND_RESEND
 *
 * This is different from the previous function since we want to mimic the
 * index menu's behavior.
 *
 * Code reuse from ci_send_message is not possible here - ci_send_message
 * relies on a context structure to find messages, while, on the attachment
 * menu, messages are referenced through the attachment index.
 */
static void attach_forward_msgs(FILE *fp, struct AttachCtx *actx, struct Body *cur, int flags)
{
  struct Email *curhdr = NULL;
  struct Email *tmphdr = NULL;
  int rc;

  struct Body **last = NULL;
  char tmpbody[PATH_MAX];
  FILE *tmpfp = NULL;

  int chflags = CH_XMIT;

  if (cur)
    curhdr = cur->email;
  else
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
      {
        curhdr = actx->idx[i]->content->email;
        break;
      }
    }
  }

  tmphdr = mutt_email_new();
  tmphdr->env = mutt_env_new();
  mutt_make_forward_subject(tmphdr->env, Context, curhdr);

  tmpbody[0] = '\0';

  rc = query_quadoption(MimeForward, _("Forward MIME encapsulated?"));
  if (rc == MUTT_NO)
  {
    /* no MIME encapsulation */

    mutt_mktemp(tmpbody, sizeof(tmpbody));
    tmpfp = mutt_file_fopen(tmpbody, "w");
    if (!tmpfp)
    {
      mutt_error(_("Can't create %s"), tmpbody);
      mutt_email_free(&tmphdr);
      return;
    }

    int cmflags = 0;
    if (ForwardQuote)
    {
      chflags |= CH_PREFIX;
      cmflags |= MUTT_CM_PREFIX;
    }

    if (ForwardDecode)
    {
      cmflags |= MUTT_CM_DECODE | MUTT_CM_CHARCONV;
      if (Weed)
      {
        chflags |= CH_WEED | CH_REORDER;
        cmflags |= MUTT_CM_WEED;
      }
    }

    if (cur)
    {
      mutt_forward_intro(Context, cur->email, tmpfp);
      mutt_copy_message_fp(tmpfp, fp, cur->email, cmflags, chflags);
      mutt_forward_trailer(Context, cur->email, tmpfp);
    }
    else
    {
      for (short i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged)
        {
          mutt_forward_intro(Context, actx->idx[i]->content->email, tmpfp);
          mutt_copy_message_fp(tmpfp, actx->idx[i]->fp,
                               actx->idx[i]->content->email, cmflags, chflags);
          mutt_forward_trailer(Context, actx->idx[i]->content->email, tmpfp);
        }
      }
    }
    mutt_file_fclose(&tmpfp);
  }
  else if (rc == MUTT_YES) /* do MIME encapsulation - we don't need to do much here */
  {
    last = &tmphdr->content;
    if (cur)
      mutt_body_copy(fp, last, cur);
    else
    {
      for (short i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged)
        {
          mutt_body_copy(actx->idx[i]->fp, last, actx->idx[i]->content);
          last = &((*last)->next);
        }
      }
    }
  }
  else
    mutt_email_free(&tmphdr);

  ci_send_message(flags, tmphdr, *tmpbody ? tmpbody : NULL, NULL, curhdr);
}

/**
 * mutt_attach_forward - Forward an Attachment
 * @param fp    Handle to the attachment
 * @param e     Email
 * @param actx  Attachment Context
 * @param cur   Current message
 * @param flags Send mode, e.g. #SEND_RESEND
 */
void mutt_attach_forward(FILE *fp, struct Email *e, struct AttachCtx *actx,
                         struct Body *cur, int flags)
{
  if (check_all_msg(actx, cur, false))
    attach_forward_msgs(fp, actx, cur, flags);
  else
  {
    const short nattach = count_tagged(actx);
    attach_forward_bodies(fp, e, actx, cur, nattach);
  }
}

/**
 ** the various reply functions, from the attachment menu
 **/

/**
 * attach_reply_envelope_defaults - Create the envelope defaults for a reply
 * @param env    Envelope to fill in
 * @param actx   Attachment Context
 * @param parent Parent Email
 * @param flags  Flags, e.g. #SEND_LIST_REPLY
 * @retval  0 Success
 * @retval -1 Error
 *
 * This function can be invoked in two ways.
 *
 * Either, parent is NULL.  In this case, all tagged bodies are of a message type,
 * and the header information is fetched from them.
 *
 * Or, parent is non-NULL.  In this case, cur is the common parent of all the
 * tagged attachments.
 *
 * Note that this code is horribly similar to envelope_defaults() from send.c.
 */
static int attach_reply_envelope_defaults(struct Envelope *env, struct AttachCtx *actx,
                                          struct Email *parent, int flags)
{
  struct Envelope *curenv = NULL;
  struct Email *curhdr = NULL;

  if (!parent)
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
      {
        curhdr = actx->idx[i]->content->email;
        curenv = curhdr->env;
        break;
      }
    }
  }
  else
  {
    curenv = parent->env;
    curhdr = parent;
  }

  if (!curenv || !curhdr)
  {
    mutt_error(_("Can't find any tagged messages"));
    return -1;
  }

#ifdef USE_NNTP
  if ((flags & SEND_NEWS))
  {
    /* in case followup set Newsgroups: with Followup-To: if it present */
    if (!env->newsgroups && curenv &&
        (mutt_str_strcasecmp(curenv->followup_to, "poster") != 0))
    {
      env->newsgroups = mutt_str_strdup(curenv->followup_to);
    }
  }
  else
#endif
  {
    if (parent)
    {
      if (mutt_fetch_recips(env, curenv, flags) == -1)
        return -1;
    }
    else
    {
      for (short i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged &&
            mutt_fetch_recips(env, actx->idx[i]->content->email->env, flags) == -1)
        {
          return -1;
        }
      }
    }

    if ((flags & SEND_LIST_REPLY) && !env->to)
    {
      mutt_error(_("No mailing lists found"));
      return -1;
    }

    mutt_fix_reply_recipients(env);
  }
  mutt_make_misc_reply_headers(env, curenv);

  if (parent)
    mutt_add_to_reference_headers(env, curenv);
  else
  {
    for (short i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged)
        mutt_add_to_reference_headers(env, actx->idx[i]->content->email->env);
    }
  }

  return 0;
}

/**
 * attach_include_reply - This is _very_ similar to send.c's include_reply()
 * @param fp    File handle to attachment
 * @param tmpfp File handle to temporary file
 * @param cur   Email
 */
static void attach_include_reply(FILE *fp, FILE *tmpfp, struct Email *cur)
{
  int cmflags = MUTT_CM_PREFIX | MUTT_CM_DECODE | MUTT_CM_CHARCONV;
  int chflags = CH_DECODE;

  mutt_make_attribution(Context, cur, tmpfp);

  if (!Header)
    cmflags |= MUTT_CM_NOHEADER;
  if (Weed)
  {
    chflags |= CH_WEED;
    cmflags |= MUTT_CM_WEED;
  }

  mutt_copy_message_fp(tmpfp, fp, cur, cmflags, chflags);
  mutt_make_post_indent(Context, cur, tmpfp);
}

/**
 * mutt_attach_reply - Attach a reply
 * @param fp    File handle to reply
 * @param e     Email
 * @param actx  Attachment Context
 * @param cur   Current message
 * @param flags Send mode, e.g. #SEND_RESEND
 */
void mutt_attach_reply(FILE *fp, struct Email *e, struct AttachCtx *actx,
                       struct Body *cur, int flags)
{
  bool mime_reply_any = false;

  short nattach = 0;
  struct AttachPtr *parent = NULL;
  struct Email *parent_hdr = NULL;
  FILE *parent_fp = NULL;
  struct Email *tmphdr = NULL;

  struct State st;
  char tmpbody[PATH_MAX];
  FILE *tmpfp = NULL;

  char prefix[SHORT_STRING];

#ifdef USE_NNTP
  if (flags & SEND_NEWS)
    OptNewsSend = true;
  else
    OptNewsSend = false;
#endif

  if (!check_all_msg(actx, cur, false))
  {
    nattach = count_tagged(actx);
    parent = find_parent(actx, cur, nattach);
    if (parent)
    {
      parent_hdr = parent->content->email;
      parent_fp = parent->fp;
    }
    else
    {
      parent_hdr = e;
      parent_fp = actx->root_fp;
    }
  }

  if (nattach > 1 && !check_can_decode(actx, cur))
  {
    const int rc = query_quadoption(MimeForwardRest,
                                    _("Can't decode all tagged attachments.  "
                                      "MIME-encapsulate the others?"));
    if (rc == MUTT_ABORT)
      return;
    else if (rc == MUTT_YES)
      mime_reply_any = true;
  }
  else if (nattach == 1)
    mime_reply_any = true;

  tmphdr = mutt_email_new();
  tmphdr->env = mutt_env_new();

  if (attach_reply_envelope_defaults(
          tmphdr->env, actx, parent_hdr ? parent_hdr : (cur ? cur->email : NULL), flags) == -1)
  {
    mutt_email_free(&tmphdr);
    return;
  }

  mutt_mktemp(tmpbody, sizeof(tmpbody));
  tmpfp = mutt_file_fopen(tmpbody, "w");
  if (!tmpfp)
  {
    mutt_error(_("Can't create %s"), tmpbody);
    mutt_email_free(&tmphdr);
    return;
  }

  if (!parent_hdr)
  {
    if (cur)
      attach_include_reply(fp, tmpfp, cur->email);
    else
    {
      for (short i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged)
          attach_include_reply(actx->idx[i]->fp, tmpfp, actx->idx[i]->content->email);
      }
    }
  }
  else
  {
    mutt_make_attribution(Context, parent_hdr, tmpfp);

    memset(&st, 0, sizeof(struct State));
    st.fpout = tmpfp;

    if (!TextFlowed)
    {
      mutt_make_string_flags(prefix, sizeof(prefix), NONULL(IndentString),
                             Context, parent_hdr, 0);
    }
    else
      mutt_str_strfcpy(prefix, ">", sizeof(prefix));

    st.prefix = prefix;
    st.flags = MUTT_CHARCONV;

    if (Weed)
      st.flags |= MUTT_WEED;

    if (Header)
      include_header(true, parent_fp, parent_hdr, tmpfp, prefix);

    if (cur)
    {
      if (mutt_can_decode(cur))
      {
        st.fpin = fp;
        mutt_body_handler(cur, &st);
        state_putc('\n', &st);
      }
      else
        mutt_body_copy(fp, &tmphdr->content, cur);
    }
    else
    {
      for (short i = 0; i < actx->idxlen; i++)
      {
        if (actx->idx[i]->content->tagged && mutt_can_decode(actx->idx[i]->content))
        {
          st.fpin = actx->idx[i]->fp;
          mutt_body_handler(actx->idx[i]->content, &st);
          state_putc('\n', &st);
        }
      }
    }

    mutt_make_post_indent(Context, parent_hdr, tmpfp);

    if (mime_reply_any && !cur && !copy_problematic_attachments(&tmphdr->content, actx, false))
    {
      mutt_email_free(&tmphdr);
      mutt_file_fclose(&tmpfp);
      return;
    }
  }

  mutt_file_fclose(&tmpfp);

  if (ci_send_message(flags, tmphdr, tmpbody, NULL,
                      parent_hdr ? parent_hdr : (cur ? cur->email : NULL)) == 0)
  {
    mutt_set_flag(Context->mailbox, e, MUTT_REPLIED, 1);
  }
}

/**
 * mutt_attach_mail_sender - Compose an email to the sender in the email attachment
 * @param fp   File containing attachment (UNUSED)
 * @param e    Email (UNUSED)
 * @param actx Attachment Context
 * @param cur  Current attachment
 */
void mutt_attach_mail_sender(FILE *fp, struct Email *e, struct AttachCtx *actx,
                             struct Body *cur)
{
  if (!check_all_msg(actx, cur, 0))
  {
    /* L10N: You will see this error message if you invoke <compose-to-sender>
       when you are on a normal attachment.
     */
    mutt_error(_("You may only compose to sender with message/rfc822 parts"));
    return;
  }

  struct Email *tmphdr = mutt_email_new();
  tmphdr->env = mutt_env_new();

  if (cur)
  {
    if (mutt_fetch_recips(tmphdr->env, cur->email->env, SEND_TO_SENDER) == -1)
      return;
  }
  else
  {
    for (int i = 0; i < actx->idxlen; i++)
    {
      if (actx->idx[i]->content->tagged &&
          mutt_fetch_recips(tmphdr->env, actx->idx[i]->content->email->env,
                            SEND_TO_SENDER) == -1)
        return;
    }
  }
  ci_send_message(0, tmphdr, NULL, NULL, NULL);
}
