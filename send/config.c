/**
 * @file
 * Config used by libsend
 *
 * @authors
 * Copyright (C) 2020 Yousef Akbar <yousef@yhakbar.com>
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2022 raf <raf@raf.org>
 * Copyright (C) 2023 Whitney Cumber
 * Copyright (C) 2023 наб <nabijaczleweli@nabijaczleweli.xyz>
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
 * @page send_config Config used by libsend
 *
 * Config used by libsend
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "expando/lib.h"
#include "smtp.h"
#ifdef USE_SASL_CYRUS
#include "conn/lib.h"
#endif

extern const struct ExpandoDefinition IndexFormatDef[];

/// IndexFormatDefNoPadding - Index format definitions, without padding or arrow
static const struct ExpandoDefinition *const IndexFormatDefNoPadding = &(IndexFormatDef[3]);

extern const struct ExpandoDefinition NntpFormatDef[];

/**
 * wrapheaders_validator - Validate the "wrap_headers" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int wrapheaders_validator(const struct ConfigDef *cdef, intptr_t value,
                                 struct Buffer *err)
{
  const int min_length = 78; // Recommendations from RFC5233
  const int max_length = 998;

  if ((value >= min_length) && (value <= max_length))
    return CSR_SUCCESS;

  // L10N: This applies to the "$wrap_headers" config variable.
  buf_printf(err, _("Option %s must be between %d and %d inclusive"),
             cdef->name, min_length, max_length);
  return CSR_ERR_INVALID;
}

/**
 * smtp_auth_validator - Validate the "smtp_authenticators" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int smtp_auth_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
  const struct Slist *smtp_auth_methods = (const struct Slist *) value;
  if (!smtp_auth_methods || (smtp_auth_methods->count == 0))
    return CSR_SUCCESS;

  struct ListNode *np = NULL;
  STAILQ_FOREACH(np, &smtp_auth_methods->head, entries)
  {
    if (smtp_auth_is_valid(np->data))
      continue;
#ifdef USE_SASL_CYRUS
    if (sasl_auth_validator(np->data))
      continue;
#endif
    buf_printf(err, _("Option %s: %s is not a valid authenticator"), cdef->name, np->data);
    return CSR_ERR_INVALID;
  }

  return CSR_SUCCESS;
}

/**
 * simple_command_validator - Validate the "sendmail" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int simple_command_validator(const struct ConfigDef *cdef,
                                    intptr_t value, struct Buffer *err)
{
  // Check for shell metacharacters that won't do what the user expects
  const char *valstr = (const char *) value;
  if (!valstr)
    return CSR_SUCCESS;

  const char c = valstr[strcspn(valstr, "|&;()<>[]{}$`'~\"\\*?")];
  if (c == '\0')
    return CSR_SUCCESS;

  // L10N: This applies to the "$sendmail" and "$inews" config variables.
  buf_printf(err, _("Option %s must not contain shell metacharacters: %c"), cdef->name, c);
  return CSR_ERR_INVALID;
}

/**
 * GreetingFormatDef - Expando definitions
 *
 * Config:
 * - $greeting
 */
static const struct ExpandoDefinition GreetingFormatDef[] = {
  // clang-format off
  { "n", "real-name",  ED_ENVELOPE, ED_ENV_REAL_NAME,  NULL },
  { "u", "user-name",  ED_ENVELOPE, ED_ENV_USER_NAME,  NULL },
  { "v", "first-name", ED_ENVELOPE, ED_ENV_FIRST_NAME, NULL },
  { NULL, NULL, 0, -1, NULL }
  // clang-format on
};

/**
 * SendVars - Config definitions for the send library
 */
static struct ConfigDef SendVars[] = {
  // clang-format off
  { "abort_noattach", DT_QUAD, MUTT_NO, 0, NULL,
    "Abort sending the email if attachments are missing"
  },
  { "abort_noattach_regex", DT_REGEX, IP "\\<(attach|attached|attachments?)\\>", 0, NULL,
    "Regex to match text indicating attachments are expected"
  },
  { "abort_nosubject", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Abort creating the email if subject is missing"
  },
  { "abort_unmodified", DT_QUAD, MUTT_YES, 0, NULL,
    "Abort the sending if the message hasn't been edited"
  },
  { "allow_8bit", DT_BOOL, true, 0, NULL,
    "Allow 8-bit messages, don't use quoted-printable or base64"
  },
  { "ask_bcc", DT_BOOL, false, 0, NULL,
    "Ask the user for the blind-carbon-copy recipients"
  },
  { "ask_cc", DT_BOOL, false, 0, NULL,
    "Ask the user for the carbon-copy recipients"
  },
  { "ask_followup_to", DT_BOOL, false, 0, NULL,
    "(nntp) Ask the user for follow-up groups before editing"
  },
  { "ask_x_comment_to", DT_BOOL, false, 0, NULL,
    "(nntp) Ask the user for the 'X-Comment-To' field before editing"
  },
  { "attach_charset", DT_SLIST|D_SLIST_SEP_COLON|D_SLIST_ALLOW_EMPTY, 0, 0, charset_slist_validator,
    "When attaching files, use one of these character sets"
  },
  // L10N: $attribution_intro default format
  { "attribution_intro", DT_EXPANDO|D_L10N_STRING, IP N_("On %d, %n wrote:"), IP IndexFormatDefNoPadding, NULL,
    "Message to start a reply, 'On DATE, PERSON wrote:'"
  },
  { "attribution_locale", DT_STRING, 0, 0, NULL,
    "Locale for dates in the attribution message"
  },
  { "attribution_trailer", DT_EXPANDO, 0, IP IndexFormatDefNoPadding, NULL,
    "Suffix message to add after reply text"
  },
  { "bounce_delivered", DT_BOOL, true, 0, NULL,
    "Add 'Delivered-To' to bounced messages"
  },
  { "content_type", DT_STRING, IP "text/plain", 0, NULL,
    "Default 'Content-Type' for newly composed messages"
  },
  { "crypt_auto_encrypt", DT_BOOL, false, 0, NULL,
    "Automatically PGP encrypt all outgoing mail"
  },
  { "crypt_auto_pgp", DT_BOOL, true, 0, NULL,
    "Allow automatic PGP functions"
  },
  { "crypt_auto_sign", DT_BOOL, false, 0, NULL,
    "Automatically PGP sign all outgoing mail"
  },
  { "crypt_auto_smime", DT_BOOL, true, 0, NULL,
    "Allow automatic SMIME functions"
  },
  { "crypt_reply_encrypt", DT_BOOL, true, 0, NULL,
    "Encrypt replies to encrypted messages"
  },
  { "crypt_reply_sign", DT_BOOL, false, 0, NULL,
    "Sign replies to signed messages"
  },
  { "crypt_reply_sign_encrypted", DT_BOOL, false, 0, NULL,
    "Sign replies to encrypted messages"
  },
  { "dsn_notify", DT_STRING, 0, 0, NULL,
    "Request notification for message delivery or delay"
  },
  { "dsn_return", DT_STRING, 0, 0, NULL,
    "What to send as a notification of message delivery or delay"
  },
  { "empty_subject", DT_STRING, IP "Re: your mail", 0, NULL,
    "Subject to use when replying to an email with none"
  },
  { "encode_from", DT_BOOL, false, 0, NULL,
    "Encode 'From ' as 'quote-printable' at the beginning of lines"
  },
  { "fast_reply", DT_BOOL, false, 0, NULL,
    "Don't prompt for the recipients and subject when replying/forwarding"
  },
  { "fcc_attach", DT_QUAD, MUTT_YES, 0, NULL,
    "Save sent message with all their attachments"
  },
  { "fcc_before_send", DT_BOOL, false, 0, NULL,
    "Save FCCs before sending the message"
  },
  { "fcc_clear", DT_BOOL, false, 0, NULL,
    "Save sent messages unencrypted and unsigned"
  },
  { "followup_to", DT_BOOL, true, 0, NULL,
    "Add the 'Mail-Followup-To' header is generated when sending mail"
  },
  { "forward_attachments", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Forward attachments when forwarding a message"
  },
  // L10N: $forward_attribution_intro default format
  { "forward_attribution_intro", DT_EXPANDO|D_L10N_STRING, IP N_("----- Forwarded message from %f -----"), IP IndexFormatDefNoPadding, NULL,
    "Prefix message for forwarded messages"
  },
  // L10N: $forward_attribution_trailer default format
  { "forward_attribution_trailer", DT_EXPANDO|D_L10N_STRING, IP N_("----- End forwarded message -----"), IP IndexFormatDefNoPadding, NULL,
    "Suffix message for forwarded messages"
  },
  { "forward_decrypt", DT_BOOL, true, 0, NULL,
    "Decrypt the message when forwarding it"
  },
  { "forward_edit", DT_QUAD, MUTT_YES, 0, NULL,
    "Automatically start the editor when forwarding a message"
  },
  { "forward_format", DT_EXPANDO|D_NOT_EMPTY, IP "[%a: %s]", IP IndexFormatDefNoPadding, NULL,
    "printf-like format string to control the subject when forwarding a message"
  },
  { "forward_references", DT_BOOL, false, 0, NULL,
    "Set the 'In-Reply-To' and 'References' headers when forwarding a message"
  },
  { "greeting", DT_EXPANDO, 0, IP &GreetingFormatDef, NULL,
    "Greeting string added to the top of all messages"
  },
  { "hdrs", DT_BOOL, true, 0, NULL,
    "Add custom headers to outgoing mail"
  },
  { "hidden_host", DT_BOOL, false, 0, NULL,
    "Don't use the hostname, just the domain, when generating the message id"
  },
  { "honor_followup_to", DT_QUAD, MUTT_YES, 0, NULL,
    "Honour the 'Mail-Followup-To' header when group replying"
  },
  { "ignore_list_reply_to", DT_BOOL, false, 0, NULL,
    "Ignore the 'Reply-To' header when using `<reply>` on a mailing list"
  },
  { "include", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Include a copy of the email that's being replied to"
  },
  { "inews", DT_EXPANDO|D_STRING_COMMAND, 0, 0, NULL,
    "(nntp) External command to post news articles"
  },
  { "me_too", DT_BOOL, false, 0, NULL,
    "Remove the user's address from the list of recipients"
  },
  { "mime_forward_decode", DT_BOOL, false, 0, NULL,
    "Decode the forwarded message before attaching it"
  },
  { "mime_type_query_command", DT_STRING|D_STRING_COMMAND, 0, 0, NULL,
    "External command to determine the MIME type of an attachment"
  },
  { "mime_type_query_first", DT_BOOL, false, 0, NULL,
    "Run the `$mime_type_query_command` before the mime.types lookup"
  },
  { "nm_record", DT_BOOL, false, 0, NULL,
    "(notmuch) If the 'record' mailbox (sent mail) should be indexed"
  },
  { "pgp_reply_inline", DT_BOOL, false, 0, NULL,
    "Reply using old-style inline PGP messages (not recommended)"
  },
  { "postpone_encrypt", DT_BOOL, false, 0, NULL,
    "Self-encrypt postponed messages"
  },
  { "postpone_encrypt_as", DT_STRING, 0, 0, NULL,
    "Fallback encryption key for postponed messages"
  },
  { "recall", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Recall postponed mesaages when asked to compose a message"
  },
  { "reply_self", DT_BOOL, false, 0, NULL,
    "Really reply to yourself, when replying to your own email"
  },
  { "reply_to", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Address to use as a 'Reply-To' header"
  },
  { "reply_with_xorig", DT_BOOL, false, 0, NULL,
    "Create 'From' header from 'X-Original-To' header"
  },
  { "resume_draft_files", DT_BOOL, false, 0, NULL,
    "Process draft files like postponed messages"
  },
  { "reverse_name", DT_BOOL, false, 0, NULL,
    "Set the 'From' from the address the email was sent to"
  },
  { "reverse_real_name", DT_BOOL, true, 0, NULL,
    "Set the 'From' from the full 'To' address the email was sent to"
  },
  { "sendmail", DT_STRING|D_STRING_COMMAND, IP SENDMAIL " -oem -oi", 0, simple_command_validator,
    "External command to send email"
  },
  { "sendmail_wait", DT_NUMBER, 0, 0, NULL,
    "Time to wait for sendmail to finish"
  },
  { "sig_dashes", DT_BOOL, true, 0, NULL,
    "Insert '-- ' before the signature"
  },
  { "sig_on_top", DT_BOOL, false, 0, NULL,
    "Insert the signature before the quoted text"
  },
  { "signature", DT_PATH|D_PATH_FILE, IP "~/.signature", 0, NULL,
    "File containing a signature to append to all mail"
  },
  { "smtp_authenticators", DT_SLIST|D_SLIST_SEP_COLON, 0, 0, smtp_auth_validator,
    "(smtp) List of allowed authentication methods (colon-separated)"
  },
  { "smtp_oauth_refresh_command", DT_STRING|D_STRING_COMMAND|D_SENSITIVE, 0, 0, NULL,
    "(smtp) External command to generate OAUTH refresh token"
  },
  { "smtp_pass", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(smtp) Password for the SMTP server"
  },
  { "smtp_url", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(smtp) Url of the SMTP server"
  },
  { "smtp_user", DT_STRING|D_SENSITIVE, 0, 0, NULL,
    "(smtp) Username for the SMTP server"
  },
  { "use_8bit_mime", DT_BOOL, false, 0, NULL,
    "Use 8-bit messages and ESMTP to send messages"
  },
  { "use_envelope_from", DT_BOOL, false, 0, NULL,
    "Set the envelope sender of the message"
  },
  { "use_from", DT_BOOL, true, 0, NULL,
    "Set the 'From' header for outgoing mail"
  },
  { "user_agent", DT_BOOL, false, 0, NULL,
    "Add a 'User-Agent' header to outgoing mail"
  },
  { "wrap_headers", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 78, 0, wrapheaders_validator,
    "Width to wrap headers in outgoing messages"
  },
  { "write_bcc", DT_BOOL, false, 0, NULL,
    "Write out the 'Bcc' field when preparing to send a mail"
  },

  { "abort_noattach_regexp",    DT_SYNONYM, IP "abort_noattach_regex",       IP "2021-03-21" },
  { "askbcc",                   DT_SYNONYM, IP "ask_bcc",                    IP "2021-03-21" },
  { "askcc",                    DT_SYNONYM, IP "ask_cc",                     IP "2021-03-21" },
  { "ask_follow_up",            DT_SYNONYM, IP "ask_followup_to",            IP "2023-01-20" },
  { "attach_keyword",           DT_SYNONYM, IP "abort_noattach_regex",       IP "2021-03-21" },
  { "attribution",              DT_SYNONYM, IP "attribution_intro",          IP "2023-02-20" },
  { "crypt_autoencrypt",        DT_SYNONYM, IP "crypt_auto_encrypt",         IP "2021-03-21" },
  { "crypt_autopgp",            DT_SYNONYM, IP "crypt_auto_pgp",             IP "2021-03-21" },
  { "crypt_autosign",           DT_SYNONYM, IP "crypt_auto_sign",            IP "2021-03-21" },
  { "crypt_autosmime",          DT_SYNONYM, IP "crypt_auto_smime",           IP "2021-03-21" },
  { "crypt_replyencrypt",       DT_SYNONYM, IP "crypt_reply_encrypt",        IP "2021-03-21" },
  { "crypt_replysign",          DT_SYNONYM, IP "crypt_reply_sign",           IP "2021-03-21" },
  { "crypt_replysignencrypted", DT_SYNONYM, IP "crypt_reply_sign_encrypted", IP "2021-03-21" },
  { "envelope_from",            DT_SYNONYM, IP "use_envelope_from",          IP "2021-03-21" },
  { "forw_decrypt",             DT_SYNONYM, IP "forward_decrypt",            IP "2021-03-21" },
  { "forw_format",              DT_SYNONYM, IP "forward_format",             IP "2021-03-21" },
  { "metoo",                    DT_SYNONYM, IP "me_too",                     IP "2021-03-21" },
  { "pgp_autoencrypt",          DT_SYNONYM, IP "crypt_auto_encrypt",         IP "2021-03-21" },
  { "pgp_autosign",             DT_SYNONYM, IP "crypt_auto_sign",            IP "2021-03-21" },
  { "pgp_auto_traditional",     DT_SYNONYM, IP "pgp_reply_inline",           IP "2021-03-21" },
  { "pgp_replyencrypt",         DT_SYNONYM, IP "crypt_reply_encrypt",        IP "2021-03-21" },
  { "pgp_replyinline",          DT_SYNONYM, IP "pgp_reply_inline",           IP "2021-03-21" },
  { "pgp_replysign",            DT_SYNONYM, IP "crypt_reply_sign",           IP "2021-03-21" },
  { "pgp_replysignencrypted",   DT_SYNONYM, IP "crypt_reply_sign_encrypted", IP "2021-03-21" },
  { "post_indent_str",          DT_SYNONYM, IP "post_indent_string",         IP "2021-03-21" },
  { "post_indent_string",       DT_SYNONYM, IP "attribution_trailer",        IP "2023-02-20" },
  { "reverse_realname",         DT_SYNONYM, IP "reverse_real_name",          IP "2021-03-21" },
  { "use_8bitmime",             DT_SYNONYM, IP "use_8bit_mime",              IP "2021-03-21" },

  { "mime_subject", D_INTERNAL_DEPRECATED|DT_BOOL, 0, IP "2021-03-24" },
  { NULL },
  // clang-format on
};

/**
 * config_init_send - Register send config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
bool config_init_send(struct ConfigSet *cs)
{
  return cs_register_variables(cs, SendVars);
}
