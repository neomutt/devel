/**
 * @file
 * Definitions of config variables
 *
 * @authors
 * Copyright (C) 2020 Aditya De Saha <adityadesaha@gmail.com>
 * Copyright (C) 2020 Louis Brauer <louis@openbooking.ch>
 * Copyright (C) 2020 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2020-2024 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2021 Ashish Panigrahi <ashish.panigrahi@protonmail.com>
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
 * @page neo_mutt_config Definitions of config variables
 *
 * Definitions of config variables
 */

#include "config.h"
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "attach/lib.h"
#include "expando/lib.h"
#include "index/lib.h"
#include "mutt_logging.h"
#include "mutt_thread.h"
#include "mx.h"

extern const struct ExpandoDefinition IndexFormatDef[];

#define CONFIG_INIT_TYPE(CS, NAME)                                             \
  extern const struct ConfigSetType Cst##NAME;                                 \
  cs_register_type(CS, &Cst##NAME)

#define CONFIG_INIT_VARS(CS, NAME)                                             \
  bool config_init_##NAME(struct ConfigSet *cs);                               \
  config_init_##NAME(CS)

/**
 * SortAuxMethods - Sort methods for '$sort_aux' for the index
 */
static const struct Mapping SortAuxMethods[] = {
  // clang-format off
  { "date",          EMAIL_SORT_DATE },
  { "date-received", EMAIL_SORT_DATE_RECEIVED },
  { "from",          EMAIL_SORT_FROM },
  { "label",         EMAIL_SORT_LABEL },
  { "score",         EMAIL_SORT_SCORE },
  { "size",          EMAIL_SORT_SIZE },
  { "spam",          EMAIL_SORT_SPAM },
  { "subject",       EMAIL_SORT_SUBJECT },
  { "to",            EMAIL_SORT_TO },
  { "unsorted",      EMAIL_SORT_UNSORTED },
  // Compatibility
  { "date-sent",     EMAIL_SORT_DATE },
  { "mailbox-order", EMAIL_SORT_UNSORTED },
  { "threads",       EMAIL_SORT_DATE },
  { NULL, 0 },
  // clang-format on
};

/**
 * SortMethods - Sort methods for '$sort' for the index
 */
const struct Mapping SortMethods[] = {
  // clang-format off
  { "date",          EMAIL_SORT_DATE },
  { "date-received", EMAIL_SORT_DATE_RECEIVED },
  { "from",          EMAIL_SORT_FROM },
  { "label",         EMAIL_SORT_LABEL },
  { "score",         EMAIL_SORT_SCORE },
  { "size",          EMAIL_SORT_SIZE },
  { "spam",          EMAIL_SORT_SPAM },
  { "subject",       EMAIL_SORT_SUBJECT },
  { "threads",       EMAIL_SORT_THREADS },
  { "to",            EMAIL_SORT_TO },
  { "unsorted",      EMAIL_SORT_UNSORTED },
  // Compatibility
  { "date-sent",     EMAIL_SORT_DATE },
  { "mailbox-order", EMAIL_SORT_UNSORTED },
  { NULL, 0 },
  // clang-format on
};

/**
 * multipart_validator - Validate the "show_multipart_alternative" config variable - Implements ConfigDef::validator() - @ingroup cfg_def_validator
 */
static int multipart_validator(const struct ConfigDef *cdef, intptr_t value, struct Buffer *err)
{
  if (value == 0)
    return CSR_SUCCESS;

  const char *str = (const char *) value;

  if (mutt_str_equal(str, "inline") || mutt_str_equal(str, "info"))
    return CSR_SUCCESS;

  buf_printf(err, _("Invalid value for option %s: %s"), cdef->name, str);
  return CSR_ERR_INVALID;
}

/**
 * AttachFormatDef - Expando definitions
 *
 * Config:
 * - $attach_format
 */
static const struct ExpandoDefinition AttachFormatDef[] = {
  // clang-format off
  { "*", "padding-soft",     ED_GLOBAL, ED_GLO_PADDING_SOFT,     node_padding_parse },
  { ">", "padding-hard",     ED_GLOBAL, ED_GLO_PADDING_HARD,     node_padding_parse },
  { "|", "padding-eol",      ED_GLOBAL, ED_GLO_PADDING_EOL,      node_padding_parse },
  { "c", "charset-convert",  ED_BODY,   ED_BOD_CHARSET_CONVERT,  NULL },
  { "C", "charset",          ED_ATTACH, ED_ATT_CHARSET,          NULL },
  { "d", "description",      ED_BODY,   ED_BOD_DESCRIPTION,      NULL },
  { "D", "deleted",          ED_BODY,   ED_BOD_DELETED,          NULL },
  { "e", "mime-encoding",    ED_BODY,   ED_BOD_MIME_ENCODING,    NULL },
  { "f", "file",             ED_BODY,   ED_BOD_FILE,             NULL },
  { "F", "file-disposition", ED_BODY,   ED_BOD_FILE_DISPOSITION, NULL },
  { "I", "disposition",      ED_BODY,   ED_BOD_DISPOSITION,      NULL },
  { "m", "mime-major",       ED_BODY,   ED_BOD_MIME_MAJOR,       NULL },
  { "M", "mime-minor",       ED_BODY,   ED_BOD_MIME_MINOR,       NULL },
  { "n", "number",           ED_ATTACH, ED_ATT_NUMBER,           NULL },
  { "Q", "attach-qualifies", ED_BODY,   ED_BOD_ATTACH_QUALIFIES, NULL },
  { "s", "file-size",        ED_BODY,   ED_BOD_FILE_SIZE,        NULL },
  { "t", "tagged",           ED_BODY,   ED_BOD_TAGGED,           NULL },
  { "T", "tree",             ED_ATTACH, ED_ATT_TREE,             NULL },
  { "u", "unlink",           ED_BODY,   ED_BOD_UNLINK,           NULL },
  { "X", "attach-count",     ED_BODY,   ED_BOD_ATTACH_COUNT,     NULL },
  { NULL, NULL, 0, -1, NULL }
  // clang-format on
};

/**
 * parse_index_date_recv_local - Parse a Date Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a custom Expando of the form, "%(string)".
 * The "string" will be passed to strftime().
 */
struct ExpandoNode *parse_index_date_recv_local(const char *str,
                                                struct ExpandoFormat *fmt, int did,
                                                int uid, ExpandoParserFlags flags,
                                                const char **parsed_until,
                                                struct ExpandoParseError *err)
{
  if (flags & EP_CONDITIONAL)
  {
    return node_conddate_parse(str, did, uid, parsed_until, err);
  }

  return node_expando_parse_enclosure(str, did, uid, ')', fmt, parsed_until, err);
}

/**
 * parse_index_date_local - Parse a Date Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a custom expando of the form, "%[string]".
 * The "string" will be passed to strftime().
 */
struct ExpandoNode *parse_index_date_local(const char *str, struct ExpandoFormat *fmt,
                                           int did, int uid, ExpandoParserFlags flags,
                                           const char **parsed_until,
                                           struct ExpandoParseError *err)
{
  if (flags & EP_CONDITIONAL)
  {
    return node_conddate_parse(str, did, uid, parsed_until, err);
  }

  return node_expando_parse_enclosure(str, did, uid, ']', fmt, parsed_until, err);
}

/**
 * parse_index_date - Parse a Date Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a custom Expando of the form, "%{string}".
 * The "string" will be passed to strftime().
 */
struct ExpandoNode *parse_index_date(const char *str, struct ExpandoFormat *fmt,
                                     int did, int uid, ExpandoParserFlags flags,
                                     const char **parsed_until,
                                     struct ExpandoParseError *err)
{
  if (flags & EP_CONDITIONAL)
  {
    return node_conddate_parse(str, did, uid, parsed_until, err);
  }

  return node_expando_parse_enclosure(str, did, uid, '}', fmt, parsed_until, err);
}

/**
 * parse_index_hook - Parse an index-hook - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a custom Expando of the form, "%@name@".
 * The "name" will be looked up as an index-hook, then the result parsed as an
 * Expando.
 */
struct ExpandoNode *parse_index_hook(const char *str, struct ExpandoFormat *fmt,
                                     int did, int uid, ExpandoParserFlags flags,
                                     const char **parsed_until,
                                     struct ExpandoParseError *err)
{
  if (flags & EP_CONDITIONAL)
  {
    snprintf(err->message, sizeof(err->message),
             _("index-hook cannot be used as a condition"));
    err->position = str;
    return NULL;
  }

  return node_expando_parse_enclosure(str, did, uid, '@', fmt, parsed_until, err);
}

/**
 * parse_tags_transformed - Parse a Tags-Transformed Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a custom expando of the form, "%G?" where '?' is an alpha-numeric character.
 */
struct ExpandoNode *parse_tags_transformed(const char *str, struct ExpandoFormat *fmt,
                                           int did, int uid, ExpandoParserFlags flags,
                                           const char **parsed_until,
                                           struct ExpandoParseError *err)
{
  // Tag expando %G must use an suffix from [A-Za-z0-9], e.g. %Ga, %GL
  if (!isalnum(str[1]))
    return NULL;

  // Let the basic expando parser do the work
  flags |= EP_NO_CUSTOM_PARSE;
  struct ExpandoNode *node = parse_short_name(str, IndexFormatDef, flags, fmt,
                                              parsed_until, err);

  // but adjust the node to take one more character
  node->text = mutt_strn_dup((*parsed_until) - 1, 2);
  (*parsed_until)++;

  if (flags & EP_CONDITIONAL)
  {
    node->type = ENT_CONDBOOL;
    node->render = node_condbool_render;
  }

  return node;
}

/**
 * parse_subject - Parse a Subject Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a Subject Expando, "%s", into two separate Nodes.
 * One for the tree, one for the subject.
 */
struct ExpandoNode *parse_subject(const char *str, struct ExpandoFormat *fmt,
                                  int did, int uid, ExpandoParserFlags flags,
                                  const char **parsed_until, struct ExpandoParseError *err)
{
  // Let the basic expando parser do the work
  flags |= EP_NO_CUSTOM_PARSE;
  struct ExpandoNode *node_subj = parse_short_name(str, IndexFormatDef, flags,
                                                   NULL, parsed_until, err);

  struct ExpandoNode *node_tree = node_expando_new(NULL, ED_ENVELOPE, ED_ENV_THREAD_TREE);
  struct ExpandoNode *node_cont = node_container_new();

  // Apply the formatting info to the container
  node_cont->format = fmt;

  node_add_child(node_cont, node_tree);
  node_add_child(node_cont, node_subj);

  return node_cont;
}

/**
 * IndexFormatDef - Expando definitions
 *
 * Config:
 * - $attribution_intro
 * - $attribution_trailer
 * - $forward_attribution_intro
 * - $forward_attribution_trailer
 * - $forward_format
 * - $index_format
 * - $message_format
 * - $pager_format
 *
 * @note Longer Expandos must precede any similar, but shorter Expandos
 */
const struct ExpandoDefinition IndexFormatDef[] = {
  // clang-format off
  { "*",  "padding-soft",        ED_GLOBAL,   ED_GLO_PADDING_SOFT,        node_padding_parse },
  { ">",  "padding-hard",        ED_GLOBAL,   ED_GLO_PADDING_HARD,        node_padding_parse },
  { "|",  "padding-eol",         ED_GLOBAL,   ED_GLO_PADDING_EOL,         node_padding_parse },
  { "(",  NULL,                  ED_EMAIL,    ED_EMA_STRF_RECV_LOCAL,     parse_index_date_recv_local },
  { "@",  NULL,                  ED_EMAIL,    ED_EMA_INDEX_HOOK,          parse_index_hook },
  { "a",  "from",                ED_ENVELOPE, ED_ENV_FROM,                NULL },
  { "A",  "reply-to",            ED_ENVELOPE, ED_ENV_REPLY_TO,            NULL },
  { "b",  "mailbox-name",        ED_MAILBOX,  ED_MBX_MAILBOX_NAME,        NULL },
  { "B",  "list-address",        ED_ENVELOPE, ED_ENV_LIST_ADDRESS,        NULL },
  { "cr", "body-characters",     ED_EMAIL,    ED_EMA_BODY_CHARACTERS,     NULL },
  { "c",  "size",                ED_EMAIL,    ED_EMA_SIZE,                NULL },
  { "C",  "number",              ED_EMAIL,    ED_EMA_NUMBER,              NULL },
  { "d",  "date-format",         ED_EMAIL,    ED_EMA_DATE_FORMAT,         NULL },
  { "D",  "date-format-local",   ED_EMAIL,    ED_EMA_DATE_FORMAT_LOCAL,   NULL },
  { "e",  "thread-number",       ED_EMAIL,    ED_EMA_THREAD_NUMBER,       NULL },
  { "E",  "thread-count",        ED_EMAIL,    ED_EMA_THREAD_COUNT,        NULL },
  { "f",  "from-full",           ED_ENVELOPE, ED_ENV_FROM_FULL,           NULL },
  { "Fp", "sender-plain",        ED_ENVELOPE, ED_ENV_SENDER_PLAIN,        NULL },
  { "F",  "sender",              ED_ENVELOPE, ED_ENV_SENDER,              NULL },
  { "g",  "tags",                ED_EMAIL,    ED_EMA_TAGS,                NULL },
  { "G",  "tags-transformed",    ED_EMAIL,    ED_EMA_TAGS_TRANSFORMED,    parse_tags_transformed },
  { "H",  "spam",                ED_ENVELOPE, ED_ENV_SPAM,                NULL },
  { "i",  "message-id",          ED_ENVELOPE, ED_ENV_MESSAGE_ID,          NULL },
  { "I",  "initials",            ED_ENVELOPE, ED_ENV_INITIALS,            NULL },
  { "J",  "thread-tags",         ED_EMAIL,    ED_EMA_THREAD_TAGS,         NULL },
  { "K",  "list-empty",          ED_ENVELOPE, ED_ENV_LIST_EMPTY,          NULL },
  { "l",  "lines",               ED_EMAIL,    ED_EMA_LINES,               NULL },
  { "L",  "from-list",           ED_EMAIL,    ED_EMA_FROM_LIST,           NULL },
  { "m",  "message-count",       ED_MAILBOX,  ED_MBX_MESSAGE_COUNT,       NULL },
  { "M",  "thread-hidden-count", ED_EMAIL,    ED_EMA_THREAD_HIDDEN_COUNT, NULL },
  { "n",  "name",                ED_ENVELOPE, ED_ENV_NAME,                NULL },
  { "N",  "score",               ED_EMAIL,    ED_EMA_SCORE,               NULL },
  { "O",  "save-folder",         ED_EMAIL,    ED_EMA_LIST_OR_SAVE_FOLDER, NULL },
  { "P",  "percentage",          ED_MAILBOX,  ED_MBX_PERCENTAGE,          NULL },
  { "q",  "newsgroup",           ED_ENVELOPE, ED_ENV_NEWSGROUP,           NULL },
  { "r",  "to-all",              ED_ENVELOPE, ED_ENV_TO_ALL,              NULL },
  { "R",  "cc-all",              ED_ENVELOPE, ED_ENV_CC_ALL,              NULL },
  { "s",  "subject",             ED_ENVELOPE, ED_ENV_SUBJECT,             parse_subject },
  { "S",  "flag-chars",          ED_EMAIL,    ED_EMA_FLAG_CHARS,          NULL },
  { "t",  "to",                  ED_ENVELOPE, ED_ENV_TO,                  NULL },
  { "T",  "to-chars",            ED_EMAIL,    ED_EMA_TO_CHARS,            NULL },
  { "u",  "username",            ED_ENVELOPE, ED_ENV_USERNAME,            NULL },
  { "v",  "first-name",          ED_ENVELOPE, ED_ENV_FIRST_NAME,          NULL },
  { "W",  "organization",        ED_ENVELOPE, ED_ENV_ORGANIZATION,        NULL },
  { "x",  "x-comment-to",        ED_ENVELOPE, ED_ENV_X_COMMENT_TO,        NULL },
  { "X",  "attachment-count",    ED_EMAIL,    ED_EMA_ATTACHMENT_COUNT,    NULL },
  { "y",  "x-label",             ED_ENVELOPE, ED_ENV_X_LABEL,             NULL },
  { "Y",  "thread-x-label",      ED_ENVELOPE, ED_ENV_THREAD_X_LABEL,      NULL },
  { "Z",  "combined-flags",      ED_EMAIL,    ED_EMA_COMBINED_FLAGS,      NULL },
  { "zc", "crypto-flags",        ED_EMAIL,    ED_EMA_CRYPTO_FLAGS,        NULL },
  { "zs", "status-flags",        ED_EMAIL,    ED_EMA_STATUS_FLAGS,        NULL },
  { "zt", "message-flags",       ED_EMAIL,    ED_EMA_MESSAGE_FLAGS,       NULL },
  { "[",  NULL,                  ED_EMAIL,    ED_EMA_DATE_STRF_LOCAL,     parse_index_date_local },
  { "{",  NULL,                  ED_EMAIL,    ED_EMA_DATE_STRF,           parse_index_date },
  { NULL, NULL, 0, -1, NULL }
  // clang-format on
};

/// IndexFormatDefNoPadding - Index format definitions, without padding
static const struct ExpandoDefinition *const IndexFormatDefNoPadding = &(IndexFormatDef[3]);

/// StatusFormatDefNoPadding - Status format definitions, without padding
const struct ExpandoDefinition *const StatusFormatDefNoPadding = &(StatusFormatDef[3]);

/**
 * MainVars - General Config definitions for NeoMutt
 */
static struct ConfigDef MainVars[] = {
  // clang-format off
  { "abort_backspace", DT_BOOL, true, 0, NULL,
    "Hitting backspace against an empty prompt aborts the prompt"
  },
  { "abort_key", DT_STRING|D_NOT_EMPTY|D_ON_STARTUP, IP "\007", 0, NULL,
    "String representation of key to abort prompts"
  },
  { "ascii_chars", DT_BOOL, false, 0, NULL,
    "Use plain ASCII characters, when drawing email threads"
  },
  { "assumed_charset", DT_SLIST|D_SLIST_SEP_COLON|D_SLIST_ALLOW_EMPTY, 0, 0, charset_slist_validator,
    "If a message is missing a character set, assume this character set"
  },
  { "attach_format", DT_EXPANDO|D_NOT_EMPTY, IP "%u%D%I %t%4n %T%d %> [%.7m/%.10M, %.6e%<C?, %C>, %s] ", IP &AttachFormatDef, NULL,
    "printf-like format string for the attachment menu"
  },
  { "attach_save_dir", DT_PATH|D_PATH_DIR, IP "./", 0, NULL,
    "Default directory where attachments are saved"
  },
  { "attach_save_without_prompting", DT_BOOL, false, 0, NULL,
    "If true, then don't prompt to save"
  },
  { "attach_sep", DT_STRING, IP "\n", 0, NULL,
    "Separator to add between saved/printed/piped attachments"
  },
  { "attach_split", DT_BOOL, true, 0, NULL,
    "Save/print/pipe tagged messages individually"
  },
  { "auto_edit", DT_BOOL, false, 0, NULL,
    "Skip the initial compose menu and edit the email"
  },
  { "auto_tag", DT_BOOL, false, 0, NULL,
    "Automatically apply actions to all tagged messages"
  },
  { "beep", DT_BOOL, true, 0, NULL,
    "Make a noise when an error occurs"
  },
  { "beep_new", DT_BOOL, false, 0, NULL,
    "Make a noise when new mail arrives"
  },
  { "bounce", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Confirm before bouncing a message"
  },
  { "braille_friendly", DT_BOOL, false, 0, NULL,
    "Move the cursor to the beginning of the line"
  },
  { "charset", DT_STRING|D_NOT_EMPTY|D_CHARSET_SINGLE, 0, 0, charset_validator,
    "Default character set for displaying text on screen"
  },
  { "collapse_flagged", DT_BOOL, true, 0, NULL,
    "Prevent the collapse of threads with flagged emails"
  },
  { "collapse_unread", DT_BOOL, true, 0, NULL,
    "Prevent the collapse of threads with unread emails"
  },
  { "color_directcolor", DT_BOOL|D_ON_STARTUP, false, 0, NULL,
    "Use 24bit colors (aka truecolor aka directcolor)"
  },
  { "config_charset", DT_STRING, 0, 0, charset_validator,
    "Character set that the config files are in"
  },
  { "confirm_append", DT_BOOL, true, 0, NULL,
    "Confirm before appending emails to a mailbox"
  },
  { "confirm_create", DT_BOOL, true, 0, NULL,
    "Confirm before creating a new mailbox"
  },
  { "copy_decode_weed", DT_BOOL, false, 0, NULL,
    "Controls whether to weed headers when copying or saving emails"
  },
  { "count_alternatives", DT_BOOL, false, 0, NULL,
    "Recurse inside multipart/alternatives while counting attachments"
  },
  { "crypt_chars", DT_MBTABLE, IP "SPsK ", 0, NULL,
    "User-configurable crypto flags: signed, encrypted etc."
  },
  { "date_format", DT_STRING|D_NOT_EMPTY, IP "!%a, %b %d, %Y at %I:%M:%S%p %Z", 0, NULL,
    "strftime format string for the `%d` expando"
  },
  { "debug_file", DT_PATH|D_PATH_FILE, IP "~/.neomuttdebug", 0, NULL,
    "File to save debug logs"
  },
  { "debug_level", DT_NUMBER, 0, 0, level_validator,
    "Logging level for debug logs"
  },
  { "default_hook", DT_STRING, IP "~f %s !~P | (~P ~C %s)", 0, NULL,
    "Pattern to use for hooks that only have a simple regex"
  },
  { "delete", DT_QUAD, MUTT_ASKYES, 0, NULL,
    "Really delete messages, when the mailbox is closed"
  },
  { "delete_untag", DT_BOOL, true, 0, NULL,
    "Untag messages when they are marked for deletion"
  },
  { "digest_collapse", DT_BOOL, true, 0, NULL,
    "Hide the subparts of a multipart/digest"
  },
  { "duplicate_threads", DT_BOOL, true, 0, NULL,
    "Highlight messages with duplicated message IDs"
  },
  { "editor", DT_STRING|D_NOT_EMPTY|D_STRING_COMMAND, 0, 0, NULL,
    "External command to use as an email editor"
  },
  { "flag_chars", DT_MBTABLE, IP "*!DdrONon- ", 0, NULL,
    "User-configurable index flags: tagged, new, etc"
  },
  { "flag_safe", DT_BOOL, false, 0, NULL,
    "Protect flagged messages from deletion"
  },
  { "folder", DT_STRING|D_STRING_MAILBOX, IP "~/Mail", 0, NULL,
    "Base folder for a set of mailboxes"
  },
  { "force_name", DT_BOOL, false, 0, NULL,
    "Save outgoing mail in a folder of their name"
  },
  { "forward_decode", DT_BOOL, true, 0, NULL,
    "Decode the message when forwarding it"
  },
  { "forward_quote", DT_BOOL, false, 0, NULL,
    "Automatically quote a forwarded message using `$indent_string`"
  },
  { "from", DT_ADDRESS, 0, 0, NULL,
    "Default 'From' address to use, if isn't otherwise set"
  },
  { "from_chars", DT_MBTABLE, 0, 0, NULL,
    "User-configurable index flags: to address, cc address, etc"
  },
  { "gecos_mask", DT_REGEX, IP "^[^,]*", 0, NULL,
    "Regex for parsing GECOS field of /etc/passwd"
  },
  { "header", DT_BOOL, false, 0, NULL,
    "Include the message headers in the reply email (Weed applies)"
  },
  { "hide_limited", DT_BOOL, false, 0, NULL,
    "Don't indicate hidden messages, in the thread tree"
  },
  { "hide_missing", DT_BOOL, true, 0, NULL,
    "Don't indicate missing messages, in the thread tree"
  },
  { "hide_thread_subject", DT_BOOL, true, 0, NULL,
    "Hide subjects that are similar to that of the parent message"
  },
  { "hide_top_limited", DT_BOOL, false, 0, NULL,
    "Don't indicate hidden top message, in the thread tree"
  },
  { "hide_top_missing", DT_BOOL, true, 0, NULL,
    "Don't indicate missing top message, in the thread tree"
  },
  { "honor_disposition", DT_BOOL, false, 0, NULL,
    "Don't display MIME parts inline if they have a disposition of 'attachment'"
  },
  { "hostname", DT_STRING, 0, 0, NULL,
    "Fully-qualified domain name of this machine"
  },
  { "implicit_auto_view", DT_BOOL, false, 0, NULL,
    "Display MIME attachments inline if a 'copiousoutput' mailcap entry exists"
  },
  { "include_encrypted", DT_BOOL, false, 0, NULL,
    "Whether to include encrypted content when replying"
  },
  { "include_only_first", DT_BOOL, false, 0, NULL,
    "Only include the first attachment when replying"
  },
  { "indent_string", DT_EXPANDO, IP "> ", IP IndexFormatDefNoPadding, NULL,
    "String used to indent 'reply' text"
  },
  { "index_format", DT_EXPANDO|D_NOT_EMPTY, IP "%4C %Z %{%b %d} %-15.15L (%<l?%4l&%4c>) %s", IP &IndexFormatDef, NULL,
    "printf-like format string for the index menu (emails)"
  },
  { "keep_flagged", DT_BOOL, false, 0, NULL,
    "Don't move flagged messages from `$spool_file` to `$mbox`"
  },
  { "local_date_header", DT_BOOL, true, 0, NULL,
    "Convert the date in the Date header of sent emails into local timezone, UTC otherwise"
  },
  { "mail_check", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 5, 0, NULL,
    "Number of seconds before NeoMutt checks for new mail"
  },
  { "mail_check_recent", DT_BOOL, true, 0, NULL,
    "Notify the user about new mail since the last time the mailbox was opened"
  },
  { "mail_check_stats", DT_BOOL, false, 0, NULL,
    "Periodically check for new mail"
  },
  { "mail_check_stats_interval", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 60, 0, NULL,
    "How often to check for new mail"
  },
  { "mailcap_path", DT_SLIST|D_SLIST_SEP_COLON, IP "~/.mailcap:" PKGDATADIR "/mailcap:" SYSCONFDIR "/mailcap:/etc/mailcap:/usr/etc/mailcap:/usr/local/etc/mailcap", 0, NULL,
    "List of mailcap files (colon-separated)"
  },
  { "mailcap_sanitize", DT_BOOL, true, 0, NULL,
    "Restrict the possible characters in mailcap expandos"
  },
  { "mark_old", DT_BOOL, true, 0, NULL,
    "Mark new emails as old when leaving the mailbox"
  },
  { "mbox", DT_STRING|D_STRING_MAILBOX, IP "~/mbox", 0, NULL,
    "Folder that receives read emails (see Move)"
  },
  { "mbox_type", DT_ENUM, MUTT_MBOX, IP &MboxTypeDef, NULL,
    "Default type for creating new mailboxes"
  },
  { "message_cache_clean", DT_BOOL, false, 0, NULL,
    "(imap/pop) Clean out obsolete entries from the message cache"
  },
  { "message_cache_dir", DT_PATH|D_PATH_DIR, 0, 0, NULL,
    "(imap/pop) Directory for the message cache"
  },
  { "message_format", DT_EXPANDO|D_NOT_EMPTY, IP "%s", IP &IndexFormatDef, NULL,
    "printf-like format string for listing attached messages"
  },
  { "meta_key", DT_BOOL, false, 0, NULL,
    "Interpret 'ALT-x' as 'ESC-x'"
  },
  { "mime_forward", DT_QUAD, MUTT_NO, 0, NULL,
    "Forward a message as a 'message/RFC822' MIME part"
  },
  { "mime_forward_rest", DT_QUAD, MUTT_YES, 0, NULL,
    "Forward all attachments, even if they can't be decoded"
  },
  { "move", DT_QUAD, MUTT_NO, 0, NULL,
    "Move emails from `$spool_file` to `$mbox` when read"
  },
  { "narrow_tree", DT_BOOL, false, 0, NULL,
    "Draw a narrower thread tree in the index"
  },
  { "new_mail_command", DT_EXPANDO|D_STRING_COMMAND, 0, IP StatusFormatDefNoPadding, NULL,
    "External command to run when new mail arrives"
  },
  { "pipe_decode", DT_BOOL, false, 0, NULL,
    "Decode the message when piping it"
  },
  { "pipe_decode_weed", DT_BOOL, true, 0, NULL,
    "Control whether to weed headers when piping an email"
  },
  { "pipe_sep", DT_STRING, IP "\n", 0, NULL,
    "Separator to add between multiple piped messages"
  },
  { "pipe_split", DT_BOOL, false, 0, NULL,
    "Run the pipe command on each message separately"
  },
  { "postponed", DT_STRING|D_STRING_MAILBOX, IP "~/postponed", 0, NULL,
    "Folder to store postponed messages"
  },
  { "preferred_languages", DT_SLIST|D_SLIST_SEP_COMMA, 0, 0, NULL,
    "List of Preferred Languages for multilingual MIME (comma-separated)"
  },
  { "print", DT_QUAD, MUTT_ASKNO, 0, NULL,
    "Confirm before printing a message"
  },
  { "print_command", DT_STRING|D_STRING_COMMAND, IP "lpr", 0, NULL,
    "External command to print a message"
  },
  { "print_decode", DT_BOOL, true, 0, NULL,
    "Decode message before printing it"
  },
  { "print_decode_weed", DT_BOOL, true, 0, NULL,
    "Control whether to weed headers when printing an email"
  },
  { "print_split", DT_BOOL, false, 0, NULL,
    "Print multiple messages separately"
  },
  { "quit", DT_QUAD, MUTT_YES, 0, NULL,
    "Prompt before exiting NeoMutt"
  },
  { "quote_regex", DT_REGEX, IP "^([ \t]*[|>:}#])+", 0, NULL,
    "Regex to match quoted text in a reply"
  },
  { "read_only", DT_BOOL, false, 0, NULL,
    "Open folders in read-only mode"
  },
  { "real_name", DT_STRING, 0, 0, NULL,
    "Real name of the user"
  },
  { "record", DT_STRING|D_STRING_MAILBOX, IP "~/sent", 0, NULL,
    "Folder to save 'sent' messages"
  },
  { "reflow_space_quotes", DT_BOOL, true, 0, NULL,
    "Insert spaces into reply quotes for 'format=flowed' messages"
  },
  { "reflow_text", DT_BOOL, true, 0, NULL,
    "Reformat paragraphs of 'format=flowed' text"
  },
  { "reflow_wrap", DT_NUMBER, 78, 0, NULL,
    "Maximum paragraph width for reformatting 'format=flowed' text"
  },
  { "resolve", DT_BOOL, true, 0, NULL,
    "Move to the next email whenever a command modifies an email"
  },
  { "resume_edited_draft_files", DT_BOOL, true, 0, NULL,
    "Resume editing previously saved draft files"
  },
  { "save_address", DT_BOOL, false, 0, NULL,
    "Use sender's full address as a default save folder"
  },
  { "save_empty", DT_BOOL, true, 0, NULL,
    "(mbox,mmdf) Preserve empty mailboxes"
  },
  { "save_name", DT_BOOL, false, 0, NULL,
    "Save outgoing message to mailbox of recipient's name if it exists"
  },
  { "score", DT_BOOL, true, 0, NULL,
    "Use message scoring"
  },
  { "score_threshold_delete", DT_NUMBER, -1, 0, NULL,
    "Messages with a lower score will be automatically deleted"
  },
  { "score_threshold_flag", DT_NUMBER, 9999, 0, NULL,
    "Messages with a greater score will be automatically flagged"
  },
  { "score_threshold_read", DT_NUMBER, -1, 0, NULL,
    "Messages with a lower score will be automatically marked read"
  },
  { "send_charset", DT_SLIST|D_SLIST_SEP_COLON|D_SLIST_ALLOW_EMPTY|D_CHARSET_STRICT, IP "us-ascii:iso-8859-1:utf-8", 0, charset_slist_validator,
    "Character sets for outgoing mail"
  },
  { "shell", DT_STRING|D_STRING_COMMAND, IP "/bin/sh", 0, NULL,
    "External command to run subshells in"
  },
  { "show_multipart_alternative", DT_STRING, 0, 0, multipart_validator,
    "How to display 'multipart/alternative' MIME parts"
  },
  { "simple_search", DT_STRING, IP "~f %s | ~s %s", 0, NULL,
    "Pattern to search for when search doesn't contain ~'s"
  },
  { "size_show_bytes", DT_BOOL, false, 0, NULL,
    "Show smaller sizes in bytes"
  },
  { "size_show_fractions", DT_BOOL, true, 0, NULL,
    "Show size fractions with a single decimal place"
  },
  { "size_show_mb", DT_BOOL, true, 0, NULL,
    "Show sizes in megabytes for sizes greater than 1 megabyte"
  },
  { "size_units_on_left", DT_BOOL, false, 0, NULL,
    "Show the units as a prefix to the size"
  },
  { "sleep_time", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 1, 0, NULL,
    "Time to pause after certain info messages"
  },
  { "sort", DT_SORT|D_SORT_REVERSE|D_SORT_LAST, EMAIL_SORT_DATE, IP SortMethods, sort_validator,
    "Sort method for the index"
  },
  { "sort_aux", DT_SORT|D_SORT_REVERSE|D_SORT_LAST, EMAIL_SORT_DATE, IP SortAuxMethods, NULL,
    "Secondary sort method for the index"
  },
  { "sort_re", DT_BOOL, true, 0, NULL,
    "Whether $reply_regex must be matched when not $strict_threads"
  },
  { "spool_file", DT_STRING|D_STRING_MAILBOX, 0, 0, NULL,
    "Inbox"
  },
  { "status_chars", DT_MBTABLE, IP "-*%A", 0, NULL,
    "Indicator characters for the status bar"
  },
  { "status_on_top", DT_BOOL, false, 0, NULL,
    "Display the status bar at the top"
  },
  { "strict_threads", DT_BOOL, false, 0, NULL,
    "Thread messages using 'In-Reply-To' and 'References' headers"
  },
  { "suspend", DT_BOOL, true, 0, NULL,
    "Allow the user to suspend NeoMutt using '^Z'"
  },
  { "text_flowed", DT_BOOL, false, 0, NULL,
    "Generate 'format=flowed' messages"
  },
  { "thread_received", DT_BOOL, false, 0, NULL,
    "Sort threaded messages by their received date"
  },
  { "timeout", DT_NUMBER|D_INTEGER_NOT_NEGATIVE, 600, 0, NULL,
    "Time to wait for user input in menus"
  },
  { "tmp_dir", DT_PATH|D_PATH_DIR|D_NOT_EMPTY, IP TMPDIR, 0, NULL,
    "Directory for temporary files"
  },
  { "to_chars", DT_MBTABLE, IP " +TCFLR", 0, NULL,
    "Indicator characters for the 'To' field in the index"
  },
  { "trash", DT_STRING|D_STRING_MAILBOX, 0, 0, NULL,
    "Folder to put deleted emails"
  },
  { "ts_enabled", DT_BOOL, false, 0, NULL,
    "Allow NeoMutt to set the terminal status line and icon"
  },
  // L10N: $ts_icon_format default format
  { "ts_icon_format", DT_EXPANDO|D_L10N_STRING, IP N_("M%<n?AIL&ail>"), IP StatusFormatDefNoPadding, NULL,
    "printf-like format string for the terminal's icon title"
  },
  // L10N: $ts_status_format default format
  { "ts_status_format", DT_EXPANDO|D_L10N_STRING, IP N_("NeoMutt with %<m?%m messages&no messages>%<n? [%n NEW]>"), IP StatusFormatDefNoPadding, NULL,
    "printf-like format string for the terminal's status (window title)"
  },
  { "use_domain", DT_BOOL, true, 0, NULL,
    "Qualify local addresses using this domain"
  },
  { "use_threads", DT_ENUM, UT_UNSET, IP &UseThreadsTypeDef, NULL,
    "Whether to use threads for the index"
  },
  { "wait_key", DT_BOOL, true, 0, NULL,
    "Prompt to press a key after running external commands"
  },
  { "weed", DT_BOOL, true, 0, NULL,
    "Filter headers when displaying/forwarding/printing/replying"
  },
  { "wrap", DT_NUMBER, 0, 0, NULL,
    "Width to wrap text in the pager"
  },
  { "wrap_search", DT_BOOL, true, 0, NULL,
    "Wrap around when the search hits the end"
  },

  { "cursor_overlay",            D_INTERNAL_DEPRECATED|DT_BOOL,   0, IP "2020-07-20" },
  { "escape",                    D_INTERNAL_DEPRECATED|DT_STRING, 0, IP "2021-03-18" },
  { "ignore_linear_white_space", D_INTERNAL_DEPRECATED|DT_BOOL,   0, IP "2021-03-18" },
  { "mixmaster",                 D_INTERNAL_DEPRECATED|DT_STRING, 0, IP "2024-05-30" },
  { "mix_entry_format",          D_INTERNAL_DEPRECATED|DT_EXPANDO,0, IP "2024-05-30" },
  { "visual",                    D_INTERNAL_DEPRECATED|DT_STRING, 0, IP "2021-03-18" },

  { "autoedit",                  DT_SYNONYM, IP "auto_edit",                  IP "2021-03-21" },
  { "confirmappend",             DT_SYNONYM, IP "confirm_append",             IP "2021-03-21" },
  { "confirmcreate",             DT_SYNONYM, IP "confirm_create",             IP "2021-03-21" },
  { "edit_hdrs",                 DT_SYNONYM, IP "edit_headers",               IP "2021-03-21" },
  { "forw_decode",               DT_SYNONYM, IP "forward_decode",             IP "2021-03-21" },
  { "forw_quote",                DT_SYNONYM, IP "forward_quote",              IP "2021-03-21" },
  { "hdr_format",                DT_SYNONYM, IP "index_format",               IP "2021-03-21" },
  { "implicit_autoview",         DT_SYNONYM, IP "implicit_auto_view",         IP "2023-01-25" },
  { "include_onlyfirst",         DT_SYNONYM, IP "include_only_first",         IP "2021-03-21" },
  { "indent_str",                DT_SYNONYM, IP "indent_string",              IP "2021-03-21" },
  { "message_cachedir",          DT_SYNONYM, IP "message_cache_dir",          IP "2023-01-25" },
  { "mime_fwd",                  DT_SYNONYM, IP "mime_forward",               IP "2021-03-21" },
  { "msg_format",                DT_SYNONYM, IP "message_format",             IP "2021-03-21" },
  { "print_cmd",                 DT_SYNONYM, IP "print_command",              IP "2021-03-21" },
  { "quote_regexp",              DT_SYNONYM, IP "quote_regex",                IP "2021-03-21" },
  { "realname",                  DT_SYNONYM, IP "real_name",                  IP "2021-03-21" },
  { "spoolfile",                 DT_SYNONYM, IP "spool_file",                 IP "2021-03-21" },
  { "tmpdir",                    DT_SYNONYM, IP "tmp_dir",                    IP "2023-01-25" },
  { "xterm_icon",                DT_SYNONYM, IP "ts_icon_format",             IP "2021-03-21" },
  { "xterm_set_titles",          DT_SYNONYM, IP "ts_enabled",                 IP "2021-03-21" },
  { "xterm_title",               DT_SYNONYM, IP "ts_status_format",           IP "2021-03-21" },

  { "devel_security", DT_BOOL, false, 0, NULL,
    "Devel feature: Security -- https://github.com/neomutt/neomutt/discussions/4251"
  },

  { NULL },
  // clang-format on
};

#if defined(HAVE_LIBIDN)
/**
 * MainVarsIdn - IDN Config definitions
 */
static struct ConfigDef MainVarsIdn[] = {
  // clang-format off
  { "idn_decode", DT_BOOL, true, 0, NULL,
    "(idn) Decode international domain names"
  },
  { "idn_encode", DT_BOOL, true, 0, NULL,
    "(idn) Encode international domain names"
  },
  { NULL },
  // clang-format on
};
#endif

/**
 * config_init_main - Register main config variables - Implements ::module_init_config_t - @ingroup cfg_module_api
 */
static bool config_init_main(struct ConfigSet *cs)
{
  bool rc = cs_register_variables(cs, MainVars);

#if defined(HAVE_LIBIDN)
  rc |= cs_register_variables(cs, MainVarsIdn);
#endif

  return rc;
}

/**
 * init_types - Create the config types
 * @param cs Config items
 *
 * Define the config types, e.g. #DT_STRING.
 */
static void init_types(struct ConfigSet *cs)
{
  CONFIG_INIT_TYPE(cs, Address);
  CONFIG_INIT_TYPE(cs, Bool);
  CONFIG_INIT_TYPE(cs, Enum);
  CONFIG_INIT_TYPE(cs, Expando);
  CONFIG_INIT_TYPE(cs, Long);
  CONFIG_INIT_TYPE(cs, Mbtable);
  CONFIG_INIT_TYPE(cs, MyVar);
  CONFIG_INIT_TYPE(cs, Number);
  CONFIG_INIT_TYPE(cs, Path);
  CONFIG_INIT_TYPE(cs, Quad);
  CONFIG_INIT_TYPE(cs, Regex);
  CONFIG_INIT_TYPE(cs, Slist);
  CONFIG_INIT_TYPE(cs, Sort);
  CONFIG_INIT_TYPE(cs, String);
}

/**
 * init_variables - Define the config variables
 * @param cs Config items
 */
static void init_variables(struct ConfigSet *cs)
{
  // Define the config variables
  config_init_main(cs);
  CONFIG_INIT_VARS(cs, alias);
#if defined(USE_AUTOCRYPT)
  CONFIG_INIT_VARS(cs, autocrypt);
#endif
  CONFIG_INIT_VARS(cs, browser);
  CONFIG_INIT_VARS(cs, compose);
  CONFIG_INIT_VARS(cs, conn);
  CONFIG_INIT_VARS(cs, email);
#if defined(USE_HCACHE)
  CONFIG_INIT_VARS(cs, hcache);
#endif
  CONFIG_INIT_VARS(cs, helpbar);
  CONFIG_INIT_VARS(cs, history);
  CONFIG_INIT_VARS(cs, imap);
  CONFIG_INIT_VARS(cs, index);
  CONFIG_INIT_VARS(cs, maildir);
  CONFIG_INIT_VARS(cs, mbox);
  CONFIG_INIT_VARS(cs, menu);
  CONFIG_INIT_VARS(cs, mh);
  CONFIG_INIT_VARS(cs, ncrypt);
  CONFIG_INIT_VARS(cs, nntp);
#if defined(USE_NOTMUCH)
  CONFIG_INIT_VARS(cs, notmuch);
#endif
  CONFIG_INIT_VARS(cs, pager);
  CONFIG_INIT_VARS(cs, pattern);
  CONFIG_INIT_VARS(cs, pop);
  CONFIG_INIT_VARS(cs, progress);
  CONFIG_INIT_VARS(cs, send);
  CONFIG_INIT_VARS(cs, sidebar);
}

/**
 * init_config - Initialise the config system
 * @param cs Config items
 */
void init_config(struct ConfigSet *cs)
{
  init_types(cs);
  init_variables(cs);
}
