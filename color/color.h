/**
 * @file
 * Color and attribute parsing
 *
 * @authors
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
 * Copyright (C) 2021-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2022 Pietro Cerutti <gahr@gahr.ch>
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

#ifndef MUTT_COLOR_COLOR_H
#define MUTT_COLOR_COLOR_H

#include "config.h"
#include "mutt/lib.h"
#include <stdbool.h>

/**
 * enum ColorId - List of all coloured objects
 */
enum ColorId
{
  MT_COLOR_NONE,                     ///< No colour
  MT_COLOR_ATTACHMENT,               ///< MIME attachments text (entire line)
  MT_COLOR_ATTACH_HEADERS,           ///< MIME attachment test (takes a pattern)
  MT_COLOR_BODY,                     ///< Pager: highlight body of message (takes a pattern)
  MT_COLOR_BOLD,                     ///< Bold text
  MT_COLOR_COMMENT,                  ///< Commented out config
  MT_COLOR_COMPOSE_HEADER,           ///< Header labels, e.g. From:
  MT_COLOR_COMPOSE_SECURITY_BOTH,    ///< Mail will be encrypted and signed
  MT_COLOR_COMPOSE_SECURITY_ENCRYPT, ///< Mail will be encrypted
  MT_COLOR_COMPOSE_SECURITY_NONE,    ///< Mail will not be encrypted or signed
  MT_COLOR_COMPOSE_SECURITY_SIGN,    ///< Mail will be signed
  MT_COLOR_DEBUG,                    ///< Debug log level message
  MT_COLOR_ENUM,                     ///< Enumeration, boolean, menu name
  MT_COLOR_ERROR,                    ///< Error message
  MT_COLOR_FUNCTION,                 ///< Function, command
  MT_COLOR_HDRDEFAULT,               ///< Header default colour
  MT_COLOR_HEADER,                   ///< Message headers (takes a pattern)
  MT_COLOR_HEADING,                  ///< Heading
  MT_COLOR_IDENTIFIER,               ///< Identifier, config option, colour object
  MT_COLOR_INDICATOR,                ///< Selected item in list
  MT_COLOR_ITALIC,                   ///< Italic text
  MT_COLOR_MARKERS,                  ///< Pager: markers, line continuation
  MT_COLOR_MESSAGE,                  ///< Informational message
  MT_COLOR_MESSAGE_LOG,              ///< Menu showing log messages
  MT_COLOR_NORMAL,                   ///< Plain text
  MT_COLOR_NUMBER,                   ///< Number
  MT_COLOR_OPERATOR,                 ///< "=", keybinding
  MT_COLOR_OPTIONS,                  ///< Options in prompt
  MT_COLOR_PROGRESS,                 ///< Progress bar
  MT_COLOR_PROMPT,                   ///< Question/user input
  MT_COLOR_QUOTED0,                  ///< Pager: quoted text, level 0
  MT_COLOR_QUOTED1,                  ///< Pager: quoted text, level 1
  MT_COLOR_QUOTED2,                  ///< Pager: quoted text, level 2
  MT_COLOR_QUOTED3,                  ///< Pager: quoted text, level 3
  MT_COLOR_QUOTED4,                  ///< Pager: quoted text, level 4
  MT_COLOR_QUOTED5,                  ///< Pager: quoted text, level 5
  MT_COLOR_QUOTED6,                  ///< Pager: quoted text, level 6
  MT_COLOR_QUOTED7,                  ///< Pager: quoted text, level 7
  MT_COLOR_QUOTED8,                  ///< Pager: quoted text, level 8
  MT_COLOR_QUOTED9,                  ///< Pager: quoted text, level 9
  MT_COLOR_SEARCH,                   ///< Pager: search matches
  MT_COLOR_SIDEBAR_BACKGROUND,       ///< Background colour for the Sidebar
  MT_COLOR_SIDEBAR_DIVIDER,          ///< Line dividing sidebar from the index/pager
  MT_COLOR_SIDEBAR_FLAGGED,          ///< Mailbox with flagged messages
  MT_COLOR_SIDEBAR_HIGHLIGHT,        ///< Select cursor
  MT_COLOR_SIDEBAR_INDICATOR,        ///< Current open mailbox
  MT_COLOR_SIDEBAR_NEW,              ///< Mailbox with new mail
  MT_COLOR_SIDEBAR_ORDINARY,         ///< Mailbox with no new or flagged messages
  MT_COLOR_SIDEBAR_SPOOLFILE,        ///< $spool_file (Spool mailbox)
  MT_COLOR_SIDEBAR_UNREAD,           ///< Mailbox with unread mail
  MT_COLOR_SIGNATURE,                ///< Pager: signature lines
  MT_COLOR_STATUS,                   ///< Status bar (takes a pattern)
  MT_COLOR_STRING,                   ///< String, character
  MT_COLOR_STRIPE_EVEN,              ///< Stripes: even lines of the Help Page
  MT_COLOR_STRIPE_ODD,               ///< Stripes: odd lines of the Help Page
  MT_COLOR_TILDE,                    ///< Pager: empty lines after message
  MT_COLOR_TREE,                     ///< Index: tree-drawing characters
  MT_COLOR_UNDERLINE,                ///< Underlined text
  MT_COLOR_WARNING,                  ///< Warning messages
  // Index colours which all take a pattern
  MT_COLOR_INDEX,                    ///< Index: default colour
  MT_COLOR_INDEX_AUTHOR,             ///< Index: author field
  MT_COLOR_INDEX_COLLAPSED,          ///< Index: number of messages in collapsed thread
  MT_COLOR_INDEX_DATE,               ///< Index: date field
  MT_COLOR_INDEX_FLAGS,              ///< Index: flags field
  MT_COLOR_INDEX_LABEL,              ///< Index: label field
  MT_COLOR_INDEX_NUMBER,             ///< Index: index number
  MT_COLOR_INDEX_SIZE,               ///< Index: size field
  MT_COLOR_INDEX_SUBJECT,            ///< Index: subject field
  MT_COLOR_INDEX_TAG,                ///< Index: tag field (%G)
  MT_COLOR_INDEX_TAGS,               ///< Index: tags field (%g, %J)
  MT_COLOR_MAX,
};

extern const struct Mapping ColorFields[];

#define COLOR_DEFAULT -1

void colors_init   (void);
void colors_reset  (void);
void colors_cleanup(void);

bool mutt_color_has_pattern(enum ColorId cid);

#endif /* MUTT_COLOR_COLOR_H */
