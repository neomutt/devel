/**
 * @file
 * Expando Parsing
 *
 * @authors
 * Copyright (C) 2023-2024 Tóth János <gomba007@gmail.com>
 * Copyright (C) 2023-2024 Richard Russon <rich@flatcap.org>
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
 * @page expando_parse Expando Parsing
 *
 * Turn a format string into a tree of Expando Nodes.
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "parse.h"
#include "definition.h"
#include "node.h"
#include "node_condition.h"
#include "node_expando.h"
#include "node_text.h"

/**
 * node_parse_one - Parse a single Expando from a format string
 * @param[in]  str          String to parse
 * @param[in]  term_chars   Terminator characters, e.g. #NTE_GREATER
 * @param[in]  defs         Expando definitions
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr Expando Node
 */
struct ExpandoNode *node_parse_one(const char *str, NodeTextTermFlags term_chars,
                                   const struct ExpandoDefinition *defs,
                                   const char **parsed_until, struct ExpandoParseError *err)
{
  if (!str || (*str == '\0') || !defs || !parsed_until || !err)
    return NULL;

  struct ExpandoNode *node = NULL;

  node = node_text_parse(str, term_chars, parsed_until);
  if (node)
    return node;

  node = node_condition_parse(str, term_chars, defs, parsed_until, err);
  if (node)
    return node;

  node = node_expando_parse_name(str, defs, EP_NO_FLAGS, parsed_until, err);
  if (node)
    return node;

  return node_expando_parse(str, defs, EP_NO_FLAGS, parsed_until, err);
}

/**
 * node_parse_many - Parse a format string
 * @param[in]  node_cont    Container for the results
 * @param[in]  str          String to parse
 * @param[in]  term_chars   Terminator characters, e.g. #NTE_GREATER
 * @param[in]  defs         Expando definitions
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval true Success
 */
bool node_parse_many(struct ExpandoNode *node_cont, const char *str,
                     NodeTextTermFlags term_chars, const struct ExpandoDefinition *defs,
                     const char **parsed_until, struct ExpandoParseError *err)
{
  if (!node_cont || !str || !parsed_until || !err)
    return false;

  while (*str)
  {
    if ((str[0] == '&') && (term_chars & NTE_AMPERSAND))
      break;

    if ((str[0] == '>') && (term_chars & NTE_GREATER))
      break;

    if ((str[0] == '?') && (term_chars & NTE_QUESTION))
      break;

    struct ExpandoNode *node = node_parse_one(str, term_chars, defs, parsed_until, err);
    if (!node)
      return false;

    node_add_child(node_cont, node);
    str = *parsed_until;
  }

  *parsed_until = str;
  return true;
}
