/**
 * @file
 * Expando Node for Text
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
 * @page expando_node_text Text Node
 *
 * Expando Node for Text
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "node_text.h"
#include "format.h"
#include "node.h"

struct ExpandoRenderData;

/**
 * node_text_render - Render a Text Node - Implements ExpandoNode::render() - @ingroup expando_render
 */
static int node_text_render(const struct ExpandoNode *node,
                            const struct ExpandoRenderData *rdata, int max_cols,
                            struct Buffer *buf)
{
  ASSERT(node->type == ENT_TEXT);

  return format_string(buf, 0, max_cols, JUSTIFY_LEFT, ' ', node->text,
                       mutt_str_len(node->text), false);
}

/**
 * node_text_new - Create a new Text ExpandoNode
 * @param text Text to store
 * @retval ptr New Text ExpandoNode
 *
 * @note The text will be copied
 */
struct ExpandoNode *node_text_new(const char *text)
{
  struct ExpandoNode *node = node_new();

  node->type = ENT_TEXT;
  node->text = mutt_str_dup(text);
  node->render = node_text_render;

  return node;
}

/**
 * node_text_parse - Extract a block of text
 * @param[in]  str          String to parse
 * @param[in]  term_chars   Terminator characters, e.g. #NTE_GREATER
 * @param[out] parsed_until First character after parsed text
 * @retval ptr New Text ExpandoNode
 *
 * Parse as much text as possible until the end of the line, or a terminator
 * character is matched.
 *
 * May return NULL if a terminator character is found immediately.
 *
 * @note `\` before a character makes it literal
 * @note `%%` is interpreted as a literal `%` character
 * @note '%' is always special
 */
struct ExpandoNode *node_text_parse(const char *str, NodeTextTermFlags term_chars,
                                    const char **parsed_until)
{
  if (!str || (str[0] == '\0') || !parsed_until)
    return NULL;

  struct Buffer *text = buf_pool_get();

  while (str[0] != '\0')
  {
    if (str[0] == '\\') // Literal character
    {
      if (str[1] == '\0')
      {
        buf_addch(text, '\\');
        str++;
        break;
      }

      buf_addch(text, str[1]);
      str += 2;
      continue;
    }

    if ((str[0] == '%') && (str[1] == '%')) // Literal %
    {
      buf_addch(text, '%');
      str += 2;
      continue;
    }

    if (str[0] == '%') // '%' is always special
      break;

    if ((str[0] == '&') && (term_chars & NTE_AMPERSAND))
      break;

    if ((str[0] == '>') && (term_chars & NTE_GREATER))
      break;

    if ((str[0] == '?') && (term_chars & NTE_QUESTION))
      break;

    buf_addch(text, str[0]); // Plain text
    str++;
  }

  *parsed_until = str; // First unused character

  struct ExpandoNode *node = NULL;
  if (!buf_is_empty(text))
    node = node_text_new(buf_string(text));

  buf_pool_release(&text);

  return node;
}
