/**
 * @file
 * Expando Node for a Condition
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
 * @page expando_node_condition Condition Node
 *
 * Expando Node for a Condition
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "node_condition.h"
#include "definition.h"
#include "format.h"
#include "helpers.h"
#include "node.h"
#include "node_condbool.h"
#include "node_container.h"
#include "node_expando.h"
#include "node_text.h"
#include "parse.h"
#include "render.h"

/**
 * node_condition_render - Render a Conditional Node - Implements ExpandoNode::render() - @ingroup expando_render
 */
static int node_condition_render(const struct ExpandoNode *node,
                                 const struct ExpandoRenderData *rdata,
                                 int max_cols, struct Buffer *buf)
{
  ASSERT(node->type == ENT_CONDITION);

  const struct ExpandoNode *node_cond = node_get_child(node, ENC_CONDITION);

  // Discard any text returned, just use the return value as a bool
  struct Buffer *buf_cond = buf_pool_get();
  int rc_cond = node_cond->render(node_cond, rdata, max_cols, buf_cond);

  int rc = 0;
  buf_reset(buf_cond);

  if (rc_cond == true)
  {
    const struct ExpandoNode *node_true = node_get_child(node, ENC_TRUE);
    rc = node_render(node_true, rdata, max_cols, buf_cond);
  }
  else
  {
    const struct ExpandoNode *node_false = node_get_child(node, ENC_FALSE);
    rc = node_render(node_false, rdata, max_cols, buf_cond);
  }

  const struct ExpandoFormat *fmt = node->format;
  if (!fmt)
  {
    buf_addstr(buf, buf_string(buf_cond));
    buf_pool_release(&buf_cond);
    return rc;
  }

  struct Buffer *tmp = buf_pool_get();

  int min_cols = MAX(fmt->min_cols, fmt->max_cols);
  min_cols = MIN(min_cols, max_cols);
  if (fmt->max_cols >= 0)
    max_cols = MIN(max_cols, fmt->max_cols);
  rc = format_string(tmp, min_cols, max_cols, fmt->justification, ' ',
                     buf_string(buf_cond), buf_len(buf_cond), true);
  if (fmt->lower)
    buf_lower_special(tmp);

  buf_addstr(buf, buf_string(tmp));
  buf_pool_release(&tmp);
  buf_pool_release(&buf_cond);

  return rc;
}

/**
 * node_condition_new - Create a new Condition Expando Node
 * @param node_cond  Expando Node that will be tested
 * @param node_true  Node tree for the 'true' case
 * @param node_false Node tree for the 'false' case
 * @param fmt        Formatting info
 * @retval ptr New Condition Expando Node
 */
struct ExpandoNode *node_condition_new(struct ExpandoNode *node_cond,
                                       struct ExpandoNode *node_true,
                                       struct ExpandoNode *node_false,
                                       struct ExpandoFormat *fmt)
{
  ASSERT(node_cond);

  struct ExpandoNode *node = node_new();

  node->type = ENT_CONDITION;
  node->render = node_condition_render;

  ARRAY_SET(&node->children, ENC_CONDITION, node_cond);
  ARRAY_SET(&node->children, ENC_TRUE, node_true);
  ARRAY_SET(&node->children, ENC_FALSE, node_false);

  node->format = fmt;

  return node;
}

/**
 * node_condition_parse - Parse a conditional Expando
 * @param[in]  str          String to parse
 * @param[in]  term_chars   Terminator characters, e.g. #NTE_GREATER
 * @param[in]  defs         Expando definitions
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr Expando Node
 */
struct ExpandoNode *node_condition_parse(const char *str, NodeTextTermFlags term_chars,
                                         const struct ExpandoDefinition *defs,
                                         const char **parsed_until,
                                         struct ExpandoParseError *err)
{
  if (!str || (str[0] != '%'))
    return NULL;

  str++; // Skip %

  struct ExpandoFormat *fmt = NULL;
  struct ExpandoNode *node_cond = NULL;
  struct ExpandoNode *node_true = NULL;
  struct ExpandoNode *node_false = NULL;

  //----------------------------------------------------------------------------
  // Parse the format (optional)
  fmt = parse_format(str, parsed_until, err);
  if (err->position)
    goto fail;

  str = *parsed_until;

  if ((str[0] != '<') && (str[0] != '?'))
    goto fail;

  const bool old_style = (str[0] == '?'); // %?X?...&...?
  str++;

  //----------------------------------------------------------------------------
  // Parse the condition
  node_cond = parse_short_name(str, defs, EP_CONDITIONAL, NULL, parsed_until, err);
  if (!node_cond)
    goto fail;

  if (node_cond->type == ENT_EXPANDO)
  {
    node_cond->type = ENT_CONDBOOL;
    node_cond->render = node_condbool_render;
  }

  str = *parsed_until; // Skip the expando
  if (str[0] != '?')
  {
    err->position = str;
    snprintf(err->message, sizeof(err->message),
             // L10N: Expando is missing a terminator character
             //       e.g. "%[..." is missing the final ']'
             _("Conditional expando is missing '%c'"), '?');
    goto fail;
  }
  str++; // Skip the '?'

  //----------------------------------------------------------------------------
  // Parse the 'true' clause (optional)
  const NodeTextTermFlags term_true = term_chars | NTE_AMPERSAND |
                                      (old_style ? NTE_QUESTION : NTE_GREATER);

  node_true = node_container_new();
  node_parse_many(node_true, str, term_true, defs, parsed_until, err);
  if (err->position)
    goto fail;

  str = *parsed_until;

  //----------------------------------------------------------------------------
  // Parse the 'false' clause (optional)

  node_false = NULL;
  if (str[0] == '&')
  {
    str++;
    const NodeTextTermFlags term_false = term_chars | (old_style ? NTE_QUESTION : NTE_GREATER);

    node_false = node_container_new();
    node_parse_many(node_false, str, term_false, defs, parsed_until, err);
    if (err->position)
      goto fail;

    str = *parsed_until;
  }

  //----------------------------------------------------------------------------
  // Check for the terminator character
  const char terminator = old_style ? '?' : '>';

  if (str[0] != terminator)
  {
    err->position = str;
    snprintf(err->message, sizeof(err->message),
             // L10N: Expando is missing a terminator character
             //       e.g. "%[..." is missing the final ']'
             _("Conditional expando is missing '%c'"), '?');
    goto fail;
  }

  *parsed_until = str + 1;

  return node_condition_new(node_cond, node_true, node_false, fmt);

fail:
  FREE(&fmt);
  node_free(&node_cond);
  node_free(&node_true);
  node_free(&node_false);
  return NULL;
}
