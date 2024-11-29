/**
 * @file
 * Expando Node for Padding
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
 * @page expando_node_padding Padding Node
 *
 * Expando Node for Padding
 */

#include "config.h"
#include <stddef.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "node_padding.h"
#include "definition.h"
#include "node.h"
#include "node_container.h"
#include "parse.h"
#include "render.h"

/**
 * node_padding_private_new - Create new Padding private data
 * @param pad_type Padding type
 * @retval ptr New Padding private data
 */
struct NodePaddingPrivate *node_padding_private_new(enum ExpandoPadType pad_type)
{
  struct NodePaddingPrivate *priv = MUTT_MEM_CALLOC(1, struct NodePaddingPrivate);

  priv->pad_type = pad_type;

  return priv;
}

/**
 * node_padding_private_free - Free Padding private data - Implements ExpandoNode::ndata_free()
 * @param ptr Data to free
 */
void node_padding_private_free(void **ptr)
{
  if (!ptr || !*ptr)
    return;

  FREE(ptr);
}

/**
 * pad_string - Pad a buffer with a character
 * @param node     Node with padding type
 * @param buf      Buffer to populate
 * @param max_cols Number of screen columns available
 *
 * Fill buf with the padding char (Node.start) to a maximum of max_cols screen cells.
 */
int pad_string(const struct ExpandoNode *node, struct Buffer *buf, int max_cols)
{
  const int pad_len = mutt_str_len(node->text);
  const int pad_cols = mutt_strnwidth(node->text, pad_len);
  int total_cols = 0;

  if (pad_len != 0)
  {
    while (pad_cols <= max_cols)
    {
      buf_addstr_n(buf, node->text, pad_len);

      max_cols -= pad_cols;
      total_cols += pad_cols;
    }
  }

  if (max_cols > 0)
  {
    buf_add_printf(buf, "%*s", max_cols, "");
    total_cols += max_cols;
  }

  return total_cols;
}

/**
 * node_padding_render_eol - Render End-of-Line Padding - Implements ExpandoNode::render() - @ingroup expando_render
 */
int node_padding_render_eol(const struct ExpandoNode *node,
                            const struct ExpandoRenderData *rdata, int max_cols,
                            struct Buffer *buf)
{
  struct ExpandoNode *left = node_get_child(node, ENP_LEFT);

  int total_cols = node_render(left, rdata, max_cols, buf);

  total_cols += pad_string(node, buf, max_cols - total_cols);

  return total_cols;
}

/**
 * node_padding_render_hard - Render Hard Padding - Implements ExpandoNode::render() - @ingroup expando_render
 *
 * Text to the left of the padding is hard and will be preserved if possible.
 * Text to the right of the padding will be truncated.
 */
int node_padding_render_hard(const struct ExpandoNode *node,
                             const struct ExpandoRenderData *rdata,
                             int max_cols, struct Buffer *buf)
{
  struct Buffer *buf_left = buf_pool_get();
  struct Buffer *buf_pad = buf_pool_get();
  struct Buffer *buf_right = buf_pool_get();

  int cols_used = 0;

  struct ExpandoNode *left = node_get_child(node, ENP_LEFT);
  if (left)
    cols_used += node_render(left, rdata, max_cols - cols_used, buf_left);

  struct ExpandoNode *right = node_get_child(node, ENP_RIGHT);
  if (right)
    cols_used += node_render(right, rdata, max_cols - cols_used, buf_right);

  if (max_cols > cols_used)
    cols_used += pad_string(node, buf_pad, max_cols - cols_used);

  buf_addstr(buf, buf_string(buf_left));
  buf_addstr(buf, buf_string(buf_pad));
  buf_addstr(buf, buf_string(buf_right));

  buf_pool_release(&buf_left);
  buf_pool_release(&buf_pad);
  buf_pool_release(&buf_right);

  return cols_used;
}

/**
 * node_padding_render_soft - Render Soft Padding - Implements ExpandoNode::render() - @ingroup expando_render
 *
 * Text to the right of the padding is hard and will be preserved if possible.
 * Text to the left of the padding will be truncated.
 */
int node_padding_render_soft(const struct ExpandoNode *node,
                             const struct ExpandoRenderData *rdata,
                             int max_cols, struct Buffer *buf)
{
  struct Buffer *buf_left = buf_pool_get();
  struct Buffer *buf_pad = buf_pool_get();
  struct Buffer *buf_right = buf_pool_get();

  int cols_used = 0;

  struct ExpandoNode *right = node_get_child(node, ENP_RIGHT);
  if (right)
    cols_used += node_render(right, rdata, max_cols - cols_used, buf_right);

  struct ExpandoNode *left = node_get_child(node, ENP_LEFT);
  if (left)
    cols_used += node_render(left, rdata, max_cols - cols_used, buf_left);

  if (max_cols > cols_used)
    cols_used += pad_string(node, buf_pad, max_cols - cols_used);

  buf_addstr(buf, buf_string(buf_left));
  buf_addstr(buf, buf_string(buf_pad));
  buf_addstr(buf, buf_string(buf_right));

  buf_pool_release(&buf_left);
  buf_pool_release(&buf_pad);
  buf_pool_release(&buf_right);

  return cols_used;
}

/**
 * node_padding_new - Creata new Padding ExpandoNode
 * @param pad_type Padding type
 * @param start    Start of padding character
 * @param end      End of padding character
 * @retval ptr New Padding ExpandoNode
 */
struct ExpandoNode *node_padding_new(enum ExpandoPadType pad_type,
                                     const char *start, const char *end)
{
  struct ExpandoNode *node = node_new();

  node->type = ENT_PADDING;
  node->text = mutt_strn_dup(start, end - start);

  switch (pad_type)
  {
    case EPT_FILL_EOL:
      node->render = node_padding_render_eol;
      break;
    case EPT_HARD_FILL:
      node->render = node_padding_render_hard;
      break;
    case EPT_SOFT_FILL:
      node->render = node_padding_render_soft;
      break;
  };

  node->ndata = node_padding_private_new(pad_type);
  node->ndata_free = node_padding_private_free;

  return node;
}

/**
 * node_padding_parse - Parse a Padding Expando - Implements ExpandoDefinition::parse() - @ingroup expando_parse_api
 *
 * Parse a Padding Expando of the form, "%|X", "%>X" or "%*X",
 * where the character 'X' will be used to fill the space.
 */
struct ExpandoNode *node_padding_parse(const char *str, struct ExpandoFormat *fmt,
                                       int did, int uid, ExpandoParserFlags flags,
                                       const char **parsed_until,
                                       struct ExpandoParseError *err)
{
  if (fmt)
  {
    // L10N: Padding expandos, %* %> %|, don't use formatting, e.g. %-30x
    snprintf(err->message, sizeof(err->message), _("Padding cannot be formatted"));
    err->position = str;
    return NULL;
  }

  if (flags & EP_CONDITIONAL)
  {
    snprintf(err->message, sizeof(err->message),
             // L10N: Conditional Expandos can only depend on other Expandos
             //       e.g. "%<X?apple>" displays "apple" if "%X" is true.
             _("Padding cannot be used as a condition"));
    err->position = str;
    return NULL;
  }

  enum ExpandoPadType pt = 0;
  if (*str == '|')
  {
    pt = EPT_FILL_EOL;
  }
  else if (*str == '>')
  {
    pt = EPT_HARD_FILL;
  }
  else if (*str == '*')
  {
    pt = EPT_SOFT_FILL;
  }
  else
  {
    return NULL;
  }
  str++;

  size_t consumed = mutt_mb_charlen(str, NULL);
  if (consumed == 0)
  {
    str = " "; // Default to a space
    consumed = 1;
  }

  *parsed_until = str + consumed;
  return node_padding_new(pt, str, str + consumed);
}

/**
 * node_padding_repad - Rearrange Padding in a tree of ExpandoNodes
 * @param ptr Parent Node
 */
void node_padding_repad(struct ExpandoNode **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct ExpandoNode *parent = *ptr;
  struct ExpandoNode **np = NULL;
  ARRAY_FOREACH(np, &parent->children)
  {
    if (!np || !*np)
      continue;

    // Repad any children, recursively
    node_padding_repad(np);

    struct ExpandoNode *node = *np;
    if (node->type != ENT_PADDING)
      continue;

    struct ExpandoNode *node_left = node_container_new();
    struct ExpandoNode *node_right = node_container_new();

    if (ARRAY_FOREACH_IDX_np > 0)
    {
      for (int i = 0; i < ARRAY_FOREACH_IDX_np; i++)
      {
        node_add_child(node_left, node_get_child(parent, i));
      }
    }

    size_t count = ARRAY_SIZE(&parent->children);
    if ((ARRAY_FOREACH_IDX_np + 1) < count)
    {
      for (int i = ARRAY_FOREACH_IDX_np + 1; i < count; i++)
      {
        node_add_child(node_right, node_get_child(parent, i));
      }
    }

    // All the children have been transferred
    ARRAY_FREE(&parent->children);

    node_add_child(node, node_left);
    node_add_child(node, node_right);

    node_add_child(parent, node);

    break; // Only repad the first padding node
  }
}
