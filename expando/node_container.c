/**
 * @file
 * Expando Node for a Container
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
 * @page expando_node_container Container Node
 *
 * Expando Node for a Container
 */

#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "node_container.h"
#include "format.h"
#include "helpers.h"
#include "node.h"
#include "render.h"

/**
 * node_container_render - Callback for a Container Node - Implements ExpandoNode::render() - @ingroup expando_render
 */
int node_container_render(const struct ExpandoNode *node,
                          const struct ExpandoRenderData *rdata, int max_cols,
                          struct Buffer *buf)
{
  ASSERT(node->type == ENT_CONTAINER);

  const struct ExpandoFormat *fmt = node->format;
  if (fmt && (fmt->max_cols != -1))
    max_cols = MIN(max_cols, fmt->max_cols);

  int total_cols = 0;

  struct Buffer *tmp = buf_pool_get();
  struct ExpandoNode **enp = NULL;
  ARRAY_FOREACH(enp, &node->children)
  {
    if (total_cols >= max_cols)
      break;
    total_cols += node_render(*enp, rdata, max_cols - total_cols, tmp);
  }

  struct Buffer *tmp2 = buf_pool_get();
  if (fmt)
  {
    int max = max_cols;
    if (fmt->max_cols >= 0)
      max = MIN(max_cols, fmt->max_cols);
    int min = MIN(fmt->min_cols, max);

    total_cols = format_string(tmp2, min, max, fmt->justification, ' ',
                               buf_string(tmp), buf_len(tmp), true);

    if (fmt->lower)
      buf_lower_special(tmp2);
  }
  else
  {
    total_cols = format_string(tmp2, 0, max_cols, JUSTIFY_LEFT, ' ',
                               buf_string(tmp), buf_len(tmp), true);
  }
  buf_addstr(buf, buf_string(tmp2));
  buf_pool_release(&tmp2);

  buf_pool_release(&tmp);
  return total_cols;
}

/**
 * node_container_new - Create a new Container ExpandoNode
 * @retval ptr New Container ExpandoNode
 */
struct ExpandoNode *node_container_new(void)
{
  struct ExpandoNode *node = node_new();

  node->type = ENT_CONTAINER;
  node->render = node_container_render;

  return node;
}

/**
 * node_container_collapse - Remove an unnecessary Container
 * @param ptr Pointer to a Container
 */
void node_container_collapse(struct ExpandoNode **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct ExpandoNode *node = *ptr;

  if (node->type != ENT_CONTAINER)
    return;

  struct ExpandoNode *child = NULL;
  struct ExpandoNode **np = NULL;
  size_t size = 0;
  ARRAY_FOREACH(np, &node->children)
  {
    if (!np || !*np)
      continue;

    size++;
    child = *np;
  }

  if (size > 1)
    return;

  if (size == 0)
  {
    node_free(ptr);
    return;
  }

  ARRAY_FREE(&node->children);
  node_free(ptr);
  *ptr = child;
}

/**
 * node_container_collapse_all - Remove unnecessary Containers
 * @param ptr Pointer to the parent node
 */
void node_container_collapse_all(struct ExpandoNode **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct ExpandoNode *parent = *ptr;

  struct ExpandoNode **np = NULL;
  ARRAY_FOREACH(np, &parent->children)
  {
    node_container_collapse_all(np);
  }

  node_container_collapse(ptr);
}
