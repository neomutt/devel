/**
 * @file
 * Basic Expando Node
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

#ifndef MUTT_EXPANDO_NODE_H
#define MUTT_EXPANDO_NODE_H

#include <stdbool.h>
#include "mutt/lib.h"
#include "format.h"

struct ExpandoRenderData;

/**
 * enum ExpandoNodeType - Type of Expando Node
 */
enum ExpandoNodeType
{
  ENT_EMPTY = 0,      ///< Empty
  ENT_TEXT,           ///< Plain text
  ENT_EXPANDO,        ///< Expando, e.g. '%n'
  ENT_PADDING,        ///< Padding: soft, hard, EOL
  ENT_CONDITION,      ///< True/False condition
  ENT_CONDBOOL,       ///< True/False boolean condition
  ENT_CONDDATE,       ///< True/False date condition
  ENT_CONTAINER,      ///< Container for other nodes
};

ARRAY_HEAD(ExpandoNodeArray, struct ExpandoNode *);

/**
 * struct ExpandoFormat - Formatting information for an Expando
 */
struct ExpandoFormat
{
  int                min_cols;        ///< Minimum number of screen columns
  int                max_cols;        ///< Maximum number of screen columns
  enum FormatJustify justification;   ///< Justification: left, centre, right
  char               leader;          ///< Leader character, 0 or space
  bool               lower;           ///< Display in lower case
};

/**
 * struct ExpandoNode - Basic Expando Node
 *
 * This is the "base class" of all Expando Nodes
 */
struct ExpandoNode
{
  enum ExpandoNodeType      type;        ///< Type of Node, e.g. #ENT_EXPANDO
  int                       did;         ///< Domain ID, e.g. #ED_EMAIL
  int                       uid;         ///< Unique ID, e.g. #ED_EMA_SIZE

  struct ExpandoFormat     *format;      ///< Formatting info
  const char               *text;        ///< Node-specific text

  struct ExpandoNodeArray   children;    ///< Children nodes

  void  *ndata;                          ///< Private node data
  void (*ndata_free)(void **ptr);        ///< Function to free the private node data

  /**
   * @defgroup expando_render Expando Render API
   *
   * render - Render an Expando
   * @param[in]  node     Node to render
   * @param[in]  rdata    Render data
   * @param[in]  max_cols Maximum number of screen columns to use
   * @param[out] buf      Buffer in which to save string
   * @retval num Number of screen columns used
   */
  int (*render)(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata,
                int max_cols, struct Buffer *buf);
};

struct ExpandoNode *node_new(void);
void                node_free(struct ExpandoNode **ptr);

void                node_add_child(struct ExpandoNode *node, struct ExpandoNode *child);
struct ExpandoNode *node_get_child(const struct ExpandoNode *node, int index);

struct ExpandoNode *node_last (struct ExpandoNode *node);

#endif /* MUTT_EXPANDO_NODE_H */
