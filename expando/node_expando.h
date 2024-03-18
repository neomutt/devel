/**
 * @file
 * Expando Node for an Expando
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

#ifndef MUTT_EXPANDO_NODE_EXPANDO_H
#define MUTT_EXPANDO_NODE_EXPANDO_H

#include <stdbool.h>
#include "definition.h"
#include "render.h"

struct Buffer;
struct ExpandoFormat;
struct ExpandoNode;
struct ExpandoParseError;

/**
 * struct NodeExpandoPrivate - Private data for an Expando
 */
struct NodeExpandoPrivate
{
  int color;         ///< ColorId to use
  bool has_tree;     ///< Contains tree characters, used in $index_format's %s
};

struct ExpandoNode *node_expando_new(const char *start, const char *end, struct ExpandoFormat *fmt, int did, int uid);

void node_expando_set_color   (const struct ExpandoNode *node, int cid);
void node_expando_set_has_tree(const struct ExpandoNode *node, bool has_tree);

struct ExpandoNode *node_expando_parse(const char *s, const char **parsed_until, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, struct ExpandoParseError *error);
int node_expando_render(const struct ExpandoNode *node, const struct ExpandoRenderData *rdata, struct Buffer *buf, int max_cols, void *data, MuttFormatFlags flags);

struct ExpandoNode *node_expando_parse_enclosure(const char *s, const char **parsed_until, int did, int uid, char terminator, struct ExpandoParseError *error);
const char *skip_classic_expando(const char *s, const struct ExpandoDefinition *defs);

#endif /* MUTT_EXPANDO_NODE_EXPANDO_H */
