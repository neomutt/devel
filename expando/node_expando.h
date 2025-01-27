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
 * struct NodeExpandoPrivate - Private data for an Expando - @extends ExpandoNode
 */
struct NodeExpandoPrivate
{
  int color;         ///< ColorId to use
  bool has_tree;     ///< Contains tree characters, used in $index_format's %s
};

struct ExpandoNode *node_expando_new(struct ExpandoFormat *fmt, int did, int uid);

void node_expando_set_color   (const struct ExpandoNode *node, int cid);
void node_expando_set_has_tree(const struct ExpandoNode *node, bool has_tree);

struct ExpandoFormat *parse_format(const char *str, const char **parsed_until, struct ExpandoParseError *err);
struct ExpandoNode *parse_long_name(const char *str, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, struct ExpandoFormat *fmt, const char **parsed_until, struct ExpandoParseError *err);
struct ExpandoNode *parse_short_name(const char *str, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, struct ExpandoFormat *fmt, const char **parsed_until, struct ExpandoParseError *err);
struct ExpandoNode *node_expando_parse(const char *str, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, const char **parsed_until, struct ExpandoParseError *err);
struct ExpandoNode *node_expando_parse_name(const char *str, const struct ExpandoDefinition *defs, ExpandoParserFlags flags, const char **parsed_until, struct ExpandoParseError *err);
int node_expando_render(const struct ExpandoNode *node, const struct ExpandoRenderCallback *erc, struct Buffer *buf, int max_cols, void *data, MuttFormatFlags flags);

struct ExpandoNode *node_expando_parse_enclosure(const char *str, int did, int uid, char terminator, struct ExpandoFormat *fmt, const char **parsed_until, struct ExpandoParseError *err);

#endif /* MUTT_EXPANDO_NODE_EXPANDO_H */
