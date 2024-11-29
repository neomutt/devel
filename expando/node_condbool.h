/**
 * @file
 * Expando Node for a Conditional Boolean
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

#ifndef MUTT_EXPANDO_NODE_CONDBOOL_H
#define MUTT_EXPANDO_NODE_CONDBOOL_H

struct Buffer;
struct ExpandoNode;
struct ExpandoRenderData;

int node_condbool_render(const struct ExpandoNode *node,
                         const struct ExpandoRenderData *rdata, int max_cols,
                         struct Buffer *buf);

#endif /* MUTT_EXPANDO_NODE_CONDBOOL_H */
