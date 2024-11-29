/**
 * @file
 * Parsed Expando
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

#ifndef MUTT_EXPANDO_EXPANDO_H
#define MUTT_EXPANDO_EXPANDO_H

#include <stdbool.h>

struct Buffer;
struct ExpandoDefinition;
struct ExpandoRenderData;

/**
 * struct Expando - Parsed Expando trees
 *
 * The text data is stored in the tree as a pair of pointers (start, end)
 * NOT as a NUL-terminated string, to avoid memory allocations.
 * This is why the pointer of the PARSED string is required alongside the tree.
 */
struct Expando
{
  const char         *string;  ///< Pointer to the parsed string
  struct ExpandoNode *node;    ///< Parsed tree
};

void            expando_free(struct Expando **ptr);
struct Expando *expando_new (const char *format);

bool expando_equal(const struct Expando *a, const struct Expando *b);

struct Expando *expando_parse(const char *str, const struct ExpandoDefinition *defs, struct Buffer *err);

int expando_render(const struct Expando *exp, const struct ExpandoRenderData *rdata, int max_cols, struct Buffer *buf);

#endif /* MUTT_EXPANDO_EXPANDO_H */
