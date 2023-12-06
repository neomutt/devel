/**
 * @file
 * A separated list of strings
 *
 * @authors
 * Copyright (C) 2018-2019 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_MUTT_SLIST_H
#define MUTT_MUTT_SLIST_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "list.h"

struct Buffer;

#define SLIST_SEP_SPACE (1 << 17)         ///< Slist items are space-separated
#define SLIST_SEP_COMMA (1 << 18)         ///< Slist items are comma-separated
#define SLIST_SEP_COLON (1 << 19)         ///< Slist items are colon-separated

#define SLIST_SEP_MASK  0xE0000

#define SLIST_ALLOW_DUPES    (1 << 21)    ///< Slist may contain duplicates
#define SLIST_ALLOW_EMPTY    (1 << 22)    ///< Slist may be empty
#define SLIST_CASE_SENSITIVE (1 << 23)    ///< Slist is case-sensitive

/**
 * struct Slist - String list
 */
struct Slist
{
  struct ListHead head; ///< List containing values
  size_t count;         ///< Number of values in list
  uint32_t flags;       ///< Flags controlling list, e.g. #SLIST_SEP_SPACE
};

struct Slist *slist_add_list     (struct Slist *list, const struct Slist *add);
struct Slist *slist_add_string   (struct Slist *list, const char *str);
struct Slist *slist_dup          (const struct Slist *list);
struct Slist *slist_empty        (struct Slist **list);
bool          slist_equal        (const struct Slist *a, const struct Slist *b);
void          slist_free         (struct Slist **ptr);
bool          slist_is_empty     (const struct Slist *list);
bool          slist_is_member    (const struct Slist *list, const char *str);
struct Slist *slist_new          (uint32_t flags);
struct Slist *slist_parse        (const char *str, uint32_t flags);
struct Slist *slist_remove_string(struct Slist *list, const char *str);
int           slist_to_buffer    (const struct Slist *list, struct Buffer *buf);

#endif /* MUTT_MUTT_SLIST_H */
