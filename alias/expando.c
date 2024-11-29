/**
 * @file
 * Alias Expando definitions
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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
 * @page alias_expando Alias Expando definitions
 *
 * Alias Expando definitions
 */

#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "expando.h"
#include "lib.h"
#include "expando/lib.h"
#include "alias.h"
#include "gui.h"

/**
 * alias_address - Alias: Full Address - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_address(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;
  const struct Alias *alias = av->alias;

  mutt_addrlist_write(&alias->addr, buf, true);
}

/**
 * alias_alias - Alias: Alias name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_alias(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;
  const struct Alias *alias = av->alias;

  const char *s = alias->name;
  buf_strcpy(buf, s);
}

/**
 * alias_comment - Alias: Comment - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_comment(const struct ExpandoNode *node, void *data,
                          MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;
  const struct Alias *alias = av->alias;

  const char *s = alias->comment;
  buf_strcpy(buf, s);
}

/**
 * alias_email - Alias: Email Address - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_email(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;
  const struct Alias *alias = av->alias;

  struct Address *a = NULL;
  TAILQ_FOREACH(a, &alias->addr, entries)
  {
    struct Address *next = TAILQ_NEXT(a, entries);

    buf_add_printf(buf, "<%s>", buf_string(a->mailbox));
    if (next)
      buf_addstr(buf, ", ");
  }
}

/**
 * alias_name - Alias: Personal Name - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_name(const struct ExpandoNode *node, void *data,
                       MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;
  const struct Alias *alias = av->alias;

  struct Address *a = NULL;
  TAILQ_FOREACH(a, &alias->addr, entries)
  {
    struct Address *next = TAILQ_NEXT(a, entries);

    buf_addstr(buf, buf_string(a->personal));
    if (next)
      buf_addstr(buf, ", ");
  }
}

/**
 * alias_tags - Alias: Tags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_tags(const struct ExpandoNode *node, void *data,
                       MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;

  alias_tags_to_buffer(&av->alias->tags, buf);
}

/**
 * alias_view_flags - AliasView: Flags - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_view_flags(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;

  // NOTE(g0mb4): use $flag_chars?
  const char *s = av->is_deleted ? "D" : " ";
  buf_strcpy(buf, s);
}

/**
 * alias_view_flags_num - AliasView: Flags - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long alias_view_flags_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AliasView *av = data;
  return av->is_deleted;
}

/**
 * alias_view_index_num - AliasView: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long alias_view_index_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AliasView *av = data;

  return av->num + 1;
}

/**
 * alias_view_tagged - AliasView: Tagged char - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void alias_view_tagged(const struct ExpandoNode *node, void *data,
                              MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AliasView *av = data;

  // NOTE(g0mb4): use $flag_chars?
  const char *s = av->is_tagged ? "*" : " ";
  buf_strcpy(buf, s);
}

/**
 * alias_view_tagged_num - AliasView: Tagged char - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long alias_view_tagged_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AliasView *av = data;
  return av->is_tagged;
}

/**
 * AliasRenderCallbacks - Callbacks for Alias Expandos
 *
 * @sa AliasFormatDef, ExpandoDataAlias
 */
const struct ExpandoRenderCallback AliasRenderCallbacks[] = {
  // clang-format off
  { ED_ALIAS, ED_ALI_ADDRESS, alias_address,     NULL },
  { ED_ALIAS, ED_ALI_ALIAS,   alias_alias,       NULL },
  { ED_ALIAS, ED_ALI_COMMENT, alias_comment,     NULL },
  { ED_ALIAS, ED_ALI_EMAIL,   alias_email,       NULL },
  { ED_ALIAS, ED_ALI_FLAGS,   alias_view_flags,  alias_view_flags_num },
  { ED_ALIAS, ED_ALI_NAME,    alias_name,        NULL },
  { ED_ALIAS, ED_ALI_NUMBER,  NULL,              alias_view_index_num },
  { ED_ALIAS, ED_ALI_TAGGED,  alias_view_tagged, alias_view_tagged_num },
  { ED_ALIAS, ED_ALI_TAGS,    alias_tags,        NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};
