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

/**
 * @page expando_node_expando Expando Node
 *
 * Expando Node for an Expando
 */

#include "config.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "node_expando.h"
#include "color/lib.h"
#include "definition.h"
#include "format.h"
#include "helpers.h"
#include "mutt_thread.h"
#include "node.h"
#include "parse.h"
#include "render.h"

/**
 * node_expando_private_new - Create new Expando private data
 * @retval ptr New Expando private data
 */
struct NodeExpandoPrivate *node_expando_private_new(void)
{
  struct NodeExpandoPrivate *priv = MUTT_MEM_CALLOC(1, struct NodeExpandoPrivate);

  // NOTE(g0mb4): Expando definition should contain this
  priv->color = -1;

  return priv;
}

/**
 * node_expando_private_free - Free Expando private data - Implements ExpandoNode::ndata_free()
 * @param ptr Data to free
 */
void node_expando_private_free(void **ptr)
{
  if (!ptr || !*ptr)
    return;

  FREE(ptr);
}

/**
 * node_expando_new - Create a new Expando ExpandoNode
 * @param fmt    Formatting data
 * @param did    Domain ID
 * @param uid    Unique ID
 * @retval ptr New Expando ExpandoNode
 */
struct ExpandoNode *node_expando_new(struct ExpandoFormat *fmt, int did, int uid)
{
  struct ExpandoNode *node = node_new();

  node->type = ENT_EXPANDO;
  node->did = did;
  node->uid = uid;
  node->render = node_expando_render;

  node->format = fmt;

  node->ndata = node_expando_private_new();
  node->ndata_free = node_expando_private_free;

  return node;
}

/**
 * node_expando_set_color - Set the colour for an Expando
 * @param node Node to alter
 * @param cid  Colour
 */
void node_expando_set_color(const struct ExpandoNode *node, int cid)
{
  if (!node || (node->type != ENT_EXPANDO) || !node->ndata)
    return;

  struct NodeExpandoPrivate *priv = node->ndata;

  priv->color = cid;
}

/**
 * node_expando_set_has_tree - Set the has_tree flag for an Expando
 * @param node     Node to alter
 * @param has_tree Flag to set
 */
void node_expando_set_has_tree(const struct ExpandoNode *node, bool has_tree)
{
  if (!node || (node->type != ENT_EXPANDO) || !node->ndata)
    return;

  struct NodeExpandoPrivate *priv = node->ndata;

  priv->has_tree = has_tree;
}

/**
 * parse_format - Parse a format string
 * @param[in]  str          String to parse
 * @param[out] parsed_until First character after the parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoFormat object
 *
 * Parse a printf()-style format, e.g. '-15.20x'
 *
 * @note A trailing `_` (underscore) means lowercase the string
 */
struct ExpandoFormat *parse_format(const char *str, const char **parsed_until,
                                   struct ExpandoParseError *err)
{
  if (!str || !parsed_until || !err)
    return NULL;

  const char *start = str;

  struct ExpandoFormat *fmt = MUTT_MEM_CALLOC(1, struct ExpandoFormat);

  fmt->leader = ' ';
  fmt->justification = JUSTIFY_RIGHT;
  fmt->min_cols = 0;
  fmt->max_cols = -1;

  if (*str == '-')
  {
    fmt->justification = JUSTIFY_LEFT;
    str++;
  }
  else if (*str == '=')
  {
    fmt->justification = JUSTIFY_CENTER;
    str++;
  }

  if (*str == '0')
  {
    // Ignore '0' with left-justification
    if (fmt->justification != JUSTIFY_LEFT)
      fmt->leader = '0';
    str++;
  }

  // Parse the width (min_cols)
  if (isdigit(*str))
  {
    unsigned short number = 0;
    const char *end_ptr = mutt_str_atous(str, &number);

    if (!end_ptr || (number == USHRT_MAX))
    {
      err->position = str;
      snprintf(err->message, sizeof(err->message), _("Invalid number: %s"), str);
      FREE(&fmt);
      return NULL;
    }

    fmt->min_cols = number;
    str = end_ptr;
  }

  // Parse the precision (max_cols)
  if (*str == '.')
  {
    str++;

    unsigned short number = 1;

    if (isdigit(*str))
    {
      const char *end_ptr = mutt_str_atous(str, &number);

      if (!end_ptr || (number == USHRT_MAX))
      {
        err->position = str;
        snprintf(err->message, sizeof(err->message), _("Invalid number: %s"), str);
        FREE(&fmt);
        return NULL;
      }

      str = end_ptr;
    }
    else
    {
      number = 0;
    }

    fmt->leader = (number == 0) ? ' ' : '0';
    fmt->max_cols = number;
  }

  // A modifier of '_' before the letter means force lower case
  if (*str == '_')
  {
    fmt->lower = true;
    str++;
  }

  if (str == start) // Failed to parse anything
    FREE(&fmt);

  if (fmt && (fmt->min_cols == 0) && (fmt->max_cols == -1) && !fmt->lower)
    FREE(&fmt);

  *parsed_until = str;
  return fmt;
}

/**
 * parse_short_name - Create an expando by its short name
 * @param[in]  str          String to parse
 * @param[in]  defs         Expando definitions
 * @param[in]  flags        Flag for conditional expandos
 * @param[in]  fmt          Formatting info
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoNode
 */
struct ExpandoNode *parse_short_name(const char *str, const struct ExpandoDefinition *defs,
                                     ExpandoParserFlags flags,
                                     struct ExpandoFormat *fmt, const char **parsed_until,
                                     struct ExpandoParseError *err)
{
  if (!str || !defs)
    return NULL;

  const struct ExpandoDefinition *def = defs;
  for (; def && (def->short_name || def->long_name); def++)
  {
    size_t len = mutt_str_len(def->short_name);

    if (mutt_strn_equal(def->short_name, str, len))
    {
      if (def->parse && !(flags & EP_NO_CUSTOM_PARSE))
      {
        return def->parse(str, fmt, def->did, def->uid, flags, parsed_until, err);
      }
      else
      {
        *parsed_until = str + len;
        return node_expando_new(fmt, def->did, def->uid);
      }
    }
  }

  return NULL;
}

/**
 * parse_long_name - Create an expando by its long name
 * @param[in]  str          String to parse
 * @param[in]  defs         Expando definitions
 * @param[in]  flags        Flag for conditional expandos
 * @param[in]  fmt          Formatting info
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoNode
 */
struct ExpandoNode *parse_long_name(const char *str, const struct ExpandoDefinition *defs,
                                     ExpandoParserFlags flags,
                                     struct ExpandoFormat *fmt, const char **parsed_until,
                                     struct ExpandoParseError *err)
{
  if (!str || !defs)
    return NULL;

  const struct ExpandoDefinition *def = defs;
  for (; def && (def->short_name || def->long_name); def++)
  {
    if (!def->long_name)
      continue;

    size_t len = mutt_str_len(def->long_name);

    if (mutt_strn_equal(def->long_name, str, len))
    {
      if (def->parse && !(flags & EP_NO_CUSTOM_PARSE))
      {
        return def->parse(str, fmt, def->did, def->uid, flags, parsed_until, err);
      }
      else
      {
        *parsed_until = str + len;
        return node_expando_new(fmt, def->did, def->uid);
      }
    }
  }

  return NULL;
}

/**
 * node_expando_parse - Parse an Expando format string
 * @param[in]  str          String to parse
 * @param[in]  defs         Expando definitions
 * @param[in]  flags        Flag for conditional expandos
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoNode
 */
struct ExpandoNode *node_expando_parse(const char *str, const struct ExpandoDefinition *defs,
                                       ExpandoParserFlags flags, const char **parsed_until,
                                       struct ExpandoParseError *err)
{
  ASSERT(str[0] == '%');
  str++;

  struct ExpandoFormat *fmt = parse_format(str, parsed_until, err);
  if (err->position)
  {
    FREE(&fmt);
    return NULL;
  }

  str = *parsed_until;

  struct ExpandoNode *node = parse_short_name(str, defs, flags, fmt, parsed_until, err);
  if (node)
    return node;

  err->position = *parsed_until;
  // L10N: e.g. "Unknown expando: %Q"
  snprintf(err->message, sizeof(err->message), _("Unknown expando: %%%.1s"), *parsed_until);
  FREE(&fmt);
  return NULL;
}

/**
 * node_expando_parse_name - Parse an Expando format string
 * @param[in]  str          String to parse
 * @param[in]  defs         Expando definitions
 * @param[in]  flags        Flag for conditional expandos
 * @param[out] parsed_until First character after parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoNode
 */
struct ExpandoNode *node_expando_parse_name(const char *str,
                                            const struct ExpandoDefinition *defs,
                                            ExpandoParserFlags flags, const char **parsed_until,
                                            struct ExpandoParseError *err)
{
  ASSERT(str[0] == '%');
  str++;

  struct ExpandoFormat *fmt = parse_format(str, parsed_until, err);
  if (err->position)
    goto fail;

  str = *parsed_until;

  if (str[0] != '{')
    goto fail;

  str++;

  struct ExpandoNode *node = parse_long_name(str, defs, flags, fmt, parsed_until, err);
  fmt = NULL; // owned by the node, now

  if (!node)
    goto fail;

  if ((*parsed_until)[0] == '}')
  {
    (*parsed_until)++;
    return node;
  }

  node_free(&node);

fail:
  FREE(&fmt);
  return NULL;
}

/**
 * skip_until_ch - Search a string for a terminator character
 * @param str        Start of string
 * @param terminator Character to find
 * @retval ptr Position of terminator character, or end-of-string
 */
const char *skip_until_ch(const char *str, char terminator)
{
  while (str[0] != '\0')
  {
    if (*str == terminator)
      break;

    if (str[0] == '\\') // Literal character
    {
      if (str[1] == '\0')
        return str + 1;

      str++;
    }

    str++;
  }

  return str;
}

/**
 * node_expando_parse_enclosure - Parse an enclosed Expando
 * @param[in]  str          String to parse
 * @param[in]  did          Domain ID
 * @param[in]  uid          Unique ID
 * @param[in]  terminator   Terminating character
 * @param[in]  fmt          Formatting info
 * @param[out] parsed_until First character after the parsed string
 * @param[out] err          Buffer for errors
 * @retval ptr New ExpandoNode
 */
struct ExpandoNode *node_expando_parse_enclosure(const char *str, int did,
                                                 int uid, char terminator,
                                                 struct ExpandoFormat *fmt,
                                                 const char **parsed_until,
                                                 struct ExpandoParseError *err)

{
  str++; // skip opening char

  const char *expando_end = skip_until_ch(str, terminator);

  if (*expando_end != terminator)
  {
    err->position = expando_end;
    snprintf(err->message, sizeof(err->message),
             // L10N: Expando is missing a terminator character
             //       e.g. "%[..." is missing the final ']'
             _("Expando is missing terminator: '%c'"), terminator);
    return NULL;
  }

  *parsed_until = expando_end + 1;

  struct ExpandoNode *node = node_expando_new(fmt, did, uid);

  struct Buffer *buf = buf_pool_get();
  for (; str < expando_end; str++)
  {
    if (str[0] == '\\')
      continue;
    buf_addch(buf, str[0]);
  }

  node->text = buf_strdup(buf);
  buf_pool_release(&buf);

  return node;
}

/**
 * add_color - Add a colour code to a buffer
 * @param buf Buffer for colour code
 * @param cid Colour
 */
void add_color(struct Buffer *buf, enum ColorId cid)
{
  ASSERT(cid < MT_COLOR_MAX);

  buf_addch(buf, MUTT_SPECIAL_INDEX);
  buf_addch(buf, cid);
}

/**
 * node_expando_render - Render an Expando Node - Implements ExpandoNode::render() - @ingroup expando_render
 */
int node_expando_render(const struct ExpandoNode *node,
                        const struct ExpandoRenderCallback *erc, struct Buffer *buf,
                        int max_cols, void *data, MuttFormatFlags flags)
{
  ASSERT(node->type == ENT_EXPANDO);

  struct Buffer *buf_expando = buf_pool_get();
  struct Buffer *buf_format = buf_pool_get();

  const struct ExpandoFormat *fmt = node->format;
  const struct NodeExpandoPrivate *priv = node->ndata;

  // ---------------------------------------------------------------------------
  // Numbers and strings get treated slightly differently. We prefer strings.
  // This allows dates to be stored as 1729850182, but displayed as "2024-10-25".

  const struct ExpandoRenderCallback *erc_match = find_get_string(erc, node->did, node->uid);
  if (erc_match)
  {
    erc_match->get_string(node, data, flags, buf_expando);

    if (fmt && fmt->lower)
      buf_lower_special(buf_expando);
  }
  else
  {
    erc_match = find_get_number(erc, node->did, node->uid);
    ASSERT(erc_match && "Unknown UID");

    const long num = erc_match->get_number(node, data, flags);

    int precision = 1;

    if (fmt)
    {
      precision = fmt->max_cols;
      if ((precision < 0) && (fmt->leader == '0'))
        precision = fmt->min_cols;
    }

    if (num < 0)
      precision--; // Allow space for the '-' sign

    buf_printf(buf_expando, "%.*ld", precision, num);
  }

  // ---------------------------------------------------------------------------

  int max = max_cols;
  int min = 0;

  if (fmt)
  {
    min = fmt->min_cols;
    if (fmt->max_cols > 0)
      max = MIN(max_cols, fmt->max_cols);
  }

  const enum FormatJustify just = fmt ? fmt->justification : JUSTIFY_LEFT;

  int total_cols = format_string(buf_format, min, max, just, ' ', buf_string(buf_expando),
                                 buf_len(buf_expando), priv->has_tree);

  if (!buf_is_empty(buf_format))
  {
    if (priv->color > -1)
      add_color(buf, priv->color);

    buf_addstr(buf, buf_string(buf_format));

    if (priv->color > -1)
      add_color(buf, MT_COLOR_INDEX);
  }

  buf_pool_release(&buf_format);
  buf_pool_release(&buf_expando);

  return total_cols;
}
