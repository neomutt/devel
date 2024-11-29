/**
 * @file
 * Shared code
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
 * @page expando_helpers Shared code
 *
 * Shared code
 */

#include "config.h"
#include <ctype.h>
#include <stddef.h>
#include "mutt/lib.h"
#include "helpers.h"
#include "mutt_thread.h"
#include "render.h"

/**
 * find_render_data - Find the Render Data for a DID
 * @param rdata Render Data
 * @param did   Domain ID to match
 * @retval ptr Matching Render Data
 */
const struct ExpandoRenderData *find_render_data(const struct ExpandoRenderData *rdata, int did)
{
  if (!rdata)
    return NULL;

  for (; rdata->did != -1; rdata++)
  {
    if (rdata->did == did)
      return rdata;
  }

  return NULL;
}

/**
 * find_get_number - Find a get_number() callback function
 * @param rcall Render Callbacks to search
 * @param uid   Unique ID to match
 * @retval ptr Matching get_number() Callback
 */
const get_number_t find_get_number(const struct ExpandoRenderCallback *rcall, int uid)
{
  if (!rcall)
    return NULL;

  for (; rcall->uid != -1; rcall++)
  {
    if ((rcall->uid == uid) && rcall->get_number)
      return rcall->get_number;
  }

  return NULL;
}

/**
 * find_get_string - Find a get_string() callback function
 * @param rcall Render Callbacks to search
 * @param uid   Unique ID to match
 * @retval ptr Matching get_string() Callback
 */
const get_string_t find_get_string(const struct ExpandoRenderCallback *rcall, int uid)
{
  if (!rcall)
    return NULL;

  for (; rcall->uid != -1; rcall++)
  {
    if ((rcall->uid == uid) && rcall->get_string)
      return rcall->get_string;
  }

  return NULL;
}

/**
 * buf_lower_special - Convert to lowercase, excluding special characters
 * @param buf String to lowercase
 *
 * The string is transformed in place.
 */
void buf_lower_special(struct Buffer *buf)
{
  if (!buf || !buf->data)
    return;

  char *p = buf->data;

  while (*p)
  {
    if (*p == MUTT_SPECIAL_INDEX)
    {
      p += 2;
      continue;
    }
    else if (*p < MUTT_TREE_MAX)
    {
      p++;
      continue;
    }

    *p = tolower((unsigned char) *p);
    p++;
  }
}
